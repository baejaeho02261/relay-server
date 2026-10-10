'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const config = require('../config/config');
const state = require('../core/state');

const { HOST, PORT, HEALTH_PORT, DATA_DIR, DB_FILE, DB_BAK_FILE, BACKUP_DIR, AUDIT_DIR, CURRENT_PROTOCOL_VERSION, DEFAULT_MIN_PROTOCOL_VERSION, DEFAULT_MIN_SERVER_VERSION, DEFAULT_MIN_CLIENT_VERSION, ADMIN_CREDENTIALS, ADMIN_AUTH_WINDOW_SECONDS, ADMIN_SESSION_TIMEOUT_MS, CONFIRM_TOKEN_TTL_MS, SERVER_KICK_BLOCK_MS, CLIENT_KICK_BLOCK_MS, RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX, MAX_CLIENTS_PER_SERVER, REQUEST_HISTORY_TIMEOUT_MS, ACK_RETRY_MS, ACK_TIMEOUT_MS, ACK_MAX_RETRIES, MAX_INPUT_BUFFER, MAX_BULK_KEYS, MAX_SEARCH_RESULTS, MAX_EVENT_MEMORY, AUTO_BACKUP_INTERVAL_MS, MAX_BACKUPS, DANGEROUS_PREFIXES } = config;
const { servers, clients, serverIdentities, clientIdentities, licenses, disabledServers, drainingServers, disabledClients, kickedServers, kickedClients, requestHistory, pendingRequests, rateLimits, events, confirmTokens, ipHistory, runtimeStats } = state;

function Now(...args) { return require('../core/utils').Now(...args); }
function SafeField(...args) { return require('../core/utils').SafeField(...args); }

function AuditFileForTime(ms) {
    const d = new Date(ms);
    const yyyy = d.getUTCFullYear();
    const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
    const dd = String(d.getUTCDate()).padStart(2, '0');
    return path.join(AUDIT_DIR, `audit-${yyyy}-${mm}-${dd}.jsonl`);
}

function EventHash(previousHash, sequence, time, type, detail) {
    return crypto.createHash('sha256')
        .update(`${previousHash}|${sequence}|${time}|${type}|${detail}`, 'utf8')
        .digest('hex').toUpperCase();
}

let operationIndex = new Map(), indexLoaded = false, poisoned = false;
const operationIdPattern = /^[a-f0-9]{64}$/;
function IndexOperation(event) {
    try {
        const detail = JSON.parse(event.detail);
        if (!operationIdPattern.test(detail.auditEventId || '')) return;
        const fingerprint = EventHash('', 0, 0, event.type, event.detail), old = operationIndex.get(detail.auditEventId);
        if (old && old.fingerprint !== fingerprint) throw Error('AUDIT_OPERATION_CONFLICT');
        operationIndex.set(detail.auditEventId, { fingerprint, sequence:event.sequence, hash:event.hash });
    } catch (error) { if (error.message === 'AUDIT_OPERATION_CONFLICT') throw error; }
}
const writeHealth = { status:'UNKNOWN', failedWrites:0, lastFailureAt:0, lastSuccessAt:0, lastErrorCode:'', lastDurableSequence:0 };
function WriteHealth() { return {...writeHealth, sinceProcessStart:true, missingRecordsRecovered:false}; }
function LogEvent(type, detail, options = {}) {
    const chain = state.production.auditChain;
    const event = {
        time: Now(), type: SafeField(type), detail: SafeField(detail),
        sequence: Math.max(0, Number(chain.count) || 0) + 1,
        previousHash: String(chain.head || '').toUpperCase()
    };
    event.hash = EventHash(event.previousHash, event.sequence, event.time, event.type, event.detail);
    let fd, beforeSize;
    try {
        if (poisoned) { const error = Error('audit rollback failed'); error.code = 'AUDIT_RESTART_REQUIRED'; throw error; }
        fd = fs.openSync(AuditFileForTime(event.time), 'a', 0o600);
        beforeSize = fs.fstatSync(fd).size;
        fs.writeFileSync(fd, JSON.stringify(event) + '\n', 'utf8');
        if (options.durable === true) {
            fs.fsyncSync(fd);
            // The daily audit filename must precede the journal ACK durably,
            // including when an earlier non-durable event created this file.
            if(process.platform!=='win32'){
                const directory=fs.openSync(AUDIT_DIR,'r');
                try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}
            }
        }
        fs.closeSync(fd); fd = undefined;
        // Never advance the chain or publish an event whose append failed.
        chain.head = event.hash; chain.count = event.sequence;
        IndexOperation(event);
        events.push(event); while (events.length > MAX_EVENT_MEMORY) events.shift();
        console.log('[EVENT]', event.type, event.detail);
        try { require('../web/webEvents').BroadcastEvent(event); } catch (_) {}
        try { require('../services/notificationCenter').CaptureEvent(event); } catch (_) {}
        try { require('../services/incidentCenter').CaptureEvent(event); } catch (_) {}
        if (options.durable === true) writeHealth.lastDurableSequence = event.sequence;
        writeHealth.status='HEALTHY';writeHealth.lastSuccessAt=event.time;writeHealth.lastErrorCode='';
        return {ok:true,sequence:event.sequence,hash:event.hash,durable:options.durable===true};
    } catch (error) {
        if (fd !== undefined) {
            try { if (beforeSize !== undefined) { fs.ftruncateSync(fd, beforeSize); fs.fsyncSync(fd); } }
            catch (_) { poisoned = true; }
            finally { try { fs.closeSync(fd); } catch (_) {} }
        }
        writeHealth.status='DEGRADED';writeHealth.failedWrites++;writeHealth.lastFailureAt=event.time;
        writeHealth.lastErrorCode=/^[A-Z0-9_]{1,40}$/.test(String(error.code||''))?error.code:'WRITE_FAILED';
        console.error('AUDIT WRITE ERROR:', writeHealth.lastErrorCode);
        const signal={time:event.time,type:'AUDIT_WRITE_FAILED',detail:'Server audit storage unavailable; failed writes: '+writeHealth.failedWrites};
        // Do not call LogEvent recursively when the audit storage itself fails.
        try { require('../services/incidentCenter').CaptureEvent(signal); } catch (_) {}
        try { require('../services/notificationCenter').CaptureEvent(signal); } catch (_) {}
        return {ok:false,sequence:event.sequence,errorCode:writeHealth.lastErrorCode};
    }
}

function LoadRecentAudit() {
    try {
        events.length = 0; operationIndex = new Map(); indexLoaded = false;
        const files = fs.readdirSync(AUDIT_DIR)
            .filter(x => /^audit-\d{4}-\d{2}-\d{2}\.jsonl$/.test(x))
            .sort();
        const loaded = [];
        const chainAnchor = String(state.production.auditChain.anchor || '').toUpperCase();
        let expectedPrevious = chainAnchor;
        let verifiedCount = 0;
        let lastError = '';
        for (const file of files) {
            const filename=path.join(AUDIT_DIR,file);
            const raw=fs.readFileSync(filename,'utf8'),lines=raw.split(/\r?\n/);
            for (let lineIndex=0;lineIndex<lines.length;lineIndex++) {
                const line=lines[lineIndex],unterminated=file===files.at(-1)&&lineIndex===lines.length-1&&raw&&!raw.endsWith('\n');
                function RepairTail(complete){
                    const fd=fs.openSync(filename,'r+');
                    try{if(complete)fs.writeSync(fd,'\n',Buffer.byteLength(raw));else fs.ftruncateSync(fd,Buffer.byteLength(raw.slice(0,raw.lastIndexOf('\n')+1)));fs.fsyncSync(fd);}
                    finally{fs.closeSync(fd);}
                }
                if (!line.trim()) continue;
                try {
                    const item = JSON.parse(line);
                    const normalized = {
                        time: Number(item.time) || 0, type: SafeField(item.type), detail: SafeField(item.detail),
                        sequence: Number(item.sequence) || 0,
                        previousHash: String(item.previousHash || '').toUpperCase(),
                        hash: String(item.hash || '').toUpperCase()
                    };
                    // Legacy audit rows remain readable, but a signed chain
                    // starts only at the first row carrying chain metadata.
                    if (normalized.sequence && normalized.hash) {
                        const computed = EventHash(normalized.previousHash, normalized.sequence, normalized.time, normalized.type, normalized.detail);
                        if (normalized.previousHash !== expectedPrevious || computed !== normalized.hash) {
                            if (!lastError) lastError = `${file}:${normalized.sequence}`;
                        } else {
                            expectedPrevious = normalized.hash;
                            verifiedCount = normalized.sequence;
                            if (!lastError) IndexOperation(normalized);
                        }
                    }
                    if(unterminated&&!lastError)RepairTail(true);
                    loaded.push(normalized);
                } catch (error) {
                    // Repair only an interrupted final append after a verified
                    // prefix. Complete corrupt rows remain fatal and untouched.
                    if(unterminated&&!lastError&&error instanceof SyntaxError)RepairTail(false);
                    else if (!lastError) lastError = file + ':INVALID_ROW';
                }
            }
        }
        loaded.sort((a, b) => a.time - b.time);
        for (const item of loaded.slice(-MAX_EVENT_MEMORY)) events.push(item);
        state.production.auditChain.head = expectedPrevious;
        state.production.auditChain.anchor = chainAnchor;
        state.production.auditChain.count = verifiedCount;
        state.production.auditChain.verifiedAt = Now();
        state.production.auditChain.lastError = lastError;
        indexLoaded = true;
    } catch (error) { state.production.auditChain.lastError = 'AUDIT_LOAD_FAILED'; }
}

function VerifyAuditChain() {
    const previousEvents = events.slice();
    events.length = 0;
    LoadRecentAudit();
    const result = {
        ok: !state.production.auditChain.lastError,
        checkedAt: state.production.auditChain.verifiedAt,
        count: state.production.auditChain.count,
        head: state.production.auditChain.head,
        error: state.production.auditChain.lastError
    };
    // LoadRecentAudit already restored the most recent authoritative view.
    if (!events.length && previousEvents.length) events.push(...previousEvents.slice(-MAX_EVENT_MEMORY));
    return result;
}

// The caller first commits this event intent to its durable journal. Only
// verified audit rows may satisfy a retry after an append/ACK crash boundary.
function AppendOperationEvent(auditEventId, type, detail) {
    if (!operationIdPattern.test(auditEventId || '') || !detail || typeof detail !== 'object' || Array.isArray(detail)) throw Error('AUDIT_OPERATION_INVALID');
    if (!indexLoaded) LoadRecentAudit();
    if (!indexLoaded || state.production.auditChain.lastError || poisoned) throw Error('AUDIT_CHAIN_UNAVAILABLE');
    const text = SafeField(JSON.stringify({ ...detail, auditEventId })), normalizedType = SafeField(type);
    const fingerprint = EventHash('', 0, 0, normalizedType, text), old = operationIndex.get(auditEventId);
    if (old) {
        if (old.fingerprint !== fingerprint) throw Error('AUDIT_OPERATION_CONFLICT');
        return { ok:true, duplicate:true, sequence:old.sequence, hash:old.hash, durable:true };
    }
    return LogEvent(normalizedType, text, { durable:true });
}

function AuditSearch(query, type, sinceMs) {
    query = String(query || '').trim().toUpperCase();
    type = String(type || '').trim().toUpperCase();
    sinceMs = Number(sinceMs) || 0;
    return events.filter(e => {
        if (sinceMs && e.time < sinceMs) return false;
        if (type && type !== 'ALL' && e.type.toUpperCase() !== type) return false;
        if (query && !`${e.type}|${e.detail}`.toUpperCase().includes(query)) return false;
        return true;
    }).slice(-MAX_SEARCH_RESULTS);
}

function ClearAudit() {
    const removedMemory = events.length;
    events.length = 0;
    let removedFiles = 0;
    try {
        for (const file of fs.readdirSync(AUDIT_DIR)) {
            if (!/^audit-\d{4}-\d{2}-\d{2}\.jsonl$/.test(file)) continue;
            try { fs.unlinkSync(path.join(AUDIT_DIR, file)); removedFiles++; } catch (_) {}
        }
    } catch (_) {}
    state.production.auditChain = { anchor: '', head: '', count: 0, verifiedAt: Now(), lastError: '' };
    operationIndex.clear(); indexLoaded = true;
    return { removedMemory, removedFiles };
}

module.exports = {
    AppendOperationEvent,
    WriteHealth,
    AuditFileForTime,
    LogEvent,
    LoadRecentAudit,
    AuditSearch,
    ClearAudit,
    VerifyAuditChain
};
