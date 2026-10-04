'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const config = require('../config/config');
const state = require('../core/state');
// Historical license records are retained for database compatibility only.
const Expired = license => !(license?.entryPass === true && Number(license.expiresAt) === 0) && Number(license?.expiresAt) <= Date.now();
const IsEntry = license => license?.entryPass === true;

const { HOST, PORT, HEALTH_PORT, DATA_DIR, DB_FILE, DB_BAK_FILE, BACKUP_DIR, AUDIT_DIR, CURRENT_PROTOCOL_VERSION, DEFAULT_MIN_PROTOCOL_VERSION, DEFAULT_MIN_SERVER_VERSION, DEFAULT_MIN_CLIENT_VERSION, ADMIN_CREDENTIALS, ADMIN_AUTH_WINDOW_SECONDS, ADMIN_SESSION_TIMEOUT_MS, CONFIRM_TOKEN_TTL_MS, SERVER_KICK_BLOCK_MS, CLIENT_KICK_BLOCK_MS, RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX, MAX_CLIENTS_PER_SERVER, REQUEST_HISTORY_TIMEOUT_MS, ACK_RETRY_MS, ACK_TIMEOUT_MS, ACK_MAX_RETRIES, MAX_INPUT_BUFFER, MAX_BULK_KEYS, MAX_SEARCH_RESULTS, MAX_EVENT_MEMORY, AUTO_BACKUP_INTERVAL_MS, MAX_BACKUPS, DANGEROUS_PREFIXES } = config;
const { servers, clients, serverIdentities, clientIdentities, licenses, disabledServers, drainingServers, disabledClients, kickedServers, kickedClients, requestHistory, pendingRequests, rateLimits, events, confirmTokens, ipHistory, runtimeStats } = state;

function GetOnlineClient(...args) { return require('../identity/identityManager').GetOnlineClient(...args); }
function GetSavedClientByID(...args) { return require('../identity/identityManager').GetSavedClientByID(...args); }
function LogEvent(...args) { return require('../storage/audit').LogEvent(...args); }
function NormalizeID(...args) { return require('../core/utils').NormalizeID(...args); }
function NormalizeLicenseKey(...args) { return require('../core/utils').NormalizeLicenseKey(...args); }
function NotifyServerUnauthorized(...args) { return require('../relay/notifications').NotifyServerUnauthorized(...args); }
function Now(...args) { return require('../core/utils').Now(...args); }
function RandomLicenseKey(...args) { return require('../core/utils').RandomLicenseKey(...args); }
function SafeField(...args) { return require('../core/utils').SafeField(...args); }
function SafeIP(...args) { return require('../core/utils').SafeIP(...args); }
function SaveDatabase(...args) { return require('../storage/database').SaveDatabase(...args); }
function SendLine(...args) { return require('../core/utils').SendLine(...args); }
function PersistLicenseChange() { state.licenseRevision = Math.max(0, Number(state.licenseRevision) || 0) + 1; return SaveDatabase(); }

function NormalizeTags(value) {
    const items = Array.isArray(value) ? value : String(value || '').split(',');
    const out = [];
    for (const raw of items) {
        const tag = SafeField(raw || '').trim().toUpperCase().replace(/[^A-Z0-9_가-힣-]/g, '').slice(0, 24);
        if (tag && !out.includes(tag)) out.push(tag);
        if (out.length >= 10) break;
    }
    return out;
}

function FindLicense(key) {
    return licenses.get(NormalizeLicenseKey(key)) || null;
}

function GetBoundLicenseEntry(clientId) {
    clientId = NormalizeID(clientId);
    for (const [key, license] of licenses) {
        if (license.boundClient === clientId) return { key, license };
    }
    return null;
}

function GetLicenseStatus(license) {
    if (!license) return 'UNKNOWN';
    if (license.suspended) return 'SUSPENDED';
    if (Expired(license)) return 'EXPIRED';
    if (license.boundClient) return 'BOUND';
    return 'AVAILABLE';
}

function CreateLicense(days, memo, tags = [], source = 'LICENSE', persist = true) {
    let key;
    do { key = RandomLicenseKey(); } while (licenses.has(key));
    const now = Now();
    const license = {
        createdAt: now, expiresAt: now + days * 86400000,
        boundClient: '', boundAt: 0, lastAuthAt: 0, lastSeenAt: 0, lastIP: '',
        authCount: 0, sendCount: 0, suspended: false, memo: SafeField(memo), tags: NormalizeTags(tags), accessType: 'TYPE1'
    };
    licenses.set(key, license);
    if (persist && !PersistLicenseChange()) { licenses.delete(key); return null; }
    LogEvent('LICENSE_CREATE', key);
    setImmediate(() => { try { require('../services/licenseMonitor').ScanLicenseExpiryAlerts(); } catch (_) {} });
    return { key, expiresAt: license.expiresAt };
}


function SetLicenseTags(key, tags) {
    const license = FindLicense(key);
    if (!license) return false;
    license.tags = NormalizeTags(tags);
    PersistLicenseChange();
    LogEvent('LICENSE_TAGS', `${NormalizeLicenseKey(key)} -> ${license.tags.join(',') || '(cleared)'}`);
    return license.tags;
}

function ExtendLicense(key, days) {
    const license = FindLicense(key);
    if (!license || IsEntry(license)) return false;
    license.expiresAt = Math.max(Now(), license.expiresAt) + days * 86400000;
    if (license.boundClient) {
        const client = GetOnlineClient(license.boundClient);
        if (client && client.licenseAuthorized && client.licenseKey === NormalizeLicenseKey(key)) {
            client.licenseExpiresAt = license.expiresAt;
            SendLine(client.socket, `LICENSE_UPDATED|${license.expiresAt}`);
        }
    }
    PersistLicenseChange();
    return true;
}

function RevokeLiveLicense(clientId, reason) {
    const client = GetOnlineClient(clientId);
    if (client) {
        client.licenseAuthorized = false;
        client.licenseExpiresAt = 0;
        client.accessType = '';
        client.lastServerAuthState = '';
        SendLine(client.socket, `LICENSE_ERROR|${reason}`);
    }
    NotifyServerUnauthorized(clientId, reason);
}

function UnbindLicense(key) {
    key = NormalizeLicenseKey(key);
    const license = FindLicense(key);
    if (!license) return false;
    const oldClient = license.boundClient;
    license.boundClient = '';
    license.boundAt = 0;
    license.lastAuthAt = 0;
    license.lastSeenAt = 0;
    license.lastIP = '';
    if (oldClient) RevokeLiveLicense(oldClient, 'UNBOUND');
    PersistLicenseChange();
    return true;
}

function SuspendLicense(key) {
    const license = FindLicense(key);
    if (!license) return false;
    license.suspended = true;
    if (license.boundClient) RevokeLiveLicense(license.boundClient, 'SUSPENDED');
    PersistLicenseChange();
    return true;
}

function ResumeLicense(key) {
    const license = FindLicense(key);
    if (!license || Expired(license)) return false;
    license.suspended = false;
    if (license.boundClient) {
        const client = GetOnlineClient(license.boundClient);
        if (client) SendLine(client.socket, `LICENSE_STATE|RESUMED|${license.expiresAt}`);
    }
    PersistLicenseChange();
    return true;
}

function DeleteLicense(key) {
    key = NormalizeLicenseKey(key);
    const license = FindLicense(key);
    if (!license) return false;
    const clientId = license.boundClient;
    licenses.delete(key);
    if (clientId) RevokeLiveLicense(clientId, 'REVOKED');
    PersistLicenseChange();
    return true;
}

function ReissueLicense(oldKey) {
    oldKey = NormalizeLicenseKey(oldKey);
    const old = FindLicense(oldKey);
    if (!old || Expired(old)) return null;
    let newKey;
    do { newKey = RandomLicenseKey(); } while (licenses.has(newKey));
    const copy = { ...old, createdAt: Now(), lastAuthAt: 0, lastSeenAt: 0, lastIP: '', authCount: 0, sendCount: 0, suspended: false };
    const oldClient = old.boundClient;
    licenses.set(newKey, copy);
    licenses.delete(oldKey);
    if (oldClient) RevokeLiveLicense(oldClient, 'REISSUED');
    PersistLicenseChange();
    LogEvent('LICENSE_REISSUE', `${oldKey} -> ${newKey}`);
    return { oldKey, newKey, expiresAt: copy.expiresAt };
}

function TransferLicense(key, newClientId) {
    key = NormalizeLicenseKey(key);
    newClientId = NormalizeID(newClientId);
    const license = FindLicense(key);
    if (!license) return { ok: false, reason: 'NOT_FOUND' };
    if (!GetSavedClientByID(newClientId)) return { ok: false, reason: 'CLIENT_NOT_FOUND' };
    const existing = GetBoundLicenseEntry(newClientId);
    if (existing && existing.key !== key) return { ok: false, reason: 'CLIENT_ALREADY_LICENSED' };
    const oldClient = license.boundClient;
    license.boundClient = newClientId;
    license.boundAt = Now();
    license.lastAuthAt = 0;
    license.lastSeenAt = 0;
    license.lastIP = '';
    if (oldClient && oldClient !== newClientId) RevokeLiveLicense(oldClient, 'TRANSFERRED');
    const target = GetOnlineClient(newClientId);
    if (target) NotifyServerUnauthorized(newClientId, 'LICENSE_REQUIRED');
    PersistLicenseChange();
    LogEvent('LICENSE_TRANSFER', `${key} -> ${newClientId}`);
    return { ok: true };
}

function SendLicenseItem(socket, key, license) {
    SendLine(socket, [
        'LIC_ITEM', key, GetLicenseStatus(license), license.expiresAt,
        license.boundClient || '', SafeField(license.memo), license.createdAt,
        license.boundAt, license.lastAuthAt, license.lastSeenAt,
        license.lastIP, license.authCount, license.sendCount
    ].join('|'));
}

function SearchLicenses(query, status) {
    query = String(query || '').trim().toUpperCase();
    status = String(status || 'ALL').trim().toUpperCase();
    const tagQuery = query.startsWith('TAG:') ? query.substring(4).trim() : '';
    const out = [];
    for (const [key, license] of licenses) {
        const st = GetLicenseStatus(license);
        if (status !== 'ALL' && st !== status) continue;
        const tags = NormalizeTags(license.tags || []);
        if (tagQuery) {
            if (!tags.includes(tagQuery)) continue;
        } else if (query && !`${key}|${license.boundClient}|${license.memo}|${tags.join(',')}`.toUpperCase().includes(query)) continue;
        out.push({ key, license });
        if (out.length >= MAX_SEARCH_RESULTS) break;
    }
    return out;
}

module.exports = {
    NormalizeTags,
    FindLicense,
    GetBoundLicenseEntry,
    GetLicenseStatus,
    CreateLicense,
    SetLicenseTags,
    ExtendLicense,
    RevokeLiveLicense,
    UnbindLicense,
    SuspendLicense,
    ResumeLicense,
    DeleteLicense,
    ReissueLicense,
    TransferLicense,
    SendLicenseItem,
    SearchLicenses,
};
