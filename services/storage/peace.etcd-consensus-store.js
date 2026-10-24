'use strict';
// Standalone shared-state adapter. NOT integrated with Relay Server's local stores.
// Ownership and the data mutation are compared/committed inside the SAME etcd
// transaction. A successful Acquire is never permission to write local files.
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const { Parse } = require("../protocol/peace.strict-json");
const MAX_BODY = 1024 * 1024;
const MAX_STATE = 256 * 1024;
const INTEGRATION = Object.freeze({ backend: 'etcd-v3', status: 'NOT_INTEGRATED', serverMultiwriterEnabled: false });
function Fail(code, uncertain = false) { const e = Error(code); e.code = code; e.outcomeUnknown = uncertain; return e; }
function Decimal(value, zero = false, unsigned = false) {
    if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) || (!zero && value === '0') || BigInt(value) > (unsigned ? 18446744073709551615n : 9223372036854775807n)) throw Fail('CONSENSUS_INTEGER_INVALID');
    return value;
}
function Name(value) { if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(value)) throw Fail('CONSENSUS_NAME_INVALID'); return value; }
function B64(value) { return Buffer.from(value).toString('base64'); }
function Decode(value) {
    if (typeof value !== 'string' || value.length > MAX_BODY || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw Fail('CONSENSUS_RESPONSE_INVALID');
    return Buffer.from(value, 'base64');
}
function Compare(key, target, field, value) { return { key: B64(key), target, result: 'EQUAL', [field]: value }; }
function Range(key) { return { request_range: { key: B64(key), serializable: false } }; }
function Row(response, key) {
    if (!response || response.more || (response.kvs && (!Array.isArray(response.kvs) || response.kvs.length > 1))) throw Fail('CONSENSUS_RESPONSE_INVALID');
    const row = response.kvs?.[0];
    if (!row) { if (response.count !== undefined && response.count !== '0') throw Fail('CONSENSUS_RESPONSE_INVALID'); return null; }
    if (row.key !== B64(key)) throw Fail('CONSENSUS_RESPONSE_INVALID');
    Decimal(row.create_revision); Decimal(row.mod_revision); Decimal(row.version);
    return { ...row, bytes: Decode(row.value || '') };
}
function Json(bytes) { try { return Parse(bytes, { maxBytes: MAX_BODY, maxNodes: 100000 }); } catch (_) { throw Fail('CONSENSUS_RESPONSE_INVALID'); } }

class EtcdConsensusStore {
    #endpoints; #cluster; #prefix; #token; #tls; #timeout; #next = 0; #ready = false; #session = null; #acquiring = false; #verified = new Set();
    constructor({ endpoints, expectedClusterId, namespace, token = '', tls = {}, timeoutMs = 3000, allowInsecureLoopback = false } = {}) {
        if (!Array.isArray(endpoints) || endpoints.length < 1 || endpoints.length > 9 || new Set(endpoints).size !== endpoints.length) throw Fail('CONSENSUS_ENDPOINT_INVALID');
        this.#endpoints = endpoints.map(value => {
            let u; try { u = new URL(value); } catch (_) { throw Fail('CONSENSUS_ENDPOINT_INVALID'); }
            const local = ['127.0.0.1', '[::1]'].includes(u.hostname);
            if (u.username || u.password || u.search || u.hash || u.pathname !== '/' || (u.protocol !== 'https:' && !(allowInsecureLoopback === true && local && u.protocol === 'http:'))) throw Fail('CONSENSUS_ENDPOINT_INVALID');
            return u.origin;
        });
        this.#cluster = Decimal(expectedClusterId, false, true);
        this.#prefix = '/gameconnect-consensus-v1/' + Name(namespace);
        if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > 30000) throw Fail('CONSENSUS_TIMEOUT_INVALID');
        if (typeof token !== 'string' || token.length > 16384 || /[^\x21-\x7e]/.test(token)) throw Fail('CONSENSUS_AUTH_INVALID');
        if (!tls || Object.getPrototypeOf(tls) !== Object.prototype || Object.keys(tls).some(k => !['ca', 'cert', 'key', 'passphrase'].includes(k))) throw Fail('CONSENSUS_TLS_INVALID');
        this.#token = token; this.#tls = { ...tls }; this.#timeout = timeoutMs;
    }
    Status() { return { ...INTEGRATION, connected: this.#ready, ownership: this.#session ? 'LEASE_HELD_ADVISORY' : 'NONE', fenceRevision: this.#session?.revision || null }; }
    #header(response) {
        if (!response || typeof response !== 'object' || response.error || response.code || response.header?.cluster_id !== this.#cluster) throw Fail('CONSENSUS_CLUSTER_OR_RESPONSE_INVALID');
        Decimal(response.header.revision, true);
        return response;
    }
    async #request(path, body, { mutation = false, stream = false, endpoint } = {}) {
        const index = endpoint === undefined ? this.#next : endpoint;
        // An endpoint unavailable during Connect must pass a read-only cluster
        // identity check before a later failover can send it any mutation.
        if (mutation && !this.#verified.has(index)) await this.#request('/v3/kv/range', { key: B64(this.#prefix + '/owner'), serializable: false }, { endpoint: index });
        const url = new URL(path, this.#endpoints[index]);
        const bytes = Buffer.from(JSON.stringify(body));
        if (bytes.length > MAX_BODY) throw Fail('CONSENSUS_REQUEST_TOO_LARGE');
        try {
            const result = await new Promise((resolve, reject) => {
                let settled = false, timer, size = 0; const chunks = [];
                const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : resolve(value); };
                const req = (url.protocol === 'https:' ? https : http).request(url, {
                    ...this.#tls, method: 'POST', minVersion: 'TLSv1.2', rejectUnauthorized: true,
                    headers: { 'content-type': 'application/json', 'content-length': bytes.length, ...(this.#token ? { authorization: this.#token } : {}) }
                }, res => {
                    if (res.statusCode !== 200) { finish(Fail('CONSENSUS_HTTP_' + res.statusCode, mutation)); res.destroy(); return; }
                    const parse = raw => { try { const value = Json(raw); finish(null, stream ? value.result : value); } catch (e) { finish(e); } };
                    res.on('data', chunk => {
                        size += chunk.length;
                        if (size > MAX_BODY) { finish(Fail('CONSENSUS_RESPONSE_TOO_LARGE', mutation)); req.destroy(); return; }
                        chunks.push(chunk);
                        if (stream) { const raw = Buffer.concat(chunks), end = raw.indexOf(10); if (end !== -1) { parse(raw.subarray(0, end)); req.destroy(); } }
                    });
                    res.on('end', () => { if (!settled) parse(Buffer.concat(chunks)); });
                    res.on('error', () => finish(Fail('CONSENSUS_UNAVAILABLE', mutation)));
                });
                req.on('error', () => finish(Fail('CONSENSUS_UNAVAILABLE', mutation)));
                timer = setTimeout(() => { finish(Fail('CONSENSUS_TIMEOUT', mutation)); req.destroy(); }, this.#timeout);
                req.end(bytes);
            });
            const checked = this.#header(result); this.#verified.add(index); return checked;
        } catch (error) {
            this.#next = (index + 1) % this.#endpoints.length;
            this.#verified.delete(index);
            if (error.code === 'CONSENSUS_CLUSTER_OR_RESPONSE_INVALID') { this.#ready = false; this.#session = null; }
            if (mutation) error.outcomeUnknown = true;
            throw error;
        }
    }
    async Connect() {
        if (this.#session || this.#acquiring) throw Fail('CONSENSUS_SESSION_BUSY');
        this.#ready = false; this.#verified.clear();
        // Validate all reachable configured endpoints against the operator-pinned
        // cluster before granting leases. Wrong-cluster responses are fatal.
        let good = -1, last;
        for (let i = 0; i < this.#endpoints.length; i++) {
            try { await this.#request('/v3/kv/range', { key: B64(this.#prefix + '/owner'), serializable: false }, { endpoint: i }); if (good === -1) good = i; }
            catch (e) { if (e.code === 'CONSENSUS_CLUSTER_OR_RESPONSE_INVALID') throw e; last = e; }
        }
        if (good === -1) throw last;
        this.#next = good; this.#ready = true;
        return this.Status();
    }
    #check() { if (!this.#ready) throw Fail('CONSENSUS_NOT_CONNECTED'); }
    #owner(session) {
        const key = this.#prefix + '/owner';
        return [Compare(key, 'CREATE', 'create_revision', session.revision), Compare(key, 'VALUE', 'value', B64(session.owner)), Compare(key, 'LEASE', 'lease', session.lease)];
    }
    async Acquire({ ttlSeconds = 15 } = {}) {
        this.#check();
        if (this.#session || this.#acquiring) throw Fail('CONSENSUS_SESSION_BUSY');
        if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 5 || ttlSeconds > 300) throw Fail('CONSENSUS_TTL_INVALID');
        this.#acquiring = true; let lease;
        try {
            const grant = await this.#request('/v3/lease/grant', { TTL: String(ttlSeconds) }, { mutation: true });
            lease = Decimal(grant.ID); Decimal(grant.TTL);
            const owner = crypto.randomBytes(32).toString('hex'), key = this.#prefix + '/owner';
            const reply = await this.#request('/v3/kv/txn', {
                compare: [Compare(key, 'VERSION', 'version', '0')],
                success: [{ request_put: { key: B64(key), value: B64(owner), lease } }], failure: []
            }, { mutation: true });
            if (reply.succeeded !== true) { if (reply.succeeded !== false && reply.succeeded !== undefined) throw Fail('CONSENSUS_RESPONSE_INVALID', true); throw Fail('CONSENSUS_OWNER_BUSY'); }
            this.#session = Object.freeze({ owner, lease, revision: Decimal(reply.header.revision) });
            return { fenceRevision: this.#session.revision, ttlSeconds: grant.TTL };
        } catch (e) {
            // Revoke only our newly granted lease; an unknown grant has no owner
            // key and expires. No unconditional owner-key delete is permitted.
            if (lease) try { await this.#request('/v3/lease/revoke', { ID: lease }, { mutation: true }); } catch (_) {}
            throw e;
        } finally { this.#acquiring = false; }
    }
    async Renew() {
        this.#check(); const session = this.#session;
        if (!session) throw Fail('CONSENSUS_NO_SESSION');
        try {
            const reply = await this.#request('/v3/lease/keepalive', { ID: session.lease }, { mutation: true, stream: true });
            if (reply.ID !== session.lease) throw Fail('CONSENSUS_RESPONSE_INVALID');
            Decimal(reply.TTL);
            return { ttlSeconds: reply.TTL };
        } catch (e) { if (this.#session === session) this.#session = null; throw e; }
    }
    async Release() {
        this.#check(); const session = this.#session; this.#session = null;
        if (session) await this.#request('/v3/lease/revoke', { ID: session.lease }, { mutation: true });
    }
    async Read(name) {
        this.#check(); const key = this.#prefix + '/state/' + Name(name);
        const reply = await this.#request('/v3/kv/range', { key: B64(key), serializable: false });
        const row = Row(reply, key);
        return row ? { value: Json(row.bytes), revision: row.mod_revision } : { value: null, revision: '0' };
    }
    Prepare({ name, expectedRevision, operationId, value }) {
        Name(name); Name(operationId); Decimal(expectedRevision, true);
        let raw; try { raw = JSON.stringify(value); } catch (_) { throw Fail('CONSENSUS_STATE_INVALID'); }
        if (typeof raw !== 'string' || Buffer.byteLength(raw) > MAX_STATE) throw Fail('CONSENSUS_STATE_TOO_LARGE');
        // Validate the exact bytes that will be replicated, including duplicate,
        // dangerous-property and integer-range rules shared with local storage.
        try { Parse(raw, { maxBytes: MAX_STATE, maxNodes: 100000 }); } catch (_) { throw Fail('CONSENSUS_STATE_INVALID'); }
        const fingerprint = crypto.createHash('sha256').update(JSON.stringify([this.#prefix, name, expectedRevision, raw])).digest('hex');
        return { name, expectedRevision, operationId, raw, fingerprint };
    }
    #receipt(row, fingerprint) {
        if (!row) return null;
        const receipt = Json(row.bytes);
        if (receipt.schema !== 1 || receipt.fingerprint !== fingerprint) throw Fail('CONSENSUS_OPERATION_CONFLICT');
        return { committed: true, replay: true, revision: row.mod_revision, fingerprint };
    }
    async Resolve(operationId, fingerprint) {
        this.#check(); Name(operationId);
        if (typeof fingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(fingerprint)) throw Fail('CONSENSUS_FINGERPRINT_INVALID');
        const key = this.#prefix + '/receipts/' + operationId;
        const response = await this.#request('/v3/kv/range', { key: B64(key), serializable: false });
        // Absence is NOT proof an in-flight timed-out txn cannot still commit.
        return this.#receipt(Row(response, key), fingerprint) || { committed: false, outcome: 'NOT_OBSERVED' };
    }
    async Commit(input) {
        this.#check(); const session = this.#session;
        if (!session) throw Fail('CONSENSUS_NO_SESSION');
        const plan = this.Prepare(input), state = this.#prefix + '/state/' + plan.name, receipt = this.#prefix + '/receipts/' + plan.operationId;
        const owner = this.#prefix + '/owner';
        const body = {
            compare: [...this.#owner(session), Compare(state, 'MOD', 'mod_revision', plan.expectedRevision), Compare(receipt, 'VERSION', 'version', '0')],
            success: [
                { request_put: { key: B64(state), value: B64(plan.raw) } },
                { request_put: { key: B64(receipt), value: B64(JSON.stringify({ schema: 1, fingerprint: plan.fingerprint })) } }
            ], failure: [Range(receipt), Range(owner)]
        };
        let reply;
        try { reply = await this.#request('/v3/kv/txn', body, { mutation: true }); }
        catch (e) { if (this.#session === session) this.#session = null; throw e; }
        if (reply.succeeded === true) return { committed: true, replay: false, revision: Decimal(reply.header.revision), fingerprint: plan.fingerprint };
        if ((reply.succeeded !== false && reply.succeeded !== undefined) || !Array.isArray(reply.responses) || reply.responses.length !== 2) throw Fail('CONSENSUS_RESPONSE_INVALID', true);
        const replay = this.#receipt(Row(reply.responses[0].response_range, receipt), plan.fingerprint);
        if (replay) return replay;
        const leader = Row(reply.responses[1].response_range, owner);
        if (!leader || leader.create_revision !== session.revision || leader.lease !== session.lease || leader.bytes.toString('utf8') !== session.owner) {
            if (this.#session === session) this.#session = null;
            throw Fail('CONSENSUS_FENCE_REJECTED');
        }
        throw Fail('CONSENSUS_STATE_CONFLICT');
    }
}

module.exports = { EtcdConsensusStore, INTEGRATION, MAX_STATE };
