'use strict';
// Wire/adapter tests against a deliberately non-consensus HTTP fixture. These
// tests make NO claim about real etcd quorum, durability, or network partitions.
const assert = require('node:assert/strict');
const http = require('node:http');
const { EtcdConsensusStore, INTEGRATION } = require("../../services/storage/peace.etcd-consensus-store");
const cluster = '18446744073709551600';
const b64 = x => Buffer.from(x).toString('base64');
const decode = x => Buffer.from(x, 'base64').toString();
async function main() {
    const rows = new Map(), leases = new Set(), calls = []; let revision = 9007199254741000n, leaseId = 9007199254741100n;
    let dropCommit = false, wrongCluster = false, zeroKeepalive = false, responseMode = '';
    const header = () => ({ cluster_id: wrongCluster ? '999' : cluster, revision: String(revision) });
    function range(body) { const row = rows.get(decode(body.key)); return { header: header(), ...(row ? { kvs: [{ ...row }], count: '1' } : {}) }; }
    function put(body) {
        const key = decode(body.key), old = rows.get(key);
        rows.set(key, { key: body.key, value: body.value, lease: body.lease || '0', create_revision: old?.create_revision || String(revision), mod_revision: String(revision), version: String(BigInt(old?.version || '0') + 1n) });
        return { response_put: { header: header() } };
    }
    function compare(c) {
        const row = rows.get(decode(c.key)), field = { CREATE: 'create_revision', MOD: 'mod_revision', VERSION: 'version', VALUE: 'value', LEASE: 'lease' }[c.target];
        assert.equal(c.result, 'EQUAL'); assert.ok(field);
        return (row?.[field] ?? (c.target === 'VALUE' ? '' : '0')) === c[field];
    }
    const server = http.createServer(async (req, res) => {
        const chunks = []; for await (const chunk of req) chunks.push(chunk);
        const body = JSON.parse(Buffer.concat(chunks)); calls.push({ path: req.url, body });
        if (responseMode) { const mode = responseMode; responseMode = ''; if (mode === 'redirect') { res.writeHead(307, { location: 'http://127.0.0.1:1/' }); res.end(); return; } if (mode === 'duplicate') { res.end('{"header":{},"header":{}}'); return; } if (mode === 'oversize') { res.end(' '.repeat(1024 * 1024 + 1)); return; } if (mode === 'timeout') return; }
        let reply;
        if (req.url === '/v3/kv/range') { assert.equal(body.serializable, false); reply = range(body); }
        else if (req.url === '/v3/lease/grant') { const id = String(++leaseId); leases.add(id); reply = { header: header(), ID: id, TTL: body.TTL }; }
        else if (req.url === '/v3/lease/revoke') { leases.delete(body.ID); for (const [key, row] of rows) if (row.lease === body.ID) { rows.delete(key); revision++; } reply = { header: header() }; }
        else if (req.url === '/v3/lease/keepalive') {
            res.write(JSON.stringify({ result: { header: header(), ID: body.ID, TTL: zeroKeepalive ? '0' : '15' } }) + '\n');
            // Keep the stream open: the adapter must consume one complete frame,
            // then close it instead of waiting for an endless streaming body.
            return;
        } else if (req.url === '/v3/kv/txn') {
            const succeeded = body.compare.every(compare);
            if (succeeded && body.success.some(x => x.request_put)) revision++;
            const responses = (succeeded ? body.success : body.failure).map(x => x.request_put ? put(x.request_put) : { response_range: range(x.request_range) });
            // protobuf JSON may omit the default false boolean on failure.
            reply = { header: header(), ...(succeeded ? { succeeded: true } : {}), responses };
            if (dropCommit && body.success.length === 2) { dropCommit = false; res.destroy(); return; }
        } else throw Error('UNEXPECTED_PATH');
        res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(reply));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const endpoint = 'http://127.0.0.1:' + server.address().port;
    const options = { endpoints: [endpoint], expectedClusterId: cluster, namespace: 'wire-test', allowInsecureLoopback: true, timeoutMs: 200 };
    const create = extra => new EtcdConsensusStore({ ...options, ...extra });
    let groups = 0;
    async function test(name, fn) { await fn(); groups++; console.log('ok ' + name); }
    try {
        await test('configuration rejects insecure external endpoints, URL credentials and TLS bypass', async () => {
            for (const url of ['http://example.test:2379', 'http://localhost:2379', 'http://user:pass@127.0.0.1:2379', endpoint + '/v3', endpoint + '/?x=1', 'ftp://127.0.0.1:2379']) assert.throws(() => create({ endpoints: [url] }), /CONSENSUS_ENDPOINT_INVALID/);
            assert.throws(() => create({ tls: { rejectUnauthorized: false } }), /CONSENSUS_TLS_INVALID/);
            assert.throws(() => create({ expectedClusterId: Number(cluster) }), /CONSENSUS_INTEGER_INVALID/);
            assert.throws(() => create({ namespace: '../escape' }), /CONSENSUS_NAME_INVALID/);
            assert.throws(() => create({ token: 'secret\nheader' }), /CONSENSUS_AUTH_INVALID/);
            assert.deepEqual(INTEGRATION, { backend: 'etcd-v3', status: 'NOT_INTEGRATED', serverMultiwriterEnabled: false });
        });
        await test('not connected never writes; wrong cluster cannot acquire a lease', async () => {
            const store = create(); await assert.rejects(store.Acquire(), /CONSENSUS_NOT_CONNECTED/);
            const before = calls.length; wrongCluster = true;
            await assert.rejects(store.Connect(), /CONSENSUS_CLUSTER_OR_RESPONSE_INVALID/); wrongCluster = false;
            assert.equal(calls.length, before + 1); assert.equal(calls.at(-1).path, '/v3/kv/range');
        });
        const a = create(), b = create(); await a.Connect(); await b.Connect();
        await test('one lease owner; competing acquisition revokes only its own lease', async () => {
            const first = await a.Acquire(); assert.equal(first.fenceRevision, '9007199254741001');
            await assert.rejects(b.Acquire(), /CONSENSUS_OWNER_BUSY/); assert.equal(leases.size, 1);
            const key = '/gameconnect-consensus-v1/wire-test/owner'; assert.ok(rows.has(key));
        });
        const input = { name: 'authority', operationId: 'first', expectedRevision: '0', value: { remaining: 1 } }; let committed;
        await test('owner fence, CAS and durable receipt share one transaction', async () => {
            committed = await a.Commit(input); assert.equal(committed.revision, '9007199254741002');
            const tx = calls.at(-1).body;
            assert.deepEqual(tx.compare.map(x => x.target), ['CREATE', 'VALUE', 'LEASE', 'MOD', 'VERSION']);
            assert.equal(tx.success.length, 2); assert.ok(tx.success.every(x => x.request_put.lease === undefined));
            const state = rows.get('/gameconnect-consensus-v1/wire-test/state/authority'), receipt = rows.get('/gameconnect-consensus-v1/wire-test/receipts/first');
            assert.equal(state.mod_revision, receipt.mod_revision);
            assert.deepEqual(await b.Read('authority'), { value: { remaining: 1 }, revision: committed.revision });
        });
        await test('operation retry resolves same commit; request collision and stale state reject', async () => {
            const replay = await a.Commit(input); assert.equal(replay.replay, true); assert.equal(replay.revision, committed.revision);
            await assert.rejects(a.Commit({ ...input, value: { remaining: 0 } }), /CONSENSUS_OPERATION_CONFLICT/);
            await assert.rejects(a.Commit({ ...input, operationId: 'stale' }), /CONSENSUS_STATE_CONFLICT/);
            assert.deepEqual(await a.Read('authority'), { value: input.value, revision: committed.revision });
        });
        await test('streaming renewal is bounded and zero TTL invalidates local session', async () => {
            assert.equal((await a.Renew()).ttlSeconds, '15'); zeroKeepalive = true;
            await assert.rejects(a.Renew(), /CONSENSUS_INTEGER_INVALID/); zeroKeepalive = false;
            await assert.rejects(a.Commit(input), /CONSENSUS_NO_SESSION/);
        });
        await test('expired owner cannot write after successor takeover', async () => {
            // Expiration is injected fixture behavior, not evidence of etcd TTL.
            rows.delete('/gameconnect-consensus-v1/wire-test/owner'); revision++; leases.clear();
            await a.Acquire();
            const staleRevision = a.Status().fenceRevision;
            rows.delete('/gameconnect-consensus-v1/wire-test/owner'); revision++; leases.clear();
            await b.Acquire(); assert.ok(BigInt(b.Status().fenceRevision) > BigInt(staleRevision));
            await assert.rejects(a.Commit({ ...input, operationId: 'old-owner', expectedRevision: committed.revision }), /CONSENSUS_FENCE_REJECTED/);
            assert.equal(a.Status().ownership, 'NONE');
            assert.equal(rows.has('/gameconnect-consensus-v1/wire-test/receipts/old-owner'), false);
        });
        await test('uncertain acknowledged commit resolves from replicated receipt without mutation retry', async () => {
            const plan = { ...input, operationId: 'lost-response', expectedRevision: committed.revision, value: { remaining: 0 } };
            const fingerprint = b.Prepare(plan).fingerprint; dropCommit = true;
            await assert.rejects(b.Commit(plan), e => e.outcomeUnknown === true && e.code === 'CONSENSUS_UNAVAILABLE');
            assert.equal(b.Status().ownership, 'NONE');
            const before = calls.length, found = await b.Resolve(plan.operationId, fingerprint);
            assert.equal(found.committed, true); assert.equal(found.replay, true); assert.equal(calls.length, before + 1); assert.equal(calls.at(-1).path, '/v3/kv/range');
            assert.deepEqual(await b.Resolve('not-observed', fingerprint), { committed: false, outcome: 'NOT_OBSERVED' });
            await assert.rejects(b.Resolve(plan.operationId, 'f'.repeat(64)), /CONSENSUS_OPERATION_CONFLICT/);
        });
        await test('bounded malformed responses, redirects and timeout never become successful reads', async () => {
            for (const [mode, error] of [['redirect', /CONSENSUS_HTTP_307/], ['duplicate', /CONSENSUS_RESPONSE_INVALID/], ['oversize', /CONSENSUS_RESPONSE_TOO_LARGE/], ['timeout', /CONSENSUS_TIMEOUT/]]) {
                responseMode = mode; await assert.rejects(b.Read('authority'), error);
            }
            assert.throws(() => b.Prepare({ ...input, expectedRevision: 1 }), /CONSENSUS_INTEGER_INVALID/);
            assert.throws(() => b.Prepare({ ...input, value: 'x'.repeat(256 * 1024) }), /CONSENSUS_STATE_TOO_LARGE/);
            assert.throws(() => b.Prepare({ ...input, value: { n: Number.MAX_SAFE_INTEGER + 1 } }), /CONSENSUS_STATE_INVALID/);
        });
        await test('explicit release keeps data and receipts durable; no local authority modules loaded', async () => {
            rows.delete('/gameconnect-consensus-v1/wire-test/owner'); revision++; leases.clear();
            await b.Acquire(); await b.Release();
            assert.equal(b.Status().ownership, 'NONE'); assert.equal((await b.Read('authority')).value.remaining, 0);
            assert.equal([...rows.keys()].filter(k => k.includes('/receipts/')).length, 2);
            for (const key of Object.keys(require.cache)) assert.ok(!/desktopBootstrapStore|desktopLicenseJournal|storage.database|desktopSingleWriter/.test(key));
        });
        console.log('ETCD ADAPTER WIRE PASS: ' + groups + ' groups. Real etcd/quorum/partition tests NOT_RUN; server integration NOT_INTEGRATED.');
    } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}
main().catch(e => { console.error(e); process.exitCode = 1; });
