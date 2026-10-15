'use strict';
// Explicit disposable-cluster acceptance test. Never run against production.
// No endpoints => NOT_RUN, not PASS. This script does not start or mutate cluster
// membership, stop nodes, or claim to test quorum loss/partitions.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { EtcdConsensusStore } = require('../services/etcdConsensusStore');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function main() {
    if (!process.env.ETCD_TEST_ENDPOINTS) { console.log('ETCD LIVE NOT_RUN: provide an isolated disposable cluster and ETCD_TEST_ENDPOINTS; GameWeb remains NOT_INTEGRATED.'); return; }
    if (!process.argv.includes('--disposable-cluster')) throw Error('ETCD_DISPOSABLE_CLUSTER_ACK_REQUIRED');
    const namespace = 'acceptance-' + crypto.randomBytes(12).toString('hex');
    const options = {
        endpoints: process.env.ETCD_TEST_ENDPOINTS.split(','), expectedClusterId: process.env.ETCD_TEST_CLUSTER_ID,
        namespace, timeoutMs: 3000, allowInsecureLoopback: process.env.ETCD_TEST_LOOPBACK === '1',
        token: process.env.ETCD_TEST_TOKEN_FILE ? fs.readFileSync(process.env.ETCD_TEST_TOKEN_FILE, 'utf8').trim() : '',
        tls: process.env.ETCD_TEST_CA_FILE ? { ca: fs.readFileSync(process.env.ETCD_TEST_CA_FILE) } : {}
    };
    const a = new EtcdConsensusStore(options), b = new EtcdConsensusStore(options);
    try {
        await a.Connect(); await b.Connect(); await a.Acquire({ ttlSeconds: 5 });
        await assert.rejects(b.Acquire({ ttlSeconds: 5 }), /CONSENSUS_OWNER_BUSY/);
        const input = { name: 'authority', operationId: 'initial', expectedRevision: '0', value: { counter: 1 } };
        const first = await a.Commit(input); assert.equal(first.committed, true);
        const replay = await a.Commit(input); assert.equal(replay.revision, first.revision); assert.equal(replay.replay, true);
        await assert.rejects(a.Commit({ ...input, operationId: 'stale-cas' }), /CONSENSUS_STATE_CONFLICT/);
        assert.deepEqual(await b.Read('authority'), { value: input.value, revision: first.revision });
        await a.Renew();
        // Let the real etcd lease expire. A intentionally retains its stale
        // local session so its later request must be rejected by etcd's txn.
        let successor = false; const deadline = Date.now() + 20000;
        while (Date.now() < deadline) {
            await delay(1000);
            try { await b.Acquire({ ttlSeconds: 15 }); successor = true; break; }
            catch (e) { if (e.code !== 'CONSENSUS_OWNER_BUSY') throw e; }
        }
        assert.equal(successor, true, 'real lease did not expire within acceptance budget');
        await assert.rejects(a.Commit({ ...input, operationId: 'stale-leader', expectedRevision: first.revision, value: { counter: 999 } }), /CONSENSUS_FENCE_REJECTED/);
        const next = await b.Commit({ ...input, operationId: 'successor', expectedRevision: first.revision, value: { counter: 2 } });
        assert.ok(BigInt(next.revision) > BigInt(first.revision));
        await b.Release();
        const c = new EtcdConsensusStore(options); await c.Connect();
        assert.deepEqual(await c.Read('authority'), { value: { counter: 2 }, revision: next.revision });
        const receipt = await c.Resolve(input.operationId, a.Prepare(input).fingerprint); assert.equal(receipt.revision, first.revision);
        console.log('ETCD LIVE LEASE/CAS PASS: independent clients, contention, real expiry, stale-owner rejection, persistent state and receipts. Namespace: /gameconnect-consensus-v1/' + namespace);
        console.log('QUORUM/PARTITION/DISK-RESTART NOT_RUN; GAMEWEB INTEGRATION NOT_INTEGRATED. Dispose of the test cluster after inspection.');
    } finally { await Promise.allSettled([a.Release(), b.Release()]); }
}
main().catch(e => { console.error(e.code || e.message); process.exitCode = 1; });
