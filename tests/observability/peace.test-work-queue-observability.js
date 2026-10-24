'use strict';
// Real worker tasks: successful, failed, admission/queued expiry and exit.
// The metric populations must remain meaningful when no task succeeds.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { WorkQueue } = require("../../services/runtime/peace.desktop-work-queue");
const { once } = require('node:events');

function signedTask() {
  const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const message = Buffer.from('GAME-QUEUE-METRIC-TEST');
  const signature = crypto.sign('sha256', message, pair.privateKey);
  return { kind: 'verify', jobs: [{ key: pair.publicKey, message, signature }] };
}
function populations(s) {
  assert(Number.isFinite(s.averageWaitMs) && s.averageWaitMs >= 0);
  assert(Number.isFinite(s.averageRunMs) && s.averageRunMs >= 0);
  assert.equal(s.averageWaitMs, s.waitSamples ? s.totalWaitMs / s.waitSamples : 0);
  assert.equal(s.averageRunMs, s.runSamples ? s.totalRunMs / s.runSamples : 0);
  assert(s.averageWaitMs <= s.maxWaitMs);
  assert(s.averageRunMs <= s.maxRunMs);
  assert(s.runSamples <= s.dispatched && s.dispatched <= s.waitSamples);
  assert(s.completed + s.failed + s.timedOut <= s.submitted);
}

(async () => {
  const queues = [];
  const make = () => { const q = new WorkQueue('metric-contract', 1, 4); queues.push(q); return q; };
  let groups = 0;
  try {
    const mixed = make();
    assert.deepEqual(await mixed.run(signedTask()), [true]);
    await assert.rejects(mixed.run({ kind: 'not-a-task' }), /WORK_TASK_FAILED/);
    let s = mixed.snapshot(); populations(s);
    assert.equal(s.completed, 1); assert.equal(s.failed, 1); assert.equal(s.runSamples, 2);
    assert(s.averageRunMs > 0); groups++;

    const failedOnly = make();
    await assert.rejects(failedOnly.run({ kind: 'not-a-task' }), /WORK_TASK_FAILED/);
    s = failedOnly.snapshot(); populations(s);
    assert.equal(s.completed, 0); assert.equal(s.runSamples, 1);
    assert(s.averageRunMs > 0, 'Failed work must have measurable runtime'); groups++;

    const expiry = make();
    // A newly created worker cannot finish before the caller's already tiny
    // deadline. Attach handlers immediately to avoid unhandled rejections.
    const running = assert.rejects(expiry.run(signedTask(), 0.001), /WORK_DEADLINE/);
    const queued = assert.rejects(expiry.run({ kind: 'not-a-task' }, 0.001), /WORK_DEADLINE/);
    await Promise.all([running, queued]);
    await expiry.close(); // wait for the late real worker result, not a sleep
    s = expiry.snapshot(); populations(s);
    assert.equal(s.submitted, 2); assert.equal(s.timedOut, 2); assert.equal(s.failed, 0);
    // A slow worker startup may itself exhaust the first budget before post.
    // Neither undelivered job belongs in the dispatch/runtime denominator.
    assert(s.waitSamples <= 1); assert.equal(s.runSamples, s.dispatched);
    assert(s.waitSamples < s.submitted); groups++;

    const exited = make();
    const rejected = assert.rejects(exited.run(signedTask()), /WORKER_EXITED/);
    const worker = exited.slots[0].worker;
    const exit = once(worker, 'exit');
    await worker.terminate(); // only a test-owned pure worker, never a client owner
    await exit; await rejected;
    s = exited.snapshot(); populations(s);
    assert.equal(s.failed, 1); assert.equal(s.runSamples, 1); groups++;

    const dispatch = make();
    await assert.rejects(dispatch.run({ kind: 'invalid', cannotClone() {} }), /WORK_TASK_INVALID/);
    s = dispatch.snapshot(); populations(s);
    assert.equal(s.waitSamples, 0); assert.equal(s.submitted, 0); assert.equal(s.pendingBytes, 0); assert.equal(s.dispatched, 0); assert.equal(s.runSamples, 0); groups++;
    console.log(`PASS ${groups} real work-queue observability groups`);
  } finally { for (const queue of queues) await queue.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
