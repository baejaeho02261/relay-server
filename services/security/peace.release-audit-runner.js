'use strict';
const { Worker } = require('node:worker_threads');
const path = require('node:path');
const MAX_RUNTIME_MS = 10000;
function ErrorCode(code, status = 503) {
  const error = Error(code); error.desktopError = true; error.status = status; return error;
}
// One active job, no waiting queue. The slot remains occupied until its worker
// has actually exited. JS heap limits do not limit external Buffer memory: file
// size/aggregate bounds and sequential processing are independently enforced.
function CreateRunner({ createWorker, timeoutMs = MAX_RUNTIME_MS } = {}) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_RUNTIME_MS) throw Error('RELEASE_AUDIT_LIMIT_INVALID');
  const launch = createWorker || (workerData => new Worker(path.join(__dirname, 'peace.release-readiness-worker.js'), {
    workerData, env: {}, execArgv: [], resourceLimits: { maxOldGenerationSizeMb: 64, maxYoungGenerationSizeMb: 8, stackSizeMb: 4 } }));
  let active = null, closed = false;
  function Run(input, { signal, checkAccess } = {}) {
    if (closed) return Promise.reject(ErrorCode('RELEASE_AUDIT_CLOSED'));
    if (signal?.aborted) return Promise.reject(ErrorCode('RELEASE_AUDIT_CANCELLED', 499));
    if (active) return Promise.reject(ErrorCode('RELEASE_AUDIT_BUSY', 429));
    try { checkAccess?.(); } catch (error) { return Promise.reject(error); }
    const job = {}; active = job;
    job.promise = new Promise((resolve, reject) => {
      let worker, deadline, accessTimer, finishing = false, exitResolve, exitObserved = false;
      const exited = new Promise(done => { exitResolve = done; });
      const finish = async (error, result) => {
        if (finishing) return; finishing = true;
        clearTimeout(deadline); clearInterval(accessTimer);
        signal?.removeEventListener('abort', abort);
        try {
          if (worker) { await worker.terminate(); await exited; }
        } catch (_) {
          // A termination failure must never open a second worker slot. This
          // runner is permanently closed and retains the live job until exit.
          closed = true; job.failedToStop = !exitObserved; error = ErrorCode('RELEASE_AUDIT_FAILED');
        }
        if (!job.failedToStop && active === job) active = null;
        if (error) reject(error); else resolve(result);
      };
      const abort = () => { void finish(ErrorCode('RELEASE_AUDIT_CANCELLED', 499)); };
      job.cancel = abort;
      try {
        worker = launch(input);
        job.retryStop = async () => { await worker.terminate(); await exited; };
        worker.once('exit', () => {
          exitObserved = true; exitResolve();
          if (job.failedToStop && active === job) active = null;
          if (!finishing) void finish(ErrorCode('RELEASE_AUDIT_FAILED'));
        });
        worker.once('error', () => { void finish(ErrorCode('RELEASE_AUDIT_FAILED')); });
        worker.once('message', message => {
          if (!message?.ok || !message.result) { void finish(ErrorCode('RELEASE_AUDIT_FAILED')); return; }
          try {
            if (JSON.stringify(message.result).length > 32768) throw Error();
            checkAccess?.();
          } catch (error) { void finish(error.desktopError ? error : ErrorCode('RELEASE_AUDIT_FAILED')); return; }
          void finish(null, message.result);
        });
        deadline = setTimeout(() => { void finish(ErrorCode('RELEASE_AUDIT_TIMEOUT', 504)); }, timeoutMs);
        if (checkAccess) accessTimer = setInterval(() => {
          try { checkAccess(); } catch (error) { void finish(error); }
        }, 100);
        signal?.addEventListener('abort', abort, { once: true });
        if (signal?.aborted) abort();
      } catch (_) { exitResolve(); void finish(ErrorCode('RELEASE_AUDIT_FAILED')); }
    });
    return job.promise;
  }
  async function Close() {
    closed = true; const job = active; job?.cancel();
    if (job) { await job.promise.catch(() => {}); if (job.failedToStop && active === job) await job.retryStop(); }
  }
  return { Run, Close };
}
module.exports = { CreateRunner, MAX_RUNTIME_MS };
