'use strict';

// Source/build-contract checks only. These do not execute Pascal or certify
// native worker scheduling. Cozy.HashLifecycleProbe performs the Win64 checks.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const native = path.resolve(__dirname, '../../../Railway');
function read(file) { return fs.readFileSync(path.join(native, file), 'utf8').replace(/^\uFEFF/, '').replace(/\r\n/g, '\n'); }
const hashes = read('Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas');
const workers = read('Cozy.Source/Cozy.Crypto/Cozy.Hashes.Workers.pas');
const integrity = read('Cozy.Source/Cozy.Integrity/Cozy.Integrity.pas');
const metadata = read('Cozy.Source/Cozy.Configuration/Cozy.Metadata.inc');
const probe = read('Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr');
const parallel = read('Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr');

function method(source, name) {
  const start = source.search(new RegExp('(?:procedure|function) ' + name.replaceAll('.', '\\.') + '\\b'));
  assert.ok(start >= 0, name + ' implementation exists');
  const next = source.slice(start + 1).search(/\n(?:procedure|function|constructor|destructor|class function) /);
  return source.slice(start, next < 0 ? undefined : start + 1 + next);
}
for (const type of ['TBlake3Hasher', 'TIntegrityHasher']) {
  for (const call of ['Update', 'UpdateParallel', 'UpdateParallelCancellable', 'Reset']) {
    const body = method(hashes, type + '.' + call);
    assert.match(body, /EnterCall;/, type + '.' + call + ' owns its entire operation');
    assert.match(body, /finally LeaveCall; end;/, type + '.' + call + ' always releases busy guard');
  }
  const enter = method(hashes, type + '.EnterCall');
  assert.ok(enter.indexOf('FOwnerThread <> @HashOwnerThreadMarker') < enter.indexOf('FInCall := True'), 'foreign-thread check precedes mutation');
  assert.ok(enter.indexOf('if FInCall then') < enter.indexOf('FInCall := True'), 'reentry rejection precedes mutation');
}
for (const call of ['TBlake3Hasher.FinishBytes', 'TBlake3Hasher.FinishHex', 'TIntegrityHasher.Finish']) {
  assert.match(method(hashes, call), /EnterCall;/);
  assert.match(method(hashes, call), /finally LeaveCall; end;/);
}
assert.match(hashes, /No raw TObject reference can make arbitrary concurrent Free safe/);
assert.match(method(hashes, 'TIntegrityHasher.UpdateCore'), /FReady := False;\s+CheckHashCancellation/);
assert.match(method(hashes, 'TIntegrityHasher.UpdateCore'), /if Take > 65536 then Take := 65536;/);
assert.match(method(hashes, 'BlakeLeafWork'), /for I := 0 to Job\^\.Count - 1 do\s+begin\s+CheckHashCancellation/);
assert.match(method(hashes, 'TBlake3Hasher.UpdateParallelCore'), /while Count > 1024 do\s+begin\s+CheckHashCancellation/);

// Public declarations precede implementation; inspect the actual method body.
const impl = workers.slice(workers.indexOf('\nimplementation\n'));
const dispatcher = method(impl, 'ExecuteBlake3WorkersCancellable');
assert.ok(dispatcher.indexOf('JoinWorker(Handles[I]') < dispatcher.indexOf('ReleaseHandle(Handles[I]'), 'join all started workers before closing any handle');
assert.ok(dispatcher.indexOf('JoinWorker(Handles[I]') < dispatcher.lastIndexOf('FillChar(Workers'), 'worker records wiped only after joins');
assert.match(dispatcher, /finally\s+for I := 0 to N - 1 do\s+if Handles\[I\] <> 0 then JoinWorker/);
assert.match(dispatcher, /if IsCancelled\(Cancellation\) then\s+begin Cancelled := True; Break; end;/);
assert.match(dispatcher, /if Handles\[I\] = 0 then WorkerEntry/);
assert.match(dispatcher, /DrainPendingHandles\(Close\);/);
assert.match(dispatcher, /PendingHandles\[I\] := Handles\[I\]/);
assert.match(method(impl, 'WorkerEntry'), /WasActive := ExecutorActiveOnThread;\s+ExecutorActiveOnThread := True;/);
assert.match(method(impl, 'WorkerEntry'), /finally\s+ExecutorActiveOnThread := WasActive;/);
assert.match(method(impl, 'JoinWorker'), /if Status = WAIT_OBJECT_0 then Break;/);
assert.doesNotMatch(impl, /TerminateThread\s*\(/, 'cooperative cancellation must not kill threads');
assert.match(integrity, /Hasher\.UpdateParallelCancellable\(Buffer\[0\], Count,\s+ExecuteBlake3WorkersCancellable, Cancellation\)/);
assert.match(integrity, /raise EMeasurement\.Create\(CancellationState\.Failure, 'HASH_STOPPED'\)/);
assert.match(metadata, /\{\$IFDEF GAME_APPLICATION_BUILD\}[\s\S]*?\{\$IFDEF COZY_HASH_WORKER_TESTS\}\s+\{\$MESSAGE FATAL/);
assert.match(probe, /Created = Joined/);
assert.match(probe, /Created = Closed/);
assert.match(probe, /PendingClose = 0/);
assert.match(probe, /WorkerReentrancyContract/);
assert.match(probe, /CancellationAndRecovery/);
assert.match(probe, /OwnershipContracts/);
assert.match(parallel, /Random/i);
assert.match(parallel, /Reset/);
assert.match(parallel, /FinishHex\(131, Seek\)/);
console.log('NATIVE HASH SOURCE CONTRACTS PASS: ownership guards, cancellation wiring, join-before-release, bounded cleanup and isolated native probes; actual Win64 execution NOT_RUN');
