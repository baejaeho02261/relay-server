'use strict';
// Actual server authority, RSA proofs, durable state and process restart.
// The sensor rows and executable fixtures are synthetic: this is not a Windows
// sensor, process-termination, GPU or hardware-attestation result.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const serverRoot = path.resolve(__dirname, '../..');
const phases = ['seed', 'recover', 'atomic-stop', 'pending-stop', 'terminal', 'full-drain'];

if (!process.argv[2]) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cozy-nhw-pending-recovery-'));
  try {
    for (const phase of phases) {
      // Each phase is a new OS process. In particular, recovery has none of
      // seed's in-memory challenge, receipt, order or module-cache state.
      const result = spawnSync(process.execPath, [__filename, phase], {
        cwd: serverRoot,
        env: {...process.env, DATA_DIR: directory, STORAGE_ENGINE: 'json', HA_ENABLED: '0',
          DESKTOP_PUBLIC_HOST: '127.0.0.1', DESKTOP_PUBLIC_PORT: '29131'},
        encoding: 'utf8', timeout: 60000, maxBuffer: 4 * 1024 * 1024
      });
      assert.equal(result.status, 0, `${phase}: ${result.error || ''}\n${result.stdout}\n${result.stderr}`);
      process.stdout.write(result.stdout.split(/\r?\n/).filter(line => line.startsWith('PASS ')).join('\n') + '\n');
    }
    console.log('NHW pending recovery: actual restart, signed exact-batch recovery, bounded terminal drain passed; Windows runtime not executed');
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
} else {
  assert.ok(phases.includes(process.argv[2]));
  runPhase(process.argv[2]);
}

function runPhase(phase) {
  const stateFile = path.join(process.env.DATA_DIR, 'nhw-recovery-test-state.json');
  const saved = phase === 'seed' ? null : JSON.parse(fs.readFileSync(stateFile, 'utf8'));
  if (saved) process.env.DESKTOP_ISSUED_A_SIGNING_PRIVATE_KEY_B64 = saved.issuer;
  require('../../core/peace.utilities').EnsureDirs();
  const fixture = require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture');
  const boot = require('../../services/bootstrap/peace.desktop-bootstrap');
  const authority = require('../../services/security/peace.desktop-security-authority');
  const paths = require('../../services/security/peace.nhw-response-paths');
  const reports = require('../../services/security/peace.security-detections');
  const store = require('../../services/bootstrap/peace.desktop-bootstrap-store');
  const hash = x => crypto.createHash('sha512').update(x).digest('hex');
  const hex = n => BigInt(n).toString(16).padStart(16, '0');
  const channels = ['trust', 'driver', 'integrity'];
  const reject = (fn, code) => assert.throws(fn, e => !code || e.message === code);
  const row = subject => store.Load().flows[subject.flowId];
  const events = subject => reports.ForFlow(subject.flowId);
  const serialize = subject => ({...subject, device: {...subject.device,
    privateKey: subject.device.privateKey.export({type: 'pkcs8', format: 'pem'})}});
  const restore = subject => ({...subject, device: {...subject.device,
    privateKey: crypto.createPrivateKey(subject.device.privateKey)}});
  function subjectB() {
    const parent = fixture.Device(), start = fixture.Begin(parent), device = fixture.Child(parent);
    fixture.Download(start.begin);
    const session = fixture.Claim(parent, start.begin, fixture.Finish(parent, start.begin), device);
    return {device, flowId: start.begin.flowId,
      ctx: {stage: 'B', sessionId: session.sessionId, sessionToken: session.sessionToken, machineId: device.machineId}};
  }
  function detection(id = 'dkNamespace', options = {}) {
    return {id, source: 'Cozy.NHW.Engine', firstTick: hex(1000), lastTick: hex(1000), count: 1,
      families: 0, confidence: 0, correlation: false, attestationSequence: hex(0), localOnly: true, ...options};
  }
  function payload(records, sequence = 1, tick = 2000, patch = {}) {
    return JSON.stringify({version: 2, sequence: hex(sequence), tick: hex(tick),
      digest: hash(JSON.stringify(records)).slice(0, 16), confirmed: false, trust: 2, detections: records, ...patch});
  }
  function request(subject, channel, text) {
    const title = channel[0].toUpperCase() + channel.slice(1);
    const body = {...subject.ctx, binding: hash(text), action: `nhw${title}Challenge`};
    const challenge = authority.Execute(body);
    const submit = {...body, action: `nhw${title}Submit`, challengeId: challenge.challengeId, payload: text};
    submit.signature = fixture.Sign(subject.device, paths.Canonical(submit, challenge, channel));
    return {challenge, submit};
  }
  function send(subject, channel, records, sequence = 1, tick = 2000, patch = {}) {
    return authority.Execute(request(subject, channel, payload(records, sequence, tick, patch)).submit);
  }
  function expectedAck(response, channel, sequence, text, subject) {
    assert.deepEqual(Object.keys(response).sort(), ['accepted', 'attested', 'channel', 'digest', 'epoch', 'scope', 'sequence', 'stopped', 'version']);
    assert.equal(response.version, 1);
    assert.equal(response.channel, channel);
    assert.equal(response.sequence, hex(sequence));
    assert.equal(response.digest, JSON.parse(text).digest);
    assert.equal(response.epoch, String(row(subject).createdAt));
    assert.equal(response.accepted, true);
    assert.equal(response.scope, 'OWNED_A_B_O');
    assert.equal(response.attested, false);
  }
  function validateStorage() {
    const db = store.Load();
    reports.Validate(db.securityDetections, db);
    for (const current of [...Object.values(db.flows), ...Object.values(db.overlays || {})]) {
      reports.ValidateOrder(current.nhwResponseOrders);
      reports.ValidateTerminal(current.nhwTerminalReport);
    }
  }
  try {
    if (phase === 'seed') {
      fixture.CurrentCohort({version: '90.0.0'});
      const subject = subjectB(), other = subjectB(), accepted = {};
      for (const channel of channels) {
        const text = payload([detection()]);
        const req = request(subject, channel, text), response = authority.Execute(req.submit);
        expectedAck(response, channel, 1, text, subject);
        assert.equal(response.stopped, false);
        accepted[channel] = {text, ...req, response};
      }
      assert.equal(row(subject).status, 'CLAIMED');
      assert.equal(events(subject).length, 3);
      assert.equal(events(other).length, 0);
      validateStorage();
      // Fixture keys only, private temporary directory; never production keys.
      fs.writeFileSync(stateFile, JSON.stringify({issuer: process.env.DESKTOP_ISSUED_A_SIGNING_PRIVATE_KEY_B64,
        subject: serialize(subject), other: serialize(other), accepted,
        eventSnapshot: events(subject), orderSnapshot: row(subject).nhwResponseOrders}), {mode: 0o600});
      console.log('PASS seed committed three independent batches with intentionally unconsumed acknowledgments');
    }
    if (phase === 'recover') {
      const subject = restore(saved.subject), other = restore(saved.other);
      assert.deepEqual(events(subject), saved.eventSnapshot);
      for (const channel of channels) {
        const original = saved.accepted[channel];
        reject(() => authority.Execute(original.submit), 'SECURITY_CHALLENGE_INVALID');
        // Renewal changes only the envelope tick, as the native transport does.
        const text = payload([detection()], 1, 4000), req = request(subject, channel, text);
        assert.notEqual(req.challenge.nonce, original.challenge.nonce);
        assert.notEqual(req.challenge.challengeId, original.challenge.challengeId);
        assert.equal(req.challenge.epoch, original.challenge.epoch);
        for (const altered of [{...req.challenge, epoch: String(BigInt(req.challenge.epoch) + 1n)},
          {...req.challenge, nonce: original.challenge.nonce}]) {
          const signature = fixture.Sign(subject.device, paths.Canonical(req.submit, altered, channel));
          reject(() => authority.Execute({...req.submit, signature}), 'SECURITY_SIGNATURE_INVALID');
        }
        const foreignChannel = channels.find(name => name !== channel);
        reject(() => authority.Execute({...req.submit, action: `nhw${foreignChannel[0].toUpperCase()}${foreignChannel.slice(1)}Submit`}), 'SECURITY_CHALLENGE_INVALID');
        const response = authority.Execute(req.submit);
        expectedAck(response, channel, 1, text, subject);
        assert.equal(response.stopped, false);
        assert.deepEqual(authority.Execute(req.submit), response);
      }
      // Neither a recovered durable receipt nor its fresh volatile replay may
      // rewrite timestamps, increment counters or promote confirmation.
      assert.deepEqual(events(subject), saved.eventSnapshot);
      assert.deepEqual(row(subject).nhwResponseOrders, saved.orderSnapshot);
      for (const channel of channels) {
        reject(() => send(subject, channel, [detection('dkNamespace', {count: 2, lastTick: hex(1100)})], 1, 5000), 'SECURITY_OBSERVATION_REPLAY');
        reject(() => send(subject, channel, [detection()], 2, 5000), 'SECURITY_EVIDENCE_REPLAY');
        assert.equal(send(subject, channel, [detection('dkNamespace', {count: 2, lastTick: hex(1200)})], 2, 5000).stopped, false);
      }
      assert.equal(events(subject).length, 3);
      for (const event of events(subject)) {
        assert.equal(event.count, 2); assert.equal(event.producerCount, 2);
        assert.equal(event.firstTick, hex(1000)); assert.equal(event.lastTick, hex(1200));
        assert.equal(event.confirmationCount, 0); assert.equal(event.invalidated, false);
      }
      assert.equal(row(subject).status, 'CLAIMED');
      assert.equal(row(other).status, 'CLAIMED'); assert.equal(events(other).length, 0);
      validateStorage();
      console.log('PASS actual process restart recovered exact signed batches without recount and unblocked all three newer revisions');
    }
    if (phase === 'atomic-stop') {
      const subject = subjectB(), other = restore(saved.other), record = detection('dkPECodeIntegrity');
      const req = request(subject, 'integrity', payload([record])), originalAtomic = store.Atomic;
      let injected = false;
      store.Atomic = mutate => originalAtomic(db => {
        const result = mutate(db);
        if (db.flows[subject.flowId].status === 'REVOKED') {
          assert.ok(db.flows[subject.flowId].nhwResponseOrders['B:integrity'].stopDecision);
          assert.equal(db.securityDetections.flows[subject.flowId].events[0].detectionId, record.id);
          injected = true;
          throw Error('INJECTED_REVOKE_WRITE_FAILURE');
        }
        return result;
      });
      try { reject(() => authority.Execute(req.submit), 'STORAGE_SAVE_FAILED'); }
      finally { store.Atomic = originalAtomic; }
      assert.equal(injected, true);
      assert.equal(row(subject).status, 'CLAIMED');
      assert.equal(row(subject).nhwResponseOrders, undefined);
      assert.equal(row(subject).nhwTerminalReport, undefined);
      assert.equal(events(subject).length, 0);
      assert.equal(send(subject, 'integrity', [record]).stopped, true);
      assert.equal(row(subject).status, 'REVOKED');
      assert.equal(events(subject).length, 1);
      assert.equal(events(subject)[0].invalidated, true);
      assert.equal(row(other).status, 'CLAIMED');
      assert.equal(events(other).length, 0);
      validateStorage();
      console.log('PASS named detection and cohort revoke roll back together and commit on an authenticated retry');
    }
    if (phase === 'pending-stop') {
      const subject = subjectB(), other = restore(saved.other), record = detection('dkPECodeIntegrity');
      // Simulate a pre-upgrade store with an exact, already authenticated
      // decision whose older two-transaction enforcement write was interrupted.
      const value = paths.Payload(payload([record]));
      const decision = reports.StopDecision('B', 'integrity', value, row(subject));
      reports.RecordPath(row(subject), 'B', 'integrity', value, decision);
      const before = structuredClone(events(subject)[0]);
      assert.equal(before.invalidated, false); assert.equal(row(subject).status, 'CLAIMED');
      assert.equal(row(subject).nhwTerminalReport, undefined);
      const acceptedOrder = structuredClone(row(subject).nhwResponseOrders['B:integrity']);
      assert.ok(acceptedOrder.stopDecision);
      paths.Clear();
      // This is now stale relative to a new report's freshness window. Recovery
      // must finish the original durable decision, not silently recompute it.
      const response = send(subject, 'integrity', [record], 1, 100000);
      assert.equal(response.stopped, true); assert.equal(row(subject).status, 'REVOKED');
      const after = events(subject)[0];
      for (const key of ['count', 'producerCount', 'firstTick', 'lastTick', 'firstAt', 'lastAt', 'confirmationCount']) assert.equal(after[key], before[key]);
      assert.equal(after.invalidated, true); assert.equal(after.correlation, false);
      assert.equal(row(subject).reason, acceptedOrder.stopDecision.reason);
      assert.deepEqual(row(subject).nhwResponseOrders['B:integrity'], acceptedOrder);
      assert.equal(row(other).status, 'CLAIMED'); assert.equal(events(other).length, 0);
      validateStorage();
      console.log('PASS lost enforcement result resumed its original exact-cohort decision without replaying observations or relabeling confidence');
    }
    if (phase === 'terminal') {
      const subject = subjectB(), other = restore(saved.other), record = detection('dkPECodeIntegrity');
      const text = payload([record]), original = request(subject, 'integrity', text);
      assert.equal(authority.Execute(original.submit).stopped, true);
      assert.equal(row(subject).status, 'REVOKED');
      reject(() => boot.AuthenticateIntegrityReport(subject.ctx));
      const before = structuredClone(events(subject)), revokedAt = row(subject).revokedAt;
      const grace = structuredClone(row(subject).nhwTerminalReport);
      paths.Clear();
      reject(() => authority.Execute(original.submit), 'SECURITY_CHALLENGE_INVALID');
      const recovery = request(subject, 'integrity', payload([record], 1, 4000));
      assert.equal(authority.Execute(recovery.submit).stopped, true);
      assert.deepEqual(events(subject), before); assert.equal(row(subject).revokedAt, revokedAt);
      assert.deepEqual(row(subject).nhwTerminalReport, grace);
      const next = detection('dkWriteIntegrity', {firstTick: hex(1300), lastTick: hex(1300)});
      assert.equal(send(subject, 'integrity', [next], 2, 5000).stopped, true);
      const drained = events(subject).find(event => event.detectionId === next.id);
      assert.ok(drained); assert.equal(drained.count, 1); assert.equal(drained.invalidated, false);
      assert.equal(drained.sessionInvalidated, true);
      assert.deepEqual(row(subject).nhwTerminalReport, grace);
      assert.equal(row(other).status, 'CLAIMED'); assert.equal(events(other).length, 0);
      const now = Date.now;
      Date.now = () => grace.expiresAt;
      try {
        reject(() => authority.Execute(recovery.submit), 'SECURITY_NHW_SESSION_REVOKED');
        reject(() => request(subject, 'driver', payload([detection()], 1, 6000)), 'SECURITY_NHW_SESSION_REVOKED');
        reject(() => boot.AuthenticateIntegrityReport(subject.ctx));
      } finally { Date.now = now; }
      const admin = subjectB();
      boot.Revoke(row(admin).sessionId, {reason: 'ADMIN_REQUEST'}, 'ADMIN');
      reject(() => request(admin, 'integrity', payload([detection()])), 'SECURITY_NHW_SESSION_REVOKED');
      for (const binding of [{sessionToken: other.ctx.sessionToken}, {machineId: other.ctx.machineId}]) {
        assert.throws(() => request({...admin, ctx: {...admin.ctx, ...binding}}, 'integrity', payload([detection()])),
          error => error.message !== 'SECURITY_NHW_SESSION_REVOKED');
      }
      validateStorage();
      console.log('PASS terminal acknowledgment recovery and queued next kind drained only within the original 30-second grant; normal authority remained revoked');
    }
    if (phase === 'full-drain') {
      const subject = subjectB(), other = restore(saved.other);
      const catalog = require('../../services/security/peace.security-detection-catalog');
      assert.equal(catalog.NHW.length, 204);
      let grace;
      for (const channel of channels) {
        let sequence = 0;
        for (let offset = 0; offset < catalog.NHW.length; offset += 32) {
          const records = catalog.NHW.slice(offset, offset + 32).map(entry => detection(entry.id, entry.id === 'dkProcess' ? {families:3, confidence:75, correlation:true, localOnly:false} : {}));
          assert.equal(send(subject, channel, records, ++sequence, 2000 + sequence).stopped, true);
          assert.equal(row(subject).status, 'REVOKED');
          grace ||= structuredClone(row(subject).nhwTerminalReport);
          assert.deepEqual(row(subject).nhwTerminalReport, grace);
        }
        assert.equal(sequence, 7);
        const delivered = events(subject).filter(event => event.responsePath === channel);
        assert.equal(delivered.length, 204);
        assert.equal(new Set(delivered.map(event => event.detectionId)).size, 204);
        assert.ok(delivered.every(event => event.count === 1 && event.producerCount === 1 && event.sessionInvalidated));
        assert.equal(row(subject).nhwResponseOrders[`B:${channel}`].sequence, hex(7));
      }
      assert.equal(events(subject).length, 612);
      assert.equal(row(other).status, 'CLAIMED'); assert.equal(events(other).length, 0);
      reject(() => boot.AuthenticateIntegrityReport(subject.ctx));
      validateStorage();
      console.log('PASS all 204 NHW states drained in seven signed batches per channel after cohort termination, without extending authority or its terminal grant');
    }
  } finally {
    boot.Stop();
  }
}
