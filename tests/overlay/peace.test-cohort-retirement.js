'use strict';
// Real server stores and signed synthetic-artifact flows. No EXE is executed,
// no process suspension/debugger observation is used, and no live server is read.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), crypto = require('node:crypto');

test('server lease retirement is terminal and restricted to the related A/B/O cohort', async t => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'peace-cohort-retirement-'));
  const realNow = Date.now, originalLog = console.log;
  let clock = realNow(), boot, failure;
  process.env.DATA_DIR = temp;
  process.env.STORAGE_ENGINE = 'json';
  process.env.HA_ENABLED = '0';
  process.env.DESKTOP_PUBLIC_HOST = '127.0.0.1';
  process.env.DESKTOP_PUBLIC_PORT = '29131';
  // Audit noise is not test evidence; the assertions below inspect durable rows.
  console.log = () => {};
  try {
    require('../../core/peace.utilities').EnsureDirs();
    const fixture = require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture');
    boot = require('../../services/bootstrap/peace.desktop-bootstrap');
    require('../../services/network/peace.connect-tls').Public();
    clock = realNow();
    Date.now = () => clock;
    const overlay = require('../../services/overlay/peace.desktop-overlay');
    const licenses = require('../../services/licensing/peace.desktop-licenses');
    const reports = require('../../services/integrity/peace.desktop-integrity-reports');
    const authority = require('../../services/security/peace.desktop-security-authority');
    const store = require('../../services/bootstrap/peace.desktop-bootstrap-store');
    fixture.CurrentCohort({version:'91.0.0'});
    const reject = fn => assert.throws(fn, error => /^(BOOTSTRAP|DESKTOP|SECURITY|INTEGRITY|KEYLESS)_/.test(error.message));
    function licenseProof(device, action, payload) {
      clock++;
      const payloadJSON = JSON.stringify(payload);
      const body = {action, requestId: crypto.randomUUID(), deviceId: device.deviceId, publicKey: device.publicKey,
        payloadHash: crypto.createHash('sha512').update(payloadJSON).digest('hex')};
      const challenge = licenses.Challenge(body);
      fixture.ObserveLicense(device, action, body.requestId, body.payloadHash, payload);
      return licenses.Execute({...body, challengeId: challenge.challengeId, payloadJSON, signature: fixture.Sign(device, challenge.canonical)});
    }
    function setup() {
      clock++;
      const parent = fixture.Device(), device = fixture.Child(parent), overlayDevice = fixture.Child(device), invitation = fixture.Begin(parent), begin = invitation.begin;
      fixture.Download(begin);
      const b = fixture.Claim(parent, begin, fixture.Finish(parent, begin), device);
      const common = {...fixture.Evidence(device, b), bootstrapSessionId: b.sessionId, bootstrapSessionToken: b.sessionToken, appVersion: '91.0.0'};
      const issued = licenses.Create({productId:'cleaner.pubg',requestId: crypto.randomUUID()}, 'COHORT_TEST');
      const activation = licenseProof(device, 'redeem', {...common, licenseKey: issued.licenseKey});
      const prepared = licenseProof(device, 'overlay', {...common, activationToken: activation.activationToken});
      for (let offset = 0; offset < prepared.release.size; offset += prepared.chunkSize)
        boot.Execute({action: 'overlayChunk', overlayId: prepared.overlayId, overlayTicket: prepared.overlayTicket, offset});
      const finished = boot.Execute({action: 'overlayFinish', overlayId: prepared.overlayId, overlayTicket: prepared.overlayTicket, signature: fixture.Sign(device, prepared.finishCanonical)});
      const o = boot.Execute({action: 'overlayClaim', overlayId: prepared.overlayId, overlayTicket: prepared.overlayTicket,
        ...fixture.Delegated(device, overlayDevice, 'O', finished.claimCanonical), binarySha512: prepared.release.sha512, crc64: prepared.release.crc64,
        oCodeSha512: prepared.release.codeSha512, oCodeCrc64: prepared.release.codeCrc64});
      const context = {stage: 'O', sessionId: o.sessionId, sessionToken: o.sessionToken, machineId: device.machineId};
      fixture.Enroll(overlayDevice, context);
      return {device, overlayDevice, invitation, begin, b, o, prepared, context, common, activation};
    }
    function observeAndVerify(s) {
      clock++;
      const base = overlay.AuthenticateIntegrityReport(s.context).integrityArtifact;
      const payload = JSON.stringify({version: 1, hashVersion: 3, check: 'OWN_IMAGE', reason: 'PERIODIC',
        own: {status: 'MEASURED', codeSha512: base.codeSha512, codeCrc64: base.codeCrc64,
          fileXxh3_128: base.fileXxh3_128, fileBlake3: base.fileBlake3, codeXxh3_128: base.codeXxh3_128, codeBlake3: base.codeBlake3}, crcLayers: base.crcLayers});
      const challenge = reports.Execute({...s.context, action: 'challenge'});
      assert.equal(reports.Execute({...s.context, action: 'submit', reportId: challenge.reportId, payload,
        signature: fixture.Sign(s.overlayDevice, reports.Canonical(s.o.sessionId, challenge, payload))}).status, 'VERIFIED');
      fixture.Observe(s.overlayDevice, {...s.context, intent: 'verify', binding: authority.Binding(s.o.sessionId, base.sha512)});
      return boot.Execute({action: 'overlayVerify', sessionId: s.o.sessionId, sessionToken: s.o.sessionToken, ...fixture.Evidence(s.overlayDevice, s.o)});
    }
    const parent = s => store.Load().flows[s.begin.flowId];
    const child = s => store.Load().overlays[s.prepared.overlayId];
    function terminal(s, status) {
      assert.equal(parent(s).status, status);
      assert.equal(child(s).status, status);
      assert.equal(parent(s).licenseLeaseExpiresAt, 0);
      for (const row of [parent(s), child(s)]) {
        assert.ok(row.retiredAt);
        for (const field of ['sessionNonce', 'downloadNonce', 'handoffNonce', 'ticketNonce']) assert.equal(row[field], undefined);
      }
      assert.equal(child(s).verifyReceipt, undefined);
      reject(() => fixture.Gate(s.device, s.b));
      reject(() => overlay.AuthenticateIntegrityReport(s.context));
      reject(() => boot.Execute(s.invitation.body));
      assert.equal(licenses.DB().licenses[s.activation.licenseId].consumed, true);
      assert.equal(boot.LicenseActivity(s.activation.licenseId).leaseExpiresAt, 0);
    }
    await t.test('ordinary parent close retires O, both runtime contexts, and displayed license lease', () => {
      const s = setup(); observeAndVerify(s);
      boot.Execute({action: 'close', sessionId: s.b.sessionId, sessionToken: s.b.sessionToken});
      terminal(s, 'CLOSED');
    });
    await t.test('child lease expiry retires a parent whose own lease still has time remaining', () => {
      const s = setup(), grant = observeAndVerify(s), parentExpiry = parent(s).sessionExpiresAt;
      assert.ok(grant.expiresAt < parentExpiry);
      clock = grant.expiresAt + 1;
      assert.equal(parent(s).status, 'CLAIMED');
      overlay.Prune();
      terminal(s, 'EXPIRED');
      assert.ok(parentExpiry > clock);
      const revision = store.Load().revision;
      overlay.Prune();
      assert.equal(store.Load().revision, revision, 'repeated retirement creates no new authority or writes');
      const expiredClock = clock;
      try {
        clock = grant.serverTime + 1;
        reject(() => fixture.Gate(s.device, s.b));
        reject(() => overlay.AuthenticateIntegrityReport(s.context));
        assert.equal(parent(s).status, 'EXPIRED');
        assert.equal(child(s).status, 'EXPIRED');
      } finally { clock = expiredClock; }
    });
    await t.test('revoking one O retires its B but preserves another machine and its license', () => {
      const failed = setup(), unrelated = setup(); observeAndVerify(failed); observeAndVerify(unrelated);
      const otherBefore = structuredClone([parent(unrelated), child(unrelated), licenses.DB().licenses[unrelated.activation.licenseId]]);
      overlay.Revoke(failed.o.sessionId, {reason: 'COHORT_TEST_REVOKE'}, 'COHORT_TEST');
      terminal(failed, 'REVOKED');
      assert.deepEqual([parent(unrelated), child(unrelated), licenses.DB().licenses[unrelated.activation.licenseId]], otherBefore);
      assert.equal(overlay.AuthenticateIntegrityReport(unrelated.context).sessionId, unrelated.o.sessionId);
    });
    await t.test('authorized optional O close does not terminate still-valid B', () => {
      const s = setup(); observeAndVerify(s);
      assert.equal(boot.Execute({action: 'overlayClose', sessionId: s.o.sessionId, sessionToken: s.o.sessionToken}).status, 'CLOSED');
      assert.equal(parent(s).status, 'CLAIMED');
      assert.equal(fixture.Gate(s.device, s.b).sessionId, s.b.sessionId);
      boot.Execute({action: 'close', sessionId: s.b.sessionId, sessionToken: s.b.sessionToken});
    });
    await t.test('completed B-to-O transfer survives normal parent close, then O expiry stays terminal', () => {
      const s = setup(), grant = observeAndVerify(s);
      const commit = {action: 'overlayCommit', handoffVersion: 1, sessionId: s.b.sessionId, sessionToken: s.b.sessionToken,
        overlayId: s.prepared.overlayId, signature: fixture.Sign(s.device, ['GAME-OVERLAY-TRANSFER-V1', s.b.sessionId, s.prepared.overlayId].join('\n'))};
      assert.equal(boot.Execute(commit).status, 'TRANSFERRED');
      assert.equal(boot.Execute({action: 'close', sessionId: s.b.sessionId, sessionToken: s.b.sessionToken}).status, 'CLOSED');
      assert.equal(child(s).status, 'CLAIMED');
      clock = grant.expiresAt + 1;
      overlay.Prune();
      assert.equal(parent(s).status, 'CLOSED');
      assert.equal(child(s).status, 'EXPIRED');
      assert.equal(child(s).sessionNonce, undefined);
      reject(() => overlay.AuthenticateIntegrityReport(s.context));
      reject(() => boot.Execute(commit));
    });
    await t.test('explicit revocation after transfer still retires O durable state', () => {
      const s = setup(); observeAndVerify(s);
      boot.Execute({action: 'overlayCommit', handoffVersion: 1, sessionId: s.b.sessionId, sessionToken: s.b.sessionToken,
        overlayId: s.prepared.overlayId, signature: fixture.Sign(s.device, ['GAME-OVERLAY-TRANSFER-V1', s.b.sessionId, s.prepared.overlayId].join('\n'))});
      boot.Revoke(s.b.sessionId, {reason: 'COHORT_TEST_PARENT_REVOKE'}, 'COHORT_TEST');
      terminal(s, 'REVOKED');
    });
    for(const stage of ['A','B','O'])await t.test('signed '+stage+' pointer mismatch retires only its real durable cohort',()=>{
      const unrelated=setup(),s=stage==='A'?null:setup(),device=s?(stage==='O'?s.overlayDevice:s.device):fixture.Device();
      const invitation=s?s.invitation:fixture.Begin(device),begin=invitation.begin;
      const context=stage==='A'?{stage,sessionId:begin.flowId,sessionToken:begin.downloadTicket,machineId:device.machineId}:stage==='B'?{stage,sessionId:s.b.sessionId,sessionToken:s.b.sessionToken,machineId:device.machineId}:s.context;
      const artifactId=boot.AuthenticateIntegrityReport(context).integrityArtifact.id;
      store.Atomic(db=>{db.artifacts[artifactId].ownMeasurementVersion=2;});
      const operations=require('../../services/security/peace.desktop-security-operations');
      operations.SetContract({expectedRevision:operations.Revision(),artifactId,contract:{version:1,evidenceVersion:1,minApiSlots:60,maxApiSlots:60,requiredChecks:['ownImage','apiStorage','mitigations']}},'POINTER_TEST');
      const base=boot.AuthenticateIntegrityReport(context).integrityArtifact;
      assert.equal(base.pointerGraphSlots,60);
      const graph=require('../../services/integrity/peace.pointer-graph-contract').Expected(60);graph.sha512='0'.repeat(128);
      const payload=JSON.stringify({version:1,hashVersion:3,check:'OWN_IMAGE',reason:'PERIODIC',own:{status:'MEASURED',codeSha512:base.codeSha512,codeCrc64:base.codeCrc64,fileXxh3_128:base.fileXxh3_128,fileBlake3:base.fileBlake3,codeXxh3_128:base.codeXxh3_128,codeBlake3:base.codeBlake3},crcLayers:base.crcLayers,ownMeasurement:{contract:'GAME-OWN-MEASUREMENT-BUNDLE-V2',version:2,startedTick:1,finishedTick:2,coverage:'FULL',fileStatus:'MEASURED',codeStatus:'MEASURED',crcStatus:'MEASURED',imageStable:true,pointerGraph:graph}});
      let challenge=reports.Execute({...context,action:'challenge'});
      reject(()=>reports.Execute({...context,action:'submit',reportId:challenge.reportId,payload,signature:Buffer.alloc(256).toString('base64')}));
      assert.equal(store.Load().flows[begin.flowId].status,stage==='A'?'STARTED':'CLAIMED');
      challenge=reports.Execute({...context,action:'challenge'});
      const response=reports.Execute({...context,action:'submit',reportId:challenge.reportId,payload,signature:fixture.Sign(device,reports.Canonical(stage==='A'?begin.flowId:context.sessionId,challenge,payload))});
      assert.equal(response.status,'REJECTED');assert.equal(response.terminate,true);
      assert.equal(store.Load().flows[begin.flowId].status,'REVOKED');
      if(s)terminal(s,'REVOKED');
      else{assert.equal(store.Load().launchers[invitation.issue.launcherId].status,'REVOKED');reject(()=>boot.Execute(invitation.body));}
      assert.equal(parent(unrelated).status,'CLAIMED');assert.equal(child(unrelated).status,'CLAIMED');
      store.Atomic(db=>{db.artifacts[artifactId].ownMeasurementVersion=0;});
    });
    await t.test('Run shutdown retires only the transferred caller cohort and preserves cleanup-only reporting', () => {
      const s=setup(),other=setup();observeAndVerify(s);observeAndVerify(other);
      const shutdown={action:'overlayShutdown',sessionId:s.o.sessionId,sessionToken:s.o.sessionToken,requestId:s.o.sessionId};
      const initialRevision=store.Load().revision;
      assert.throws(()=>boot.Execute(shutdown),/BOOTSTRAP_OVERLAY_NOT_READY/);
      assert.equal(store.Load().revision,initialRevision,'untransferred O cannot end B through this intent');
      const requestId=crypto.randomUUID(),permit=boot.Execute({action:'lifecycleChallenge',stage:'O',sessionId:s.o.sessionId,sessionToken:s.o.sessionToken,targetRole:'O',requestId});
      boot.Execute({action:'overlayCommit',handoffVersion:1,sessionId:s.b.sessionId,sessionToken:s.b.sessionToken,
        overlayId:s.prepared.overlayId,signature:fixture.Sign(s.device,['GAME-OVERLAY-TRANSFER-V1',s.b.sessionId,s.prepared.overlayId].join('\n'))});
      const otherBefore=structuredClone([parent(other),child(other),licenses.DB().licenses[other.activation.licenseId]]);
      assert.throws(()=>boot.Execute({...shutdown,sessionToken:other.o.sessionToken}),/BOOTSTRAP_SESSION_INVALID/);
      assert.throws(()=>boot.Execute({...shutdown,targetSessionId:other.o.sessionId}),/BOOTSTRAP_INPUT_INVALID/);
      let response,drift=0;Date.now=()=>clock+drift++;
      try{response=boot.Execute(shutdown);}finally{clock+=drift;Date.now=()=>clock;}
      assert.deepEqual(response,{version:1,sessionId:s.o.sessionId,parentSessionId:s.b.sessionId,status:'CLOSED',scope:'OWNED_A_B_O',cleanup:'PENDING'});
      assert.deepEqual([parent(other),child(other),licenses.DB().licenses[other.activation.licenseId]],otherBefore);
      assert.equal(parent(s).status,'CLOSED');assert.equal(child(s).status,'CLOSED');
      assert.equal(store.Load().launchers[parent(s).launcherId].status,'CONSUMED');
      assert.equal(parent(s).licenseLeaseExpiresAt,0);assert.equal(boot.LicenseActivity(s.activation.licenseId).leaseExpiresAt,0);
      assert.equal(child(s).sessionNonce,undefined);assert.equal(child(s).verifyReceipt,undefined);
      assert.equal(child(s).shutdownIntent.until,child(s).retiredAt+30000);
      const malformed=structuredClone(store.Load());malformed.overlays[s.prepared.overlayId].shutdownIntent.until++;
      assert.throws(()=>overlay.ValidateTransferRows(malformed),/OVERLAY_STORE_INVALID/);
      reject(()=>fixture.Gate(s.device,s.b));reject(()=>overlay.AuthenticateIntegrityReport(s.context));reject(()=>boot.Execute(s.invitation.body));
      const trace=require('../../services/observability/peace.desktop-lifecycle-trace');
      assert.equal(trace.Flow(s.begin.flowId).roles.O.fileCleanup,'NOT_REPORTED','intent acknowledgement does not invent local cleanup');
      const revision=store.Load().revision,state=require('../../core/peace.runtime-state'),maintenance=state.maintenanceMode;
      try{state.maintenanceMode=true;assert.deepEqual(boot.Execute(shutdown),response);}finally{state.maintenanceMode=maintenance;}
      assert.equal(store.Load().revision,revision,'same bounded acknowledgement performs no repeated retirement');
      assert.throws(()=>boot.Execute({...shutdown,requestId:crypto.randomUUID()}),/BOOTSTRAP_REQUEST_REUSED/);
      const summary={version:1,joinElapsedMs:45,joinBudgetMissed:false,durationTruncated:false},work=require('../../services/runtime/peace.desktop-work-queue');
      const before=work.Snapshot().shutdown.received;
      assert.equal(boot.Execute({action:'overlayClose',sessionId:s.o.sessionId,sessionToken:s.o.sessionToken,shutdown:summary}).status,'CLOSED');
      const cleanupRevision=store.Load().revision;
      assert.equal(work.Snapshot().shutdown.received,before+1,'final teardown diagnostics remain accepted after the earlier intent');
      boot.Execute({action:'overlayClose',sessionId:s.o.sessionId,sessionToken:s.o.sessionToken,shutdown:summary});
      assert.equal(store.Load().revision,cleanupRevision);assert.equal(work.Snapshot().shutdown.received,before+1);
      assert.throws(()=>boot.Execute({action:'overlayClose',sessionId:s.o.sessionId,sessionToken:s.o.sessionToken,shutdown:{...summary,joinElapsedMs:46}}),/BOOTSTRAP_REQUEST_REUSED/);
      const intentAt=child(s).shutdownIntent.at;clock=intentAt+31000;
      assert.throws(()=>boot.Execute(shutdown),/BOOTSTRAP_SESSION_CLOSED/);
      assert.throws(()=>boot.Execute({action:'overlayClose',sessionId:s.o.sessionId,sessionToken:s.o.sessionToken}),/BOOTSTRAP_SESSION_CLOSED/);
      assert.throws(()=>boot.Execute({action:'overlayClose',sessionId:s.o.sessionId,sessionToken:s.o.sessionToken,shutdown:summary}),/BOOTSTRAP_SESSION_CLOSED/);
      const eventsJson=JSON.stringify([{event:'SHUTDOWN_BEGIN',status:'REQUESTED'},{event:'FILE_CLEANUP',status:'REMOVED',win32Error:0}]);
      const report={action:'lifecycleReport',permitId:permit.permitId,requestId,eventsJson,
        signature:fixture.Sign(s.overlayDevice,['GAME-LIFECYCLE-REPORT-V1',permit.permitId,permit.nonce,requestId,fixture.sha512(eventsJson)].join('\n'))};
      assert.equal(boot.Execute(report).status,'RECORDED','preissued signed diagnostic permit survives authority retirement and the 30-second close window');
      assert.equal(trace.Flow(s.begin.flowId).roles.O.fileCleanup,'REMOVED');
      assert.equal(trace.Flow(s.begin.flowId).events.at(-1).source,'CLIENT_REPORTED');
      clock=intentAt+1;assert.throws(()=>boot.Execute(shutdown),/BOOTSTRAP_SESSION_CLOSED/,'wall-clock rollback cannot reopen expired acknowledgement');
      clock=intentAt+31001;
    });
    await t.test('retired cohorts survive a fresh store load without restoring runtime capabilities', () => {
      const script = 'const out=console.log;console.log=()=>{};Date.now=()=>Number(process.argv[1]);const boot=require(process.argv[2]),overlay=require(process.argv[3]);const db=boot.Initialize();overlay.ValidateStore(db);overlay.ValidateTransferRows(db);for(const row of [...Object.values(db.flows),...Object.values(db.overlays)]){if(["CLOSED","REVOKED","EXPIRED"].includes(row.status)&&row.sessionNonce!==undefined)throw Error("RETIRED_CAPABILITY_RESTORED");}boot.Stop();out("COHORT_RELOAD_OK");';
      const result = require('node:child_process').spawnSync(process.execPath, ['-e', script, String(clock),
        require.resolve('../../services/bootstrap/peace.desktop-bootstrap'), require.resolve('../../services/overlay/peace.desktop-overlay')],
      {env: {...process.env}, encoding: 'utf8', timeout: 10000, maxBuffer: 65536});
      assert.equal(result.status, 0, 'fresh isolated store must validate: ' + (result.error?.code || result.stderr));
      assert.equal(result.stdout.trim(), 'COHORT_RELOAD_OK');
    });

  } catch (error) { failure = error; }
  finally {
    Date.now = realNow; console.log = originalLog;
    const errors = [];
    for (const [label, dispose] of [
      ['BOOTSTRAP', () => boot?.Stop()],
      ['METRICS', () => require.cache[require.resolve('../../services/observability/peace.desktop-performance-metrics')]?.exports.Close()],
      ['SQLITE', () => require.cache[require.resolve('../../storage/sqlite/peace.sqlite-database')]?.exports.Close()],
      ['TEMP_DATA', () => fs.rmSync(temp, {recursive: true, force: true})],
      ['TEMP_CHECK', () => assert.equal(fs.existsSync(temp), false)]
    ]) { try { dispose(); } catch (_) { errors.push(label); } }
    if (errors.length) {
      const cleanup = Error('COHORT_TEST_CLEANUP_FAILED: ' + errors.join(','));
      throw failure ? new AggregateError([failure, cleanup], 'COHORT_TEST_FAILED') : cleanup;
    }
  }
  if (failure) throw failure;
});
