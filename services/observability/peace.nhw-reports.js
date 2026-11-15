'use strict';

// Only signed, role-bound observations enter this store. A signature proves
// the reporting session's identity and can end its own cohort. It is not an
// independent attestation of the underlying Windows activity.
const crypto = require('node:crypto');
const store = require('../bootstrap/peace.desktop-bootstrap-store');
const protocol = require('../protocol/peace.desktop-request-protocol');
const schema = require('../protocol/peace.packet-schema');
const { persistent } = require('../runtime/peace.desktop-deadline');
const { detections } = require('../../contracts/native-monitor/peace.nhw-detections-v1.json');

const catalog = Object.freeze(detections.map(row => Object.freeze({...row})));
const terminalIds = new Set(catalog.filter(row => row.terminal === true).map(row => row.id));
const publicCatalog = Object.freeze(catalog.map(({id, symbol, label, legacyLabel}) =>
 Object.freeze({id, symbol, label, legacyLabel})));
const MAX_REPORTS = 4096;
const MAX_REPORTS_PER_STAGE = 32;
const REPLAY_MS = 30000;
const ROLES = ['A', 'B', 'O'];
const TERMINAL = new Set(['CLOSED', 'REVOKED', 'EXPIRED']);
const ID = /^(?:(?:BF|DS)-)?[A-F0-9]{24}$/;
const DIGEST = /^[a-f0-9]{128}$/;
const REQUEST_ID = /^[-A-Za-z0-9_]{8,80}$/;

function Fail(code, status = 400) {
 throw Object.assign(Error(code), {desktopError: true, status});
}

function Canonical(body) {
 return ['COZY-NHW-REPORT-V1', body.stage, body.sessionId, body.requestId,
  body.ids.join(','), body.confirmedIds.join(',')].join('\n');
}

function RequestKey(stage, sessionId, requestId) {
 return crypto.createHash('sha512').update(['COZY-NHW-RECORD-V1', stage, sessionId, requestId].join('\n')).digest('hex');
}

function SortedIds(ids) {
 return Array.isArray(ids) && ids.length <= catalog.length &&
  ids.every((id, index) => Number.isInteger(id) && catalog[id]?.id === id &&
   (index === 0 || ids[index - 1] < id));
}

function ValidIds(ids, confirmedIds) {
 return SortedIds(ids) && ids.length > 0 && SortedIds(confirmedIds) &&
  confirmedIds.every(id => terminalIds.has(id) && ids.includes(id));
}

function Parse(body) {
 try {
  schema.ValidateRequest('bootstrap', body);
 } catch (_) {
  Fail('NHW_REPORT_INVALID');
 }
 if (body.action !== 'nhwReport' || !ValidIds(body.ids, body.confirmedIds)) Fail('NHW_REPORT_INVALID');
 return {
  id: RequestKey(body.stage, body.sessionId, body.requestId),
  fingerprint: protocol.Fingerprint('nhw.report', body)
 };
}

function Receipt(row) {
 return schema.ValidateDocument('nhwReport', {
  version: 1,
  status: 'RECORDED',
  terminate: row.confirmedIds.length > 0
 });
}

function Replay(db, request) {
 const row = db.nhwReports?.[request.id];
 if (!row) return null;
 if (row.fingerprint !== request.fingerprint) Fail('NHW_REQUEST_REUSED', 409);
 if (row.serverEpoch !== (db.serverRecovery?.epoch || 0) ||
  persistent.expired('nhw.report:' + row.id, row.at, row.at + REPLAY_MS)) {
  Fail('NHW_REPORT_EXPIRED', 410);
 }
 // Equality includes the originally accepted complete signature and capability,
 // yet neither secret is retained in the durable record.
 return Receipt(row);
}

function Authenticate(body) {
 const boot = require('../bootstrap/peace.desktop-bootstrap');
 try {
  return boot.AuthenticateIntegrityReport(body);
 } catch (error) {
  if (!error.desktopError || body.stage === 'O' ||
   !['BOOTSTRAP_SESSION_CLOSED', 'BOOTSTRAP_SESSION_INVALID', 'BOOTSTRAP_FLOW_INVALID', 'BOOTSTRAP_LAUNCHER_USED'].includes(error.message)) throw error;
  return boot.AuthenticateNhwHandoff(body);
 }
}

function ProofTasks(body) {
 const request = Parse(body);
 if (Replay(store.Load(), request)) return [];
 const identity = Authenticate(body);
 return [require('../integrity/peace.desktop-proof-work').Job(identity.publicKey, Canonical(body), body.signature)];
}

function EndCohort(db, flow, at) {
 const boot = require('../bootstrap/peace.desktop-bootstrap');
 const overlay = require('../overlay/peace.desktop-overlay');
 overlay.RetireNhwCohort(db, flow, at);
 if (!TERMINAL.has(flow.status)) {
  flow.status = 'CLOSED';
  flow.closedAt = at;
  flow.reason = 'NHW_CONFIRMED_DETECTION';
 }
 // Normal A->B->O ownership and already recorded release outcomes remain
 // intact. Only credentials and volatile authority for this flow retire.
 boot.RetireFlow(flow, db, {sessionOnly: true});
 boot.RetireLauncher(db.launchers[flow.launcherId], at);
}

function Forget(id) {
 store.AfterCommit(() => persistent.forget('nhw.report:' + id));
}

function Trim(rows, current) {
 const existingStage = Object.values(rows).filter(row => row.stage === current.stage && row.sessionId === current.sessionId);
 if (existingStage.length >= MAX_REPORTS_PER_STAGE) {
  const earliest = existingStage.sort((a, b) => a.at - b.at)[0];
  delete rows[earliest.id];
  Forget(earliest.id);
 }
 const all = Object.values(rows);
 if (all.length >= MAX_REPORTS) {
  const earliest = all.sort((a, b) => a.at - b.at)[0];
  delete rows[earliest.id];
  Forget(earliest.id);
 }
}

function Clear(db) {
 for (const id of Object.keys(db.nhwReports || {})) Forget(id);
 delete db.nhwReports;
}

function Record(body) {
 const request = Parse(body);
 const db = store.Load();
 const prior = Replay(db, request);
 if (prior) return prior;
 const boot = require('../bootstrap/peace.desktop-bootstrap');
 const identity = Authenticate(body);
 boot.Verify(identity, Canonical(body), body.signature);
 const flowId = body.stage === 'O' ? identity.parentFlowId : identity.id;
 const audit = require('../storage/peace.desktop-operation-audit');
 const actor = 'NHW_' + body.stage;
 return audit.Run('NHW_DETECTION_REPORT', actor, {component: body.stage, count: body.ids.length}, next => {
  const replay = Replay(next, request);
  if (replay) return replay;
  const flow = next.flows[flowId];
  if (!flow) Fail('NHW_REPORT_INVALID', 403);
  const row = {
   ...request, flowId, stage: body.stage, sessionId: body.sessionId, requestId: body.requestId,
   at: Date.now(), ids: [...body.ids], confirmedIds: [...body.confirmedIds],
   serverEpoch: next.serverRecovery?.epoch || 0
  };
  const rows = next.nhwReports || (next.nhwReports = {});
  Trim(rows, row);
  rows[row.id] = row;
  if (row.confirmedIds.length > 0) EndCohort(next, flow, row.at);
  return Receipt(row);
 });
}

function MemberIndex(db) {
 return Object.values(db.nhwReports || {}).map(row => ({
  id: row.id, flowId: row.flowId, at: row.at, stage: row.stage, detectionIds: [...row.ids],
  protectionEnded: row.confirmedIds.length > 0
 }));
}

function ValidateState(db) {
 const rows = db.nhwReports;
 const fields = ['at', 'confirmedIds', 'fingerprint', 'flowId', 'id', 'ids', 'requestId',
  'serverEpoch', 'sessionId', 'stage'].sort().join(',');
 const validObject = value => value && Object.getPrototypeOf(value) === Object.prototype;
 const invalid = () => { throw Error('NHW_REPORT_STORAGE_INVALID'); };
 if (!validObject(rows) || Object.keys(rows).length > MAX_REPORTS) invalid();
 const overlayBySession = new Map(Object.values(db.overlays || {}).map(row => [row.sessionId, row]));
 const limitBySession = new Map();
 for (const [key, row] of Object.entries(rows)) {
  if (!validObject(row) || Object.keys(row).sort().join(',') !== fields ||
   key !== row.id || !DIGEST.test(key) || !DIGEST.test(row.fingerprint) ||
   !ROLES.includes(row.stage) || !ID.test(row.sessionId) || !ID.test(row.flowId) || !REQUEST_ID.test(row.requestId) ||
   RequestKey(row.stage, row.sessionId, row.requestId) !== key ||
   !Number.isSafeInteger(row.at) || row.at < 1 || !Number.isSafeInteger(row.serverEpoch) ||
   row.serverEpoch < 0 || row.serverEpoch > (db.serverRecovery?.epoch || 0) ||
   !ValidIds(row.ids, row.confirmedIds)) invalid();
  const flow = db.flows?.[row.flowId];
  const overlay = overlayBySession.get(row.sessionId);
  if (!flow || (row.stage === 'A' && row.sessionId !== flow.id) ||
   (row.stage === 'B' && row.sessionId !== flow.sessionId) ||
   (row.stage === 'O' && (overlay?.parentFlowId !== flow.id || overlay.parentSessionId !== flow.sessionId))) invalid();
  const scope = row.stage + ':' + row.sessionId;
  const count = (limitBySession.get(scope) || 0) + 1;
  if (count > MAX_REPORTS_PER_STAGE) invalid();
  limitBySession.set(scope, count);
 }
}

module.exports = {Canonical, ProofTasks, Record, MemberIndex, PublicCatalog: () => publicCatalog, ValidateState, Clear};
