'use strict';
// Internal purpose separation does not change any signed wire transcript.
const crypto = require('node:crypto'), deadline = require("../runtime/peace.desktop-deadline");
const catalog = {};
function Add(names, domain, role, id, retry) {
  for (const name of names.split(' ')) catalog[name] = Object.freeze({ name, domain, role, id, retry });
}
Add('admin.license.create admin.license.reissue admin.license.revoke', 'ADMIN_SESSION_CSRF', 'ADMIN', 'requestId (mandatory for every version; v2 recommended)', 'durable outcome; current admin authorization');
Add('admin.launcher.issue', 'ADMIN_SESSION_CSRF', 'ADMIN', 'requestId', 'durable issue receipt; current authorization');
Add('admin.launcher.download', 'ADMIN_SESSION_CSRF', 'ADMIN', 'launcherId', 'same bytes only while capability is live');
Add('bootstrap.begin', 'LAUNCHER_CAPABILITY (inside GAME-CONNECT-4)', 'A', 'requestId', 'existing flow; live launcher and device');
Add('bootstrap.download', 'DOWNLOAD_CAPABILITY', 'A', 'flowId + offset', 'live capability; same bytes');
Add('bootstrap.finish', 'GAME-A85-FINISH-V2', 'A', 'flowId', 'live exact flow; no new handoff lifetime');
Add('bootstrap.claim', 'GAME-B85-CLAIM-V2 / GAME-HANDOFF-CLAIM-V3', 'B', 'flowId', 'exact child claim; authority re-evaluated');
Add('bootstrap.status', 'SESSION_CAPABILITY', 'B', 'sessionId', 'authenticated retained capability; projected status only; no refresh');
Add('bootstrap.close bootstrap.abort', 'SESSION_OR_DOWNLOAD_CAPABILITY', 'A/B', 'flowId/sessionId', 'terminal acknowledgement only; V3 30 seconds');
Add('lifecycle.challenge lifecycle.report','GAME-LIFECYCLE-REPORT-V1','A/B/O','requestId + role + target + one-use permit','signed diagnostic receipt only, <=180 seconds; never renews runtime authority');
Add('license.redeem license.verify license.release license.overlay', 'GAME-DESKTOP-V2 + action', 'B', 'deviceId + requestId', 'redeem/release durable; verify 240 seconds; current authority');
Add('license.challenge', 'GAME-DESKTOP-V2 + action', 'B', 'challengeId', 'new nonce; 120 second dual-clock deadline');
Add('overlay.prepare', 'GAME-DESKTOP-V2 + overlay', 'B', 'parentSessionId + requestId', 'same prepared O; no new deadline');
Add('overlay.download', 'OVERLAY_DOWNLOAD_CAPABILITY', 'B', 'overlayId + offset', 'live capability; same bytes');
Add('overlay.finish', 'GAME-OVERLAY-FINISH-V2', 'B', 'overlayId', 'live exact O handoff');
Add('overlay.claim', 'GAME-OVERLAY-CLAIM-V2 / GAME-HANDOFF-CLAIM-V3', 'O', 'overlayId', 'exact child claim; current parent/license authority');
Add('overlay.progress', 'GAME-OVERLAY-PROGRESS-V1', 'O', 'session + increasing sequence', 'diagnostics only; never extends authority');
Add('overlay.verify', 'OVERLAY_SESSION_CAPABILITY', 'O', 'server authority epoch + sequence', 'same observed renewal returns original bounded lease; current session, license, policy');
Add('overlay.commit', 'GAME-OVERLAY-TRANSFER-V1', 'B', 'parentSessionId + overlayId', 'bounded same transfer; no new authority');
Add('overlay.close', 'OVERLAY_SESSION_CAPABILITY', 'O', 'sessionId', 'terminal acknowledgement only; V3 30 seconds');
Add('overlay.abort', 'GAME-OVERLAY-ABORT-V3', 'B', 'parentSessionId + scope + identifier', 'terminal cancellation only; 30 seconds');
Add('authority.challenge authority.submit', 'GAME-AUTHORITY-V2', 'A/B/O', 'challengeId', 'submit exact receipt <=30 seconds and original decision lifetime; current authority');
Add('report.challenge report.submit', 'GAME-INTEGRITY-REPORT-V2', 'A/B/O', 'reportId', 'submit exact receipt 30 seconds; current authority, terminal denial only');
Add('device.policy device.challenge device.complete device.tpmActivate','GAME-DEVICE-IDENTITY-V2 / GAME-DEVICE-ACTIVATION-V2','A/B/O','challengeId + current session','dual-clock one-use challenge; durable exact receipt; live identity policy');
Object.freeze(catalog);
function Purpose(name) { const value = Object.hasOwn(catalog,name) ? catalog[name] : null; if (!value) throw Error('DESKTOP_PURPOSE_INVALID'); return value; }
function Resolve(operation, action) {
  const bootstrap={begin:'bootstrap.begin',chunk:'bootstrap.download',finish:'bootstrap.finish',claim:'bootstrap.claim',status:'bootstrap.status',close:'bootstrap.close',abort:'bootstrap.abort',overlayChunk:'overlay.download',overlayFinish:'overlay.finish',overlayClaim:'overlay.claim',overlayVerify:'overlay.verify',overlayProgress:'overlay.progress',overlayCommit:'overlay.commit',overlayClose:'overlay.close',overlayAbort:'overlay.abort'};
  let name;
  if(operation==='device'&&['policy','challenge','complete','tpmActivate'].includes(action))name='device.'+action;
  else if(operation==='bootstrap')name=action==='lifecycleChallenge'?'lifecycle.challenge':action==='lifecycleReport'?'lifecycle.report':Object.hasOwn(bootstrap,action)?bootstrap[action]:undefined;
  else if(operation==='security'&&['challenge','submit'].includes(action))name='authority.'+action;
  else if(operation==='report'&&['challenge','submit'].includes(action))name='report.'+action;
  else if(['challenge','execute'].includes(operation)&&['redeem','verify','release','overlay'].includes(action))name=operation==='challenge'?'license.challenge':'license.'+action;
  if(!name){const error=Error(operation==='bootstrap'?'BOOTSTRAP_INPUT_INVALID':operation==='security'?'SECURITY_INPUT_INVALID':operation==='report'?'INTEGRITY_REPORT_INVALID':'INPUT_INVALID');error.desktopError=true;error.status=400;throw error;}
  return Purpose(name);
}
function Stable(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(Stable).join(',') + ']';
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + Stable(value[key])).join(',') + '}';
}
function Fingerprint(name, body) {
  Purpose(name);
  return crypto.createHash('sha512').update('GAME-REQUEST-RECEIPT-V1\n' + name + '\n' + Stable(body)).digest('hex');
}
function RequestId(body, { legacy = true } = {}) {
  if (body.requestVersion !== undefined && body.requestVersion !== 1 && body.requestVersion !== 2) throw Error('INPUT_INVALID');
  if (body.requestId === undefined && legacy && body.requestVersion !== 2) return '';
  if (typeof body.requestId !== 'string' || !/^[-A-Za-z0-9_]{8,80}$/.test(body.requestId)) throw Error('INPUT_INVALID');
  return body.requestId;
}
function CreateReceipts({ ttlMs = 30000, max = 2048, conflict = 'REQUEST_ID_REUSED' } = {}) {
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || !Number.isSafeInteger(max) || max < 1) throw Error('DESKTOP_RECEIPT_OPTIONS_INVALID');
  const entries = new Map();
  function reused() { const error=Error(conflict); error.desktopError=true; error.status=409; throw error; }
  function prune() { const at = deadline.Now(); for (const [key, value] of entries) if (deadline.Expired(value, at)) entries.delete(key); }
  return Object.freeze({
    get(id, purpose, body) {
      prune(); const entry = entries.get(id); if (!entry) return null;
      if (entry.fingerprint !== Fingerprint(purpose, body)) reused();
      return structuredClone({ response: entry.response, meta: entry.meta });
    },
    put(id, purpose, body, response, meta, options = {}) {
      prune();
      const fingerprint=Fingerprint(purpose,body), previous=entries.get(id);
      if (previous) {
        if (previous.fingerprint!==fingerprint) reused();
        // An exact duplicate can never replace the committed response or renew
        // its original dual-clock deadline, even when put() is called twice.
        return;
      }
      const requested=options.ttlMs??ttlMs;
      if (!Number.isSafeInteger(requested)) throw Error('DESKTOP_RECEIPT_OPTIONS_INVALID');
      const bound=Math.min(ttlMs,requested);
      if (bound<=0) return;
      // Validate/clone before changing the bounded map: failed serialization
      // must not evict an unrelated live receipt.
      const value={fingerprint,response:structuredClone(response),meta:structuredClone(meta),...deadline.After(bound)};
      if (entries.size>=max) entries.delete(entries.keys().next().value);
      entries.set(id,value);
    },
    deleteWhere(predicate) { for (const [id, entry] of entries) if (predicate(entry.meta, entry.response)) entries.delete(id); },
    clear() { entries.clear(); }, prune
  });
}
module.exports = { Purpose, Resolve, Stable, Fingerprint, RequestId, CreateReceipts, catalog };
