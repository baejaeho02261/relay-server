'use strict';
// Process-local monotonic bounds complement the existing signed wall-clock
// expiry. Never serialize deadline or reconstruct it from a client timestamp.
const { performance } = require('node:perf_hooks');
function Now() { return { wall: Date.now(), tick: performance.now() }; }
function After(milliseconds) {
  if (!Number.isSafeInteger(milliseconds) || milliseconds <= 0) throw Error('DESKTOP_DEADLINE_INVALID');
  const at = Now(), expiresAt = at.wall + milliseconds, deadline = at.tick + milliseconds;
  if (!Number.isSafeInteger(expiresAt) || !Number.isFinite(deadline)) throw Error('DESKTOP_DEADLINE_INVALID');
  return { expiresAt, deadline };
}
function Expired(value, at = Now()) {
  return !value || !Number.isSafeInteger(value.expiresAt) || !Number.isFinite(value.deadline) ||
    !Number.isFinite(at.wall) || !Number.isFinite(at.tick) || value.expiresAt <= at.wall || value.deadline <= at.tick;
}
// Durable capabilities retain their signed wall expiry; process-local bounds
// are adopted once, then retained across store clones. No monotonic timestamp
// is serialized. A restart adopts only the remaining wall lifetime and rejects
// a clock earlier than issuance. A host clock cannot be attested by this helper.
function CreatePersistentBounds({max = 131072} = {}) {
  const entries = new Map();
  if (!Number.isSafeInteger(max) || max < 1) throw Error('DESKTOP_DEADLINE_INVALID');
  return Object.freeze({
    expired(id, issuedAt, expiresAt) {
      const at = Now();
      if (typeof id !== 'string' || !id || !Number.isSafeInteger(issuedAt) ||
          !Number.isSafeInteger(expiresAt) || expiresAt <= issuedAt ||
          at.wall < issuedAt || !Number.isFinite(at.tick)) return true;
      let item = entries.get(id);
      if (!item || item.issuedAt !== issuedAt || item.expiresAt !== expiresAt) {
        // Only a newly committed generation may have a new deadline. Reading
        // the same capability again cannot extend its monotonic allowance.
        if (item && (issuedAt < item.issuedAt || issuedAt === item.issuedAt && expiresAt < item.expiresAt)) return true;
        if (!item && entries.size >= max) return true;
        item = {issuedAt, expiresAt, deadline: at.tick + Math.max(0, expiresAt - at.wall)};
        entries.set(id, item);
      }
      return Expired(item, at);
    },
    forget(id) { entries.delete(id); }
  });
}
const persistent = CreatePersistentBounds();
module.exports = { Now, After, Expired, CreatePersistentBounds, persistent };
