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
module.exports = { Now, After, Expired };
