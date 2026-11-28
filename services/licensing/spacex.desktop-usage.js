'use strict';

// Keep credits with the single-writer bootstrap authority. The final charge
// and retirement of the owning execution are committed together.
const DEFAULT_LIMIT = 100;
const LICENSE_ID = /^(?:DL-)?[A-F0-9]{24}$/;
const plain = value => !!value && Object.getPrototypeOf(value) === Object.prototype;

function Validate(db) {
 const rows = db.licenseUsage;
 if (rows === undefined) return;
 if (!plain(rows)) throw Error('BOOTSTRAP_STORAGE_INVALID');
 for (const [id, row] of Object.entries(rows)) {
  if (!LICENSE_ID.test(id) || !plain(row) || Object.keys(row).sort().join(',') !== 'exhaustedAt,limit,remaining' ||
      !Number.isSafeInteger(row.limit) || row.limit < 1 || row.limit > DEFAULT_LIMIT ||
      !Number.isSafeInteger(row.remaining) || row.remaining < 0 || row.remaining >= row.limit ||
      !Number.isSafeInteger(row.exhaustedAt) || (row.remaining === 0 ? row.exhaustedAt < 1 : row.exhaustedAt !== 0)) {
   throw Error('BOOTSTRAP_STORAGE_INVALID');
  }
 }
}

function Snapshot(db, id) {
 return db.licenseUsage?.[id] ?? {limit:DEFAULT_LIMIT, remaining:DEFAULT_LIMIT, exhaustedAt:0};
}

function Charge(db, id, at) {
 if (!LICENSE_ID.test(id) || !Number.isSafeInteger(at) || at < 1) throw Error('BOOTSTRAP_STORAGE_INVALID');
 const prior = Snapshot(db, id);
 if (!prior.remaining) throw Error('BOOTSTRAP_STORAGE_INVALID');
 const remaining = prior.remaining - 1;
 const next = {limit:prior.limit, remaining, exhaustedAt:remaining ? 0 : at};
 (db.licenseUsage ||= {})[id] = next;
 return next;
}

function ExhaustedAt(id) {
 const db = require('../bootstrap/spacex.desktop-bootstrap-store').Load();
 return Snapshot(db, id).exhaustedAt;
}

module.exports = {DEFAULT_LIMIT, Validate, Snapshot, Charge, ExhaustedAt};
