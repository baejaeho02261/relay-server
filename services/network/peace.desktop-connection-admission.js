"use strict";
// A synchronous, atomic pre-TLS reservation. Rejected attempts never spend
// another peer's budget, add map entries, or move a fixed window deadline.
const { performance } = require('node:perf_hooks');
const { Address } = require("../../web/authentication/peace.web-auth-policy");
class Admission {
    constructor({ windowMs = 60000, globalMax = 1800, ipMax = 1200, activeMax = 512,
        ipActiveMax = 32, maxEntries = 12000, now = () => performance.now() } = {}) {
        for (const value of [windowMs, globalMax, ipMax, activeMax, ipActiveMax, maxEntries])
            if (!Number.isSafeInteger(value) || value < 1) throw Error('CONNECT_ADMISSION_CONFIG_INVALID');
        if (typeof now !== 'function') throw Error('CONNECT_ADMISSION_CONFIG_INVALID');
        Object.assign(this, { windowMs, globalMax, ipMax, activeMax, ipActiveMax, maxEntries, now });
        this.rows = new Map(); this.active = 0; this.global = { count: 0, until: 0 };
        this.lastPrune = -Infinity; this.lastTick = -Infinity;
    }
    Acquire(rawIp) {
        const address = Address(rawIp);
        if (!address) throw Error('CONNECT_PEER_INVALID');
        const ip = address.text, at = this.now();
        if (!Number.isFinite(at) || at < this.lastTick) throw Error('CONNECT_CLOCK_INVALID');
        this.lastTick = at;
        if (at - this.lastPrune >= 1000) {
            this.lastPrune = at;
            for (const [key, row] of this.rows) if (row.until <= at && row.active === 0) this.rows.delete(key);
        }
        const row = this.rows.get(ip);
        if ((row?.active || 0) >= this.ipActiveMax || this.active >= this.activeMax) throw Error('CONNECT_CAPACITY');
        if (row && row.until > at && row.count >= this.ipMax) throw Error('CONNECT_RATE_LIMIT');
        if (this.global.until > at && this.global.count >= this.globalMax) throw Error('CONNECT_RATE_LIMIT');
        if (!row && this.rows.size >= this.maxEntries) throw Error('CONNECT_CAPACITY');
        // Commit both counters only after every admission check succeeds.
        const target = row || { count: 0, until: at + this.windowMs, active: 0 };
        if (target.until <= at) { target.count = 0; target.until = at + this.windowMs; }
        if (this.global.until <= at) this.global = { count: 0, until: at + this.windowMs };
        target.count++; target.active++; this.global.count++; this.active++;
        this.rows.set(ip, target);
        let released = false;
        return { ip, release: () => {
            if (released) return false;
            released = true; this.active--; target.active--;
            return true;
        } };
    }
}
module.exports = { Admission };
