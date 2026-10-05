'use strict';
const { TextDecoder } = require('node:util');

// A single bounded reader for administrator JSON bodies. Rejection settles the
// promise and releases buffers even when a sender disconnects before end.
function ReadJsonBody(req, maxBytes = 128 * 1024) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0, settled = false;
        const timer = setTimeout(() => {
            finish(new Error('BODY_TIMEOUT'));
            req.destroy();
        }, 15000);
        timer.unref();
        function cleanup() {
            clearTimeout(timer);
            req.removeListener('data', data);
            req.removeListener('end', end);
            req.removeListener('aborted', aborted);
            req.removeListener('close', close);
            chunks.length = 0;
        }
        function finish(error, value) {
            if (settled) return;
            settled = true;
            cleanup();
            if (error) reject(error); else resolve(value);
        }
        function data(chunk) {
            size += chunk.length;
            if (size > maxBytes) {
                finish(new Error('BODY_TOO_LARGE'));
                req.resume();
                return;
            }
            chunks.push(chunk);
        }
        function end() {
            let bytes;
            try {
                bytes = Buffer.concat(chunks, size);
                const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
                const value = text ? JSON.parse(text) : {};
                if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error();
                finish(null, value);
            } catch (_) { finish(new Error('INVALID_JSON')); }
            finally { bytes?.fill(0); }
        }
        function aborted() { finish(new Error('BODY_ABORTED')); }
        function close() { if (!req.complete) aborted(); }
        req.on('data', data);
        req.once('end', end);
        req.once('aborted', aborted);
        req.once('close', close);
        // Retain this once listener through close so a late socket error cannot
        // become an unhandled EventEmitter error after an early size rejection.
        req.once('error', error => finish(error));
        const declared = req.headers?.['content-length'];
        if (declared !== undefined && (!/^\d+$/.test(String(declared)) || Number(declared) > maxBytes)) {
            finish(new Error('BODY_TOO_LARGE'));
            req.resume();
        }
        if (req.aborted || req.destroyed) aborted();
    });
}
module.exports = { ReadJsonBody };
