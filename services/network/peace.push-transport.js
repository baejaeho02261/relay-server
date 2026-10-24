'use strict';
// The existing web-push dependency performs standards-based payload encryption
// and VAPID signing only. This module owns every network operation.
const https = require('node:https'), tls = require('node:tls');
const { performance } = require('node:perf_hooks');
const destination = require('./peace.push-destination');
const MAX_ACTIVE = 8, TOTAL_MS = 10000, MAX_PAYLOAD = 3072, MAX_RESPONSE = 16384;
let active = 0;
async function Send(webPush, subscription, payload, options) {
    if (typeof payload !== 'string' || Buffer.byteLength(payload) > MAX_PAYLOAD)
        throw destination.Failure('PUSH_PAYLOAD_TOO_LARGE');
    if (active >= MAX_ACTIVE) throw destination.Failure('PUSH_SEND_BUSY');
    active++;
    const expires = performance.now() + TOTAL_MS;
    let details;
    try {
        const target = await destination.ResolveEndpoint(subscription.endpoint, 3000);
        details = webPush.generateRequestDetails({ ...subscription, endpoint: target.endpoint }, payload, {
            TTL: 300, urgency: options?.urgency === 'high' ? 'high' : 'normal', contentEncoding: 'aes128gcm'
        });
        if (details.endpoint !== target.endpoint || details.method !== 'POST' || !Buffer.isBuffer(details.body) ||
            details.body.length > MAX_PAYLOAD + 1024 || !details.headers || typeof details.headers !== 'object')
            throw destination.Failure('PUSH_REQUEST_INVALID');
        const remaining = Math.floor(expires - performance.now());
        if (remaining < 1) throw destination.Failure('PUSH_DEADLINE');
        return await new Promise((resolve, reject) => {
            let req, response, timer, settled = false;
            function Finish(error, value) {
                if (settled) return;
                settled = true; clearTimeout(timer);
                if (error) { response?.destroy(); req?.destroy(); reject(error); }
                else resolve(value);
            }
            timer = setTimeout(() => Finish(destination.Failure('PUSH_DEADLINE')), remaining);
            try {
                const headers = { ...details.headers };
                for (const key of Object.keys(headers)) if (['host', 'connection', 'proxy-authorization'].includes(key.toLowerCase())) delete headers[key];
                headers.Host = target.hostname; headers.Connection = 'close';
                req = https.request({
                    protocol: 'https:', hostname: target.address, family: target.family, port: 443,
                    method: 'POST', path: target.path, headers, servername: target.hostname,
                    rejectUnauthorized: true, minVersion: 'TLSv1.2', agent: false,
                    // Never let IP pinning replace original-hostname validation.
                    checkServerIdentity: (_name, certificate) => tls.checkServerIdentity(target.hostname, certificate),
                    maxHeaderSize: 8192
                }, res => {
                    response = res;
                    let size = 0;
                    res.on('error', () => Finish(destination.Failure('PUSH_RESPONSE_FAILED')));
                    res.on('aborted', () => Finish(destination.Failure('PUSH_RESPONSE_ABORTED')));
                    res.on('data', chunk => { size += chunk.length;
                        if (size > MAX_RESPONSE) Finish(destination.Failure('PUSH_RESPONSE_TOO_LARGE'));
                    });
                    res.on('end', () => {
                        const statusCode = res.statusCode;
                        if (!Number.isInteger(statusCode) || statusCode < 200 || statusCode >= 300) {
                            const error = destination.Failure(statusCode >= 300 && statusCode < 400 ? 'PUSH_REDIRECT_BLOCKED' : 'PUSH_SERVICE_REJECTED');
                            error.statusCode = statusCode; Finish(error);
                        } else Finish(null, { statusCode });
                    });
                    // There is deliberately no redirect handler, proxy option,
                    // pooled socket, environment proxy or DNS fallback here.
                });
                req.on('error', () => Finish(destination.Failure('PUSH_NETWORK_FAILED')));
                req.on('close', () => { if (!settled) Finish(destination.Failure('PUSH_CONNECTION_CLOSED')); });
                req.once('socket', socket => {
                    socket.once('secureConnect', () => {
                        if (settled) return;
                        if (socket.authorized !== true || !destination.PeerMatches(socket.remoteAddress, target))
                            return Finish(destination.Failure('PUSH_PEER_INVALID'));
                        // No subscription data or HTTP headers are sent until
                        // the selected peer and TLS identity have both passed.
                        req.end(details.body);
                    });
                });
            } catch (_) { Finish(destination.Failure('PUSH_REQUEST_FAILED')); }
        });
    } finally { details?.body?.fill(0); active--; }
}
module.exports = { Send };
