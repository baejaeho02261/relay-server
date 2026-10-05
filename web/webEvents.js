'use strict';

const { Now } = require('../core/utils');
const { IsSessionActive } = require('./webAuth');

const streams = new Set();
let timer = null;

function WriteEvent(res, event, data) {
    try {
        if (res.destroyed || res.writableEnded) return false;
        // SSE is advisory: close a slow consumer instead of growing its queue.
        if (!res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)) { res.destroy(); return false; }
        return true;
    } catch (_) {
        return false;
    }
}

function EnsureTimer() {
    if (timer) return;
    timer = setInterval(() => {
        const now = Now();
        for (const item of Array.from(streams)) {
            if (!IsSessionActive(item.session)) {
                try { WriteEvent(item.res, 'session', { expired: true }); item.res.end(); } catch (_) {}
                streams.delete(item);
                continue;
            }
            if (!WriteEvent(item.res, 'tick', { time: now })) streams.delete(item);
        }
        if (streams.size === 0 && timer) {
            clearInterval(timer);
            timer = null;
        }
    }, 3000);
    timer.unref();
}

function BroadcastEvent(data) {
    for (const item of Array.from(streams)) {
        if (!IsSessionActive(item.session)) { try { item.res.end(); } catch (_) {} streams.delete(item); continue; }
        if (!WriteEvent(item.res, 'relay-event', data)) streams.delete(item);
    }
}

function BroadcastNotification(data) {
    for (const item of Array.from(streams)) {
        if (!IsSessionActive(item.session)) { try { item.res.end(); } catch (_) {} streams.delete(item); continue; }
        if (!WriteEvent(item.res, 'notification', data)) streams.delete(item);
    }
}

function BroadcastServiceState(data) {
    for (const item of Array.from(streams)) {
        if (!IsSessionActive(item.session)) { try { item.res.end(); } catch (_) {} streams.delete(item); continue; }
        if (!WriteEvent(item.res, 'service-state', data)) streams.delete(item);
    }
}

function OpenEventStream(req, res, session) {
    if (!IsSessionActive(session)) { res.writeHead(401); res.end(); return; }
    if (streams.size >= 256 || [...streams].filter(item => item.session === session).length >= 8) {
        res.writeHead(429, { 'Retry-After': '3', 'Cache-Control': 'no-store' }); res.end(); return;
    }
    res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
    });
    res.write(': connected\n\n');
    if (!WriteEvent(res, 'ready', { time: Now(), role: session.role })) return;

    const item = { res, session };
    streams.add(item);
    EnsureTimer();

    res.once('close', () => streams.delete(item));
    res.once('error', () => { streams.delete(item); res.destroy(); });
}

module.exports = {
    OpenEventStream,
    BroadcastEvent,
    BroadcastNotification,
    BroadcastServiceState
};
