'use strict';

const { Now } = require('../core/utils');
const { IsSessionActive } = require('./webAuth');

const streams = new Set();
const MAX_STREAMS = 256;
const MAX_STREAMS_PER_SESSION = 8;
let timer = null;

function StopTimerIfIdle() {
    if (streams.size === 0 && timer) { clearInterval(timer); timer = null; }
}

function CloseStream(item, destroy = false) {
    streams.delete(item);
    try { if (destroy) item.res.destroy(); else item.res.end(); } catch (_) {}
    StopTimerIfIdle();
}

function WriteEvent(res, event, data) {
    if (res.destroyed || res.writableEnded) return false;
    try {
        // One bounded write: disconnect slow peers rather than queue indefinitely.
        return res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`) !== false;
    } catch (_) {
        return false;
    }
}

function Broadcast(event, data) {
    for (const item of Array.from(streams)) {
        if (!IsSessionActive(item.session)) {
            WriteEvent(item.res, 'session', { expired: true });
            CloseStream(item);
        } else if (!WriteEvent(item.res, event, data)) CloseStream(item, true);
    }
}

function EnsureTimer() {
    if (timer) return;
    timer = setInterval(() => Broadcast('tick', { time: Now() }), 3000);
    timer.unref();
}

function BroadcastEvent(data) { Broadcast('relay-event', data); }
function BroadcastNotification(data) { Broadcast('notification', data); }
function BroadcastServiceState(data) { Broadcast('service-state', data); }

function OpenEventStream(req, res, session) {
    if (!IsSessionActive(session)) {
        res.writeHead(401, { 'Cache-Control': 'no-store' });
        res.end();
        return;
    }
    // Reclaim revoked sessions before enforcing limits on new connections.
    for (const item of Array.from(streams)) if (!IsSessionActive(item.session)) CloseStream(item);
    let sessionCount = 0;
    for (const item of streams) if (item.session === session) sessionCount++;
    if (streams.size >= MAX_STREAMS || sessionCount >= MAX_STREAMS_PER_SESSION) {
        res.writeHead(429, { 'Retry-After': '5', 'Cache-Control': 'no-store' });
        res.end();
        return;
    }
    res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
    });
    const item = { res, session };
    streams.add(item);
    const onClose = () => { streams.delete(item); StopTimerIfIdle(); };
    res.once('close', onClose);
    res.once('error', () => CloseStream(item, true));
    req.once('aborted', () => CloseStream(item, true));
    if (!WriteEvent(res, 'ready', { time: Now(), role: session.role })) { CloseStream(item, true); return; }
    EnsureTimer();
}

module.exports = {
    OpenEventStream,
    BroadcastEvent,
    BroadcastNotification,
    BroadcastServiceState
};
