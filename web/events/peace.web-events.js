'use strict';

const { Now } = require("../../core/peace.utilities.js");

const streams = new Set();
const MAX_BUFFER_BYTES = 64 * 1024;
let timer = null;

function DestroyResponse(res) {
    try { if (typeof res.destroy === 'function') res.destroy(); else res.end(); } catch (_) {}
}

function WriteEvent(res, event, data) {
    try {
        if (res.destroyed || res.writableEnded) return false;
        const packet = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
        // A slow browser must not retain an unbounded queue of administrator
        // events. Reconnection fetches the current state through the normal API.
        if ((Number(res.writableLength) || 0) + Buffer.byteLength(packet) > MAX_BUFFER_BYTES || !res.write(packet)) {
            DestroyResponse(res);
            return false;
        }
        return true;
    } catch (_) {
        DestroyResponse(res);
        return false;
    }
}

function Remove(item) {
    streams.delete(item);
    item.req.removeListener('close', item.closed);
    if (streams.size === 0 && timer) { clearInterval(timer); timer = null; }
}

function EnsureTimer() {
    if (timer) return;
    timer = setInterval(() => {
        const now = Now();
        for (const item of Array.from(streams)) {
            if (!require("../authentication/peace.web-auth").IsSessionActive(item.session)) {
                try { WriteEvent(item.res, 'session', { expired: true }); item.res.end(); } catch (_) {}
                Remove(item);
                continue;
            }
            if (!WriteEvent(item.res, 'tick', { time: now })) Remove(item);
        }
    }, 3000);
    timer.unref();
}

function Broadcast(event, data) {
    for (const item of Array.from(streams)) {
        if (!require("../authentication/peace.web-auth").IsSessionActive(item.session)) {
            try { item.res.end(); } catch (_) {}
            Remove(item);
            continue;
        }
        if (!WriteEvent(item.res, event, data)) Remove(item);
    }
}

function BroadcastEvent(data) { Broadcast('relay-event', data); }
function BroadcastNotification(data) { Broadcast('notification', data); }
function BroadcastServiceState(data) { Broadcast('service-state', data); }

function OpenEventStream(req, res, session) {
    res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
    });
    if (!WriteEvent(res, 'ready', { time: Now(), role: session.role })) return;

    const item = { req, res, session, closed: null };
    item.closed = () => Remove(item);
    streams.add(item);
    req.once('close', item.closed);
    EnsureTimer();
}

function Stop() {
    if (timer) { clearInterval(timer); timer = null; }
    for (const item of Array.from(streams)) {
        Remove(item);
        DestroyResponse(item.res);
    }
}

module.exports = {
    OpenEventStream,
    BroadcastEvent,
    BroadcastNotification,
    BroadcastServiceState,
    Stop
};
