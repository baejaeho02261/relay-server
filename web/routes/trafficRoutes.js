'use strict';
const { ListNotifications, NotificationSummary, MarkRead, MarkAllRead, ClearNotifications, Json, ApiError, DecodePart, RequireAdmin, RequireOperation } = require('../apiContext');
async function Handle({ method, pathname, url, body, req, res, session }) {
    let match, m;
    if (method === 'GET' && pathname === '/api/notifications') {
        if (!RequireOperation(res, session, 'DASHBOARD')) return true;
        Json(res, 200, {
            ok: true,
            summary: NotificationSummary(),
            notifications: ListNotifications({
                unreadOnly: url.searchParams.get('unread') === '1',
                severity: url.searchParams.get('severity') || 'ALL',
                limit: Number(url.searchParams.get('limit') || 200)
            })
        });
        return true;
    }

    match = pathname.match(/^\/api\/notifications\/([^/]+)\/read$/);
    if (method === 'POST' && match) {
        if (!RequireOperation(res, session, 'DASHBOARD')) return true;
        if (!MarkRead(DecodePart(match[1]), body.read !== false)) { ApiError(res, 404, 'NOTIFICATION_NOT_FOUND'); return true; }
        Json(res, 200, { ok: true, summary: NotificationSummary() });
        return true;
    }

    if (method === 'POST' && pathname === '/api/notifications/read-all') {
        if (!RequireOperation(res, session, 'DASHBOARD')) return true;
        MarkAllRead();
        Json(res, 200, { ok: true, summary: NotificationSummary() });
        return true;
    }

    if (method === 'POST' && pathname === '/api/notifications/clear') {
        if (!RequireAdmin(res, session)) return true;
        ClearNotifications();
        Json(res, 200, { ok: true, summary: NotificationSummary() });
        return true;
    }

    if (method === 'GET' && pathname === '/api/request-traces') {
        if (!RequireOperation(res, session, 'DASHBOARD')) return true;
        const traces = require('../../services/requestTrace').SearchTraces(url.searchParams.get('query') || '');
        Json(res, 200, { ok: true, traces });
        return true;
    }

    return false;
}
module.exports = { Handle };
