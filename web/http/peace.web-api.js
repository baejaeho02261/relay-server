'use strict';
// Request parsing and authorization gates precede every feature route.
const { productionRoutes, historyCleanup, Json, ApiError, RequireAdmin, RequireOperation, ReadJsonBody, BuildDashboard, BuildServers } = require('./peace.api-context');

async function HandleApiRequest(req, res, session) {
    const url = new URL(req.url, 'http://localhost');
    let pathname = url.pathname;
    const method = String(req.method || 'GET').toUpperCase();
    const reset=require('../../services/operations/peace.registration-reset');
    if(reset.IsDraining()&&!(method==='GET'&&pathname===reset.PATH)){ApiError(res,503,'REGISTRATION_RESET_IN_PROGRESS');return;}
    let body = {};
    const desktopMode = require("../../services/runtime/peace.desktop-mode");
    if (desktopMode.RetiredPath(pathname)) { desktopMode.Reject(res); return; }
    if (await require("../routes/bootstrap/peace.desktop-bootstrap-routes").HandleUpload({method,pathname,url,req,res,session})) return;

    if (!['GET', 'HEAD'].includes(method)) {
        const maxBodyBytes = 128 * 1024;
        try { body = await ReadJsonBody(req, maxBodyBytes); }
        catch (error) { ApiError(res, error.message === 'BODY_TOO_LARGE' ? 413 : 400, error.message); return; }
    }

    // Authentication precedes asynchronous body receipt. Recheck the live
    // managed session before any route can read protected data or mutate state.
    const webAuth = require("../authentication/peace.web-auth");
    if (webAuth.IsManagedSession(session) && !webAuth.IsSessionActive(session)) {
        ApiError(res, 401, 'NOT_AUTHORIZED'); return;
    }

    if (!body || typeof body !== 'object' || Array.isArray(body)) { ApiError(res, 400, 'INPUT_INVALID'); return; }
    if(reset.IsDraining()&&!(method==='GET'&&pathname===reset.PATH)){ApiError(res,503,'REGISTRATION_RESET_IN_PROGRESS');return;}
    if (desktopMode.RetiredTarget(pathname, body, url.searchParams)) { desktopMode.Reject(res); return; }

    if (!['GET', 'HEAD'].includes(method) && pathname !== '/api/logout' && !require("../../services/network/peace.ha-coordinator").CanAcceptTraffic()) {
        ApiError(res, 409, 'RELAY_STANDBY_READ_ONLY');
        return;
    }

    let desktopAuthorization=null;
    const desktopGuard=require("../../services/authentication/peace.desktop-admin-guard");
    if(!['GET','HEAD'].includes(method)&&desktopGuard.IsMutation(pathname)) {
        if(!require("../authentication/peace.web-auth").ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return;}
        const guarded=desktopGuard.Authorize(session,method,pathname,body,String(req.headers['x-approval-ticket']||''),String(req.headers['x-admin-enrollment-token']||''),String(req.headers['x-admin-action']||''));
        if(!guarded.ok){require("../../services/authentication/peace.desktop-action-approval").Deny(res,guarded);return;}
        desktopAuthorization=guarded;
    }
    if (!['GET','HEAD'].includes(method) && !desktopGuard.IsMutation(pathname) && require("../../services/authentication/peace.privileged-approval").Required(pathname)) {
        const ticketId = String(req.headers['x-approval-ticket'] || '');
        const approval = require("../../services/authentication/peace.privileged-approval").Consume(ticketId, session, method, pathname, body);
        if (!approval.ok) {
            if (approval.reason === 'DUAL_APPROVAL_REQUIRED') {
                const requested = require("../../services/authentication/peace.privileged-approval").Request(session, method, pathname, body, 'AUTO_GUARD');
                ApiError(res, 428, approval.reason, requested.ok ? requested.ticket.ticketId : '');
            } else ApiError(res, 428, approval.reason);
            return;
        }
    }

    if (method === 'GET' && pathname === '/api/ha/status') {
        if (!RequireOperation(res, session, 'VIEW')) return;
        Json(res, 200, { ok: true, ha: require("../../services/network/peace.ha-coordinator").Status() });
        return;
    }

    if (method === 'GET' && pathname === '/api/dashboard') {
        if (!RequireOperation(res, session, 'DASHBOARD')) return;
        Json(res, 200, { ok: true, dashboard: BuildDashboard() });
        return;
    }

    if (method === 'POST' && pathname === '/api/history/clean') {
        if (!RequireAdmin(res, session)) return;
        const result = historyCleanup.Clean(body.scope, `WEB_${String(session.role || 'ADMIN').toUpperCase()}`);
        if (!result.ok) { ApiError(res, 400, result.reason); return; }
        Json(res, 200, result);
        return;
    }

    const context = { method, pathname, url, body, req, res, session, desktopAuthorization };
    const routes=[
        require("../routes/web/peace.desktop-server-state-routes").Handle,
        require("../routes/web/peace.desktop-workspace-routes").Handle,
        require("../routes/bootstrap/peace.desktop-bootstrap-routes").Handle,
        require("../routes/licensing/peace.desktop-member-routes").Handle,
        require("../routes/licensing/peace.desktop-license-routes").Handle,
        c=>productionRoutes.Handle({...c,RequireAdmin,Json,ApiError}),
        require("../routes/devices/peace.device-routes").Handle,
        require("../routes/runtime/peace.traffic-routes").Handle,
        require("../routes/runtime/peace.history-routes").Handle,
        require("../routes/runtime/peace.report-routes").Handle,
        require("../routes/runtime/peace.deployment-routes").Handle,
        require("../routes/runtime/peace.infrastructure-routes").Handle,
        require("../routes/runtime/peace.system-routes").Handle
    ];
    for(const handle of routes){
        // A false asynchronous handler yields too: recheck between dispatches,
        // not only once before the first router receives the request.
        if(reset.IsDraining()&&!(method==='GET'&&pathname===reset.PATH)){ApiError(res,503,'REGISTRATION_RESET_IN_PROGRESS');return;}
        if(await handle(context))return;
    }
    ApiError(res, 404, 'NOT_FOUND');
}

module.exports = {
    Json,
    ApiError,
    ReadJsonBody,
    HandleApiRequest,
    BuildServers
};
