'use strict';
// Request parsing and authorization gates precede every feature route.
const { productionRoutes, historyCleanup, Json, ApiError, RequireAdmin, RequireOperation, ReadJsonBody, BuildDashboard, BuildServers } = require('./apiContext');

async function HandleApiRequest(req, res, session) {
    const url = new URL(req.url, 'http://localhost');
    let pathname = url.pathname;
    const method = String(req.method || 'GET').toUpperCase();
    let body = {};
    const desktopMode = require('../services/desktopMode');
    if (desktopMode.RetiredPath(pathname)) { desktopMode.Reject(res); return; }
    if (await require('./routes/desktopBootstrapRoutes').HandleUpload({method,pathname,url,req,res,session})) return;

    if (!['GET', 'HEAD'].includes(method)) {
        const maxBodyBytes = 128 * 1024;
        try { body = await ReadJsonBody(req, maxBodyBytes); }
        catch (error) { ApiError(res, error.message === 'BODY_TOO_LARGE' ? 413 : 400, error.message); return; }
    }

    // Body collection can outlive logout, revocation or credential rotation.
    if (!require('./webAuth').IsSessionActive(session)) { ApiError(res, 401, 'NOT_AUTHORIZED'); return; }

    if (!body || typeof body !== 'object' || Array.isArray(body)) { ApiError(res, 400, 'INPUT_INVALID'); return; }
    if (desktopMode.RetiredTarget(pathname, body, url.searchParams)) { desktopMode.Reject(res); return; }

    if (!['GET', 'HEAD'].includes(method) && pathname !== '/api/logout' && !require('../services/haCoordinator').CanAcceptTraffic()) {
        ApiError(res, 409, 'RELAY_STANDBY_READ_ONLY');
        return;
    }

    let desktopAuthorization=null;
    const desktopGuard=require('../services/desktopAdminGuard');
    if(!['GET','HEAD'].includes(method)&&desktopGuard.IsMutation(pathname)) {
        if(!require('./webAuth').ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return;}
        const guarded=desktopGuard.Authorize(session,method,pathname,body,String(req.headers['x-approval-ticket']||''));
        if(!guarded.ok){ApiError(res,guarded.status||428,guarded.reason,guarded.ticketId||'');return;}
        desktopAuthorization=guarded;
    }
    if (!['GET','HEAD'].includes(method) && !desktopGuard.IsMutation(pathname) && require('../services/privilegedApproval').Required(pathname)) {
        const ticketId = String(req.headers['x-approval-ticket'] || '');
        const approval = require('../services/privilegedApproval').Consume(ticketId, session, method, pathname, body);
        if (!approval.ok) {
            if (approval.reason === 'DUAL_APPROVAL_REQUIRED') {
                const requested = require('../services/privilegedApproval').Request(session, method, pathname, body, 'AUTO_GUARD');
                ApiError(res, 428, approval.reason, requested.ok ? requested.ticket.ticketId : '');
            } else ApiError(res, 428, approval.reason);
            return;
        }
    }

    if (method === 'GET' && pathname === '/api/ha/status') {
        if (!RequireOperation(res, session, 'VIEW')) return;
        Json(res, 200, { ok: true, ha: require('../services/haCoordinator').Status() });
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
    if (await require('./routes/desktopWorkspaceRoutes').Handle(context)) return;
    if (await require('./routes/desktopBootstrapRoutes').Handle(context)) return;
    if (await require('./routes/desktopLicenseRoutes').Handle(context)) return;

    if (await productionRoutes.Handle({
        method, pathname, body, req, res, session,
        RequireAdmin, Json, ApiError
    })) return;

    if (await require('./routes/deviceRoutes').Handle(context)) return;
    if (await require('./routes/trafficRoutes').Handle(context)) return;
    if (await require('./routes/historyRoutes').Handle(context)) return;
    if (await require('./routes/reportRoutes').Handle(context)) return;
    if (await require('./routes/deploymentRoutes').Handle(context)) return;
    if (await require('./routes/infrastructureRoutes').Handle(context)) return;
    if (await require('./routes/systemRoutes').Handle(context)) return;
    ApiError(res, 404, 'NOT_FOUND');
}

module.exports = {
    Json,
    ApiError,
    ReadJsonBody,
    HandleApiRequest,
    BuildServers
};
