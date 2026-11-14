'use strict';

const state = require("../../core/peace.runtime-state");

function Save() { return require("../../storage/snapshots/peace.database.js").SaveDatabase(); }

function Clean(scope, actor = 'admin') {
    scope = String(scope || '').trim().toUpperCase();
    const valid = ['ALL', 'REQUEST_TRACES', 'CONFIG', 'DAILY_REPORTS', 'SERVER_HISTORY', 'CLIENT_HISTORY', 'NOTIFICATIONS', 'AUDIT'];
    if (!valid.includes(scope)) return { ok: false, reason: 'INVALID_HISTORY_SCOPE' };
    const audit=require('./peace.desktop-operation-audit'),operation=audit.Begin('ADMIN_HISTORY_CLEAN',actor,{reasonCode:scope});
    try {
    const result = {};
    if (scope === 'ALL' || scope === 'REQUEST_TRACES') result.requestTraces = require("../observability/peace.request-trace").ClearHistory();
    if (scope === 'ALL' || scope === 'CONFIG') result.config = require("../runtime/peace.config-history").ClearHistory(actor);
    if (scope === 'ALL' || scope === 'DAILY_REPORTS') result.dailyReports = require("../observability/peace.daily-health").ClearHistory();
    if (scope === 'ALL' || scope === 'SERVER_HISTORY') {
        const reconnectDevices = state.runtimeStats.serverReconnectHistory.size;
        const flappingDevices = state.runtimeStats.serverFlappingAlerts.size;
        state.runtimeStats.serverReconnectHistory.clear();
        state.runtimeStats.serverFlappingAlerts.clear();
        result.serverHistory = { reconnectDevices, flappingDevices };
    }
    if (scope === 'ALL' || scope === 'CLIENT_HISTORY') {
        const reconnectDevices = state.runtimeStats.clientReconnectHistory.size;
        const flappingDevices = state.runtimeStats.clientFlappingAlerts.size;
        state.runtimeStats.clientReconnectHistory.clear();
        state.runtimeStats.clientFlappingAlerts.clear();
        result.clientHistory = { reconnectDevices, flappingDevices };
    }
    if (scope === 'ALL' || scope === 'NOTIFICATIONS') {
        const removed = state.notifications.length;
        require("../observability/peace.notification-center").ClearNotifications();
        result.notifications = { removed };
    }
    if(Save()===false)throw Error('HISTORY_STORAGE_SAVE_FAILED');
    if (scope === 'ALL' || scope === 'AUDIT') result.audit = require("../../storage/audit/peace.audit.js").ClearAudit(actor);
    audit.CommitExternal(operation);
    console.log('[ADMIN]', 'HISTORY_CLEAN '+scope);
    return { ok: true, scope, result };
    } catch(error) {audit.Failed(operation,error);throw error;}
}

module.exports = { Clean };
