'use strict';

const state = require('../core/state');

function Save() { return require('../storage/database').SaveDatabase(); }

function Clean(scope, actor = 'admin') {
    scope = String(scope || '').trim().toUpperCase();
    const result = {};
    if (scope === 'ALL' || scope === 'REQUEST_TRACES') result.requestTraces = require('./requestTrace').ClearHistory();
    if (scope === 'ALL' || scope === 'CONFIG') result.config = require('./configHistory').ClearHistory(actor);
    if (scope === 'ALL' || scope === 'DAILY_REPORTS') result.dailyReports = require('./dailyHealth').ClearHistory();
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
        require('./notificationCenter').ClearNotifications();
        result.notifications = { removed };
    }
    const valid = ['ALL', 'REQUEST_TRACES', 'CONFIG', 'DAILY_REPORTS', 'SERVER_HISTORY', 'CLIENT_HISTORY', 'NOTIFICATIONS', 'AUDIT'];
    if (!valid.includes(scope)) return { ok: false, reason: 'INVALID_HISTORY_SCOPE' };
    Save();
    if (scope === 'ALL' || scope === 'AUDIT') result.audit = require('../storage/audit').ClearAudit();
    console.log('[ADMIN]', `HISTORY_CLEAN ${scope} BY ${actor}`);
    return { ok: true, scope, result };
}

module.exports = { Clean };
