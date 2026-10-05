'use strict';
const state = require('../core/state');
const save = () => require('../storage/database').SaveDatabase();
function Stop(actor = 'ADMIN') {
    const before = state.serviceEnabled;
    state.serviceEnabled = false;
    if (!save()) { state.serviceEnabled = before; return { ok: false, reason: 'DATABASE_SAVE_FAILED' }; }
    require('../storage/audit').LogEvent('SERVICE_STOP', String(actor) + ' WINDOWS_LICENSE');
    require('../web/webEvents').BroadcastServiceState({ enabled: false });
    return { ok: true, cleared: {}, preserved: true };
}
function Start(actor = 'ADMIN') {
    if (state.serviceEnabled) return { ok: true, alreadyStarted: true, resumed: 0 };
    const maintenanceBefore = state.maintenanceMode;
    state.serviceEnabled = true;
    state.maintenanceMode = false;
    if (!save()) { state.serviceEnabled = false; state.maintenanceMode = maintenanceBefore; return { ok: false, reason: 'DATABASE_SAVE_FAILED' }; }
    require('../storage/audit').LogEvent('SERVICE_START', String(actor) + ' resumed=0');
    require('../web/webEvents').BroadcastServiceState({ enabled: true });
    return { ok: true, resumed: 0 };
}
module.exports = { Start, Stop };
