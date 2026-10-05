'use strict';
const state = require('./state');
const { SendLine } = require('./utils');
function ForceReconnectAll(reason) {
    for (const c of state.servers.values()) {
        SendLine(c.socket, `ERROR|${reason}`);
        try { c.socket.destroy(); } catch (_) {}
    }
}
function Shutdown() {
    try { require('../storage/backup').CreateBackup('shutdown'); require('../storage/database').SaveDatabase(); }
    finally { process.exit(0); }
}
module.exports = { ForceReconnectAll, Shutdown };
