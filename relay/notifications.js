'use strict';
const state = require('../core/state');
const { SafeField, SendLine } = require('../core/utils');
function NoticeAll(text, level = 'INFO') {
    const clean = SafeField(text);
    let count = 0;
    for (const server of state.servers.values()) if (SendLine(server.socket, `NOTICE|${clean}`)) count++;
    state.runtimeStats.notices += count;
    require('../storage/audit').LogEvent('NOTICE_ALL', `${count} / ${clean}`);
    return count;
}
module.exports = { NoticeAll };
