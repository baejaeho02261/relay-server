'use strict';

// Resolve only public connection settings. Never serialize process.env.
const net = require('node:net');
function Value(value) {
    const text = String(value || '').trim();
    if (text.length >= 2 && ((text[0] === '"' && text.at(-1) === '"') || (text[0] === "'" && text.at(-1) === "'"))) return text.slice(1, -1).trim();
    return text;
}
function Resolve(env = process.env) {
    const manualHost = Value(env.DESKTOP_PUBLIC_HOST), manualPort = Value(env.DESKTOP_PUBLIC_PORT);
    // An explicitly configured pair always wins. Do not silently replace an
    // invalid explicit endpoint with a different Railway destination.
    const manual = !!(manualHost || manualPort);
    const hostVariable = manual ? 'DESKTOP_PUBLIC_HOST' : 'RAILWAY_TCP_PROXY_DOMAIN';
    const portVariable = manual ? 'DESKTOP_PUBLIC_PORT' : 'RAILWAY_TCP_PROXY_PORT';
    const host = (manual ? manualHost : Value(env.RAILWAY_TCP_PROXY_DOMAIN)).toLowerCase();
    const portText = manual ? manualPort : Value(env.RAILWAY_TCP_PROXY_PORT);
    const port = /^\d{1,5}$/.test(portText) ? Number(portText) : 0;
    const dns = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/.test(host);
    const validHost = net.isIP(host) === 4 || (dns && !/^[\d.]+$/.test(host));
    const problems = [];
    if (!host) problems.push(hostVariable + ' 값을 현재 실행 중인 서버에서 읽지 못했습니다.');
    else if (!validHost) problems.push(hostVariable + '에는 IPv4 또는 호스트 이름만 입력하세요. https://, 경로, :포트는 제외합니다.');
    if (!portText) problems.push(portVariable + ' 값을 현재 실행 중인 서버에서 읽지 못했습니다.');
    else if (port < 1 || port > 65535) problems.push(portVariable + '에는 외부 TCP 포트 숫자(1~65535)만 입력하세요.');
    return { ready: problems.length === 0, source: manual ? 'manual' : 'railway',
        host, port, portText, hostVariable, portVariable, problems };
}
function Diagnostics(env = process.env) {
    const config = require('../config/config'), endpoint = Resolve(env);
    const probePort = Number(env.PORT || config.WEB_ADMIN_PORT);
    return { revision: config.WEB_UI_REVISION, source: endpoint.source, ready: endpoint.ready,
        host: endpoint.host.slice(0, 253), port: endpoint.portText.slice(0, 32),
        hostVariable: endpoint.hostVariable, portVariable: endpoint.portVariable,
        problems: endpoint.problems, tcpPort: config.CONNECT_TCP_PORT,
        httpPort: config.WEB_ADMIN_PORT, probePort: Number.isInteger(probePort) ? probePort : null,
        probePortMatches: probePort === config.WEB_ADMIN_PORT };
}
function LogConfiguration() {
    const info = Diagnostics();
    console.log('Connect public endpoint:', info.ready ? `${info.host}:${info.port} (${info.source})` : `NOT CONFIGURED (${info.hostVariable}, ${info.portVariable})`);
    console.log('Connect server revision:', info.revision);
    console.log('HTTP deployment check:', `/readyz on ${info.httpPort}; PORT=${info.probePort}`);
    if (!info.probePortMatches && (process.env.RAILWAY_SERVICE_ID || process.env.RAILWAY_ENVIRONMENT_ID)) {
        console.warn('RAILWAY_HEALTHCHECK_PORT_MISMATCH: set PORT=' + info.httpPort + ' and CONNECT_TCP_PORT=' + info.tcpPort + ', then deploy both changes together.');
    }
}
module.exports = { Resolve, Diagnostics, LogConfiguration };
