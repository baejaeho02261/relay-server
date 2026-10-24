'use strict';
// Production networking and storage are supplied by the deployment environment.
// Development/test defaults are isolated from NODE_ENV=production.
const net = require('node:net'), path = require('node:path');
function fail(name, reason) { throw Error('RUNTIME_CONFIG_' + name + '_' + reason); }
function port(env, name, value, allowDisabled = false) {
    if (allowDisabled && (value === undefined || value === '' || value === '0')) return 0;
    if (typeof value !== 'string' || !/^[1-9][0-9]{0,4}$/.test(value) || Number(value) > 65535)
        fail(name, value === undefined || value === '' ? 'REQUIRED' : 'INVALID');
    return Number(value);
}
function bind(env, name) {
    const value = env[name];
    if (typeof value !== 'string' || !value) fail(name, 'REQUIRED');
    if (!net.isIP(value)) fail(name, 'INVALID');
    return value;
}
function directory(env) {
    const value = env.DATA_DIR;
    if (typeof value !== 'string' || !value) fail('DATA_DIR', 'REQUIRED');
    if (/[\0\r\n]/.test(value) || !path.isAbsolute(value)) fail('DATA_DIR', 'INVALID');
    const resolved = path.resolve(value);
    if (resolved === path.parse(resolved).root) fail('DATA_DIR', 'INVALID');
    return resolved;
}
const LISTENERS = Object.freeze({
    witness:{ hostKey:'WITNESS_HOST', portKey:'WITNESS_PORT', testHost:'0.0.0.0', testPort:9444 },
    packer:{ hostKey:'PACKER_HOST', portKey:'PACKER_PORT', testHost:'127.0.0.1', testPort:9443 },
    gateway:{ hostKey:'GATEWAY_HOST', portKey:'PORT', testHost:'0.0.0.0', testPort:8080 }
});
function ReadListener(role, env = process.env) {
    const fields = Object.hasOwn(LISTENERS, role) ? LISTENERS[role] : null;
    if (!fields) fail('LISTENER_ROLE', 'INVALID');
    if (env.NODE_ENV === 'production') {
        return { host:bind(env, fields.hostKey), port:port(env, fields.portKey, env[fields.portKey]) };
    }
    const host = env[fields.hostKey] || fields.testHost;
    if (!net.isIP(host)) fail(fields.hostKey, 'INVALID');
    const rawPort = env[fields.portKey] === undefined || env[fields.portKey] === '' ? String(fields.testPort) : String(env[fields.portKey]);
    return { host, port:rawPort === '0' ? 0 : port(env, fields.portKey, rawPort) };
}
function Read(env = process.env, developmentRoot = path.resolve(__dirname, '..')) {
    const railway = env.WEB_ADMIN_TRANSPORT === 'railway';
    if (env.NODE_ENV !== 'production') {
        return {
            HOST: env.CONNECT_TCP_HOST || '0.0.0.0',
            CONNECT_TCP_PORT: Number(env.CONNECT_TCP_PORT || env.RAILWAY_TCP_APPLICATION_PORT || (railway ? 3000 : env.PORT) || 3000),
            HEALTH_PORT: Number(env.HEALTH_PORT || 0),
            WEB_ADMIN_PORT: Number(env.WEB_ADMIN_PORT || (railway ? env.PORT : 0) || 8080),
            WEB_ADMIN_HOST: env.WEB_ADMIN_HOST || (env.WEB_ADMIN_TRANSPORT === 'proxy' || !env.WEB_ADMIN_TRANSPORT ? '127.0.0.1' : '0.0.0.0'),
            DATA_DIR: env.DATA_DIR ? path.resolve(env.DATA_DIR) : path.resolve(developmentRoot)
        };
    }
    const tcp = port(env, 'CONNECT_TCP_PORT', env.CONNECT_TCP_PORT || env.RAILWAY_TCP_APPLICATION_PORT || (!railway ? env.PORT : undefined));
    const web = port(env, 'WEB_ADMIN_PORT', env.WEB_ADMIN_PORT || (railway ? env.PORT : undefined));
    if (railway && env.PORT !== undefined && port(env, 'PORT', env.PORT) !== web) fail('HTTP_PORT', 'MISMATCH');
    const health = port(env, 'HEALTH_PORT', env.HEALTH_PORT, true);
    if (tcp === web || health && (health === tcp || health === web)) fail('LISTENER_PORTS', 'CONFLICT');
    return {
        HOST: bind(env, 'CONNECT_TCP_HOST'), CONNECT_TCP_PORT: tcp,
        HEALTH_PORT: health, WEB_ADMIN_PORT: web,
        WEB_ADMIN_HOST: bind(env, 'WEB_ADMIN_HOST'), DATA_DIR: directory(env)
    };
}
module.exports = { Read, ReadListener };

