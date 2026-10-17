"use strict";
// Read-only preflight. Never prints passwords/private keys, changes firewall,
// writes a database, generates an identity, or opens a listening port.
const transport = require('../web/webTransport');
try {
    const settings = transport.Settings();
    const context = require('../services/passkeyContext').Configuration();
    if (settings.mode === 'direct') transport.CreateServer((_req, res) => res.end()).server.close();
    const ingress = settings.mode === 'railway' ? require('../web/railwayIngress').Settings() : null;
    console.log('ADMIN_SECURITY_CONFIG_OK');
    console.log(JSON.stringify({ transport: settings.mode, bind: settings.host, rpId: context.rpId,
        origin: context.origin, httpsRequired: true, secureCookie: true, firewallVerified: false,
        proxyVerified: false, physicalPasskeyVerified: false,
        ...(ingress ? { httpPort: ingress.port, tcpPort: ingress.tcpPort, healthcheckPath: '/readyz',
            trustBoundary: 'Railway edge only; no raw TCP/Docker public exposure; isolate other services',
            railwayNetworkIsolationVerified: false } : {}) }, null, 2));
} catch (error) { console.error('ADMIN_SECURITY_CONFIG_FAILED:', error.code || error.message); process.exitCode = 1; }
