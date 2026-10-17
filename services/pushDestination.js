'use strict';
// Server-side destination policy. No browser flag or persisted subscription can
// disable it. DNS is resolved once per send; HTTPS receives a numeric address.
const net = require('node:net');
const { Resolver } = require('node:dns/promises');
const DEFAULT_HOSTS = Object.freeze([
    'fcm.googleapis.com', 'updates.push.services.mozilla.com', 'web.push.apple.com'
]);
const denied4 = new net.BlockList(), denied6 = new net.BlockList(), global6 = new net.BlockList();
for (const [ip, prefix] of [
    ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
    ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
    ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
    ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
]) denied4.addSubnet(ip, prefix, 'ipv4');
// Azure platform virtual address is not a public push-service destination.
denied4.addAddress('168.63.129.16', 'ipv4');
global6.addSubnet('2000::', 3, 'ipv6');
for (const [ip, prefix] of [['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20]])
    denied6.addSubnet(ip, prefix, 'ipv6');
function Failure(code) { const e = Error(code); e.pushPolicy = true; return e; }
function Hostname(value) {
    return typeof value === 'string' && value.length <= 253 && value.includes('.') &&
        !net.isIP(value) && value.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}
function Policy() {
    // An explicit server setting REPLACES the defaults. Only exact DNS names;
    // there is no configurable wildcard, CIDR, URL or "allow private" option.
    const raw = process.env.WEB_PUSH_ALLOWED_HOSTS;
    if (raw === undefined) return { hosts: DEFAULT_HOSTS, windowsProvider: true };
    if (typeof raw !== 'string' || raw.length > 4096) throw Failure('PUSH_HOST_POLICY_INVALID');
    const hosts = raw.split(',').map(x => x.trim().toLowerCase());
    if (!hosts.length || hosts.length > 16 || hosts.some(x => !Hostname(x)) || new Set(hosts).size !== hosts.length)
        throw Failure('PUSH_HOST_POLICY_INVALID');
    return { hosts, windowsProvider: false };
}
function ValidateEndpoint(raw) {
    if (typeof raw !== 'string' || !raw || raw.length > 4096 || /[^\x21-\x7e]|[\\#]/.test(raw))
        throw Failure('PUSH_ENDPOINT_INVALID');
    let url; try { url = new URL(raw); } catch (_) { throw Failure('PUSH_ENDPOINT_INVALID'); }
    // Reject ambiguous authorities BEFORE relying on normalized URL fields.
    const authority = /^https:\/\/([^/]+)(?:\/|$)/i.exec(raw)?.[1];
    if (!authority || /[@%?]/.test(authority) || url.protocol !== 'https:' || url.username || url.password ||
        url.port || url.hash || !Hostname(url.hostname) || !url.pathname || url.pathname === '/')
        throw Failure('PUSH_ENDPOINT_INVALID');
    const policy = Policy(), windows = policy.windowsProvider &&
        /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.notify\.windows\.com$/.test(url.hostname);
    if (!policy.hosts.includes(url.hostname) && !windows) throw Failure('PUSH_HOST_NOT_ALLOWED');
    // Only the validated URL's canonical fields are used by the HTTP writer.
    return Object.freeze({ endpoint: url.href, hostname: url.hostname, path: url.pathname + url.search });
}
function IsPublicAddress(address, expectedFamily) {
    const family = net.isIP(address);
    if (!family || (expectedFamily !== undefined && family !== expectedFamily) || address.includes('%')) return false;
    if (family === 4) return !denied4.check(address, 'ipv4');
    // Reject IPv4-mapped, NAT64, loopback, ULA, link-local, multicast and special
    // transition addresses rather than treating an embedded IPv4 as public.
    return global6.check(address, 'ipv6') && !denied6.check(address, 'ipv6');
}
async function ResolveEndpoint(raw, timeoutMs = 3000) {
    const target = ValidateEndpoint(raw);
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10000) throw Failure('PUSH_DEADLINE');
    const resolver = new Resolver({ timeout: Math.min(timeoutMs, 1500), tries: 1 });
    let timer;
    try {
        const timeout = new Promise((_, reject) => { timer = setTimeout(() => {
            resolver.cancel(); reject(Failure('PUSH_DNS_TIMEOUT'));
        }, timeoutMs); });
        const results = await Promise.race([
            Promise.allSettled([resolver.resolve4(target.hostname), resolver.resolve6(target.hostname)]), timeout
        ]);
        const addresses = [];
        for (let i = 0; i < results.length; i++) {
            const result = results[i], family = i === 0 ? 4 : 6;
            if (result.status === 'rejected') {
                if (['ENODATA', 'ENOTFOUND'].includes(result.reason?.code)) continue;
                throw Failure('PUSH_DNS_FAILED');
            }
            if (!Array.isArray(result.value) || result.value.length > 32) throw Failure('PUSH_DNS_INVALID');
            for (const address of result.value) {
                if (!IsPublicAddress(address, family)) throw Failure('PUSH_ADDRESS_NOT_PUBLIC');
                addresses.push({ address, family });
            }
        }
        if (!addresses.length || addresses.length > 32) throw Failure('PUSH_DNS_EMPTY');
        // All A/AAAA answers were checked. A failed attempt is not retried via a
        // fresh unchecked lookup or an unvalidated address-family fallback.
        return Object.freeze({ ...target, ...addresses[0] });
    } finally { clearTimeout(timer); resolver.cancel(); }
}
function PeerMatches(address, target) {
    // A socket may represent an IPv4 peer as a mapped address. Only accept that
    // textual representation when the selected, validated destination was IPv4.
    if (target.family === 4 && address?.toLowerCase().startsWith('::ffff:')) address = address.slice(7);
    if (!IsPublicAddress(address, target.family)) return false;
    const allowed = new net.BlockList(); allowed.addAddress(target.address, target.family === 4 ? 'ipv4' : 'ipv6');
    return allowed.check(address, target.family === 4 ? 'ipv4' : 'ipv6');
}
module.exports = { Policy, ValidateEndpoint, ResolveEndpoint, IsPublicAddress, PeerMatches, Failure };
