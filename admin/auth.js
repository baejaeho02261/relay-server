'use strict';
// Shared role policy for the authenticated web administrator.

function ResolveAdminRole(role) {
    const r = String(role || '').trim().toLowerCase();
    return ['admin', 'operator', 'viewer'].includes(r) ? r : '';
}

function AdminAllowed(role, operation) {
    if (role === 'admin') return true;
    const viewer = new Set(['WHOAMI','LIST','SEARCH','VIEW','DASHBOARD','SERVER_LIST','CLIENT_LIST','CLIENT_DETAIL','SERVER_TREE','AUDIT','VERSION_STATUS','SCHEDULE_STATUS']);
    const operator = new Set([...viewer, 'EXTEND','UNBIND','SUSPEND','RESUME','TRANSFER','NOTICE','NOTE']);
    return role === 'viewer' ? viewer.has(operation) : role === 'operator' ? operator.has(operation) : false;
}

module.exports = { ResolveAdminRole, AdminAllowed };
