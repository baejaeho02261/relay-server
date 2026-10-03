'use strict';

const crypto = require('crypto');
const state = require('../core/state');
const { Now, SafeField } = require('../core/utils');

const PROTECTED = [
    /^\/api\/system\/service\/stop$/,
    /^\/api\/backups\/[^/]+\/(restore|delete)$/,
    /^\/api\/(servers|clients|licenses)\/[^/]+$/,
    /^\/api\/(servers|clients)\/[^/]+\/(kick|disable)$/,
    /^\/api\/licenses\/bulk$/,
    /^\/api\/licenses\/[^/]+\/(reissue|delete)$/,
    /^\/api\/production\/(config\/apply|transport|retention\/apply|update\/rollback)$/,
    /^\/api\/production\/(dual-policy|passkeys\/revoke)$/,
    /^\/api\/desktop\/bootstrap\/(security-authority|integrity-policy|artifacts|module-baselines)$/,
    /^\/api\/desktop\/bootstrap\/security-operations\/(controls|contracts|signers|rollout|test-evidence|activate|enable-all)$/
];

function Digest(method, path, body) {
    return crypto.createHash('sha256').update(`${String(method).toUpperCase()}|${path}|${JSON.stringify(body || {})}`).digest('hex').toUpperCase();
}
function Required(pathname) {
    if(pathname==='/api/desktop/bootstrap/security-operations/enable-all')return true;
    const desktop=require('./desktopAdminGuard').IsMutation(pathname);
    return (state.production.deploymentManifest.dualApprovalRequired === true || desktop&&require('./desktopSecurityActivation').AdminEnforced()) && PROTECTED.some(re=>re.test(pathname));
}
function Request(session, method, pathname, body, note='') {
    if (!session || session.role !== 'admin') return {ok:false,reason:'ADMIN_REQUIRED'};
    const desktop=require('./desktopAdminGuard').IsMutation(pathname);
    const principal=desktop?require('./desktopAdminGuard').Identity(session):'';
    if(desktop&&!principal)return{ok:false,reason:'SECURITY_ADMIN_IDENTITY_REQUIRED'};
    const digest=Digest(method,pathname,body);
    const existing=Array.from(state.production.privilegedApprovals.values()).find(x=>x.status==='PENDING'&&x.expiresAt>Now()&&x.requestedBy===session.id&&x.payloadHash===digest);
    if(existing)return{ok:true,ticket:existing};
    const ticket={ticketId:`DUAL-${crypto.randomBytes(10).toString('hex').toUpperCase()}`,method:String(method).toUpperCase(),pathname:String(pathname),payloadHash:Digest(method,pathname,body),note:SafeField(note).slice(0,200),status:'PENDING',requestedAt:Now(),requestedBy:session.id,approvedAt:0,approvedBy:'',expiresAt:Now()+10*60000,consumedAt:0};
    if(desktop){ticket.requestedPrincipal=principal;ticket.summary=require('./desktopAdminGuard').Summary(pathname,body);}
    state.production.privilegedApprovals.set(ticket.ticketId,ticket);if(!require('../storage/database').SaveDatabase()&&desktop){state.production.privilegedApprovals.delete(ticket.ticketId);return{ok:false,reason:'SECURITY_APPROVAL_STORAGE_UNAVAILABLE'};}require('../storage/audit').LogEvent('DUAL_APPROVAL_REQUESTED',`${ticket.ticketId} / ${ticket.pathname}`);return {ok:true,ticket};
}
function Approve(ticketId,session){
    const item=state.production.privilegedApprovals.get(String(ticketId||'').toUpperCase());
    if(!item)return{ok:false,reason:'TICKET_NOT_FOUND'};if(item.expiresAt<=Now())return{ok:false,reason:'TICKET_EXPIRED'};if(item.status!=='PENDING')return{ok:false,reason:`TICKET_${item.status}`};if(!session||session.role!=='admin')return{ok:false,reason:'ADMIN_REQUIRED'};if(item.requestedBy===session.id)return{ok:false,reason:'SECOND_ADMIN_SESSION_REQUIRED'};
    const previous={...item};
    if(require('./desktopAdminGuard').IsMutation(item.pathname)){const principal=require('./desktopAdminGuard').Identity(session);if(!principal)return{ok:false,reason:'SECURITY_ADMIN_IDENTITY_REQUIRED'};if(!item.requestedPrincipal||principal===item.requestedPrincipal)return{ok:false,reason:'SECOND_ADMIN_IDENTITY_REQUIRED'};item.approvedPrincipal=principal;item.approvedCredentialId=session.passkeyCredentialId;}
    item.status='APPROVED';item.approvedAt=Now();item.approvedBy=session.id;if(!require('../storage/database').SaveDatabase()&&require('./desktopAdminGuard').IsMutation(item.pathname)){for(const key of Object.keys(item))delete item[key];Object.assign(item,previous);return{ok:false,reason:'SECURITY_APPROVAL_STORAGE_UNAVAILABLE'};}require('../storage/audit').LogEvent('DUAL_APPROVAL_GRANTED',`${item.ticketId} / ${item.approvedBy}`);return{ok:true,ticket:item};
}
function Consume(ticketId,session,method,pathname,body){
    const hash=Digest(method,pathname,body);
    let item=state.production.privilegedApprovals.get(String(ticketId||'').toUpperCase());
    if(!item&&session)item=Array.from(state.production.privilegedApprovals.values()).find(x=>x.status==='APPROVED'&&x.requestedBy===session.id&&x.payloadHash===hash);
    if(!item)return{ok:false,reason:'DUAL_APPROVAL_REQUIRED'};if(item.status!=='APPROVED')return{ok:false,reason:`TICKET_${item.status}`};if(item.expiresAt<=Now())return{ok:false,reason:'TICKET_EXPIRED'};if(!session||session.role!=='admin')return{ok:false,reason:'ADMIN_REQUIRED'};if(item.payloadHash!==Digest(method,pathname,body))return{ok:false,reason:'TICKET_PAYLOAD_MISMATCH'};
    if(require('./desktopAdminGuard').IsMutation(pathname)){const principal=require('./desktopAdminGuard').Identity(session);if(!principal||item.requestedBy!==session.id||item.requestedPrincipal!==principal||!item.approvedPrincipal||item.approvedPrincipal===principal||!require('./desktopAdminGuard').ProvisionedCredential(item.approvedCredentialId,item.approvedPrincipal))return{ok:false,reason:'SECURITY_APPROVAL_IDENTITY_MISMATCH'};}
    item.status='CONSUMED';item.consumedAt=Now();item.consumedBy=session.id;if(!require('../storage/database').SaveDatabase()&&require('./desktopAdminGuard').IsMutation(pathname))return{ok:false,reason:'SECURITY_APPROVAL_STORAGE_UNAVAILABLE'};require('../storage/audit').LogEvent('DUAL_APPROVAL_CONSUMED',`${item.ticketId} / ${pathname}`);return{ok:true,ticket:item};
}
function SetRequired(value,actor){state.production.deploymentManifest.dualApprovalRequired=!!value;state.production.deploymentManifest.updatedAt=Now();state.production.deploymentManifest.updatedBy=SafeField(actor).slice(0,64);require('../storage/database').SaveDatabase();return{ok:true,required:!!value};}
function List(){const now=Now();for(const item of state.production.privilegedApprovals.values())if(item.status==='PENDING'&&item.expiresAt<=now)item.status='EXPIRED';return Array.from(state.production.privilegedApprovals.values()).sort((a,b)=>b.requestedAt-a.requestedAt).slice(0,200);}

module.exports={Digest,Required,Request,Approve,Consume,SetRequired,List};
