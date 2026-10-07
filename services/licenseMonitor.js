'use strict';
// Read-only aggregate for historical license snapshots.
const state = require('../core/state');
const { Now } = require('../core/utils');
const { GetLicenseStatus } = require('../storage/licenseArchive');
const DAY = 86400000;

function GetExpirySummary() {
    const summary = { expired: 0, within1d: 0, within3d: 0, within7d: 0, within30d: 0 };
    const now = Now();
    for (const license of state.licenses.values()) {
        if(license.entryPass===true)continue;
        const status = GetLicenseStatus(license);
        if (status === 'EXPIRED') { summary.expired++; continue; }
        const remain = Number(license.expiresAt || 0) - now;
        if (remain <= DAY) summary.within1d++;
        if (remain <= 3 * DAY) summary.within3d++;
        if (remain <= 7 * DAY) summary.within7d++;
        if (remain <= 30 * DAY) summary.within30d++;
    }
    return summary;
}

function MatchesExpiryFilter(license, filter) {
 const name=String(filter||'ALL').toUpperCase();
 if(name==='ALL')return true;
 const status=GetLicenseStatus(license);
 if(name==='EXPIRED')return status==='EXPIRED';
 const days={WITHIN_1D:1,WITHIN_3D:3,WITHIN_7D:7,WITHIN_30D:30,'1D':1,'3D':3,'7D':7,'30D':30}[name];
 return !!days&&license.entryPass!==true&&status!=='EXPIRED'&&license.expiresAt>Now()&&license.expiresAt<=Now()+days*DAY;
}
module.exports = { GetExpirySummary, MatchesExpiryFilter };
