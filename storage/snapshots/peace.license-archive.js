'use strict';
// Read-only status for archived APK licenses. Not an authorization check.
function GetLicenseStatus(license) {
 if(!license)return 'UNKNOWN';
 if(license.suspended)return 'SUSPENDED';
 if(license.entryPass!==true&&(!Number.isFinite(license.expiresAt)||license.expiresAt<=Date.now()))return 'EXPIRED';
 return license.boundClient?'BOUND':'AVAILABLE';
}
module.exports={GetLicenseStatus};
