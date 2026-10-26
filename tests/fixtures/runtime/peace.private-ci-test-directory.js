'use strict';
// Own only the test-created directory passed by the caller. Windows ignores
// POSIX 0700, so portable private-IR tests install the same inheritable ACL as
// the real Windows wrapper before creating any fixture input material.
const fs=require('node:fs'),path=require('node:path'),child=require('node:child_process');
function Prepare(directory){
 const stat=fs.lstatSync(directory);
 if(!path.isAbsolute(directory)||!stat.isDirectory()||stat.isSymbolicLink()||fs.readdirSync(directory).length)throw Error('TEST_NEW_PRIVATE_DIRECTORY_REQUIRED');
 if(process.platform==='win32'){
  const root=process.env.SystemRoot||process.env.SYSTEMROOT;if(!root)throw Error('TEST_WINDOWS_ROOT_REQUIRED');
  const script="$ErrorActionPreference='Stop';$p=$env:COZY_TEST_PRIVATE_ROOT;$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$me=[Security.Principal.WindowsIdentity]::GetCurrent().User;foreach($who in @($me,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))){$rule=[Security.AccessControl.FileSystemAccessRule]::new($who,'FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.AddAccessRule($rule)};Set-Acl -LiteralPath $p -AclObject $acl;Write-Output 'PRIVATE_TEST_ROOT_READY'";
  const r=child.spawnSync(path.join(root,'System32','WindowsPowerShell','v1.0','powershell.exe'),['-NoLogo','-NoProfile','-NonInteractive','-Command',script],{env:{SystemRoot:root,windir:root,COZY_TEST_PRIVATE_ROOT:directory},encoding:'utf8',timeout:10000,maxBuffer:1024,windowsHide:true,shell:false});
  if(r.error||r.signal||r.status!==0||r.stdout.trim()!=='PRIVATE_TEST_ROOT_READY')throw Error('TEST_PRIVATE_ACL_FAILED');
 }else fs.chmodSync(directory,0o700);
 fs.writeFileSync(path.join(directory,'ci-owned-marker'),'SYNTHETIC_TEST_ONLY',{flag:'wx',mode:0o600});
 return directory;
}
module.exports={Prepare};
