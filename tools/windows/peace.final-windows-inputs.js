'use strict';
// Private Windows test preparation. This is not a compiler, production signer,
// hardware attestation or receipt-authenticity verifier. Never executes an EXE.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const reader=require('../../services/artifacts/peace.bounded-artifact-read');
const strict=require('../../services/protocol/peace.strict-json');
const receipts=require('../../services/artifacts/peace.desktop-packing-evidence');
const protection=require('../../services/artifacts/peace.cozy-protection-engine');
const serverProtection=require('../../services/artifacts/peace.server-policy-protection');
const provenance=require('../../services/artifacts/peace.desktop-release-provenance');
const ROLE=['A','B','O'],KIND='FINAL_WINDOWS_EXECUTION_INPUTS_V1';
const sha=b=>crypto.createHash('sha512').update(b).digest('hex');
function Fail(code){throw Error('WINDOWS_TEST_FINAL_'+code);}
function Exact(x,keys){if(!x||typeof x!=='object'||Array.isArray(x)||Object.keys(x).sort().join(',')!==keys.slice().sort().join(','))Fail('INPUT_INVALID');}
function Read(file,max){if(!path.isAbsolute(file))Fail('ABSOLUTE_INPUT_REQUIRED');file=path.resolve(file);let at=path.parse(file).root;for(const part of file.slice(at.length).split(path.sep).filter(Boolean)){at=path.join(at,part);if(fs.lstatSync(at).isSymbolicLink())Fail('INPUT_SYMLINK');}return reader.Read(file,max);}
function Json(file,max=65536){return strict.Parse(Read(file,max),{maxBytes:max,maxNodes:50000});}
function Write(file,value){fs.writeFileSync(file,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});}
function Directory(directory){
 if(!path.isAbsolute(directory))Fail('ABSOLUTE_INPUT_REQUIRED');
 let at=path.parse(directory).root;
 for(const part of path.resolve(directory).slice(at.length).split(path.sep).filter(Boolean)){
  at=path.join(at,part);const stat=fs.lstatSync(at);if(stat.isSymbolicLink()||!stat.isDirectory())Fail('INPUT_SYMLINK');
 }
}
function PrivateOutputParent(output){
 const parent=path.dirname(output);Directory(parent);
 let marker;try{marker=Read(path.join(parent,'test-owned-marker'),128).toString('utf8');}catch(_){Fail('PRIVATE_SERVER_POLICY_PARENT_REQUIRED');}
 if(!['GAME_WINDOWS_TEST_V1','SYNTHETIC_TEST_ONLY'].includes(marker))Fail('PRIVATE_SERVER_POLICY_PARENT_REQUIRED');
 const stat=fs.lstatSync(parent);
 if(process.platform!=='win32'){
  if((stat.mode&0o077)!==0||typeof process.getuid!=='function'||stat.uid!==process.getuid())Fail('PRIVATE_SERVER_POLICY_PERMISSIONS_REQUIRED');
  return;
 }
 // POSIX mode bits do not establish Windows privacy. Query the actual DACL
 // through the OS PowerShell, using a literal environment path, a clean child
 // environment and a short timeout. No IR/key data enters this process.
 const systemRoot=process.env.SystemRoot||process.env.SYSTEMROOT;
 if(!systemRoot||!path.isAbsolute(systemRoot)||/^[/\\]{2}/.test(systemRoot))Fail('PRIVATE_SERVER_POLICY_ACL_REQUIRED');
 const powershell=path.join(systemRoot,'System32','WindowsPowerShell','v1.0','powershell.exe');Directory(path.dirname(powershell));
 const exe=fs.lstatSync(powershell);if(!exe.isFile()||exe.isSymbolicLink())Fail('PRIVATE_SERVER_POLICY_ACL_REQUIRED');
 const command="$ErrorActionPreference='Stop';$p=$env:COZY_FINAL_PRIVATE_ROOT;$acl=Get-Acl -LiteralPath $p;$me=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$system='S-1-5-18';if(-not $acl.AreAccessRulesProtected){exit 1};$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;if($owner -ne $me -and $owner -ne $system){exit 1};$mine=$false;foreach($r in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($r.AccessControlType -eq 'Allow'){if($r.IdentityReference.Value -ne $me -and $r.IdentityReference.Value -ne $system){exit 1};if(([int]$r.InheritanceFlags -band 3) -ne 3 -or [int]$r.PropagationFlags -ne 0){exit 1};if($r.IdentityReference.Value -eq $me){$mine=$true}}};if(-not $mine){exit 1};Write-Output 'COZY_PRIVATE_ACL_OK'";
 const checked=require('node:child_process').spawnSync(powershell,['-NoLogo','-NoProfile','-NonInteractive','-Command',command],{env:{SystemRoot:systemRoot,windir:systemRoot,COZY_FINAL_PRIVATE_ROOT:parent},encoding:'utf8',timeout:10000,maxBuffer:1024,windowsHide:true,shell:false});
 if(checked.error||checked.signal||checked.status!==0||checked.stdout.trim()!=='COZY_PRIVATE_ACL_OK')Fail('PRIVATE_SERVER_POLICY_ACL_REQUIRED');
}
function CheckReceipts(records,artifacts){
 if(!Array.isArray(records)||records.length!==3)Fail('RECEIPT_COHORT_REQUIRED');
 const map=Object.fromEntries(records.map(r=>[receipts.ReceiptId(r),r]));
 if(Object.keys(map).length!==3||new Set(records.map(r=>r.jobId)).size!==1)Fail('RECEIPT_COHORT_REQUIRED');
 receipts.ValidateStore({artifacts:{},packingEvidence:map});
 for(const role of ROLE){const row=records.find(x=>x.component===role);if(row.outputSha512!==artifacts[role].sha512||row.size!==artifacts[role].size)Fail('RECEIPT_FILE_MISMATCH');}
 return records;
}
function CheckServerPolicies(records,artifacts){
 if(!Array.isArray(records)||records.length!==3)Fail('SERVER_POLICY_COHORT_REQUIRED');
 const roles=new Set(),ids=new Set();
 for(const record of records){
  serverProtection.ValidateServerPolicy(record);
  if(roles.has(record.role)||ids.has(record.policyId))Fail('SERVER_POLICY_COHORT_REQUIRED');
  roles.add(record.role);ids.add(record.policyId);
  const expected=artifacts[record.role]?.serverPolicy;
  if(!expected||record.policyId!==expected.policyId||record.policySha512!==expected.policySha512||record.functionCount!==expected.functionCount)Fail('SERVER_POLICY_ARTIFACT_MISMATCH');
 }
 if(ROLE.some(role=>!roles.has(role)))Fail('SERVER_POLICY_COHORT_REQUIRED');
 return records;
}
function PolicyDigest(records){return sha(Buffer.from(provenance.Stable(records),'utf8'));}
function InspectProtection(bytes){
 const knownV2=[serverProtection.FORMAT.headHex,serverProtection.FORMAT.tailHex].some(x=>bytes.includes(Buffer.from(x,'hex')));
 return knownV2?serverProtection.Inspect(bytes):protection.Inspect(bytes);
}
function Prepare(configFile,sourceRoot,output){
 Directory(sourceRoot);if(!path.isAbsolute(output))Fail('ABSOLUTE_INPUT_REQUIRED');Directory(path.dirname(output));
 sourceRoot=path.resolve(sourceRoot);output=path.resolve(output);
 const config=Json(configFile);Exact(config,['version','releaseVersion','artifacts','packingReceiptsFile','policyFile',...(Object.hasOwn(config,'serverPoliciesFile')?['serverPoliciesFile']:[])]);Exact(config.artifacts,ROLE);
 if(config.version!==1||!/^\d+(?:\.\d+){0,3}$/.test(config.releaseVersion)||config.releaseVersion.length>40)Fail('INPUT_INVALID');
 if(fs.existsSync(output))Fail('NEW_OUTPUT_REQUIRED');
 const blobs={},artifacts={},engines=new Set();let created,serverPolicies;
 try{
  for(const role of ROLE){const b=Read(config.artifacts[role],64*1024*1024);blobs[role]=b;const own=InspectProtection(b);
   const keyless=own?.engine===serverProtection.ENGINE&&own.state==='BOUND';
   if(!own||!keyless&&(own.engine!=='COZY_VM_V1'||own.state!=='SEALED')||own.role!==role)Fail('PROTECTED_ARTIFACTS_REQUIRED');
   if(role==='A'&&['GAMEA80CONFIG!','COZYA2CONFIG!','COZYA3CONFIG!'].some(x=>b.subarray(-x.length).equals(Buffer.from(x))))Fail('ISSUED_A_NOT_TEMPLATE');
   engines.add(own.engine);artifacts[role]={sha512:sha(b),size:b.length,embeddedClientKeyPresent:!keyless};
   if(keyless)artifacts[role].serverPolicy={policyId:own.policyId,policySha512:own.policySha512,functionCount:own.functionCount};
  }
  if(engines.size!==1)Fail('PROTECTION_COHORT_MIXED');
  const keyless=engines.has(serverProtection.ENGINE);
  if(keyless){PrivateOutputParent(output);if(!config.serverPoliciesFile)Fail('SERVER_POLICIES_REQUIRED');serverPolicies=CheckServerPolicies(Json(config.serverPoliciesFile),artifacts);}
  else if(Object.hasOwn(config,'serverPoliciesFile'))Fail('SERVER_POLICIES_UNEXPECTED');
  const records=CheckReceipts(Json(config.packingReceiptsFile),artifacts);
  const authority=require('../../services/security/peace.desktop-security-authority');
  const supplied=authority.ValidatePolicy(Json(config.policyFile));
  if(supplied.mode!=='enforce'||!supplied.requireReadonlyApi||!supplied.requireCompleteCrcLayers||!supplied.requireReleaseSignature)Fail('ENFORCED_POLICY_REQUIRED');
  const source=Read(path.join(sourceRoot,'Relay Server','maintenance','source-manifest.json'),8*1024*1024);
  const {privateKey,publicKey}=crypto.generateKeyPairSync('ed25519'),keyId=provenance.KeyId(publicKey),publicPem=publicKey.export({type:'spki',format:'pem'}).toString();
  const policy={...supplied,trustedReleaseKeys:[{keyId,publicKey:publicPem}]};authority.ValidatePolicy(policy);
  const manifest={version:1,releaseName:'Isolated final-file execution '+config.releaseVersion,securityVersion:1,protocol:'GAME-CONNECT-4',hashVersion:3,handoffVersion:3,sourceManifestSha512:sha(source),policySha512:provenance.PolicyDigest(policy),toolchain:{delphi:'NOT_ATTESTED',cpp:'NOT_ATTESTED',windowsSdk:'NOT_ATTESTED',imgui:'NOT_ATTESTED'},artifacts:Object.fromEntries(ROLE.map(r=>[r,artifacts[r].sha512]))};
  const summary={version:1,kind:KIND,releaseVersion:config.releaseVersion,finalExecutionOnly:true,buildProvenance:'NOT_ATTESTED',productionApproved:false,windowsExecuted:false,receiptAuthenticity:'OPERATOR_SUPPLIED_NOT_INDEPENDENTLY_ATTESTED',sourceManifestSha512:sha(source),reviewedPolicySha512:provenance.PolicyDigest(supplied),fixturePolicySha512:provenance.PolicyDigest(policy),artifacts};
  if(keyless){summary.protectionEngine=serverProtection.ENGINE;summary.privateServerPoliciesSha512=PolicyDigest(serverPolicies);summary.serverPolicyAuthenticity='OPERATOR_SUPPLIED_NOT_INDEPENDENTLY_ATTESTED';summary.fixtureEnrollmentApproval=true;}
  if(keyless)PrivateOutputParent(output);
  fs.mkdirSync(output,{mode:0o700});created=fs.lstatSync(output);
  for(const role of ROLE){fs.writeFileSync(path.join(output,role+'.exe'),blobs[role],{flag:'wx',mode:0o600});Write(path.join(output,role+'.approval.json'),{keyId,signature:crypto.sign(null,Buffer.from(['GAME-RELEASE-APPROVAL-V2',role,config.releaseVersion,artifacts[role].sha512].join('\n')),privateKey).toString('base64')});}
  Write(path.join(output,'policy.json'),policy);Write(path.join(output,'manifest.json'),{manifestId:provenance.ManifestId(manifest),manifest});
  Write(path.join(output,'packing-receipts.json'),records);Write(path.join(output,'final-execution-inputs.json'),summary);
  // This file belongs only to the isolated test SERVER's private input tree.
  // It must never be downloaded to customers, appended to an EXE or printed.
  if(serverPolicies)Write(path.join(output,'server-policies.json'),serverPolicies);
  return summary;
 }catch(error){
  // Never remove a path merely because it exists after an error. It may have
  // been created/replaced by another caller while the inputs were inspected.
  if(created){
   try{Directory(path.dirname(output));const now=fs.lstatSync(output);
    if(now.isDirectory()&&!now.isSymbolicLink()&&now.dev===created.dev&&now.ino===created.ino)fs.rmSync(output,{recursive:true,force:true});
   }catch(cleanup){if(cleanup.code!=='ENOENT')Fail('OWNED_CLEANUP_FAILED');}
  }
  throw error;
 }finally{for(const b of Object.values(blobs))b.fill(0);}
}
function Verify(output){
 const summary=Json(path.join(output,'final-execution-inputs.json'));
 if(summary.version!==1||summary.kind!==KIND||summary.finalExecutionOnly!==true||summary.buildProvenance!=='NOT_ATTESTED'||summary.productionApproved!==false)Fail('CONTEXT_INVALID');
 const engines=new Set();
 for(const role of ROLE){const b=Read(path.join(output,role+'.exe'),64*1024*1024);try{
  if(sha(b)!==summary.artifacts[role].sha512||b.length!==summary.artifacts[role].size)Fail('ARTIFACT_CHANGED');
  const own=InspectProtection(b);if(!own||own.role!==role)Fail('PROTECTED_ARTIFACTS_REQUIRED');engines.add(own.engine);
  const keyless=own.engine===serverProtection.ENGINE&&own.state==='BOUND';
  if(summary.artifacts[role].embeddedClientKeyPresent!==!keyless)Fail('PROTECTION_CONTEXT_CHANGED');
  if(keyless){const expected=summary.artifacts[role].serverPolicy;
   if(!expected||expected.policyId!==own.policyId||expected.policySha512!==own.policySha512||expected.functionCount!==own.functionCount)Fail('SERVER_POLICY_ARTIFACT_MISMATCH');
  }
 }finally{b.fill(0);}}
 if(engines.size!==1||engines.has(serverProtection.ENGINE)!==(summary.protectionEngine===serverProtection.ENGINE))Fail('PROTECTION_CONTEXT_CHANGED');
 CheckReceipts(Json(path.join(output,'packing-receipts.json')),summary.artifacts);
 if(summary.protectionEngine===serverProtection.ENGINE){
  const policies=CheckServerPolicies(Json(path.join(output,'server-policies.json')),summary.artifacts);
  if(PolicyDigest(policies)!==summary.privateServerPoliciesSha512||summary.fixtureEnrollmentApproval!==true||summary.serverPolicyAuthenticity!=='OPERATOR_SUPPLIED_NOT_INDEPENDENTLY_ATTESTED')Fail('SERVER_POLICIES_CHANGED');
 }
 if(provenance.PolicyDigest(Json(path.join(output,'policy.json')))!==summary.fixturePolicySha512)Fail('POLICY_CHANGED');
 return summary;
}
if(require.main===module){try{const[cmd,...args]=process.argv.slice(2);let value;if(cmd==='prepare'&&args.length===3)value=Prepare(...args);else if(cmd==='verify'&&args.length===1)value=Verify(args[0]);else Fail('ARGUMENTS_INVALID');process.stdout.write(JSON.stringify(value)+'\n');}catch(error){process.stderr.write(/^WINDOWS_TEST_FINAL_[A-Z_]+$/.test(error.message)?error.message+'\n':'WINDOWS_TEST_FINAL_INPUTS_REJECTED\n');process.exitCode=1;}}
module.exports={KIND,Prepare,Verify,CheckReceipts,CheckServerPolicies};
