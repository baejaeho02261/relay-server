@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "GAME_APPROVAL_BAT=%~f0"
set "_GC_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "_GC_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%_GC_PS%" (
  echo Windows PowerShell 5.1 is required.
  pause
  exit /b 1
)
"%_GC_PS%" -NoProfile -STA -Command "$ErrorActionPreference='Stop'; $text=[IO.File]::ReadAllText($env:GAME_APPROVAL_BAT,[Text.Encoding]::UTF8); $mark='#'+'__GAME_APPROVAL_POWERSHELL__'; $at=$text.IndexOf($mark,[StringComparison]::Ordinal); if($at -lt 0){throw 'Batch payload missing.'}; & ([ScriptBlock]::Create($text.Substring($at+$mark.Length)))"
set "_GC_EXIT=%ERRORLEVEL%"
echo.
pause
exit /b %_GC_EXIT%
#__GAME_APPROVAL_POWERSHELL__
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$ProgressPreference = 'SilentlyContinue'
$script:Utf8 = New-Object System.Text.UTF8Encoding($false)
try { [Console]::OutputEncoding = $script:Utf8 } catch { }

# All JavaScript below runs locally through Node's stdin. No private key is
# downloaded, uploaded, printed, or embedded in this batch file.
$script:Worker = @'
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const env = process.env;
function stop(code) { const e = new Error(code); e.safeCode = code; throw e; }

// Standalone, built-in modules only. Do not load GameWeb/services, config,
// vendor, node_modules, or sign-release-approval.js on an operator's PC.
// PE validation rules and metadata fields match SERVER_OPERATIONS sources.
function ReadBoundedInput(file, min, max, code) {
  const fd = fs.openSync(file, 'r');
  let bytes;
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.size < min || before.size > max) stop(code);
    bytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const n = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (n === 0) stop('INPUT_CHANGED_DURING_READ');
      offset += n;
    }
    const after = fs.fstatSync(fd);
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) stop('INPUT_CHANGED_DURING_READ');
    return bytes;
  } catch (error) {
    if (bytes) bytes.fill(0);
    throw error;
  } finally { fs.closeSync(fd); }
}
function ReleaseCanonical(component, version, sha256) {
  return ['GAME-RELEASE-APPROVAL-V1', component, version, sha256].join('\n');
}
function SignRelease(component, version, file, keyFile) {
  if (!['A', 'B', 'O'].includes(component) || typeof version !== 'string' || version.length > 40 || !/^\d+(?:\.\d+){0,3}$/.test(version)) stop('RELEASE_ARGUMENT_INVALID');
  const bytes = ReadBoundedInput(file, 512, (component === 'O' ? 16 : 64) * 1024 * 1024, 'RELEASE_FILE_INVALID');
  ValidatePeImage(bytes, component);
  const keyBytes = ReadBoundedInput(keyFile, 1, 16384, 'KEY_FILE_INVALID');
  let key;
  try {
    if (keyBytes.includes(Buffer.from('ENCRYPTED PRIVATE KEY'))) stop('ENCRYPTED_KEY_NOT_SUPPORTED');
    try { key = crypto.createPrivateKey({ key: keyBytes, format: 'pem' }); }
    catch (_) { stop('KEY_PEM_INVALID'); }
  } finally { keyBytes.fill(0); }
  if (key.asymmetricKeyType !== 'ed25519') stop('ED25519_KEY_REQUIRED');
  const publicKey = crypto.createPublicKey(key);
  const keyId = crypto.createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
  const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
  const signature = crypto.sign(null, Buffer.from(ReleaseCanonical(component, version, sha256), 'utf8'), key).toString('base64');
  return { component, version, sha256, ...PeCapabilities(bytes),
    trustedKey: { keyId, publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString() },
    approval: { keyId, signature },
    headers: { 'x-game-release-key-id': keyId, 'x-game-release-signature': signature } };
}

function ValidatePeImage(bytes,component){
 const bad=()=>{const error=Error(component==='O'?'OVERLAY_PLUGIN_PE_INVALID':'BOOTSTRAP_PE_INVALID');error.safeCode=error.message;throw error;};
 if(!Buffer.isBuffer(bytes)||bytes.length<512||bytes.length>(component==='O'?16:64)*1024*1024||bytes.readUInt16LE(0)!==0x5a4d)bad();
 const pe=bytes.readUInt32LE(0x3c);if(pe<64||pe>bytes.length-24||bytes.readUInt32LE(pe)!==0x4550||bytes.readUInt16LE(pe+4)!==0x8664)bad();
 if(component==='O'&&(bytes.readUInt16LE(pe+22)&0x2002)!==0x2002)bad();
 const count=bytes.readUInt16LE(pe+6),opt=pe+24,optSize=bytes.readUInt16LE(pe+20),table=opt+optSize;
 if(count<1||count>96||optSize<160||table+count*40>bytes.length||bytes.readUInt16LE(opt)!==0x20b)bad();
 const imageSize=bytes.readUInt32LE(opt+56),headerSize=bytes.readUInt32LE(opt+60),dirCount=bytes.readUInt32LE(opt+108);
 if(imageSize<4096||imageSize>128*1024*1024||headerSize<table+count*40||headerSize>bytes.length||dirCount>16||112+dirCount*8>optSize)bad();
 const sections=[];let total=0;
 for(let i=0;i<count;i++){
  const at=table+i*40,virtualSize=bytes.readUInt32LE(at+8),rva=bytes.readUInt32LE(at+12),rawSize=bytes.readUInt32LE(at+16),raw=bytes.readUInt32LE(at+20),flags=bytes.readUInt32LE(at+36),span=virtualSize||rawSize,mapped=Math.max(span,rawSize);
  if(!span||rva<headerSize||rva+mapped>imageSize||rawSize&&(raw<headerSize||raw+rawSize>bytes.length)||sections.some(s=>rva<s.rva+s.mapped&&rva+mapped>s.rva||rawSize&&s.rawSize&&raw<s.raw+s.rawSize&&raw+rawSize>s.raw))bad();
  const protectedCode=!!(flags&0x20000000)&&!(flags&0x80000000);if(protectedCode){total+=span;if(total>64*1024*1024)bad();}
  sections.push({rva,span,mapped,raw,rawSize,protectedCode});
 }
 const protectedSections=sections.filter(s=>s.protectedCode).sort((a,b)=>a.rva-b.rva);if(!protectedSections.length)bad();
 for(const section of protectedSections){section.bytes=Buffer.alloc(section.span);bytes.copy(section.bytes,0,section.raw,section.raw+Math.min(section.rawSize,section.span));}
 const rawAt=(rva,length)=>{if(!Number.isSafeInteger(length)||length<0)bad();if(rva<headerSize&&rva+length<=headerSize)return rva;const s=sections.find(s=>rva>=s.rva&&rva+length<=s.rva+s.rawSize);if(!s)bad();return s.raw+(rva-s.rva);};
 const relocRva=dirCount>5?bytes.readUInt32LE(opt+112+5*8):0,relocSize=dirCount>5?bytes.readUInt32LE(opt+116+5*8):0;
 if(!!relocRva!==!!relocSize||relocSize>16*1024*1024)bad();
 let relocations=0;
 if(relocSize){
  let cursor=rawAt(relocRva,relocSize),end=cursor+relocSize;const seen=[];
  while(cursor<end){
   if(cursor+8>end)bad();const page=bytes.readUInt32LE(cursor),block=bytes.readUInt32LE(cursor+4);if(block<8||block%2||cursor+block>end||page>=imageSize)bad();
   for(let at=cursor+8;at<cursor+block;at+=2){
    const entry=bytes.readUInt16LE(at),type=entry>>>12,target=page+(entry&0xfff);if(type===0)continue;
    const width=type===10?8:type===3?4:1,section=protectedSections.find(s=>target<s.rva+s.span&&target+width>s.rva);
    if(!section)continue;if(type!==10&&type!==3||target<section.rva||target+width>section.rva+section.span)bad();
    section.bytes.fill(0,target-section.rva,target-section.rva+width);seen.push([target,target+width]);if(++relocations>1000000)bad();
   }
   cursor+=block;
  }
  seen.sort((a,b)=>a[0]-b[0]);for(let i=1;i<seen.length;i++)if(seen[i][0]<seen[i-1][1])bad();
 }
 if(component==='O')ValidateOverlayExport(bytes);
 return true;
}

// O uses the server's fixed DLL ABI; export bytes are inspected, never executed.
function ValidateOverlayExport(bytes){
 const requiredExport='GameOverlayRunV1',MAX_SPAN=8*1024*1024,MAX_ENTRIES=131072,MAX_STRING=512;
 const bad=()=>{throw Error('EXPORT_LAYOUT');};
 try{
  if(!Buffer.isBuffer(bytes)||bytes.length<512||bytes.length>64*1024*1024||bytes.readUInt16LE(0)!==0x5a4d)bad();
  const pe=bytes.readUInt32LE(0x3c);if(pe<64||pe+24>bytes.length||bytes.readUInt32LE(pe)!==0x4550||bytes.readUInt16LE(pe+4)!==0x8664)bad();
  const count=bytes.readUInt16LE(pe+6),opt=pe+24,optSize=bytes.readUInt16LE(pe+20),table=opt+optSize;
  if(count<1||count>96||optSize<112||table+count*40>bytes.length||bytes.readUInt16LE(opt)!==0x20b)bad();
  const imageSize=bytes.readUInt32LE(opt+56),headers=bytes.readUInt32LE(opt+60),dirs=bytes.readUInt32LE(opt+108);
  if(imageSize<4096||imageSize>128*1024*1024||headers<table+count*40||headers>bytes.length||dirs>16||112+dirs*8>optSize)bad();
  if(!dirs)bad();
  const directoryOffset=opt+112,rva=bytes.readUInt32LE(directoryOffset),span=bytes.readUInt32LE(directoryOffset+4);
  if(!rva&&!span)bad();
  if(!rva||span<40||span>MAX_SPAN||rva+span>imageSize)bad();
  const sections=[];
  for(let i=0;i<count;i++){
   const at=table+i*40,virtualSize=bytes.readUInt32LE(at+8),start=bytes.readUInt32LE(at+12),rawSize=bytes.readUInt32LE(at+16),raw=bytes.readUInt32LE(at+20),flags=bytes.readUInt32LE(at+36),mapped=Math.max(virtualSize||rawSize,rawSize);
   if(!mapped||start<headers||start+mapped>imageSize||rawSize&&(raw<headers||raw+rawSize>bytes.length)||sections.some(s=>start<s.start+s.mapped&&start+mapped>s.start||rawSize&&s.rawSize&&raw<s.raw+s.rawSize&&raw+rawSize>s.raw))bad();
   sections.push({start,mapped,span:virtualSize||rawSize,rawSize,raw,flags});
  }
  const section=sections.find(s=>rva>=s.start&&rva+span<=s.start+s.rawSize&&rva+span<=s.start+s.span);
  if(!section||(section.flags&0x80000000))bad();
  const start=section.raw+rva-section.start,end=rva+span;
  const inside=(at,length)=>{if(!Number.isSafeInteger(at)||!Number.isSafeInteger(length)||length<0||at<rva||at+length>end)bad();return start+at-rva;};
  const stringAt=(at,forwarder=false)=>{const offset=inside(at,1);for(let i=0;i<MAX_STRING;i++){if(at+i>=end)bad();const c=bytes[offset+i];if(c===0){if(i===0)bad();return i;}if(c<32||c>126||forwarder&&c===32)bad();}bad();};
  const functions=bytes.readUInt32LE(start+20),names=bytes.readUInt32LE(start+24);
  if(functions>MAX_ENTRIES||names>MAX_ENTRIES||names>functions)bad();
  stringAt(bytes.readUInt32LE(start+12));
  const functionRva=bytes.readUInt32LE(start+28),nameRva=bytes.readUInt32LE(start+32),ordinalRva=bytes.readUInt32LE(start+36);
  const functionAt=functions?inside(functionRva,functions*4):0,nameAt=names?inside(nameRva,names*4):0,ordinalAt=names?inside(ordinalRva,names*2):0;
  let exported=0,code=0,forwarded=0;
  for(let i=0;i<functions;i++){
   const target=bytes.readUInt32LE(functionAt+i*4);if(!target)continue;if(target>=imageSize)bad();exported++;
   if(target>=rva&&target<end){stringAt(target,true);forwarded++;}
   else if(sections.some(s=>target>=s.start&&target<s.start+s.span&&(s.flags&0x20000000)&&!(s.flags&0x80000000)))code++;
  }
  let requiredExportRva=0;
  for(let i=0;i<names;i++){const ordinal=bytes.readUInt16LE(ordinalAt+i*2);if(ordinal>=functions)bad();const nameRvaValue=bytes.readUInt32LE(nameAt+i*4),length=stringAt(nameRvaValue);if(requiredExport&&bytes.toString('ascii',inside(nameRvaValue,length),inside(nameRvaValue,length)+length)===requiredExport){const target=bytes.readUInt32LE(functionAt+ordinal*4);if(target>=rva&&target<end||!sections.some(s=>target>=s.start&&target<s.start+s.span&&(s.flags&0x20000000)&&!(s.flags&0x80000000))||requiredExportRva)bad();requiredExportRva=target;}}
  // Export tables should hold RVAs, not loader-relocated VA operands. Decline
  // unsupported images rather than normalize away a redirected API address.
  if(dirs>5){
   const relocRva=bytes.readUInt32LE(opt+152),relocSize=bytes.readUInt32LE(opt+156);
   if(!!relocRva!==!!relocSize||relocSize>16*1024*1024)bad();
   if(relocSize){const rs=sections.find(s=>relocRva>=s.start&&relocRva+relocSize<=s.start+s.rawSize);if(!rs)bad();let at=rs.raw+relocRva-rs.start,stop=at+relocSize;
    while(at<stop){if(at+8>stop)bad();const page=bytes.readUInt32LE(at),size=bytes.readUInt32LE(at+4);if(size<8||size%2||at+size>stop||page>=imageSize)bad();
     for(let p=at+8;p<at+size;p+=2){const entry=bytes.readUInt16LE(p),type=entry>>>12,target=page+(entry&0xfff);if(!type)continue;const width=type===10?8:type===3?4:1;if(target<end&&target+width>rva)bad();}
     at+=size;
    }
   }
  }
  if(!requiredExportRva)bad();
  return true;
 }catch(_){const error=Error('OVERLAY_PLUGIN_PE_INVALID');error.safeCode=error.message;throw error;}
}
function PeCapabilities(bytes) {
  // Only metadata of administrator-uploaded bytes, never a client capability claim.
  const authorityVersion = bytes.includes(Buffer.from('GAME-AUTHORITY-V1')) || bytes.includes(Buffer.from('GAME-AUTHORITY-V1', 'utf16le')) ? 1 : 0;
  let compiledCfg = false;
  try {
    const pe = bytes.readUInt32LE(0x3c), opt = pe + 24, optSize = bytes.readUInt16LE(pe + 20), count = bytes.readUInt16LE(pe + 6);
    if (bytes.readUInt16LE(opt) === 0x20b && optSize >= 200 && (bytes.readUInt16LE(opt + 70) & 0x4000) && bytes.readUInt32LE(opt + 108) > 10) {
      const rva = bytes.readUInt32LE(opt + 112 + 80), size = bytes.readUInt32LE(opt + 116 + 80);
      for (let i = 0; i < count; i++) {
        const at = opt + optSize + i * 40, va = bytes.readUInt32LE(at + 12), rawSize = bytes.readUInt32LE(at + 16), raw = bytes.readUInt32LE(at + 20);
        if (size >= 148 && rva >= va && rva - va + 148 <= rawSize && raw + rva - va + 148 <= bytes.length) {
          const lc = raw + rva - va;
          compiledCfg = bytes.readUInt32LE(lc) >= 148 && (bytes.readUInt32LE(lc + 144) & 0x500) === 0x500 && bytes.readBigUInt64LE(lc + 136) > 0n;
        }
      }
    }
  } catch (_) { compiledCfg = false; }
  return { authorityVersion, compiledCfg };
}

function saveNew(file, bytes, mode) {
  let fd, created = false;
  try {
    fd = fs.openSync(file, 'wx', mode);
    created = true;
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
  } catch (e) {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch (_) {} }
    if (created) { try { fs.unlinkSync(file); } catch (_) {} }
    throw e;
  }
}
function main() {
  const action = env.GC_APPROVAL_ACTION;
  if (action === 'probe') {
    return { version: process.version, major: Number(process.versions.node.split('.')[0]), lts: process.release.lts || '' };
  }
  if (action === 'new-key') {
    if (!env.GC_APPROVAL_KEY || !path.isAbsolute(env.GC_APPROVAL_KEY)) stop('KEY_PATH_INVALID');
    if (fs.existsSync(env.GC_APPROVAL_KEY)) stop('KEY_ALREADY_EXISTS');
    const pair = crypto.generateKeyPairSync('ed25519');
    const secret = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
    const secretBytes = Buffer.from(secret, 'utf8');
    try { saveNew(env.GC_APPROVAL_KEY, secretBytes, 0o600); }
    finally { secretBytes.fill(0); }
    // Node's key object/string lifetime is GC-managed, not guaranteed erasure.
    return { created: true, keyId: crypto.createHash('sha256').update(pair.publicKey.export({ type: 'spki', format: 'der' })).digest('hex') };
  }
  if (action === 'self-test') {
    const pair = crypto.generateKeyPairSync('ed25519');
    const data = Buffer.from('GAME-APPROVAL-SELFTEST-V2', 'ascii');
    const signature = crypto.sign(null, data, pair.privateKey);
    if (!crypto.verify(null, data, pair.publicKey, signature)) stop('CRYPTO_SELF_TEST_FAILED');
    return { ready: true, standalone: true, format: 'GAME-RELEASE-APPROVAL-V1' };
  }
  if (action !== 'sign') stop('ACTION_INVALID');
  const component = env.GC_APPROVAL_COMPONENT;
  const version = env.GC_APPROVAL_VERSION;
  const file = env.GC_APPROVAL_EXE;
  const key = env.GC_APPROVAL_KEY;
  const output = env.GC_APPROVAL_OUTPUT;
  if (![file, key, output].every(p => typeof p === 'string' && path.isAbsolute(p))) stop('INPUT_PATH_INVALID');
  if (fs.existsSync(output)) stop('OUTPUT_ALREADY_EXISTS');
  const approval = SignRelease(component, version, file, key);
  if (approval.component !== component || approval.version !== version || !approval.trustedKey || !approval.approval) stop('APPROVAL_INVALID');
  // Recheck the exact release bytes and signature before creating any output.
  const currentHash = crypto.createHash('sha256').update(ReadBoundedInput(file, 512, (component === 'O' ? 16 : 64) * 1024 * 1024, 'RELEASE_FILE_INVALID')).digest('hex');
  if (approval.sha256 !== currentHash) stop('EXE_CHANGED_DURING_SIGNING');
  const pub = crypto.createPublicKey(approval.trustedKey.publicKey);
  const keyId = crypto.createHash('sha256').update(pub.export({ type: 'spki', format: 'der' })).digest('hex');
  if (pub.asymmetricKeyType !== 'ed25519' || keyId !== approval.trustedKey.keyId || keyId !== approval.approval.keyId) stop('PUBLIC_KEY_MISMATCH');
  const canonical = ['GAME-RELEASE-APPROVAL-V1', component, version, currentHash].join('\n');
  if (!crypto.verify(null, Buffer.from(canonical, 'utf8'), pub, Buffer.from(approval.approval.signature, 'base64'))) stop('SIGNATURE_RECHECK_FAILED');
  const text = JSON.stringify(approval, null, 2) + '\n';
  if (/PRIVATE KEY/.test(text)) stop('PRIVATE_DATA_IN_OUTPUT');
  saveNew(output, Buffer.from(text, 'utf8'), 0o600);
  return { output, component, version, sha256: currentHash, keyId };
}
try { process.stdout.write(JSON.stringify(main()) + '\n'); }
catch (e) {
  // Never emit a stack, PEM contents, environment, or raw input buffers.
  const known = new Set(['RELEASE_ARGUMENT_INVALID','RELEASE_FILE_INVALID','ED25519_KEY_REQUIRED','BOOTSTRAP_PE_INVALID']);
  const code = e.safeCode || (known.has(e.message) ? e.message :
    e.code === 'MODULE_NOT_FOUND' ? 'NODE_RUNTIME_MODULE_MISSING' :
    e.code === 'ENOENT' ? 'INPUT_FILE_MISSING' :
    e.code === 'EEXIST' ? 'OUTPUT_ALREADY_EXISTS' :
    ['EACCES','EPERM'].includes(e.code) ? 'ACCESS_DENIED' : 'SIGNING_FAILED');
  process.stderr.write(code + '\n');
  process.exitCode = 1;
}
'@

function Invoke-Worker {
    param([string]$Node, [hashtable]$Values, [string]$WorkingDirectory)
    $si = New-Object System.Diagnostics.ProcessStartInfo
    $si.FileName = $Node
    $si.Arguments = '--input-type=commonjs -'
    $si.WorkingDirectory = $WorkingDirectory
    $si.UseShellExecute = $false
    $si.CreateNoWindow = $true
    $si.RedirectStandardInput = $true
    $si.RedirectStandardOutput = $true
    $si.RedirectStandardError = $true
    $si.StandardOutputEncoding = $script:Utf8
    $si.StandardErrorEncoding = $script:Utf8
    # Do not inherit arbitrary Node preload hooks into the signing subprocess.
    [void]$si.EnvironmentVariables.Remove('NODE_OPTIONS')
    [void]$si.EnvironmentVariables.Remove('NODE_PATH')
    foreach ($name in @('ACTION','SCRIPT','KEY','EXE','OUTPUT','COMPONENT','VERSION')) {
        [void]$si.EnvironmentVariables.Remove('GC_APPROVAL_' + $name)
    }
    foreach ($name in $Values.Keys) { $si.EnvironmentVariables[$name] = [string]$Values[$name] }
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $si
    try {
        if (-not $p.Start()) { throw 'Node.js 프로세스를 시작하지 못했습니다.' }
        $outTask = $p.StandardOutput.ReadToEndAsync()
        $errTask = $p.StandardError.ReadToEndAsync()
        $p.StandardInput.Write($script:Worker)
        $p.StandardInput.Close()
        if (-not $p.WaitForExit(60000)) {
            try { $p.Kill() } catch { }
            throw '서명 도구가 제한 시간 내에 종료되지 않았습니다.'
        }
        $p.WaitForExit()
        $stdout = $outTask.GetAwaiter().GetResult()
        $stderr = $errTask.GetAwaiter().GetResult()
        if ($p.ExitCode -ne 0) {
            $code = $stderr.Trim()
            if ($code -notmatch '^[A-Z_]{1,80}$') { $code = 'NODE_EXECUTION_FAILED' }
            throw ('서명 도구 오류: ' + $code)
        }
        if ([string]::IsNullOrWhiteSpace($stdout)) { throw '서명 도구가 결과를 반환하지 않았습니다.' }
        return ($stdout | ConvertFrom-Json)
    } finally {
        try { if (-not $p.HasExited) { $p.Kill() } } catch { }
        $p.Dispose()
    }
}

function Choose-File {
    param([string]$Title, [string]$Filter, [string]$InitialDirectory)
    $dialog = $null
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title = $Title
        $dialog.Filter = $Filter
        $dialog.CheckFileExists = $true
        $dialog.Multiselect = $false
        if (Test-Path -LiteralPath $InitialDirectory -PathType Container) { $dialog.InitialDirectory = $InitialDirectory }
        $selected = $dialog.ShowDialog()
        if ($selected -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
        return $dialog.FileName
    } catch {
        Write-Host '파일 선택 창을 열 수 없어 경로를 직접 입력받습니다.'
        $typed = (Read-Host $Title).Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($typed)) { return $null }
        $item = Get-Item -LiteralPath $typed -ErrorAction Stop
        if ($item.PSIsContainer) { throw '파일을 선택해야 합니다.' }
        return $item.FullName
    } finally {
        if ($null -ne $dialog) { $dialog.Dispose() }
    }
}

function Test-Node {
    param([string]$Path, [string]$Base)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try {
        $info = Invoke-Worker $Path @{GC_APPROVAL_ACTION='probe'} $Base
        return ($info.major -ge 22 -and -not [string]::IsNullOrWhiteSpace([string]$info.lts))
    } catch { return $false }
}

function Get-NodeRuntime {
    param([string]$HomeDirectory, [string]$Base)
    $runtime = Join-Path $HomeDirectory 'runtime'
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    $found = Get-Command node.exe -CommandType Application -ErrorAction SilentlyContinue
    if ($found) { foreach ($command in @($found)) { $candidates.Add($command.Source) } }
    foreach ($folder in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, (Join-Path $env:LOCALAPPDATA 'Programs'))) {
        if ($folder) { $candidates.Add((Join-Path $folder 'nodejs\node.exe')) }
    }
    if (Test-Path -LiteralPath $runtime -PathType Container) {
        $cached = @(Get-ChildItem -LiteralPath $runtime -Directory |
            Where-Object { $_.Name -match '^node-v\d+\.\d+\.\d+-win-(x64|arm64)$' } |
            Sort-Object LastWriteTime -Descending)
        foreach ($folder in $cached) {
            $binary = Join-Path $folder.FullName 'node.exe'
            $receipt = Join-Path $folder.FullName 'download.json'
            if ((Test-Path -LiteralPath $binary -PathType Leaf) -and (Test-Path -LiteralPath $receipt -PathType Leaf)) {
                try {
                    $data = Get-Content -LiteralPath $receipt -Raw -Encoding UTF8 | ConvertFrom-Json
                    if ((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -ieq $data.nodeSha256) { $candidates.Add($binary) }
                } catch { }
            }
        }
    }
    foreach ($candidate in $candidates) {
        if (Test-Node $candidate $Base) { return $candidate }
    }

    Write-Host ''
    Write-Host '사용 가능한 Node.js LTS(22 이상)를 찾지 못했습니다.'
    Write-Host '공식 nodejs.org에서 LTS Windows ZIP을 내려받아 SHA-256을 확인합니다.'
    Write-Host ('준비 위치: ' + $runtime)
    Write-Host '시스템 설치, PATH/레지스트리 변경, npm 설치는 하지 않습니다.'
    if ((Read-Host '휴대용 Node.js를 준비할까요? [Y/N]').Trim() -notmatch '^(?i)y(es)?$') {
        throw 'Node.js 준비가 취소되었습니다. 승인 파일은 생성하지 않았습니다.'
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $arch = 'x64'
    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { $arch = 'arm64' }
    if (-not [Environment]::Is64BitOperatingSystem) { throw '이 배치 파일은 64비트 Windows용입니다.' }
    $index = Invoke-RestMethod -Uri 'https://nodejs.org/dist/index.json' -TimeoutSec 30
    $release = $index | Where-Object {
        $_.lts -is [string] -and $_.version -match '^v\d+\.\d+\.\d+$' -and $_.files -contains ('win-' + $arch + '-zip')
    } | Sort-Object { [version]$_.version.Substring(1) } -Descending | Select-Object -First 1
    if (-not $release -or ([version]$release.version.Substring(1)).Major -lt 22) { throw '공식 LTS 배포 정보를 확인하지 못했습니다.' }
    $version = [string]$release.version
    $stem = 'node-' + $version + '-win-' + $arch
    $zipName = $stem + '.zip'
    $baseUrl = 'https://nodejs.org/dist/' + $version + '/'
    Write-Host ('준비할 버전: ' + $version + ' (' + $arch + ')')
    $sumText = (Invoke-WebRequest -UseBasicParsing -Uri ($baseUrl + 'SHASUMS256.txt') -TimeoutSec 30).Content
    $sumPattern = '(?m)^([a-fA-F0-9]{64})[ \t]+\*?' + [regex]::Escape($zipName) + '\r?$'
    $sumMatch = [regex]::Match([string]$sumText, $sumPattern)
    if (-not $sumMatch.Success) { throw '공식 SHA-256 목록에서 해당 ZIP을 찾지 못했습니다.' }
    $expected = $sumMatch.Groups[1].Value
    [void][IO.Directory]::CreateDirectory($runtime)
    $stage = Join-Path $runtime ('prepare-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($stage)
    $zipPath = Join-Path $stage $zipName
    $unpacked = Join-Path $stage $stem
    [void][IO.Directory]::CreateDirectory($unpacked)
    try {
        Write-Host '공식 ZIP 다운로드 및 무결성 확인 중...'
        Invoke-WebRequest -UseBasicParsing -Uri ($baseUrl + $zipName) -OutFile $zipPath -TimeoutSec 300
        $actual = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
        if ($actual -ine $expected) { throw 'ZIP의 SHA-256이 공식 값과 다릅니다. 실행하지 않습니다.' }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            # Extract only the executable and license; npm is not needed.
            foreach ($name in @('node.exe','LICENSE')) {
                $entry = $archive.GetEntry($stem + '/' + $name)
                if ($null -eq $entry) { throw ('공식 ZIP에 필요한 파일이 없습니다: ' + $name) }
                if ($entry.Length -gt 268435456) { throw '비정상적으로 큰 런타임 파일입니다.' }
                $entryStream = $entry.Open()
                $output = [IO.File]::Open((Join-Path $unpacked $name), [IO.FileMode]::CreateNew)
                try { $entryStream.CopyTo($output) } finally { $output.Dispose(); $entryStream.Dispose() }
            }
        } finally { $archive.Dispose() }
        $nodePath = Join-Path $unpacked 'node.exe'
        $receipt = [ordered]@{
            version=$version; source=($baseUrl+$zipName); zipSha256=$actual.ToLowerInvariant();
            nodeSha256=(Get-FileHash -LiteralPath $nodePath -Algorithm SHA256).Hash.ToLowerInvariant()
        } | ConvertTo-Json
        [IO.File]::WriteAllText((Join-Path $unpacked 'download.json'), $receipt, $script:Utf8)
        $final = Join-Path $runtime $stem
        if (Test-Path -LiteralPath $final) { throw ('같은 버전의 런타임 폴더가 이미 있습니다. 확인 후 다시 실행하세요: ' + $final) }
        [IO.Directory]::Move($unpacked, $final)
        $nodePath = Join-Path $final 'node.exe'
        if (-not (Test-Node $nodePath $Base)) { throw '다운로드한 Node.js를 실행하지 못했습니다. Windows 버전/보안 정책을 확인하세요.' }
        return $nodePath
    } finally {
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Choose-Key {
    param([string]$HomeDirectory, [string]$Node, [string]$Base)
    $keys = Join-Path $HomeDirectory 'keys'
    $defaultKey = Join-Path $keys 'release-ed25519.pem'
    Write-Host ''
    Write-Host '[1] 기존 배포 개인키(.pem) 선택 - 기존 배포 키가 있으면 이 항목'
    if (Test-Path -LiteralPath $defaultKey -PathType Leaf) {
        Write-Host '[2] 이 도구로 만든 기본 개인키 재사용'
    } else {
        Write-Host '[2] 처음 사용하는 새 Ed25519 개인키 생성'
    }
    $choice = (Read-Host '개인키 선택 [1/2]').Trim()
    if ($choice -eq '1') {
        $chosen = Choose-File '기존 배포용 Ed25519 PEM 개인키 선택' 'PEM 개인키 (*.pem)|*.pem|모든 파일 (*.*)|*.*' $Base
        if (-not $chosen) { throw '개인키 선택이 취소되었습니다.' }
        return $chosen
    }
    if ($choice -ne '2') { throw '개인키 선택은 1 또는 2를 입력해 주세요.' }
    if (Test-Path -LiteralPath $defaultKey -PathType Leaf) { return $defaultKey }
    Write-Host ''
    Write-Host '새 키는 기존 서버 신뢰 키를 자동으로 대체하거나 등록하지 않습니다.'
    Write-Host '기존 서명 도구와 호환되는 비암호화 PKCS#8 PEM으로 저장합니다.'
    Write-Host '개인키는 운영자 PC에만 보관하고 별도로 안전하게 백업하세요.'
    Write-Host ('저장 위치: ' + $defaultKey)
    if ((Read-Host '새 개인키 생성에 동의하면 CREATE 입력').Trim() -cne 'CREATE') { throw '개인키 생성을 취소했습니다.' }
    [void][IO.Directory]::CreateDirectory($keys)
    # Restrict this tool-owned key directory before writing secret material.
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
    $systemRule = [System.Security.AccessControl.FileSystemAccessRule]::new($system, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
    $acl.AddAccessRule($systemRule)
    $acl.SetOwner($sid)
    Set-Acl -LiteralPath $keys -AclObject $acl
    [void](Invoke-Worker $Node @{GC_APPROVAL_ACTION='new-key';GC_APPROVAL_KEY=$defaultKey} $Base)
    Write-Host '개인키를 생성했습니다. 웹에는 .approval.json만 업로드하세요.'
    return $defaultKey
}

function Main {
    if ($PSVersionTable.PSVersion -lt [version]'5.1') { throw 'Windows PowerShell 5.1 이상이 필요합니다.' }
    $base = Split-Path -Parent $env:GAME_APPROVAL_BAT
    $homeDirectory = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'GameConnectReleaseTools'
    Write-Host ''
    Write-Host '=== GameConnect 공개 배포 승인 파일 생성 ==='
    Write-Host '기존 서버/클라이언트 소스와 배포 파일은 수정하지 않습니다.'
    Write-Host '서버로 자동 업로드하거나 정책/신뢰 키를 자동 변경하지 않습니다.'
    Write-Host '실행 버전: FIX3 / BAT 단독형 (A/B/O 지원, 서버 모듈 불필요)'
    Write-Host '서명 도구: 이 BAT에 포함된 독립 서명기'
    $node = Get-NodeRuntime $homeDirectory $base
    Write-Host ('사용 Node: ' + $node)
    [void](Invoke-Worker $node @{GC_APPROVAL_ACTION='self-test'} $base)
    Write-Host '서명 기능 자체 점검: 정상'
    $keyPath = $null
    do {
        Write-Host ''
        Write-Host 'A = 런처 / B = 클라이언트 / O = 오버레이 플러그인 (.bin)'
        $component = (Read-Host '생성할 구분 [A/B/O]').Trim().ToUpperInvariant()
        if ($component -notin @('A','B','O')) { throw 'A, B 또는 O를 입력해 주세요.' }
        $version = (Read-Host '서버 업로드에 사용할 버전 (예: 1.0.0)').Trim()
        if ($version.Length -gt 40 -or $version -notmatch '^\d+(\.\d+){0,3}$') { throw '버전은 1.0.0처럼 1~4단계 숫자로 입력하세요(최대 40자).' }
        if ($component -eq 'O') {
            Write-Host 'O는 최대 16MiB의 Win64 DLL 형식 .bin 파일이며 GameOverlayRunV1 내보내기가 필요합니다.'
            $exe = Choose-File 'O 최종 오버레이 플러그인 선택' '오버레이 플러그인 (*.bin)|*.bin|모든 파일 (*.*)|*.*' $base
        } else {
            Write-Host ($component + ' EXE 파일을 선택하세요. 예시 경로가 아닌 실제 빌드 파일을 선택합니다.')
            $exe = Choose-File ($component + ' 최종 Windows EXE 선택') '실행 파일 (*.exe)|*.exe|모든 파일 (*.*)|*.*' $base
        }
        if (-not $exe) { throw '배포 파일 선택이 취소되었습니다.' }
        if (-not $keyPath) { $keyPath = Choose-Key $homeDirectory $node $base }
        $target = [IO.Path]::ChangeExtension($exe, 'approval.json')
        if (Test-Path -LiteralPath $target) {
            $suffix = '.' + $component + '.' + $version + '.' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '.approval.json'
            $target = Join-Path (Split-Path -Parent $exe) ([IO.Path]::GetFileNameWithoutExtension($exe) + $suffix)
        }
        Write-Host ''
        Write-Host ('배포 파일: ' + $exe)
        Write-Host ('구분/버전: ' + $component + ' / ' + $version)
        Write-Host ('승인 파일: ' + $target)
        if ((Read-Host '위 파일에 대한 공개 승인 파일을 생성할까요? [Y/N]').Trim() -notmatch '^(?i)y(es)?$') { throw '서명을 취소했습니다.' }
        $result = Invoke-Worker $node @{
            GC_APPROVAL_ACTION='sign'; GC_APPROVAL_COMPONENT=$component;
            GC_APPROVAL_VERSION=$version; GC_APPROVAL_EXE=$exe; GC_APPROVAL_KEY=$keyPath; GC_APPROVAL_OUTPUT=$target
        } $base
        Write-Host ''
        Write-Host '[완료] 공개 배포 승인 파일을 생성했습니다.'
        Write-Host $result.output
        Write-Host ('파일 SHA-256: ' + $result.sha256)
        Write-Host ('서명자 keyId: ' + $result.keyId)
        Write-Host '웹에서 같은 배포 파일 / 같은 구분 / 같은 버전과 함께 이 .approval.json을 선택하세요.'
        Write-Host '최초 사용 키라면 JSON의 trustedKey를 서버 신뢰 서명자에 먼저 등록해야 합니다.'
        Write-Host 'PEM 개인키는 업로드하거나 소스 ZIP에 넣지 마세요.'
        $again = (Read-Host '같은 개인키로 다른 배포 파일도 생성할까요? [Y/N]').Trim()
    } while ($again -match '^(?i)y(es)?$')
}

try { Main; exit 0 }
catch {
    Write-Host ''
    Write-Host ('[중단] ' + $_.Exception.Message)
    Write-Host '기존 배포 파일, 기존 개인키, 기존 승인 파일은 덮어쓰지 않습니다.'
    Write-Host '이 버전은 sign-release-approval.js, services, vendor, npm 설치가 필요하지 않습니다.'
    Write-Host 'BOOTSTRAP_PE_INVALID / RELEASE_FILE_INVALID: A/B는 Win64 EXE(최대 64MiB), O는 플러그인(최대 16MiB)인지 확인하세요.'
    Write-Host 'OVERLAY_PLUGIN_PE_INVALID: O 파일이 Win64 DLL이며 실행 가능한 GameOverlayRunV1 내보내기를 포함하는지 확인하세요.'
    Write-Host 'ED25519_KEY_REQUIRED / KEY_PEM_INVALID: 올바른 배포용 Ed25519 개인키를 선택하세요.'
    Write-Host 'ENCRYPTED_KEY_NOT_SUPPORTED: 기존 도구와 같은 비암호화 PEM만 지원합니다.'
    Write-Host 'NODE_RUNTIME_MODULE_MISSING: 서버 소스가 아니라 Node 런타임 파일을 확인하세요.'
    Write-Host 'SIGNING_FAILED이면 실제 Win64 배포 파일과 비암호화 Ed25519 PEM 개인키인지 확인하세요.'
    Write-Host '다운로드 오류이면 nodejs.org 연결/프록시를 확인하세요. 인증서 검사는 끄지 않습니다.'
    exit 1
}
