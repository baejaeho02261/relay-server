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
function ReleaseCanonical(component, version, sha512) {
  return ['GAME-RELEASE-APPROVAL-V2', component, version, sha512].join('\n');
}
function SignRelease(component, version, file, keyFile) {
  if (!['A', 'B', 'O'].includes(component) || typeof version !== 'string' || version.length > 40 || !/^\d+(?:\.\d+){0,3}$/.test(version)) stop('RELEASE_ARGUMENT_INVALID');
  const bytes = ReadBoundedInput(file, 512, 64 * 1024 * 1024, 'RELEASE_FILE_INVALID');
  ValidatePeImage(bytes,stop);
  const sha512 = crypto.createHash('sha512').update(bytes).digest('hex');
  if (component === 'O') {
    if (typeof env.GC_APPROVAL_PREPARED_SHA512 !== 'string' || !/^[a-f0-9]{128}$/.test(env.GC_APPROVAL_PREPARED_SHA512)) stop('OVERLAY_PREPARATION_REQUIRED');
    if (sha512 !== env.GC_APPROVAL_PREPARED_SHA512) stop('OVERLAY_PREPARED_IMAGE_CHANGED');
  }
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
  const signature = crypto.sign(null, Buffer.from(ReleaseCanonical(component, version, sha512), 'utf8'), key).toString('base64');
  return { component, version, sha512, ...PeCapabilities(bytes),
    trustedKey: { keyId, publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString() },
    approval: { keyId, signature },
    headers: { 'x-game-release-key-id': keyId, 'x-game-release-signature': signature } };
}

// BEGIN STANDALONE PE PREFLIGHT
function ValidatePeImage(bytes,reject){
 const bad=()=>reject('BOOTSTRAP_PE_INVALID');
 if(!Buffer.isBuffer(bytes)||bytes.length<512||bytes.length>64*1024*1024||bytes.readUInt16LE(0)!==0x5a4d)bad();
 const pe=bytes.readUInt32LE(0x3c);if(pe<64||pe>bytes.length-24||bytes.readUInt32LE(pe)!==0x4550||bytes.readUInt16LE(pe+4)!==0x8664)bad();
 const count=bytes.readUInt16LE(pe+6),opt=pe+24,optSize=bytes.readUInt16LE(pe+20),table=opt+optSize;
 if(count<1||count>96||optSize<160||table+count*40>bytes.length||bytes.readUInt16LE(opt)!==0x20b)bad();
 const imageSize=bytes.readUInt32LE(opt+56),headerSize=bytes.readUInt32LE(opt+60),dirCount=bytes.readUInt32LE(opt+108);
 if(imageSize<4096||imageSize>128*1024*1024||headerSize<table+count*40||headerSize>bytes.length||dirCount>16||112+dirCount*8>optSize)bad();
 const sections=[];let total=0;
 for(let i=0;i<count;i++){
  const at=table+i*40,virtualSize=bytes.readUInt32LE(at+8),rva=bytes.readUInt32LE(at+12),rawSize=bytes.readUInt32LE(at+16),raw=bytes.readUInt32LE(at+20),flags=bytes.readUInt32LE(at+36),span=virtualSize||rawSize,mapped=Math.max(span,rawSize);
  if(!span||rva<headerSize||rva+mapped>imageSize||rawSize&&(raw<headerSize||raw+rawSize>bytes.length)||sections.some(s=>rva<s.rva+s.mapped&&rva+mapped>s.rva||rawSize&&s.rawSize&&raw<s.raw+s.rawSize&&raw+rawSize>s.raw))bad();
  const protectedCode=!!(flags&0x20000000)&&!(flags&0x80000000);if(protectedCode){total+=span;if(total>64*1024*1024)bad();}
  sections.push({rva,span,mapped,raw,rawSize,flags,protectedCode});
 }
 const protectedSections=sections.filter(s=>s.protectedCode).sort((a,b)=>a.rva-b.rva);if(!protectedSections.length)bad();
 ValidatePeExceptionTable(bytes,opt,dirCount,sections,reject);
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
 return true;
}
function ValidatePeExceptionTable(bytes,opt,dirCount,sections,reject){
 // Read-only preflight: normalization belongs to the completed build, before
 // detached approval binds its SHA-512. Server CRC/coverage checks still apply.
 const rva=dirCount>3?bytes.readUInt32LE(opt+136):0,size=dirCount>3?bytes.readUInt32LE(opt+140):0;
 if(!rva&&!size)return; // The server separately determines missing CRC coverage.
 const bad=()=>reject('PE_EXCEPTION_TABLE_INVALID');
 if(!rva||rva%4||!size||size%12||size>16*1024*1024)bad();
 const locate=(at,length)=>sections.find(s=>at>=s.rva&&at+length<=s.rva+Math.min(s.rawSize,s.span));
 const table=locate(rva,size);
 if(!table||(table.flags&0x80000000)||(table.flags&0x20000000))bad();
 const raw=table.raw+rva-table.rva,end=raw+size;let previousBegin=-1,previousEnd=0;
 for(let at=raw;at<end;at+=12){
  const begin=bytes.readUInt32LE(at),finish=bytes.readUInt32LE(at+4),unwind=bytes.readUInt32LE(at+8);
  if(finish<=begin||unwind%4)bad();
  const code=locate(begin,finish-begin),metadata=locate(unwind,4);
  if(!code||!(code.flags&0x20000000)||(code.flags&0x80000000)||!metadata||!(metadata.flags&0x40000000)||(metadata.flags&0x20000000))bad();
  if(begin<previousBegin)reject('PE_EXCEPTION_TABLE_UNSORTED');
  if(begin<previousEnd)bad();
  previousBegin=begin;previousEnd=finish;
 }
}
// END STANDALONE PE PREFLIGHT
// BEGIN STANDALONE CFG PREFLIGHT
function PeCapabilities(bytes){
 const authorityVersion=Buffer.isBuffer(bytes)&&(bytes.includes(Buffer.from('GAME-AUTHORITY-V2'))||bytes.includes(Buffer.from('GAME-AUTHORITY-V2','utf16le')))?1:0;
 let cfg={status:'ABSENT',instrumentedMetadata:false,functionCount:0,reason:'NO_CFG_METADATA',callSiteCoverage:'REQUIRES_TOOLCHAIN_AND_WINDOWS_EVIDENCE'};
 const bad=reason=>{throw Error(reason);};
 try{
  if(!Buffer.isBuffer(bytes)||bytes.length<512||bytes.length>64*1024*1024||bytes.readUInt16LE(0)!==0x5a4d)bad('PE_HEADER');
  const pe=bytes.readUInt32LE(0x3c);if(pe<64||pe+24>bytes.length||bytes.readUInt32LE(pe)!==0x4550||bytes.readUInt16LE(pe+4)!==0x8664)bad('PE_MACHINE');
  const opt=pe+24,size=bytes.readUInt16LE(pe+20),count=bytes.readUInt16LE(pe+6),table=opt+size;
  if(size<112||count<1||count>96||table+40*count>bytes.length||bytes.readUInt16LE(opt)!==0x20b)bad('PE_OPTIONAL_HEADER');
  const dirs=bytes.readUInt32LE(opt+108),headers=bytes.readUInt32LE(opt+60),imageSize=bytes.readUInt32LE(opt+56),base=bytes.readBigUInt64LE(opt+24),sections=[];
  if(dirs>16||112+dirs*8>size||headers<table+40*count||headers>bytes.length||imageSize<4096||imageSize>128*1024*1024)bad('PE_BOUNDS');
  for(let i=0;i<count;i++){const p=table+40*i,s={rva:bytes.readUInt32LE(p+12),span:Math.max(bytes.readUInt32LE(p+8),bytes.readUInt32LE(p+16)),raw:bytes.readUInt32LE(p+20),rawSize:bytes.readUInt32LE(p+16),flags:bytes.readUInt32LE(p+36)};
   if(!s.span||s.rva<headers||s.rva+s.span>imageSize||s.rawSize&&(s.raw<headers||s.raw+s.rawSize>bytes.length)||sections.some(x=>s.rva<x.rva+x.span&&x.rva<s.rva+s.span||s.rawSize&&x.rawSize&&s.raw<x.raw+x.rawSize&&x.raw<s.raw+s.rawSize))bad('PE_SECTIONS');sections.push(s);}
  const rawAt=(rva,length)=>{const s=sections.find(s=>rva>=s.rva&&rva+length<=s.rva+s.rawSize);if(!s)bad('CFG_UNMAPPED');return {at:s.raw+rva-s.rva,s};};
  const toRva=va=>{if(va<base||va-base>=BigInt(imageSize))bad('CFG_VA');return Number(va-base);};
  const hasFlag=!!(bytes.readUInt16LE(opt+70)&0x4000);
  if(dirs<=10){if(hasFlag)bad('CFG_FLAG_WITHOUT_LOAD_CONFIG');return {authorityVersion,compiledCfg:false,cfg};}
  const rva=bytes.readUInt32LE(opt+192),length=bytes.readUInt32LE(opt+196);
  if(!rva&&!length){if(hasFlag)bad('CFG_FLAG_WITHOUT_LOAD_CONFIG');return {authorityVersion,compiledCfg:false,cfg};}
  if(!rva||!length)bad('CFG_LOAD_CONFIG_RANGE');
  const lc=rawAt(rva,length);if(length<148){if(hasFlag)bad('CFG_LOAD_CONFIG_SHORT');return {authorityVersion,compiledCfg:false,cfg};}
  const structSize=bytes.readUInt32LE(lc.at),flags=bytes.readUInt32LE(lc.at+144);
  if(structSize<148||structSize>length)bad('CFG_LOAD_CONFIG_SIZE');
  if(!hasFlag&&(flags&0x500))bad('CFG_INCONSISTENT_FLAGS');
  if(!hasFlag)return {authorityVersion,compiledCfg:false,cfg};
  if((flags&0x500)!==0x500)bad('CFG_INSTRUMENTATION_FLAGS');
  const check=bytes.readBigUInt64LE(lc.at+112),tableVA=bytes.readBigUInt64LE(lc.at+128),n=bytes.readBigUInt64LE(lc.at+136);
  if(!check||!tableVA||n===0n||n>1000000n)bad('CFG_TABLE_MISSING');
  rawAt(toRva(check),8);const stride=4+((flags>>>28)&15),total=Number(n)*stride,entries=rawAt(toRva(tableVA),total);
  if(entries.s.flags&0x80000000)bad('CFG_TABLE_WRITABLE');
  let previous=-1;for(let i=0;i<Number(n);i++){const target=bytes.readUInt32LE(entries.at+i*stride);if(target<=previous)bad('CFG_TARGET_ORDER');previous=target;const s=sections.find(s=>target>=s.rva&&target<s.rva+s.span);if(!s||!(s.flags&0x20000000)||(s.flags&0x80000000))bad('CFG_TARGET_NOT_IMMUTABLE_CODE');}
  cfg={...cfg,status:'STRUCTURALLY_VALID',instrumentedMetadata:true,functionCount:Number(n),reason:'',guardFlags:flags};
 }catch(error){cfg={...cfg,status:'INVALID',reason:error.message};}
 return {authorityVersion,compiledCfg:cfg.instrumentedMetadata,cfg};
}
// END STANDALONE CFG PREFLIGHT

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
    return { ready: true, standalone: true, format: 'GAME-RELEASE-APPROVAL-V2' };
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
  // Recheck the exact EXE bytes and signature before creating any output.
  const currentHash = crypto.createHash('sha512').update(ReadBoundedInput(file, 512, 64 * 1024 * 1024, 'RELEASE_FILE_INVALID')).digest('hex');
  if (approval.sha512 !== currentHash) stop('EXE_CHANGED_DURING_SIGNING');
  const pub = crypto.createPublicKey(approval.trustedKey.publicKey);
  const keyId = crypto.createHash('sha256').update(pub.export({ type: 'spki', format: 'der' })).digest('hex');
  if (pub.asymmetricKeyType !== 'ed25519' || keyId !== approval.trustedKey.keyId || keyId !== approval.approval.keyId) stop('PUBLIC_KEY_MISMATCH');
  const canonical = ['GAME-RELEASE-APPROVAL-V2', component, version, currentHash].join('\n');
  if (!crypto.verify(null, Buffer.from(canonical, 'utf8'), pub, Buffer.from(approval.approval.signature, 'base64'))) stop('SIGNATURE_RECHECK_FAILED');
  const text = JSON.stringify(approval, null, 2) + '\n';
  if (/PRIVATE KEY/.test(text)) stop('PRIVATE_DATA_IN_OUTPUT');
  saveNew(output, Buffer.from(text, 'utf8'), 0o600);
  return { output, component, version, sha512: currentHash, keyId };
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

# BEGIN INTEGRATED OVERLAY PREPARATION
# Embedded build normalization core: identical to the existing ImGui normalizer.
# The JavaScript worker signs only the hash returned by this preparation step.
$script:OverlayNormalizerLoaded = $false
$script:OverlayPreparationAttempted = $false
$script:OverlayNormalizerSource = @'
using System;
using System.Collections.Generic;

namespace GameImGui {
    public sealed class NormalizeResult {
        public byte[] Bytes;
        public bool Changed;
        public int RecordCount;
        public int Inversions;
    }

    public static class PeUnwindNormalizer {
        private sealed class Section {
            public uint Rva, Span, Raw, RawSize, Flags;
            public ulong Mapped;
        }
        private sealed class Record {
            public uint Begin, End, Unwind;
            public int Offset;
        }
        private sealed class Image {
            public byte[] Bytes;
            public uint ImageSize, Headers, ExceptionRva, ExceptionSize;
            public ulong ImageBase;
            public int Optional, DirectoryCount, ChecksumOffset;
            public List<Section> Sections = new List<Section>();

            public Section Locate(uint rva, uint size) {
                if (size == 0) Fail("EMPTY_RANGE");
                foreach (Section s in Sections)
                    if (rva >= s.Rva && (ulong)rva + size <= (ulong)s.Rva + Math.Min(s.Span, s.RawSize)) return s;
                Fail("RANGE_NOT_FILE_BACKED"); return null;
            }
            public int RawAt(uint rva, uint size) {
                Section s = Locate(rva, size);
                return checked((int)((ulong)s.Raw + rva - s.Rva));
            }
            public void Code(uint begin, uint end) {
                if (end <= begin) Fail("CODE_RANGE_INVALID");
                Section s = Locate(begin, end - begin);
                if ((s.Flags & 0xA0000000U) != 0x20000000U) Fail("CODE_NOT_READONLY_EXECUTABLE");
            }
            public int Metadata(uint rva, uint size) {
                Section s = Locate(rva, size);
                if ((s.Flags & 0x60000000U) != 0x40000000U) Fail("UNWIND_NOT_READABLE_METADATA");
                if (Overlaps(rva, size, ExceptionRva, ExceptionSize)) Fail("UNWIND_ALIASES_EXCEPTION_TABLE");
                return checked((int)((ulong)s.Raw + rva - s.Rva));
            }
            public void Unwind(uint rva, HashSet<uint> done, HashSet<uint> active, int depth) {
                // Low-bit indirect RUNTIME_FUNCTION pointers would be invalidated
                // by reordering, so this deliberately supports direct records only.
                if ((rva & 3) != 0) Fail("INDIRECT_OR_UNALIGNED_UNWIND");
                if (done.Contains(rva)) return;
                if (depth > 64 || !active.Add(rva)) Fail("UNWIND_CHAIN_INVALID");
                int at = Metadata(rva, 4);
                int version = Bytes[at] & 7, flags = Bytes[at] >> 3;
                if ((version != 1 && version != 2) || flags > 7 || ((flags & 4) != 0 && (flags & 3) != 0)) Fail("UNWIND_FORMAT_UNSUPPORTED");
                uint body = checked((uint)(4 + 2 * ((Bytes[at + 2] + 1) & ~1)));
                uint trailer = (flags & 4) != 0 ? 12U : ((flags & 3) != 0 ? 4U : 0U);
                at = Metadata(rva, body + trailer);
                int tail = checked(at + (int)body);
                if ((flags & 4) != 0) {
                    Code(U32(Bytes, tail), U32(Bytes, tail + 4));
                    Unwind(U32(Bytes, tail + 8), done, active, depth + 1);
                } else if ((flags & 3) != 0) {
                    uint handler = U32(Bytes, tail);
                    if (handler == uint.MaxValue) Fail("UNWIND_HANDLER_INVALID");
                    Code(handler, handler + 1);
                }
                active.Remove(rva); done.Add(rva);
            }
        }

        private static void Fail(string reason) { throw new InvalidOperationException("PE_UNWIND_" + reason); }
        private static bool Overlaps(ulong a, ulong an, ulong b, ulong bn) { return an != 0 && bn != 0 && a < b + bn && b < a + an; }
        private static ushort U16(byte[] b, int at) { return (ushort)(b[at] | (b[at + 1] << 8)); }
        private static uint U32(byte[] b, int at) { return (uint)(b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)); }
        private static ulong U64(byte[] b, int at) { return U32(b, at) | ((ulong)U32(b, at + 4) << 32); }
        private static void Put32(byte[] b, int at, uint value) { for (int i = 0; i < 4; ++i) b[at + i] = (byte)(value >> (8 * i)); }

        private static Image Parse(byte[] bytes) {
            if (bytes == null || bytes.Length < 512 || bytes.Length > 64 * 1024 * 1024 || U16(bytes, 0) != 0x5A4D) Fail("FILE_INVALID");
            uint peValue = U32(bytes, 0x3C);
            if (peValue < 64 || (ulong)peValue + 24 > (ulong)bytes.Length) Fail("HEADER_INVALID");
            int pe = (int)peValue, opt = pe + 24, count = U16(bytes, pe + 6), optSize = U16(bytes, pe + 20);
            uint attributes = U16(bytes, pe + 22);
            if (U32(bytes, pe) != 0x4550 || U16(bytes, pe + 4) != 0x8664 || (attributes & 2) == 0 || (attributes & 0x2000) != 0 || count < 1 || count > 96 || optSize < 160 || (ulong)opt + (uint)optSize + (uint)count * 40 > (ulong)bytes.Length) Fail("AMD64_EXECUTABLE_REQUIRED");
            if (U16(bytes, opt) != 0x20B || U16(bytes, opt + 68) != 2) Fail("PE32PLUS_GUI_REQUIRED");
            Image image = new Image();
            image.Bytes = bytes; image.Optional = opt; image.ChecksumOffset = opt + 64;
            image.ImageSize = U32(bytes, opt + 56); image.Headers = U32(bytes, opt + 60); image.ImageBase = U64(bytes, opt + 24);
            uint directories = U32(bytes, opt + 108);
            if (image.ImageSize < 4096 || image.ImageSize > 128 * 1024 * 1024 || image.Headers < opt + optSize + count * 40 || image.Headers > bytes.Length || image.Headers > image.ImageSize || directories > 16 || 112 + directories * 8 > optSize) Fail("LAYOUT_INVALID");
            image.DirectoryCount = (int)directories;
            if (directories <= 3) Fail("EXCEPTION_DIRECTORY_REQUIRED");
            // Authenticode signatures bind the bytes: signed files are never edited,
            // even if their exception directory is already in canonical order.
            if (directories > 4 && (U32(bytes, opt + 144) != 0 || U32(bytes, opt + 148) != 0)) Fail("SIGNED_IMAGE_REFUSED");
            for (int i = 0; i < count; ++i) {
                int at = opt + optSize + i * 40;
                Section s = new Section();
                s.Span = U32(bytes, at + 8); s.Rva = U32(bytes, at + 12); s.RawSize = U32(bytes, at + 16); s.Raw = U32(bytes, at + 20); s.Flags = U32(bytes, at + 36);
                if (s.Span == 0) s.Span = s.RawSize;
                s.Mapped = Math.Max(s.Span, s.RawSize);
                if (s.Span == 0 || s.Rva < image.Headers || (ulong)s.Rva + s.Mapped > image.ImageSize || (s.RawSize != 0 && (s.Raw < image.Headers || (ulong)s.Raw + s.RawSize > (ulong)bytes.Length))) Fail("SECTION_INVALID");
                foreach (Section old in image.Sections)
                    if (Overlaps(s.Rva, s.Mapped, old.Rva, old.Mapped) || Overlaps(s.Raw, s.RawSize, old.Raw, old.RawSize)) Fail("SECTION_OVERLAP");
                image.Sections.Add(s);
            }
            uint entry = U32(bytes, opt + 16);
            if (entry == uint.MaxValue) Fail("ENTRY_INVALID");
            image.Code(entry, entry + 1);
            image.ExceptionRva = U32(bytes, opt + 136); image.ExceptionSize = U32(bytes, opt + 140);
            if (image.ExceptionRva == 0 || (image.ExceptionRva & 3) != 0 || image.ExceptionSize == 0 || image.ExceptionSize % 12 != 0 || image.ExceptionSize > 16 * 1024 * 1024) Fail("EXCEPTION_DIRECTORY_INVALID");
            Section table = image.Locate(image.ExceptionRva, image.ExceptionSize);
            if ((table.Flags & 0xE0000000U) != 0x40000000U) Fail("EXCEPTION_TABLE_NOT_READONLY_METADATA");
            for (int i = 0; i < image.DirectoryCount; ++i) {
                if (i == 3 || i == 4) continue;
                uint rva = U32(bytes, opt + 112 + i * 8), size = U32(bytes, opt + 116 + i * 8);
                if (Overlaps(rva, size, image.ExceptionRva, image.ExceptionSize)) Fail("DIRECTORY_ALIASES_EXCEPTION_TABLE");
            }
            return image;
        }

        private static void CheckRelocations(Image image) {
            if (image.DirectoryCount <= 5) return;
            byte[] b = image.Bytes;
            uint rva = U32(b, image.Optional + 152), size = U32(b, image.Optional + 156);
            if ((rva == 0) != (size == 0) || size > 16 * 1024 * 1024) Fail("RELOCATION_DIRECTORY_INVALID");
            if (size == 0) return;
            int at = image.RawAt(rva, size), end = checked(at + (int)size);
            while (at < end) {
                if (end - at < 8) Fail("RELOCATION_BLOCK_INVALID");
                uint page = U32(b, at), block = U32(b, at + 4);
                if (page >= image.ImageSize || (page & 4095) != 0 || block < 8 || (block & 1) != 0 || (ulong)at + block > (ulong)end) Fail("RELOCATION_BLOCK_INVALID");
                int stop = checked(at + (int)block);
                for (int p = at + 8; p < stop; p += 2) {
                    ushort slot = U16(b, p); int kind = slot >> 12;
                    if (kind == 0) continue;
                    // This is an AMD64 template normalizer, not a relocation editor.
                    // Unknown operand types could hide pointers into moved rows.
                    if (kind != 10 && kind != 3) Fail("RELOCATION_KIND_UNSUPPORTED");
                    uint width = kind == 10 ? 8U : 4U;
                    ulong targetValue = (ulong)page + (uint)(slot & 4095);
                    if (targetValue + width > image.ImageSize) Fail("RELOCATION_TARGET_INVALID");
                    uint target = (uint)targetValue;
                    if (Overlaps(target, width, image.ExceptionRva, image.ExceptionSize)) Fail("RELOCATION_TOUCHES_EXCEPTION_TABLE");
                    // The operand can end in loader zero-fill. Read the actual
                    // pristine value rather than treating virtual bytes as file data.
                    ulong operand = 0;
                    Section section = null;
                    foreach (Section s in image.Sections)
                        if (target >= s.Rva && targetValue + width <= (ulong)s.Rva + s.Span) { section = s; break; }
                    if (section == null) Fail("RELOCATION_TARGET_INVALID");
                    for (int j = 0; j < width; ++j) {
                        ulong offset = targetValue - section.Rva + (uint)j;
                        if (offset < section.RawSize) operand |= (ulong)b[checked((int)((ulong)section.Raw + offset))] << (j * 8);
                    }
                    if (operand >= image.ImageBase && operand - image.ImageBase >= image.ExceptionRva && operand - image.ImageBase < (ulong)image.ExceptionRva + image.ExceptionSize) Fail("RELOCATED_POINTER_TO_EXCEPTION_TABLE");
                }
                at = stop;
            }
        }

        private static uint Checksum(byte[] bytes, int checksumOffset) {
            ulong sum = 0;
            for (int i = 0; i < bytes.Length; i += 2) {
                uint word = (i >= checksumOffset && i < checksumOffset + 4) ? 0U : bytes[i];
                if (i + 1 < bytes.Length && !(i + 1 >= checksumOffset && i + 1 < checksumOffset + 4)) word |= (uint)bytes[i + 1] << 8;
                sum += word; sum = (sum & 0xFFFF) + (sum >> 16);
            }
            sum = (sum & 0xFFFF) + (sum >> 16);
            return checked((uint)((sum & 0xFFFF) + (sum >> 16) + (ulong)bytes.Length));
        }

        public static NormalizeResult Normalize(byte[] input) {
            Image image = Parse(input);
            CheckRelocations(image);
            int at = image.RawAt(image.ExceptionRva, image.ExceptionSize), count = checked((int)(image.ExceptionSize / 12));
            List<Record> records = new List<Record>(count);
            HashSet<uint> done = new HashSet<uint>(), active = new HashSet<uint>();
            int inversions = 0; uint previous = 0;
            for (int i = 0; i < count; ++i) {
                int p = at + i * 12;
                Record item = new Record(); item.Begin = U32(input, p); item.End = U32(input, p + 4); item.Unwind = U32(input, p + 8); item.Offset = p;
                image.Code(item.Begin, item.End); image.Unwind(item.Unwind, done, active, 0);
                if (i != 0 && item.Begin < previous) ++inversions;
                previous = item.Begin; records.Add(item);
            }
            records.Sort(delegate(Record a, Record b) { return a.Begin.CompareTo(b.Begin); });
            for (int i = 1; i < count; ++i)
                if (records[i].Begin < records[i - 1].End) Fail("DUPLICATE_OR_OVERLAPPING_FUNCTIONS");
            NormalizeResult result = new NormalizeResult();
            result.RecordCount = count; result.Inversions = inversions; result.Changed = inversions != 0; result.Bytes = input;
            if (!result.Changed) return result;
            result.Bytes = (byte[])input.Clone();
            for (int i = 0; i < count; ++i) Buffer.BlockCopy(input, records[i].Offset, result.Bytes, at + i * 12, 12);
            if (U32(input, image.ChecksumOffset) != 0) Put32(result.Bytes, image.ChecksumOffset, Checksum(result.Bytes, image.ChecksumOffset));
            return result;
        }
    }
}
'@

function Prepare-OverlayImage {
    param([Parameter(Mandatory = $true)][string]$ImagePath)
    $temporary = $null
    $stream = $null
    try {
        if (-not $script:OverlayNormalizerLoaded) {
            Add-Type -TypeDefinition $script:OverlayNormalizerSource -Language CSharp
            $script:OverlayNormalizerLoaded = $true
        }
        $resolved = (Resolve-Path -LiteralPath $ImagePath).ProviderPath
        if (-not [IO.File]::Exists($resolved)) { throw 'PE_UNWIND_FILE_REQUIRED' }
        if (([IO.File]::GetAttributes($resolved) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'PE_UNWIND_REPARSE_POINT_REFUSED' }
        $stream = New-Object IO.FileStream($resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        if ($stream.Length -lt 512 -or $stream.Length -gt (64 * 1024 * 1024)) { throw 'PE_UNWIND_FILE_INVALID' }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw 'PE_UNWIND_READ_INCOMPLETE' }
            $offset += $read
        }
        $result = [GameImGui.PeUnwindNormalizer]::Normalize($bytes)
        if ($result.Changed) {
            $temporary = [IO.Path]::Combine([IO.Path]::GetDirectoryName($resolved), '.game-unwind-' + [Guid]::NewGuid().ToString('N') + '.pending')
            $output = New-Object IO.FileStream($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $output.Write($result.Bytes, 0, $result.Bytes.Length); $output.Flush($true) } finally { $output.Dispose() }
            $stream.Dispose(); $stream = $null
            # Same-directory atomic replacement; PowerShell must pass an actual
            # null backup filename instead of converting $null to String.Empty.
            [IO.File]::Replace($temporary, $resolved, [System.Management.Automation.Language.NullString]::Value)
            $temporary = $null
        }
        # Verify saved bytes and derive a receipt for the separate signing worker.
        $savedBytes = [IO.File]::ReadAllBytes($resolved)
        $verified = [GameImGui.PeUnwindNormalizer]::Normalize($savedBytes)
        if ($verified.Changed -or $verified.Inversions -ne 0) { throw 'PE_UNWIND_READBACK_NOT_ORDERED' }
        $sha512 = [Security.Cryptography.SHA512]::Create()
        try {
            $expectedHash = [BitConverter]::ToString($sha512.ComputeHash($result.Bytes)).Replace('-', '').ToLowerInvariant()
            $savedHash = [BitConverter]::ToString($sha512.ComputeHash($savedBytes)).Replace('-', '').ToLowerInvariant()
        } finally { $sha512.Dispose() }
        if ($savedBytes.Length -ne $result.Bytes.Length -or $savedHash -ne $expectedHash) { throw 'PE_UNWIND_READBACK_MISMATCH' }
        if ($result.Changed) {
            Write-Host ('[O 준비] 예외 테이블 정렬 완료: {0}개 항목, 역순 {1}곳 교정' -f $result.RecordCount, $result.Inversions)
        } else {
            Write-Host ('[O 준비] 예외 테이블 정상: {0}개 항목, EXE 변경 없음' -f $result.RecordCount)
        }
        Write-Host ('[O 준비] 저장 결과 재검사 통과 / SHA-512: ' + $savedHash)
        return [pscustomobject]@{ image=$resolved; sha512=$savedHash; changed=[bool]$result.Changed; records=$verified.RecordCount; bytes=$savedBytes.Length }
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $temporary -and [IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

# END INTEGRATED OVERLAY PREPARATION

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
    foreach ($name in @('ACTION','SCRIPT','KEY','EXE','OUTPUT','COMPONENT','VERSION','PREPARED_SHA512')) {
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
            if ($code -notmatch '^[A-Z][A-Z0-9_]{0,79}$') { $code = 'NODE_EXECUTION_FAILED' }
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
            version=$version; source=($baseUrl+$zipName); zipSha512=$actual.ToLowerInvariant();
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
    Write-Host 'O는 선택한 EXE의 예외 테이블을 검사·정렬한 뒤 승인 JSON을 생성합니다.'
    Write-Host 'A/B EXE와 기존 승인 JSON은 변경하지 않습니다.'
    Write-Host '승인 JSON은 EXE 폴더가 아니라 이 BAT와 같은 폴더에 저장합니다.'
    Write-Host '서버로 자동 업로드하거나 정책/신뢰 키를 자동 변경하지 않습니다.'
    Write-Host '실행 버전: FIX4 / BAT 단독형 (O 자동 정렬 + 승인 JSON 생성)'
    Write-Host '서명 도구: 이 BAT에 포함된 독립 서명기'
    $node = Get-NodeRuntime $homeDirectory $base
    Write-Host ('사용 Node: ' + $node)
    [void](Invoke-Worker $node @{GC_APPROVAL_ACTION='self-test'} $base)
    Write-Host '서명 기능 자체 점검: 정상'
    $keyPath = $null
    do {
        $script:OverlayPreparationAttempted = $false
        Write-Host ''
        Write-Host 'A = 런처 / B = 클라이언트 / O = 오버레이'
        $component = (Read-Host '생성할 구분 [A/B/O]').Trim().ToUpperInvariant()
        if ($component -notin @('A','B','O')) { throw 'A, B 또는 O를 입력해 주세요.' }
        $version = (Read-Host '서버 업로드에 사용할 버전 (예: 1.0.0)').Trim()
        if ($version.Length -gt 40 -or $version -notmatch '^\d+(\.\d+){0,3}$') { throw '버전은 1.0.0처럼 1~4단계 숫자로 입력하세요(최대 40자).' }
        Write-Host ($component + ' EXE 파일을 선택하세요. 예시 경로가 아닌 실제 빌드 파일을 선택합니다.')
        $exe = Choose-File ($component + ' 최종 Windows EXE 선택') '실행 파일 (*.exe)|*.exe|모든 파일 (*.*)|*.*' $base
        if (-not $exe) { throw 'EXE 선택이 취소되었습니다.' }
        $target = Join-Path $base ([IO.Path]::GetFileNameWithoutExtension($exe) + '.approval.json')
        if (Test-Path -LiteralPath $target) {
            $suffix = '.' + $component + '.' + $version + '.' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '.approval.json'
            $target = Join-Path $base ([IO.Path]::GetFileNameWithoutExtension($exe) + $suffix)
        }
        Write-Host ''
        Write-Host ('EXE: ' + $exe)
        Write-Host ('구분/버전: ' + $component + ' / ' + $version)
        Write-Host ('승인 파일: ' + $target)
        $confirmPrompt = '위 파일에 대한 공개 승인 파일을 생성할까요? [Y/N]'
        if ($component -eq 'O') {
            Write-Host '선택한 O EXE의 예외 테이블이 역순이면 이 파일을 직접 정렬하고 저장합니다.'
            Write-Host '정렬된 최종 EXE에 맞는 새 JSON을 생성합니다. 이 EXE의 이전 JSON은 다시 사용하지 마세요.'
            $confirmPrompt = '선택한 O EXE를 검사·정렬한 뒤 공개 승인 파일을 생성할까요? [Y/N]'
        }
        if ((Read-Host $confirmPrompt).Trim() -notmatch '^(?i)y(es)?$') { throw '서명을 취소했습니다.' }
        $prepared = $null
        if ($component -eq 'O') {
            $script:OverlayPreparationAttempted = $true
            $prepared = Prepare-OverlayImage -ImagePath $exe
            $exe = $prepared.image
        }
        if (-not $keyPath) { $keyPath = Choose-Key $homeDirectory $node $base }
        $signValues = @{
            GC_APPROVAL_ACTION='sign'; GC_APPROVAL_COMPONENT=$component;
            GC_APPROVAL_VERSION=$version; GC_APPROVAL_EXE=$exe; GC_APPROVAL_KEY=$keyPath; GC_APPROVAL_OUTPUT=$target
        }
        if ($component -eq 'O') { $signValues.GC_APPROVAL_PREPARED_SHA512 = $prepared.sha512 }
        $result = Invoke-Worker $node $signValues $base
        Write-Host ''
        Write-Host '[완료] 공개 배포 승인 파일을 생성했습니다.'
        Write-Host $result.output
        Write-Host ('EXE SHA-512: ' + $result.sha512)
        Write-Host ('서명자 keyId: ' + $result.keyId)
        Write-Host '웹에서 같은 EXE / 같은 구분 / 같은 버전과 함께 이 .approval.json을 선택하세요.'
        Write-Host '최초 사용 키라면 JSON의 trustedKey를 서버 신뢰 서명자에 먼저 등록해야 합니다.'
        Write-Host 'PEM 개인키는 업로드하거나 소스 ZIP에 넣지 마세요.'
        $again = (Read-Host '같은 개인키로 다른 EXE도 생성할까요? [Y/N]').Trim()
    } while ($again -match '^(?i)y(es)?$')
}

try { Main; exit 0 }
catch {
    Write-Host ''
    Write-Host ('[중단] ' + $_.Exception.Message)
    if ($script:OverlayPreparationAttempted) {
        Write-Host 'O EXE는 준비 단계에서 이미 정렬되어 저장됐을 수 있습니다. 이후 서명 실패나 취소는 EXE를 이전 상태로 되돌리지 않습니다.'
        Write-Host '다시 이 도구에서 O와 같은 EXE를 선택해 새 승인 JSON 생성을 완료하세요.'
    }
    Write-Host '기존 개인키와 기존 승인 JSON은 덮어쓰지 않았습니다.'
    Write-Host '이 버전은 sign-release-approval.js, services, vendor, npm 설치가 필요하지 않습니다.'
    Write-Host 'BOOTSTRAP_PE_INVALID / RELEASE_FILE_INVALID: 실제 Win64 EXE인지 확인하세요.'
    Write-Host 'PE_EXCEPTION_TABLE_UNSORTED: 이 도구에서 O를 선택하면 서명 전에 자동 정렬합니다.'
    Write-Host 'PE_UNWIND_*: O 예외 테이블 준비가 실패했습니다. 위 상세 오류와 정상 Win64 Release 빌드를 확인하세요.'
    Write-Host 'OVERLAY_PREPARATION_REQUIRED: 이 BAT에서 O 준비와 서명을 순서대로 실행하세요.'
    Write-Host 'OVERLAY_PREPARED_IMAGE_CHANGED: O 준비 후 EXE가 변경됐습니다. 빌드를 마친 뒤 이 도구로 다시 생성하세요.'
    Write-Host 'PE_EXCEPTION_TABLE_INVALID: 예외 테이블 범위가 잘못되었습니다. 정상 Release 빌드와 빌드 로그를 확인하세요.'
    Write-Host 'ED25519_KEY_REQUIRED / KEY_PEM_INVALID: 올바른 배포용 Ed25519 개인키를 선택하세요.'
    Write-Host 'ENCRYPTED_KEY_NOT_SUPPORTED: 기존 도구와 같은 비암호화 PEM만 지원합니다.'
    Write-Host 'NODE_RUNTIME_MODULE_MISSING: 서버 소스가 아니라 Node 런타임 파일을 확인하세요.'
    Write-Host 'SIGNING_FAILED이면 실제 Win64 EXE와 비암호화 Ed25519 PEM 개인키인지 확인하세요.'
    Write-Host '다운로드 오류이면 nodejs.org 연결/프록시를 확인하세요. 인증서 검사는 끄지 않습니다.'
    exit 1
}
