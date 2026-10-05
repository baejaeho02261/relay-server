@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "GAME_APPROVAL_CHECK_BAT=%~f0"
set "_GC_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "_GC_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%_GC_PS%" (
  echo Windows PowerShell 5.1 is required.
  pause
  exit /b 1
)
"%_GC_PS%" -NoProfile -STA -Command "$ErrorActionPreference='Stop'; $text=[IO.File]::ReadAllText($env:GAME_APPROVAL_CHECK_BAT,[Text.Encoding]::UTF8); $mark='#'+'__GAME_APPROVAL_CHECK_POWERSHELL__'; $at=$text.IndexOf($mark,[StringComparison]::Ordinal); if($at -lt 0){throw 'Batch payload missing.'}; & ([ScriptBlock]::Create($text.Substring($at+$mark.Length)))"
set "_GC_EXIT=%ERRORLEVEL%"
echo.
pause
exit /b %_GC_EXIT%
#__GAME_APPROVAL_CHECK_POWERSHELL__
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$ProgressPreference = 'SilentlyContinue'
$script:Utf8 = New-Object System.Text.UTF8Encoding($false)
try { [Console]::OutputEncoding = $script:Utf8 } catch { }

# Read-only local approval checker. No private key is requested or generated.
$script:Worker = @'
'use strict';
// Read-only inspection. Uses Node built-ins only. No signing, key generation,
// network, server policy changes, module loading or output-file writes.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const env = process.env;
function fail(code) { const e = new Error(code); e.safeCode = code; throw e; }
function plain(v) { return v && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype; }
function readBounded(file, min, max, code) {
  if (typeof file !== 'string' || !path.isAbsolute(file)) fail('INPUT_PATH_INVALID');
  const fd = fs.openSync(file, 'r');
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.size < min || before.size > max) fail(code);
    const b = Buffer.alloc(before.size); let at = 0;
    while (at < b.length) { const n = fs.readSync(fd, b, at, b.length-at, at); if (!n) fail('INPUT_CHANGED_DURING_READ'); at += n; }
    const after = fs.fstatSync(fd);
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) fail('INPUT_CHANGED_DURING_READ');
    return b;
  } finally { fs.closeSync(fd); }
}
function main() {
  if (env.GC_APPROVAL_ACTION === 'probe') {
    return { version: process.version, major: Number(process.versions.node.split('.')[0]), lts: process.release.lts || '' };
  }
  if (env.GC_APPROVAL_ACTION !== 'inspect') fail('ACTION_INVALID');
  const bytes = readBounded(env.GC_APPROVAL_EXE, 512, 64*1024*1024, 'EXE_FILE_INVALID');
  const raw = readBounded(env.GC_APPROVAL_JSON, 1, 16384, 'APPROVAL_FILE_INVALID');
  const text = raw.toString('utf8').replace(/^\uFEFF/, '');
  if (text.includes('PRIVATE KEY')) fail('PRIVATE_KEY_NOT_ALLOWED');
  let a; try { a = JSON.parse(text); } catch (_) { fail('APPROVAL_JSON_INVALID'); }
  if (!plain(a) || !['A','B','O'].includes(a.component) || typeof a.version !== 'string' || a.version.length > 40 || !/^\d+(?:\.\d+){0,3}$/.test(a.version) || typeof a.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(a.sha256)) fail('APPROVAL_FIELDS_INVALID');
  if (!plain(a.trustedKey) || Object.keys(a.trustedKey).some(k => !['keyId','publicKey'].includes(k))) fail('TRUSTED_KEY_MISSING_OR_INVALID');
  const k = a.trustedKey;
  if (typeof k.keyId !== 'string' || !/^[a-f0-9]{64}$/.test(k.keyId) || typeof k.publicKey !== 'string' || k.publicKey.length > 4096 || !/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END PUBLIC KEY-----\r?\n?$/.test(k.publicKey)) fail('PUBLIC_KEY_FORMAT_INVALID');
  if (!plain(a.approval) || typeof a.approval.keyId !== 'string' || typeof a.approval.signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(a.approval.signature)) fail('SIGNATURE_FORMAT_INVALID');
  const signature = Buffer.from(a.approval.signature, 'base64');
  if (signature.length !== 64 || signature.toString('base64') !== a.approval.signature) fail('SIGNATURE_FORMAT_INVALID');
  let key; try { key = crypto.createPublicKey(k.publicKey); } catch (_) { fail('PUBLIC_KEY_FORMAT_INVALID'); }
  if (key.asymmetricKeyType !== 'ed25519') fail('ED25519_PUBLIC_KEY_REQUIRED');
  const id = crypto.createHash('sha256').update(key.export({type:'spki',format:'der'})).digest('hex');
  if (k.keyId !== id || a.approval.keyId !== id) fail('KEY_ID_MISMATCH');
  const digest = crypto.createHash('sha256').update(bytes).digest('hex');
  const canonical = ['GAME-RELEASE-APPROVAL-V1', a.component, a.version, a.sha256].join('\n');
  if (!crypto.verify(null, Buffer.from(canonical, 'utf8'), key, signature)) fail('SIGNATURE_INVALID');
  if (digest !== a.sha256) fail('EXE_SHA256_MISMATCH');
  // This is a signature/hash check, NOT a full PE parser or release-policy gate.
  if (env.GC_APPROVAL_COMPONENT !== a.component) fail('UPLOAD_COMPONENT_MISMATCH');
  if (env.GC_APPROVAL_VERSION !== a.version) fail('UPLOAD_VERSION_MISMATCH');
  return { ok:true, component:a.component, version:a.version, sha256:digest, keyId:id,
    serverTrustChecked:false, serverPolicyChanged:false,
    // Explicit array: this is the policy field's required JSON shape.
    trustedKeysJson:JSON.stringify([{keyId:id,publicKey:key.export({type:'spki',format:'pem'}).toString()}], null, 2) };
}
try { process.stdout.write(JSON.stringify(main()) + '\n'); }
catch (e) {
  const code = e.safeCode || (e.code === 'ENOENT' ? 'INPUT_FILE_MISSING' : ['EACCES','EPERM'].includes(e.code) ? 'ACCESS_DENIED' : 'INSPECTION_FAILED');
  process.stderr.write(code + '\n'); process.exitCode = 1;
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
    [void]$si.EnvironmentVariables.Remove('NODE_REPL_EXTERNAL_MODULE')
    foreach ($name in @('ACTION','SCRIPT','KEY','EXE','JSON','OUTPUT','COMPONENT','VERSION')) {
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
            throw '승인 점검 도구가 제한 시간 내에 종료되지 않았습니다.'
        }
        $p.WaitForExit()
        $stdout = $outTask.GetAwaiter().GetResult()
        $stderr = $errTask.GetAwaiter().GetResult()
        if ($p.ExitCode -ne 0) {
            $code = $stderr.Trim()
            if ($code -notmatch '^[A-Z_]{1,80}$') { $code = 'NODE_EXECUTION_FAILED' }
            throw ('승인 점검 도구 오류: ' + $code)
        }
        if ([string]::IsNullOrWhiteSpace($stdout)) { throw '승인 점검 도구가 결과를 반환하지 않았습니다.' }
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


function Find-ExistingNode {
    param([string]$Base)
    $homeDirectory = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'GameConnectReleaseTools'
    $runtime = Join-Path $homeDirectory 'runtime'
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    # Prefer the previously downloaded runtime. Check its local receipt first.
    if (Test-Path -LiteralPath $runtime -PathType Container) {
        $cached = @(Get-ChildItem -LiteralPath $runtime -Directory | Where-Object { $_.Name -match '^node-v\d+\.\d+\.\d+-win-(x64|arm64)$' } | Sort-Object LastWriteTime -Descending)
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
    $found = Get-Command node.exe -CommandType Application -ErrorAction SilentlyContinue
    if ($found) { foreach ($command in @($found)) { $candidates.Add($command.Source) } }
    foreach ($folder in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, (Join-Path $env:LOCALAPPDATA 'Programs'))) {
        if ($folder) { $candidates.Add((Join-Path $folder 'nodejs\node.exe')) }
    }
    foreach ($candidate in $candidates) { if (Test-Node $candidate $Base) { return $candidate } }
    Write-Host '기존 Node.js를 자동으로 찾지 못했습니다. 이미 준비한 node.exe를 선택하세요.'
    $chosen = Choose-File '기존 node.exe 선택 (새 다운로드나 설치 없음)' 'Node.js (node.exe)|node.exe' $homeDirectory
    if (-not $chosen -or -not (Test-Node $chosen $Base)) { throw '사용 가능한 기존 Node.js LTS(22 이상)를 찾지 못했습니다.' }
    return $chosen
}

function Main {
    if ($PSVersionTable.PSVersion -lt [version]'5.1') { throw 'Windows PowerShell 5.1 이상이 필요합니다.' }
    $base = Split-Path -Parent $env:GAME_APPROVAL_CHECK_BAT
    Write-Host ''
    Write-Host '=== GameConnect 공개 배포 승인 점검 ==='
    Write-Host 'EXE와 approval.json을 읽기만 합니다. 개인키는 필요하지 않습니다.'
    Write-Host '네트워크 접속, 서버 신뢰 등록, 소스 변경, 새 파일 저장은 하지 않습니다.'
    $node = Find-ExistingNode $base
    Write-Host ('사용 Node: ' + $node)
    $exe = Choose-File '업로드했던 실제 EXE 선택' '실행 파일 (*.exe)|*.exe' $base
    if (-not $exe) { throw 'EXE 선택이 취소되었습니다.' }
    $approval = Choose-File '함께 업로드했던 .approval.json 선택' '공개 승인 JSON (*.json)|*.json' (Split-Path -Parent $exe)
    if (-not $approval) { throw '승인 파일 선택이 취소되었습니다.' }
    $component = (Read-Host '웹에서 등록한 구분 [A=GameLauncher / B=GameConnect / O=GameOverlay]').Trim().ToUpperInvariant()
    if ($component -notin @('A','B','O')) { throw 'A, B 또는 O를 입력하세요.' }
    $version = (Read-Host '웹 업로드 창의 버전 (예: 1.0.0)').Trim()
    if ($version.Length -gt 40 -or $version -notmatch '^\d+(\.\d+){0,3}$') { throw '웹에 입력한 숫자 버전을 확인하세요.' }
    $result = Invoke-Worker $node @{
        GC_APPROVAL_ACTION='inspect'; GC_APPROVAL_EXE=$exe; GC_APPROVAL_JSON=$approval;
        GC_APPROVAL_COMPONENT=$component; GC_APPROVAL_VERSION=$version
    } $base
    Write-Host ''
    Write-Host '[정상] 선택한 EXE SHA-256 / 공개키 ID / Ed25519 서명 / 구분 / 버전 일치'
    Write-Host ('구분: ' + $result.component + '  |  웹 버전: ' + $result.version)
    Write-Host ('EXE SHA-256: ' + $result.sha256)
    Write-Host ('서명자 keyId: ' + $result.keyId)
    Write-Host ''
    Write-Host '서버 등록 여부와 철회 상태는 이 도구에서 조회하지 않습니다.'
    Write-Host '위 키는 본인이 생성한 배포 키가 맞을 때만 서버에 신뢰 등록하세요.'
    Write-Host '관리자 > 서버 보안 · 배포 운영 > 정책 편집 > 신뢰 서명자 공개키 목록'
    Write-Host '목록이 []일 때는 아래 배열을 넣으세요. 기존 키가 있으면 삭제하지 말고 항목을 추가하세요.'
    Write-Host ''
    Write-Host $result.trustedKeysJson
    Write-Host ''
    if ((Read-Host '위 공개키 배열을 클립보드로 복사할까요? [Y/N]').Trim() -match '^(?i)y(es)?$') {
        try { Set-Clipboard -Value ([string]$result.trustedKeysJson); Write-Host '공개키 배열을 복사했습니다. 기존 클립보드 내용을 교체했습니다.' }
        catch { Write-Host '클립보드 복사를 못했습니다. 위 배열을 수동으로 복사하세요.' }
    }
    Write-Host ''
    Write-Host '웹에서 영향 미리보기 > 미리본 정책 적용 순서로 저장한 뒤 후보 등록을 다시 시도하세요.'
    Write-Host '이미 같은 keyId가 등록됐으면 중복 추가하지 말고 공개키 내용과 정상 사용(ACTIVE) 상태를 확인하세요.'
    Write-Host 'REVOKED(철회) 상태인 키를 이 도구가 복원하거나 재신뢰 처리하지 않습니다.'
    Write-Host '배포 서명 강제 등 다른 정책 값은 바꾸지 마세요.'
    Write-Host '로컬 점검 통과는 서버 배포 승인 또는 하드웨어 실행 검증이 아닙니다.'
}

try { Main; exit 0 }
catch {
    Write-Host ''
    Write-Host ('[중단] ' + $_.Exception.Message)
    Write-Host 'EXE_SHA256_MISMATCH: 선택한 EXE가 승인 대상과 다릅니다. 재빌드/수정 뒤에는 기존 키로 새 승인을 생성하세요.'
    Write-Host 'UPLOAD_COMPONENT_MISMATCH / UPLOAD_VERSION_MISMATCH: 웹의 A/B/O 및 버전을 승인 생성 때와 맞추세요.'
    Write-Host 'SIGNATURE_INVALID / KEY_ID_MISMATCH: JSON의 서명/공개키/ID가 맞지 않습니다. 올바른 원본 승인 파일을 선택하세요.'
    Write-Host 'PRIVATE_KEY_NOT_ALLOWED: PEM 개인키가 아니라 공개 approval.json을 선택하세요.'
    Write-Host 'TRUSTED_KEY_MISSING_OR_INVALID / PUBLIC_KEY_FORMAT_INVALID: FIX2로 만든 완전한 공개 승인 JSON을 선택하세요.'
    Write-Host '입력 파일과 서버는 변경하지 않았습니다. 원본 자료는 삭제하거나 덮어쓰지 않았습니다.'
    exit 1
}
