# Windows PowerShell 5.1. Public verification data only; no private key input.
# The Launcher DPROJ runs this before its existing brcc32 resource compilation.
[CmdletBinding()]
param([string]$SourceRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$pending = $null
$replacementBackup = $null
try {
    if ([string]::IsNullOrWhiteSpace($SourceRoot)) {
        $scriptDirectory = [string]$PSScriptRoot
        if ([string]::IsNullOrWhiteSpace($scriptDirectory)) {
            $scriptPath = [string]$PSCommandPath
            if ([string]::IsNullOrWhiteSpace($scriptPath)) {
                $pathProperty = $MyInvocation.MyCommand.PSObject.Properties['Path']
                if ($null -ne $pathProperty) { $scriptPath = [string]$pathProperty.Value }
            }
            if ([string]::IsNullOrWhiteSpace($scriptPath)) { throw 'ISSUED_A_SOURCE_ROOT_REQUIRED' }
            $scriptDirectory = [IO.Path]::GetDirectoryName($scriptPath)
        }
        if ([string]::IsNullOrWhiteSpace($scriptDirectory)) { throw 'ISSUED_A_SOURCE_ROOT_REQUIRED' }
        $SourceRoot = [IO.Path]::Combine($scriptDirectory, '..')
    }
    $nativeRoot = [IO.Path]::GetFullPath($SourceRoot)
    $configuration = Join-Path $nativeRoot 'Cozy.Source\Cozy.Configuration'
    $includePath = Join-Path $configuration 'Cozy.IssuedA.Trust.inc'
    $outputPath = Join-Path $configuration 'Cozy.IssuedA.Trust.bin'
    $sourceInfo = Get-Item -LiteralPath $includePath -Force
    if ($sourceInfo.PSIsContainer -or $sourceInfo.Length -gt 16384 -or
        ($sourceInfo.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'ISSUED_A_PUBLIC_INCLUDE_INVALID'
    }
    # Parse data; never evaluate the Pascal source or any text it contains.
    $source = [IO.File]::ReadAllText($includePath)
    # The source package deliberately contains no default operational issuer.
    # Refuse setup placeholders before examining any older generated binary.
    if ($source.Contains('COZY_ISSUED_A_PUBLIC_KEY_SETUP_REQUIRED')) {
        throw 'COZY_ISSUED_A_PUBLIC_KEY_SETUP_REQUIRED'
    }
    $source = [regex]::Replace($source, '\{[^}]*\}', '')
    $match = [regex]::Match($source, '(?is)\A\s*const\s+CozyIssuedATrustAnchor\s*:\s*array\s*\[0\.\.330\]\s+of\s+Byte\s*=\s*\((?<bytes>[^)]*)\)\s*;\s*\z')
    if (-not $match.Success) { throw 'ISSUED_A_PUBLIC_INCLUDE_INVALID' }
    $parts = $match.Groups['bytes'].Value.Split(',')
    if ($parts.Length -ne 331) { throw 'ISSUED_A_PUBLIC_ANCHOR_SIZE_INVALID' }
    [byte[]]$anchor = New-Object byte[] 331
    for ($i = 0; $i -lt $parts.Length; $i++) {
        $part = $parts[$i].Trim()
        if ($part -notmatch '^\$[0-9a-fA-F]{2}$') { throw 'ISSUED_A_PUBLIC_INCLUDE_INVALID' }
        $anchor[$i] = [Convert]::ToByte($part.Substring(1), 16)
    }
    if ([Text.Encoding]::ASCII.GetString($anchor, 0, 16) -cne 'COZYAISSUERKEY1!') {
        throw 'ISSUED_A_PUBLIC_ANCHOR_INVALID'
    }
    [uint32[]]$header = @(0x31415352, 2048, 3, 256, 0, 0)
    for ($i = 0; $i -lt $header.Length; $i++) {
        if ([BitConverter]::ToUInt32($anchor, 48 + 4 * $i) -ne $header[$i]) {
            throw 'ISSUED_A_PUBLIC_RSA_INVALID'
        }
    }
    if ($anchor[72] -ne 1 -or $anchor[73] -ne 0 -or $anchor[74] -ne 1 -or
        ($anchor[75] -band 128) -eq 0 -or ($anchor[330] -band 1) -ne 1) {
        throw 'ISSUED_A_PUBLIC_RSA_INVALID'
    }
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { $keyId = $sha256.ComputeHash($anchor, 48, 283) }
    finally { $sha256.Dispose() }
    for ($i = 0; $i -lt 32; $i++) {
        if ($anchor[16 + $i] -ne $keyId[$i]) { throw 'ISSUED_A_PUBLIC_KEY_ID_INVALID' }
    }
    if (Test-Path -LiteralPath $outputPath) {
        $outputInfo = Get-Item -LiteralPath $outputPath -Force
        if ($outputInfo.PSIsContainer -or ($outputInfo.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'ISSUED_A_PUBLIC_OUTPUT_INVALID'
        }
        if ($outputInfo.Length -eq 331) {
            $current = [IO.File]::ReadAllBytes($outputPath)
            if ([Convert]::ToBase64String($current) -ceq [Convert]::ToBase64String($anchor)) { exit 0 }
        }
    }
    $pending = Join-Path $configuration ([IO.Path]::GetRandomFileName())
    $stream = [IO.File]::Open($pending, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($anchor, 0, $anchor.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    if ([IO.File]::Exists($outputPath)) {
        # A real same-directory backup path avoids PowerShell converting a null
        # string argument to an empty path. Keep File.Replace atomic.
        $replacementBackup = Join-Path $configuration ('Cozy.IssuedA.Trust.' + [guid]::NewGuid().ToString('N') + '.backup')
        if (Test-Path -LiteralPath $replacementBackup) { throw 'ISSUED_A_PUBLIC_BACKUP_EXISTS' }
        [IO.File]::Replace($pending, $outputPath, $replacementBackup)
        $pending = $null
        [IO.File]::Delete($replacementBackup)
        $replacementBackup = $null
    } else {
        [IO.File]::Move($pending, $outputPath)
        $pending = $null
    }
} catch {
    [Console]::Error.WriteLine('Issuer public resource preparation failed: ' + $_.Exception.Message)
    if ($null -ne $replacementBackup -and [IO.File]::Exists($replacementBackup)) {
        [Console]::Error.WriteLine('Previous public resource backup retained: ' + $replacementBackup)
    }
    exit 1
} finally {
    if ($null -ne $pending -and [IO.File]::Exists($pending)) { [IO.File]::Delete($pending) }
}
