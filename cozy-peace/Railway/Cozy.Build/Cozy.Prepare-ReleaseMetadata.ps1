# Windows PowerShell 5.1 compatible. Public product metadata only.
# One reviewed JSON source supplies the PE version, manifest and runtime version.
[CmdletBinding()]
param(
    [string]$SourceRoot = (Join-Path $PSScriptRoot '..'),
    [ValidateSet('A','B','O','All')][string]$Role = 'All'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$pending = New-Object 'System.Collections.Generic.List[string]'
$utf8 = New-Object System.Text.UTF8Encoding($false, $true)

function Read-MetadataText([string]$Path) {
    $info = Get-Item -LiteralPath $Path -Force
    if ($info.PSIsContainer -or $info.Length -eq 0 -or $info.Length -gt 65536 -or
        ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'COZY_RELEASE_METADATA_INPUT_INVALID'
    }
    return $utf8.GetString([IO.File]::ReadAllBytes($Path)).TrimStart([char]0xfeff)
}

function Require-Properties($Value, [string[]]$Names) {
    if ($null -eq $Value -or $Value -isnot [pscustomobject]) {
        throw 'COZY_RELEASE_METADATA_SCHEMA_INVALID'
    }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expected = @($Names | Sort-Object)
    if (($actual -join '|') -cne ($expected -join '|')) {
        throw 'COZY_RELEASE_METADATA_SCHEMA_INVALID'
    }
}

function Replace-One([string]$Text, [string]$Pattern, [string]$Replacement) {
    if ([regex]::Matches($Text, $Pattern).Count -ne 1) {
        throw 'COZY_RELEASE_METADATA_TEMPLATE_INVALID'
    }
    # A match evaluator keeps replacement values literal (no regex $ expansion).
    return [regex]::Replace($Text, $Pattern, { param($match) $Replacement })
}

function Write-MetadataText([string]$Path, [string]$Text) {
    [byte[]]$bytes = $utf8.GetBytes($Text.Replace("`r`n", "`n").Replace("`n", "`r`n"))
    if (Test-Path -LiteralPath $Path) {
        $info = Get-Item -LiteralPath $Path -Force
        if ($info.PSIsContainer -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'COZY_RELEASE_METADATA_OUTPUT_INVALID'
        }
        if ($info.Length -eq $bytes.Length -and
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($Path)) -ceq
            [Convert]::ToBase64String($bytes)) { return }
    }
    $temporary = Join-Path ([IO.Path]::GetDirectoryName($Path)) ([IO.Path]::GetRandomFileName())
    $pending.Add($temporary)
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    if ([IO.File]::Exists($Path)) {
        # PowerShell can convert a null string backup argument into an invalid
        # empty path. Use a real same-directory path and retain it on failure.
        $replacementBackup = Join-Path ([IO.Path]::GetDirectoryName($Path)) `
            ('Cozy.ReleaseMetadata.' + [guid]::NewGuid().ToString('N') + '.backup')
        if (Test-Path -LiteralPath $replacementBackup) { throw 'COZY_RELEASE_METADATA_BACKUP_EXISTS' }
        try {
            [IO.File]::Replace($temporary, $Path, $replacementBackup)
            [void]$pending.Remove($temporary)
            [IO.File]::Delete($replacementBackup)
        } catch {
            if ([IO.File]::Exists($replacementBackup)) {
                [Console]::Error.WriteLine('Previous release metadata backup retained: ' + $replacementBackup)
            }
            throw
        }
    } else {
        [IO.File]::Move($temporary, $Path)
        [void]$pending.Remove($temporary)
    }
}

try {
    $root = [IO.Path]::GetFullPath($SourceRoot)
    $configuration = Join-Path (Join-Path $root 'Cozy.Source') 'Cozy.Configuration'
    $spec = Read-MetadataText (Join-Path $configuration 'Cozy.ReleaseMetadata.json') | ConvertFrom-Json
    Require-Properties $spec @('schemaVersion','version','companyName','productName','descriptions')
    Require-Properties $spec.descriptions @('A','B','O')
    if (($spec.schemaVersion -isnot [int] -and $spec.schemaVersion -isnot [long]) -or
        $spec.schemaVersion -ne 1 -or $spec.version -isnot [string] -or
        $spec.version -notmatch '^(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){3}$') {
        throw 'COZY_RELEASE_METADATA_VERSION_INVALID'
    }
    foreach ($part in $spec.version.Split('.')) {
        if ([int]$part -gt 65535) { throw 'COZY_RELEASE_METADATA_VERSION_INVALID' }
    }
    foreach ($value in @($spec.companyName, $spec.productName,
                         $spec.descriptions.A, $spec.descriptions.B, $spec.descriptions.O)) {
        # brcc32 input remains ASCII; quotes, escapes and control data are forbidden.
        if ($value -isnot [string] -or $value -cnotmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$') {
            throw 'COZY_RELEASE_METADATA_TEXT_INVALID'
        }
    }
    $projects = [ordered]@{ A = 'Cozy.Launcher'; B = 'Cozy.Client'; O = 'Cozy.Overlay' }
    $writes = New-Object 'System.Collections.Generic.List[object]'
    foreach ($key in $projects.Keys) {
        if ($Role -ne 'All' -and $Role -ne $key) { continue }
        $name = $projects[$key]
        $directory = Join-Path (Join-Path $root 'Cozy.Projects') $name
        $resourcePath = Join-Path $directory ($name + '.rc')
        $manifestPath = Join-Path $directory ($name + '.manifest')
        $resource = Read-MetadataText $resourcePath
        if ($resource -cmatch '[^\x00-\x7f]') { throw 'COZY_RELEASE_METADATA_RC_ASCII_REQUIRED' }
        foreach ($kind in @('FILEVERSION', 'PRODUCTVERSION')) {
            $resource = Replace-One $resource ('(?m)^ *' + $kind + ' +[0-9]+,[0-9]+,[0-9]+,[0-9]+ *\r?$') `
                (' ' + $kind + ' ' + $spec.version.Replace('.', ','))
        }
        $values = [ordered]@{
            CompanyName = $spec.companyName; FileDescription = $spec.descriptions.$key;
            FileVersion = $spec.version; ProductName = $spec.productName; ProductVersion = $spec.version
        }
        foreach ($field in $values.Keys) {
            $resource = Replace-One $resource ('(?m)^ *VALUE "' + $field + '", "[^"\r\n]*" *\r?$') `
                ('      VALUE "' + $field + '", "' + $values[$field] + '\0"')
        }
        $manifest = Read-MetadataText $manifestPath
        # Only update the unique identity version and description. Keep asInvoker,
        # supported OS, and O PerMonitorV2/PerMonitor settings byte-for-byte.
        $manifest = Replace-One $manifest '(?<=<assemblyIdentity version=")[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?=")' $spec.version
        $manifest = Replace-One $manifest '<description>[^<]*</description>' `
            ('<description>' + $spec.descriptions.$key + '</description>')
        $writes.Add(@{Path = $resourcePath; Text = $resource})
        $writes.Add(@{Path = $manifestPath; Text = $manifest})
    }
    # Included inside Cozy.Api's existing const section; not a separate unit.
    $include = "{ Generated from Cozy.ReleaseMetadata.json. Do not edit independently. }`r`n" +
        "  AppVersion = '" + $spec.version + "';`r`n"
    $writes.Add(@{Path = (Join-Path $configuration 'Cozy.Version.inc'); Text = $include})
    # Validate all templates before publishing any update; a failed preparation
    # aborts the build before resource/native compilation.
    foreach ($write in $writes) { Write-MetadataText $write.Path $write.Text }
    Write-Output ('COZY_RELEASE_METADATA_OK role=' + $Role + ' version=' + $spec.version)
} catch {
    [Console]::Error.WriteLine('Release metadata preparation failed: ' + $_.Exception.Message)
    exit 1
} finally {
    foreach ($temporary in $pending) {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}
