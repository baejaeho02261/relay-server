@echo off
setlocal DisableDelayedExpansion
set "COZY_FINISH_SELF=%~f0"
set "COZY_FINISH_BASE=%~dp0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$s=[IO.File]::ReadAllText($env:COZY_FINISH_SELF,[Text.Encoding]::UTF8);$m='#==COZY_FINISH_PUBLIC_TRUST==';$i=$s.LastIndexOf($m,[StringComparison]::Ordinal);if($i -lt 0){exit 2};& ([ScriptBlock]::Create($s.Substring($i+$m.Length)))"
set "COZY_FINISH_EXIT=%ERRORLEVEL%"
echo.
pause
exit /b %COZY_FINISH_EXIT%
#==COZY_FINISH_PUBLIC_TRUST==
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-OwnedFile([string]$Path, [bool]$Required = $true) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw '연결된 파일·폴더 경로는 사용할 수 없습니다.' }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    if ($Required -and -not [IO.File]::Exists($Path)) { throw ('필요한 파일이 없습니다: ' + $Path) }
}


function Get-PublicPreparerHash([byte[]]$Bytes) {
    $text = [Text.Encoding]::UTF8.GetString($Bytes)
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xfeff) { $text = $text.Substring(1) }
    $normalized = [Text.Encoding]::UTF8.GetBytes($text.Replace("`r`n","`n"))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($normalized)).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Install-PublicPreparer([string]$PreparePath, [string]$BackupDirectory) {
    $currentHash = Get-PublicPreparerHash ([IO.File]::ReadAllBytes($PreparePath))
    if ($currentHash -ceq '7897c32c4e6f547363ab79e6bb2e2bddcbddf743918c80e7cf4bf268d493bb57') { return }
    if (@('189a95ea7ca888b54b12e827289f9a6bf88208c5083ebfd1684c270010818ce7', '5cc2c67ed54a4e3d431a8abc96cfad15d48294fbf4d56de8509cf7bef8ca6765') -cnotcontains $currentHash) { throw '공개 리소스 준비 스크립트가 알려진 버전과 다릅니다. 기존 파일을 덮어쓰지 않았습니다.' }
    $replacement = [Convert]::FromBase64String('77u/IyBXaW5kb3dzIFBvd2VyU2hlbGwgNS4xLiBQdWJsaWMgdmVyaWZpY2F0aW9uIGRhdGEgb25seTsgbm8gcHJpdmF0ZSBrZXkgaW5wdXQuDQojIFRoZSBMYXVuY2hlciBEUFJPSiBydW5zIHRoaXMgYmVmb3JlIGl0cyBleGlzdGluZyBicmNjMzIgcmVzb3VyY2UgY29tcGlsYXRpb24uDQpbQ21kbGV0QmluZGluZygpXQ0KcGFyYW0oW3N0cmluZ10kU291cmNlUm9vdCkNCiRFcnJvckFjdGlvblByZWZlcmVuY2UgPSAnU3RvcCcNClNldC1TdHJpY3RNb2RlIC1WZXJzaW9uIExhdGVzdA0KJHBlbmRpbmcgPSAkbnVsbA0KJHJlcGxhY2VtZW50QmFja3VwID0gJG51bGwNCnRyeSB7DQogICAgaWYgKFtzdHJpbmddOjpJc051bGxPcldoaXRlU3BhY2UoJFNvdXJjZVJvb3QpKSB7DQogICAgICAgICRzY3JpcHREaXJlY3RvcnkgPSBbc3RyaW5nXSRQU1NjcmlwdFJvb3QNCiAgICAgICAgaWYgKFtzdHJpbmddOjpJc051bGxPcldoaXRlU3BhY2UoJHNjcmlwdERpcmVjdG9yeSkpIHsNCiAgICAgICAgICAgICRzY3JpcHRQYXRoID0gW3N0cmluZ10kUFNDb21tYW5kUGF0aA0KICAgICAgICAgICAgaWYgKFtzdHJpbmddOjpJc051bGxPcldoaXRlU3BhY2UoJHNjcmlwdFBhdGgpKSB7DQogICAgICAgICAgICAgICAgJHBhdGhQcm9wZXJ0eSA9ICRNeUludm9jYXRpb24uTXlDb21tYW5kLlBTT2JqZWN0LlByb3BlcnRpZXNbJ1BhdGgnXQ0KICAgICAgICAgICAgICAgIGlmICgkbnVsbCAtbmUgJHBhdGhQcm9wZXJ0eSkgeyAkc2NyaXB0UGF0aCA9IFtzdHJpbmddJHBhdGhQcm9wZXJ0eS5WYWx1ZSB9DQogICAgICAgICAgICB9DQogICAgICAgICAgICBpZiAoW3N0cmluZ106OklzTnVsbE9yV2hpdGVTcGFjZSgkc2NyaXB0UGF0aCkpIHsgdGhyb3cgJ0lTU1VFRF9BX1NPVVJDRV9ST09UX1JFUVVJUkVEJyB9DQogICAgICAgICAgICAkc2NyaXB0RGlyZWN0b3J5ID0gW0lPLlBhdGhdOjpHZXREaXJlY3RvcnlOYW1lKCRzY3JpcHRQYXRoKQ0KICAgICAgICB9DQogICAgICAgIGlmIChbc3RyaW5nXTo6SXNOdWxsT3JXaGl0ZVNwYWNlKCRzY3JpcHREaXJlY3RvcnkpKSB7IHRocm93ICdJU1NVRURfQV9TT1VSQ0VfUk9PVF9SRVFVSVJFRCcgfQ0KICAgICAgICAkU291cmNlUm9vdCA9IFtJTy5QYXRoXTo6Q29tYmluZSgkc2NyaXB0RGlyZWN0b3J5LCAnLi4nKQ0KICAgIH0NCiAgICAkbmF0aXZlUm9vdCA9IFtJTy5QYXRoXTo6R2V0RnVsbFBhdGgoJFNvdXJjZVJvb3QpDQogICAgJGNvbmZpZ3VyYXRpb24gPSBKb2luLVBhdGggJG5hdGl2ZVJvb3QgJ0NvenkuU291cmNlXENvenkuQ29uZmlndXJhdGlvbicNCiAgICAkaW5jbHVkZVBhdGggPSBKb2luLVBhdGggJGNvbmZpZ3VyYXRpb24gJ0NvenkuSXNzdWVkQS5UcnVzdC5pbmMnDQogICAgJG91dHB1dFBhdGggPSBKb2luLVBhdGggJGNvbmZpZ3VyYXRpb24gJ0NvenkuSXNzdWVkQS5UcnVzdC5iaW4nDQogICAgJHNvdXJjZUluZm8gPSBHZXQtSXRlbSAtTGl0ZXJhbFBhdGggJGluY2x1ZGVQYXRoIC1Gb3JjZQ0KICAgIGlmICgkc291cmNlSW5mby5QU0lzQ29udGFpbmVyIC1vciAkc291cmNlSW5mby5MZW5ndGggLWd0IDE2Mzg0IC1vcg0KICAgICAgICAoJHNvdXJjZUluZm8uQXR0cmlidXRlcyAtYmFuZCBbSU8uRmlsZUF0dHJpYnV0ZXNdOjpSZXBhcnNlUG9pbnQpKSB7DQogICAgICAgIHRocm93ICdJU1NVRURfQV9QVUJMSUNfSU5DTFVERV9JTlZBTElEJw0KICAgIH0NCiAgICAjIFBhcnNlIGRhdGE7IG5ldmVyIGV2YWx1YXRlIHRoZSBQYXNjYWwgc291cmNlIG9yIGFueSB0ZXh0IGl0IGNvbnRhaW5zLg0KICAgICRzb3VyY2UgPSBbSU8uRmlsZV06OlJlYWRBbGxUZXh0KCRpbmNsdWRlUGF0aCkNCiAgICAjIFRoZSBzb3VyY2UgcGFja2FnZSBkZWxpYmVyYXRlbHkgY29udGFpbnMgbm8gZGVmYXVsdCBvcGVyYXRpb25hbCBpc3N1ZXIuDQogICAgIyBSZWZ1c2Ugc2V0dXAgcGxhY2Vob2xkZXJzIGJlZm9yZSBleGFtaW5pbmcgYW55IG9sZGVyIGdlbmVyYXRlZCBiaW5hcnkuDQogICAgaWYgKCRzb3VyY2UuQ29udGFpbnMoJ0NPWllfSVNTVUVEX0FfUFVCTElDX0tFWV9TRVRVUF9SRVFVSVJFRCcpKSB7DQogICAgICAgIHRocm93ICdDT1pZX0lTU1VFRF9BX1BVQkxJQ19LRVlfU0VUVVBfUkVRVUlSRUQnDQogICAgfQ0KICAgICRzb3VyY2UgPSBbcmVnZXhdOjpSZXBsYWNlKCRzb3VyY2UsICdce1tefV0qXH0nLCAnJykNCiAgICAkbWF0Y2ggPSBbcmVnZXhdOjpNYXRjaCgkc291cmNlLCAnKD9pcylcQVxzKmNvbnN0XHMrQ296eUlzc3VlZEFUcnVzdEFuY2hvclxzKjpccyphcnJheVxzKlxbMFwuXC4zMzBcXVxzK29mXHMrQnl0ZVxzKj1ccypcKCg/PGJ5dGVzPlteKV0qKVwpXHMqO1xzKlx6JykNCiAgICBpZiAoLW5vdCAkbWF0Y2guU3VjY2VzcykgeyB0aHJvdyAnSVNTVUVEX0FfUFVCTElDX0lOQ0xVREVfSU5WQUxJRCcgfQ0KICAgICRwYXJ0cyA9ICRtYXRjaC5Hcm91cHNbJ2J5dGVzJ10uVmFsdWUuU3BsaXQoJywnKQ0KICAgIGlmICgkcGFydHMuTGVuZ3RoIC1uZSAzMzEpIHsgdGhyb3cgJ0lTU1VFRF9BX1BVQkxJQ19BTkNIT1JfU0laRV9JTlZBTElEJyB9DQogICAgW2J5dGVbXV0kYW5jaG9yID0gTmV3LU9iamVjdCBieXRlW10gMzMxDQogICAgZm9yICgkaSA9IDA7ICRpIC1sdCAkcGFydHMuTGVuZ3RoOyAkaSsrKSB7DQogICAgICAgICRwYXJ0ID0gJHBhcnRzWyRpXS5UcmltKCkNCiAgICAgICAgaWYgKCRwYXJ0IC1ub3RtYXRjaCAnXlwkWzAtOWEtZkEtRl17Mn0kJykgeyB0aHJvdyAnSVNTVUVEX0FfUFVCTElDX0lOQ0xVREVfSU5WQUxJRCcgfQ0KICAgICAgICAkYW5jaG9yWyRpXSA9IFtDb252ZXJ0XTo6VG9CeXRlKCRwYXJ0LlN1YnN0cmluZygxKSwgMTYpDQogICAgfQ0KICAgIGlmIChbVGV4dC5FbmNvZGluZ106OkFTQ0lJLkdldFN0cmluZygkYW5jaG9yLCAwLCAxNikgLWNuZSAnQ09aWUFJU1NVRVJLRVkxIScpIHsNCiAgICAgICAgdGhyb3cgJ0lTU1VFRF9BX1BVQkxJQ19BTkNIT1JfSU5WQUxJRCcNCiAgICB9DQogICAgW3VpbnQzMltdXSRoZWFkZXIgPSBAKDB4MzE0MTUzNTIsIDIwNDgsIDMsIDI1NiwgMCwgMCkNCiAgICBmb3IgKCRpID0gMDsgJGkgLWx0ICRoZWFkZXIuTGVuZ3RoOyAkaSsrKSB7DQogICAgICAgIGlmIChbQml0Q29udmVydGVyXTo6VG9VSW50MzIoJGFuY2hvciwgNDggKyA0ICogJGkpIC1uZSAkaGVhZGVyWyRpXSkgew0KICAgICAgICAgICAgdGhyb3cgJ0lTU1VFRF9BX1BVQkxJQ19SU0FfSU5WQUxJRCcNCiAgICAgICAgfQ0KICAgIH0NCiAgICBpZiAoJGFuY2hvcls3Ml0gLW5lIDEgLW9yICRhbmNob3JbNzNdIC1uZSAwIC1vciAkYW5jaG9yWzc0XSAtbmUgMSAtb3INCiAgICAgICAgKCRhbmNob3JbNzVdIC1iYW5kIDEyOCkgLWVxIDAgLW9yICgkYW5jaG9yWzMzMF0gLWJhbmQgMSkgLW5lIDEpIHsNCiAgICAgICAgdGhyb3cgJ0lTU1VFRF9BX1BVQkxJQ19SU0FfSU5WQUxJRCcNCiAgICB9DQogICAgJHNoYTI1NiA9IFtTZWN1cml0eS5DcnlwdG9ncmFwaHkuU0hBMjU2XTo6Q3JlYXRlKCkNCiAgICB0cnkgeyAka2V5SWQgPSAkc2hhMjU2LkNvbXB1dGVIYXNoKCRhbmNob3IsIDQ4LCAyODMpIH0NCiAgICBmaW5hbGx5IHsgJHNoYTI1Ni5EaXNwb3NlKCkgfQ0KICAgIGZvciAoJGkgPSAwOyAkaSAtbHQgMzI7ICRpKyspIHsNCiAgICAgICAgaWYgKCRhbmNob3JbMTYgKyAkaV0gLW5lICRrZXlJZFskaV0pIHsgdGhyb3cgJ0lTU1VFRF9BX1BVQkxJQ19LRVlfSURfSU5WQUxJRCcgfQ0KICAgIH0NCiAgICBpZiAoVGVzdC1QYXRoIC1MaXRlcmFsUGF0aCAkb3V0cHV0UGF0aCkgew0KICAgICAgICAkb3V0cHV0SW5mbyA9IEdldC1JdGVtIC1MaXRlcmFsUGF0aCAkb3V0cHV0UGF0aCAtRm9yY2UNCiAgICAgICAgaWYgKCRvdXRwdXRJbmZvLlBTSXNDb250YWluZXIgLW9yICgkb3V0cHV0SW5mby5BdHRyaWJ1dGVzIC1iYW5kIFtJTy5GaWxlQXR0cmlidXRlc106OlJlcGFyc2VQb2ludCkpIHsNCiAgICAgICAgICAgIHRocm93ICdJU1NVRURfQV9QVUJMSUNfT1VUUFVUX0lOVkFMSUQnDQogICAgICAgIH0NCiAgICAgICAgaWYgKCRvdXRwdXRJbmZvLkxlbmd0aCAtZXEgMzMxKSB7DQogICAgICAgICAgICAkY3VycmVudCA9IFtJTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCRvdXRwdXRQYXRoKQ0KICAgICAgICAgICAgaWYgKFtDb252ZXJ0XTo6VG9CYXNlNjRTdHJpbmcoJGN1cnJlbnQpIC1jZXEgW0NvbnZlcnRdOjpUb0Jhc2U2NFN0cmluZygkYW5jaG9yKSkgeyBleGl0IDAgfQ0KICAgICAgICB9DQogICAgfQ0KICAgICRwZW5kaW5nID0gSm9pbi1QYXRoICRjb25maWd1cmF0aW9uIChbSU8uUGF0aF06OkdldFJhbmRvbUZpbGVOYW1lKCkpDQogICAgJHN0cmVhbSA9IFtJTy5GaWxlXTo6T3BlbigkcGVuZGluZywgW0lPLkZpbGVNb2RlXTo6Q3JlYXRlTmV3LCBbSU8uRmlsZUFjY2Vzc106OldyaXRlLCBbSU8uRmlsZVNoYXJlXTo6Tm9uZSkNCiAgICB0cnkgeyAkc3RyZWFtLldyaXRlKCRhbmNob3IsIDAsICRhbmNob3IuTGVuZ3RoKTsgJHN0cmVhbS5GbHVzaCgkdHJ1ZSkgfQ0KICAgIGZpbmFsbHkgeyAkc3RyZWFtLkRpc3Bvc2UoKSB9DQogICAgaWYgKFtJTy5GaWxlXTo6RXhpc3RzKCRvdXRwdXRQYXRoKSkgew0KICAgICAgICAjIEEgcmVhbCBzYW1lLWRpcmVjdG9yeSBiYWNrdXAgcGF0aCBhdm9pZHMgUG93ZXJTaGVsbCBjb252ZXJ0aW5nIGEgbnVsbA0KICAgICAgICAjIHN0cmluZyBhcmd1bWVudCB0byBhbiBlbXB0eSBwYXRoLiBLZWVwIEZpbGUuUmVwbGFjZSBhdG9taWMuDQogICAgICAgICRyZXBsYWNlbWVudEJhY2t1cCA9IEpvaW4tUGF0aCAkY29uZmlndXJhdGlvbiAoJ0NvenkuSXNzdWVkQS5UcnVzdC4nICsgW2d1aWRdOjpOZXdHdWlkKCkuVG9TdHJpbmcoJ04nKSArICcuYmFja3VwJykNCiAgICAgICAgaWYgKFRlc3QtUGF0aCAtTGl0ZXJhbFBhdGggJHJlcGxhY2VtZW50QmFja3VwKSB7IHRocm93ICdJU1NVRURfQV9QVUJMSUNfQkFDS1VQX0VYSVNUUycgfQ0KICAgICAgICBbSU8uRmlsZV06OlJlcGxhY2UoJHBlbmRpbmcsICRvdXRwdXRQYXRoLCAkcmVwbGFjZW1lbnRCYWNrdXApDQogICAgICAgICRwZW5kaW5nID0gJG51bGwNCiAgICAgICAgW0lPLkZpbGVdOjpEZWxldGUoJHJlcGxhY2VtZW50QmFja3VwKQ0KICAgICAgICAkcmVwbGFjZW1lbnRCYWNrdXAgPSAkbnVsbA0KICAgIH0gZWxzZSB7DQogICAgICAgIFtJTy5GaWxlXTo6TW92ZSgkcGVuZGluZywgJG91dHB1dFBhdGgpDQogICAgICAgICRwZW5kaW5nID0gJG51bGwNCiAgICB9DQp9IGNhdGNoIHsNCiAgICBbQ29uc29sZV06OkVycm9yLldyaXRlTGluZSgnSXNzdWVyIHB1YmxpYyByZXNvdXJjZSBwcmVwYXJhdGlvbiBmYWlsZWQ6ICcgKyAkXy5FeGNlcHRpb24uTWVzc2FnZSkNCiAgICBpZiAoJG51bGwgLW5lICRyZXBsYWNlbWVudEJhY2t1cCAtYW5kIFtJTy5GaWxlXTo6RXhpc3RzKCRyZXBsYWNlbWVudEJhY2t1cCkpIHsNCiAgICAgICAgW0NvbnNvbGVdOjpFcnJvci5Xcml0ZUxpbmUoJ1ByZXZpb3VzIHB1YmxpYyByZXNvdXJjZSBiYWNrdXAgcmV0YWluZWQ6ICcgKyAkcmVwbGFjZW1lbnRCYWNrdXApDQogICAgfQ0KICAgIGV4aXQgMQ0KfSBmaW5hbGx5IHsNCiAgICBpZiAoJG51bGwgLW5lICRwZW5kaW5nIC1hbmQgW0lPLkZpbGVdOjpFeGlzdHMoJHBlbmRpbmcpKSB7IFtJTy5GaWxlXTo6RGVsZXRlKCRwZW5kaW5nKSB9DQp9DQo=')
    if ((Get-PublicPreparerHash $replacement) -cne '7897c32c4e6f547363ab79e6bb2e2bddcbddf743918c80e7cf4bf268d493bb57') { throw '내장 공개 리소스 도구 검사에 실패했습니다.' }
    $token = [guid]::NewGuid().ToString('N')
    $outsideBackup = Join-Path $BackupDirectory ('previous-public-preparer-' + $token + '.ps1')
    Copy-Item -LiteralPath $PreparePath -Destination $outsideBackup -ErrorAction Stop
    $directory = [IO.Path]::GetDirectoryName($PreparePath)
    $pendingTool = Join-Path $directory ('Cozy.Prepare-' + $token + '.pending')
    $replacementBackup = Join-Path $directory ('Cozy.Prepare-' + $token + '.backup')
    try {
        $stream = [IO.File]::Open($pendingTool,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $stream.Write($replacement,0,$replacement.Length); $stream.Flush($true) }
        finally { $stream.Dispose() }
        [IO.File]::Replace($pendingTool,$PreparePath,$replacementBackup)
        $pendingTool = $null
        [IO.File]::Delete($replacementBackup)
    } finally {
        if ($pendingTool -and [IO.File]::Exists($pendingTool)) { [IO.File]::Delete($pendingTool) }
    }
    Write-Host '공개 리소스 도구의 경로·파일 교체·공개키 미설정 차단 처리를 갱신했습니다.'
}

function Backup-PublicSourceFiles([string[]]$Paths, [string]$BackupStem) {
    $saved = New-Object 'System.Collections.Generic.List[object]'
    for ($index = 0; $index -lt $Paths.Length; $index++) {
        $source = $Paths[$index]
        Assert-OwnedFile $source $false
        $existed = [IO.File]::Exists($source)
        $backup = $BackupStem + '.' + $index
        if ($existed) { Copy-Item -LiteralPath $source -Destination $backup -ErrorAction Stop }
        $saved.Add([pscustomobject]@{ Path = $source; Backup = $backup; Existed = $existed })
    }
    return $saved.ToArray()
}

function Restore-PublicSourceFiles([object[]]$Saved) {
    $errors = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in $Saved) {
        try {
            Assert-OwnedFile $entry.Path $false
            if ($entry.Existed) {
                Copy-Item -LiteralPath $entry.Backup -Destination $entry.Path -Force -ErrorAction Stop
            } elseif ([IO.File]::Exists($entry.Path)) {
                Remove-Item -LiteralPath $entry.Path -Force -ErrorAction Stop
            }
        } catch { $errors.Add($_.Exception.Message) }
    }
    if ($errors.Count -gt 0) { throw ('공개 소스 복원이 일부 실패했습니다: ' + ($errors -join ' / ')) }
}

function Find-NativeRoot {
    if ([string]::IsNullOrWhiteSpace($env:COZY_FINISH_BASE)) { throw 'BAT 경로를 확인하지 못했습니다.' }
    $cursor = [IO.Path]::GetFullPath($env:COZY_FINISH_BASE)
    while ($cursor) {
        foreach ($candidate in @((Join-Path $cursor 'cozy-peace\Railway'),(Join-Path $cursor 'Railway'),$cursor)) {
            if ([IO.File]::Exists((Join-Path $candidate 'Cozy.Build\Cozy.Prepare-IssuedATrust.ps1')) -and
                [IO.File]::Exists((Join-Path $candidate 'Cozy.Source\Cozy.Configuration\Cozy.IssuedA.Trust.inc'))) { return $candidate }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    throw 'Railway 소스를 찾지 못했습니다. BAT을 풀 소스 최상위 또는 cozy-peace 폴더 안에 넣으세요.'
}

try {
    if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA 경로를 찾을 수 없습니다.' }
    $nativeRoot = Find-NativeRoot
    $prepare = Join-Path $nativeRoot 'Cozy.Build\Cozy.Prepare-IssuedATrust.ps1'
    $launcherProject = Join-Path $nativeRoot 'Cozy.Projects\Cozy.Launcher\Cozy.Launcher.dproj'
    $launcherOutput = Join-Path $nativeRoot 'Cozy.Projects\Cozy.Launcher\Cozy.Launcher.exe'
    $launcherDirectory = [IO.Path]::GetDirectoryName($launcherProject)
    $launcherResourceTool = Join-Path $nativeRoot 'Cozy.Build\Cozy.Prepare-LauncherResource.js'
    $metadataPrepare = Join-Path $nativeRoot 'Cozy.Build\Cozy.Prepare-ReleaseMetadata.ps1'
    $metadataSpec = Join-Path $nativeRoot 'Cozy.Source\Cozy.Configuration\Cozy.ReleaseMetadata.json'
    $versionInclude = Join-Path $nativeRoot 'Cozy.Source\Cozy.Configuration\Cozy.Version.inc'
    $resourceScript = Join-Path $launcherDirectory 'Cozy.Launcher.rc'
    $launcherManifest = Join-Path $launcherDirectory 'Cozy.Launcher.manifest'
    $compiledResource = Join-Path $launcherDirectory 'Cozy.LauncherResources.res'
    $configuration = Join-Path $nativeRoot 'Cozy.Source\Cozy.Configuration'
    $destination = Join-Path $configuration 'Cozy.IssuedA.Trust.inc'
    $resource = Join-Path $configuration 'Cozy.IssuedA.Trust.bin'
    $keyDir = Join-Path $env:LOCALAPPDATA 'Cozy.IssuedKeys\Manual-Recovery-v1'
    $publicInclude = Join-Path $keyDir 'Cozy.IssuedA.Trust.inc'
    Assert-OwnedFile $prepare
    Assert-OwnedFile $launcherProject
    Assert-OwnedFile $launcherResourceTool $false
    if (-not [IO.File]::Exists($launcherResourceTool)) {
        throw 'A 리소스 생성 도구가 없습니다. 최신 전체 소스를 풀고 Cozy.Build\Cozy.Prepare-LauncherResource.js가 있는지 확인하세요.'
    }
    Assert-OwnedFile $metadataPrepare
    Assert-OwnedFile $metadataSpec
    Assert-OwnedFile $versionInclude
    Assert-OwnedFile $resourceScript
    Assert-OwnedFile $launcherManifest
    Assert-OwnedFile $compiledResource $false
    $node = (Get-Command node.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    Assert-OwnedFile $destination
    Assert-OwnedFile $resource $false
    Assert-OwnedFile $publicInclude
    Install-PublicPreparer -PreparePath $prepare -BackupDirectory $keyDir
    $includeText = [IO.File]::ReadAllText($publicInclude)
    $keyMatch = [regex]::Match($includeText, 'Key ID:\s*([a-f0-9]{64})')
    if (-not $keyMatch.Success) { throw '기존 공개 include에서 공개 키 ID를 확인하지 못했습니다.' }
    Write-Host '서버 ACTIVE 등록 이후의 3단계만 다시 진행합니다.' -ForegroundColor Cyan
    Write-Host ('적용할 공개 키 ID: ' + $keyMatch.Groups[1].Value)
    $backupStem = Join-Path $keyDir ('retry-public-backup-' + [guid]::NewGuid().ToString('N'))
    $savedPublicSources = @(Backup-PublicSourceFiles -Paths @(
        $destination, $resource, $compiledResource, $resourceScript, $launcherManifest, $versionInclude
    ) -BackupStem $backupStem)
    try {
        Copy-Item -LiteralPath $publicInclude -Destination $destination -Force -ErrorAction Stop
        & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File $prepare -SourceRoot $nativeRoot
        if ($LASTEXITCODE -ne 0) { throw 'A 공개 리소스 준비가 실패했습니다.' }
        & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File $metadataPrepare -SourceRoot $nativeRoot -Role A
        if ($LASTEXITCODE -ne 0) { throw 'A 버전·매니페스트 준비가 실패했습니다.' }
        $resourceOutput = & $node $launcherResourceTool '--source-root' $nativeRoot
        if ($LASTEXITCODE -ne 0) { throw 'A의 Cozy.LauncherResources.res 생성이 실패했습니다.' }
        $resourceResult = ($resourceOutput -join "`n") | ConvertFrom-Json
        if (-not $resourceResult.ok -or $resourceResult.publicOnly -ne $true -or
            $resourceResult.keyId -cne $keyMatch.Groups[1].Value) {
            throw '생성된 A 리소스의 공개 키 ID가 적용한 키와 다릅니다.'
        }
        Assert-OwnedFile $compiledResource
        if ((Get-Item -LiteralPath $compiledResource -Force).Length -ne $resourceResult.resourceBytes) {
            throw '생성된 A 리소스의 파일 크기 검사가 실패했습니다.'
        }
    } catch {
        $originalError = $_
        try { Restore-PublicSourceFiles -Saved $savedPublicSources }
        catch {
            Write-Host ('복원 오류: ' + $_.Exception.Message) -ForegroundColor Red
            Write-Host ('공개 소스 백업은 이 경로 접두사로 보존했습니다: ' + $backupStem)
        }
        throw $originalError
    }
    Write-Host '완료: A 공개 include·bin·Cozy.LauncherResources.res를 갱신했습니다.' -ForegroundColor Green
    Write-Host ('갱신한 소스 폴더: ' + $nativeRoot)
    Write-Host ('생성한 공개 리소스: ' + $compiledResource)
    Write-Host ('리소스의 공개 키 ID: ' + $resourceResult.keyId)
    Write-Host ('RAD Studio에서 열 프로젝트: ' + $launcherProject)
    Write-Host '위 프로젝트를 Win64 / Release로 Rebuild하세요.'
    Write-Host ('재빌드 후 사용할 A EXE: ' + $launcherOutput)
    Write-Host '기존 EXE는 갱신되지 않습니다. 위 경로에서 재빌드한 새 A로 승인·등록·명세·조합검증을 진행하세요.'
    Write-Host '재빌드 후 tools\Cozy.Check-IssuedA-Trust.bat에 새 A를 끌어 놓고 웹의 ACTIVE 공개 키 ID와 대조하세요.'
    Write-Host '새 발급용 키는 ACTIVE로 유지하세요. 기존 발급만 허용은 신규 발급을 중단하며 되돌릴 수 없습니다.'
    Write-Host '서버 키·ACTIVE 상태·클립보드·라이선스 내역은 이 BAT에서 변경하지 않습니다.'
    exit 0
} catch {
    Write-Host ('실패: ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
