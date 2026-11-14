@echo off
setlocal DisableDelayedExpansion
set "COZY_TRUST_CHECK_SELF=%~f0"
set "COZY_TRUST_CHECK_BASE=%~dp0"
set "COZY_TRUST_CHECK_INPUT=%~1"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$s=[IO.File]::ReadAllText($env:COZY_TRUST_CHECK_SELF,[Text.Encoding]::UTF8);$m='#==COZY_PUBLIC_TRUST_CHECK==';$i=$s.LastIndexOf($m,[StringComparison]::Ordinal);if($i -lt 0){exit 2};& ([ScriptBlock]::Create($s.Substring($i+$m.Length)))"
set "COZY_TRUST_CHECK_EXIT=%ERRORLEVEL%"
echo.
pause
exit /b %COZY_TRUST_CHECK_EXIT%
#==COZY_PUBLIC_TRUST_CHECK==
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Find-InspectionTool {
    $cursor = [IO.Path]::GetFullPath($env:COZY_TRUST_CHECK_BASE)
    while ($cursor) {
        foreach ($candidate in @(
            (Join-Path $cursor 'cozy-peace\Relay Server\tools\security\peace.inspect-issued-a-trust.js'),
            (Join-Path $cursor 'Relay Server\tools\security\peace.inspect-issued-a-trust.js'),
            (Join-Path $cursor 'tools\security\peace.inspect-issued-a-trust.js'))) {
            if ([IO.File]::Exists($candidate)) { return $candidate }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    throw '풀 소스를 찾지 못했습니다. 이 BAT을 풀 소스의 tools 폴더에 넣으세요.'
}
try {
    $tool = Find-InspectionTool
    $node = Get-Command node.exe -CommandType Application -ErrorAction Stop
    $launcher = $env:COZY_TRUST_CHECK_INPUT
    if ([string]::IsNullOrWhiteSpace($launcher)) {
        $launcher = Read-Host '확인할 A EXE의 전체 경로'
    }
    $launcher = $launcher.Trim()
    if ($launcher.Length -ge 2 -and $launcher[0] -eq '"' -and $launcher[$launcher.Length - 1] -eq '"') {
        $launcher = $launcher.Substring(1, $launcher.Length - 2)
    }
    if (-not [IO.Path]::IsPathRooted($launcher)) { throw 'A EXE의 전체 경로를 입력하세요.' }
    $expectedKeyId = (Read-Host '관리자 웹에서 ACTIVE인 공개 키 ID (64자리)').Trim()
    if ($expectedKeyId -cnotmatch '^[a-f0-9]{64}$') { throw '공개 키 ID는 소문자 16진수 64자리입니다. 개인키를 입력하지 마세요.' }
    $output = & $node.Source $tool '--launcher' $launcher '--expected-key-id' $expectedKeyId
    $resultCode = $LASTEXITCODE
    $result = ($output -join "`n") | ConvertFrom-Json
    if ($result.PSObject.Properties.Name -contains 'keyId') {
        Write-Host ('A 내장 공개 키: ' + $result.keyId)
        Write-Host ('대조한 공개 키: ' + $result.expectedKeyId)
        Write-Host ('A 파일 SHA-512: ' + $result.sha512)
    }
    if ($resultCode -eq 0 -and $result.ok -and $result.matchesExpected -eq $true) {
        Write-Host '일치: 이 A는 입력한 공개 키를 내장하고 있습니다.' -ForegroundColor Green
        Write-Host '서버 ACTIVE 상태·게시 승인·Windows 실행 여부는 별도로 확인하세요.'
        exit 0
    }
    if ($result.PSObject.Properties.Name -contains 'error') {
        Write-Host ('검사 실패: ' + $result.error) -ForegroundColor Red
    }
    Write-Host '불일치하면 공개 검증키를 적용한 뒤 A를 다시 빌드하고 새 후보를 선택하세요.'
    exit 1
} catch {
    Write-Host ('검사 실패: ' + $_.Exception.Message) -ForegroundColor Red
    Write-Host '이 검사는 A 파일 실행·변경, 서버 접속, 키 생성을 하지 않습니다.'
    exit 1
}

