# Windows PowerShell 5.1. Operator-only one-shot runner; never writes a log.
[CmdletBinding()]
param([string]$LauncherPath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$stages = @{
    31000 = '실행 인수 검사'
    31001 = 'API 포인터 저장소 봉인'
    31004 = 'Windows API 자료형 크기 검사'
    31005 = 'API 포인터 봉인 상태 검사'
    31006 = 'A의 API 목록 검사'
    31007 = '프로그램·공개키 리소스 검사'
    31008 = '해시 알고리즘 자체 검사'
    31009 = '서버 정책 연결 슬롯 검사'
    31010 = '자기 실행 파일 경로 확인'
    31011 = '실행 폴더·상위 폴더 고정'
    31012 = '자기 파일 열기·일반 파일 검사'
    31013 = '최종 발급 A 서명 검증'
    31014 = '발급 설정·공개 서버 프로필 해석'
    31015 = '발급 유효기간 검사'
    31016 = '최종 A 파일 해시 계산'
    31017 = '실행 코드 무결성 기준 생성'
    31018 = '실행 파일 무결성 기준 생성'
    31019 = 'B 파일 이름 준비'
    31020 = '앱 기기 키 생성'
    31021 = '서버 통신 객체 생성'
    31022 = '최초 서버 실행 흐름 준비'
    31023 = '서버 요청 전 코드 무결성 측정'
    31024 = '서버 기기 정책 요청·응답 검사'
    31025 = 'Windows 영속 기기 키 준비'
    31026 = '서버 기기 확인 요청·응답 검사'
    31027 = '기기 서명 증명 생성·전송·응답 검사'
    31028 = '최초 기기 승인 대기·상태 조회'
    31029 = '승인된 일회용 A 실행 시작 요청'
    31030 = '첫 무결성 보고'
    31031 = 'B 다운로드·파일 검증'
    31032 = 'A 파일 최종 재검사'
    31033 = '최종 모듈·무결성 보고'
    31034 = '서버 인계 승인 요청'
    31035 = 'B 프로세스 인계'
    31099 = '실행 흐름에서 처리되지 않은 오류 또는 정리 오류'
}
$process = $null
try {
    if ([string]::IsNullOrWhiteSpace($LauncherPath)) {
        $LauncherPath = Read-Host '웹에서 최종 발급받은 A.exe의 전체 경로'
        $LauncherPath = $LauncherPath.Trim().Trim('"')
    }
    if (-not [IO.Path]::IsPathRooted($LauncherPath)) { throw 'PATH_REQUIRED' }
    $item = Get-Item -LiteralPath $LauncherPath -Force
    if ($item.PSIsContainer -or $item.Extension -ine '.exe') { throw 'EXE_REQUIRED' }
    Write-Host '선택한 A를 실제로 한 번 실행합니다. 서버 실행 승인이 성공하면 일회용 발급이 사용 처리됩니다.'
    Write-Host '최대 6분 동안 종료를 기다립니다. 최초 기기 승인 요청이 있으면 관리자 웹에서 확인하세요.'
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $item.FullName
    $start.WorkingDirectory = $item.DirectoryName
    $start.UseShellExecute = $false
    $start.Arguments = ''
    $start.RedirectStandardOutput = $false
    $start.RedirectStandardError = $false
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $process = [Diagnostics.Process]::Start($start)
    if (-not $process.WaitForExit(360000)) {
        Write-Host '상태: 아직 실행 중입니다. 종료 코드는 없습니다. 이 도구는 A를 재실행하거나 강제 종료하지 않습니다.'
        exit 2
    }
    $code = $process.ExitCode
    Write-Host ('실행 시간: {0:N1}초' -f $clock.Elapsed.TotalSeconds)
    Write-Host ('종료 코드: {0}' -f $code)
    if ($code -eq 0) {
        Write-Host '결과: A가 B 인계 완료를 반환했습니다. B의 라이선스 승인 완료를 의미하지는 않습니다.'
    } elseif ($stages.ContainsKey($code)) {
        Write-Host ('실패 단계: {0}' -f $stages[$code])
    } elseif ($code -eq 1) {
        Write-Host '결과: 세부 단계 코드가 없습니다. 이전 A이거나 단계 설정 전 초기화 실패일 수 있습니다.'
    } else {
        $unsigned = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$code), 0)
        Write-Host ('결과: 분류되지 않은 Windows/RTL 종료 코드 0x{0:X8}' -f $unsigned)
    }
    Write-Host '위 실행 시간·종료 코드·실패 단계만 전달하세요. 키나 발급 설정은 출력하지 않습니다.'
} catch {
    Write-Host '진단 도구가 A를 실행하거나 종료 상태를 읽지 못했습니다. EXE 경로와 실행 권한을 확인하세요.'
    exit 3
} finally {
    if ($null -ne $process) { $process.Dispose() }
}
