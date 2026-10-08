'use strict';
// Public administrator guidance only. Never reflect tokens, PEMs or arbitrary errors.
const rows={
 OVERLAY_PREPARE_FAILED:['O 실행 준비를 완료하지 못했습니다.','B가 O 준비 단계의 실패를 보고했습니다.','같은 시각의 서버 요청 거절, 라이선스, 배포 조합 기록을 확인하세요.','security'],
 OVERLAY_LAUNCH_FAILED:['O 다운로드 또는 실행 연결을 완료하지 못했습니다.','B가 O 준비 응답 이후의 실패를 보고했습니다.','O PREPARED·READY·CLAIMED 기록과 등록한 A/B/O 버전을 함께 확인하세요.','deploy'],
 HANDOFF_KEY_EXPORT_FAILED:['실행 연결용 세션 키 전달을 준비하지 못했습니다.','B가 메모리 내 키 전달 준비 실패를 보고했습니다.','B의 가져온 키 재전달 정책 수정이 적용됐는지 확인하고 A/B/O를 다시 빌드·게시하세요.','deploy'],
 HANDOFF_PROCESS_CREATE_FAILED:['O 프로세스를 시작하지 못했습니다.','B가 Windows 프로세스 생성 실패를 보고했습니다.','등록한 O 빌드와 해당 PC의 실행 차단·파일 접근 상태를 확인하세요.','deploy'],
 HANDOFF_PIPE_TIMEOUT:['O로 실행 연결 정보를 전달하는 시간이 초과됐습니다.','B가 제한 시간 내 파이프 전송을 마치지 못했다고 보고했습니다.','해당 PC의 O 조기 종료·보안 제품 차단 여부와 A/B/O 버전을 확인하세요.','security'],
 HANDOFF_PIPE_FAILED:['O로 실행 연결 정보를 전달하지 못했습니다.','B가 파이프 전송 실패를 보고했습니다.','해당 PC의 O 조기 종료와 A/B/O 실행 연결 규격을 확인하세요.','deploy'],
 HANDOFF_CHILD_EXITED:['O가 준비 완료를 알리기 전에 종료됐습니다.','B가 생성한 O 프로세스의 조기 종료를 보고했습니다.','같은 시각의 O CLAIMED·무결성 기록과 Windows 오류 기록을 확인하세요.','security'],
 HANDOFF_READY_TIMEOUT:['O의 준비 완료 대기 시간이 초과됐습니다.','B가 제한 시간 내 O 준비 완료 신호를 받지 못했다고 보고했습니다.','O CLAIMED·서버 인증·렌더링 시작 기록과 해당 PC의 처리 지연을 확인하세요.','security'],
 HANDOFF_WAIT_FAILED:['O 준비 완료 상태를 확인하지 못했습니다.','B가 Windows 대기 처리 실패를 보고했습니다.','해당 PC의 Windows 오류 기록과 실행 연결 핸들 상태를 확인하세요.','security'],
 CRC_BASELINE_UNAVAILABLE:['이 빌드의 CRC 기준값을 확인할 수 없습니다.','배포 파일에 유효한 CRC 계층 기준값이 없습니다.','수정된 서버에 다시 빌드·서명한 A/B/O 후보를 등록하고 조합을 검증하세요.','deploy'],
 CRC_COVERAGE_INCOMPLETE:['이 빌드의 필수 CRC 검사 범위가 부족합니다.','일부 검사 함수의 측정 범위가 제공되지 않아 현재 정책을 충족하지 않습니다.','수정된 소스로 A/B/O를 다시 빌드·서명한 뒤 후보 등록, 조합 게시, 새 A 발급 순서로 적용하세요.','deploy'],
 INTEGRITY_CRC_COVERAGE_INCOMPLETE:['필수 CRC 검사 범위가 부족해 실행을 거절했습니다.','해시값이 일치해도 일부 CRC 검사 범위가 없으면 승인되지 않습니다.','모듈·무결성의 계층별 상태를 확인하고 수정한 A/B/O를 다시 빌드·게시하세요.','deploy'],
 INTEGRITY_CRC_ROLE_MISMATCH:['CRC 계층의 측정값이 서버 기준과 다릅니다.','독립 CRC 검사 중 하나 이상이 일치하지 않습니다.','모듈·무결성에서 불일치 계층과 해당 배포 버전을 확인하세요.','security'],
 INTEGRITY_CODE_HASH_MISMATCH:['실행 코드 해시가 서버 기준과 다릅니다.','코드 SHA-512 또는 CRC64 비교가 일치하지 않습니다.','모듈·무결성에서 기준값과 측정값을 확인하고 등록한 원본 빌드와 비교하세요.','security'],
 INTEGRITY_CODE_EXTENDED_HASH_MISMATCH:['코드 확장 해시가 서버 기준과 다릅니다.','코드 XXH3-128 또는 BLAKE3 비교가 일치하지 않습니다.','모듈·무결성의 코드 확장 해시와 배포 버전을 확인하세요.','security'],
 INTEGRITY_FILE_EXTENDED_HASH_MISMATCH:['파일 확장 해시가 서버 기준과 다릅니다.','파일 XXH3-128 또는 BLAKE3 비교가 일치하지 않습니다.','모듈·무결성의 파일 확장 해시와 발급·배포 대상을 확인하세요.','security'],
 SECURITY_RELEASE_SIGNATURE:['배포 승인 서명을 확인하지 못했습니다.','공개키 등록·A/B/O 구분·버전·파일 내용 중 하나가 일치하지 않습니다.','신뢰 서명자 목록과 선택한 EXE/승인 JSON을 확인하세요.','security'],
 SECURITY_SIGNER_NOT_ACTIVE:['서명자가 신규 배포를 허용하지 않습니다.','키가 전환 중이거나 철회된 상태입니다.','서명자 상태를 확인하고 허용된 키로 서명한 파일을 사용하세요.','security'],
 WORKSPACE_LICENSE_REQUIRED:['현재 운영 B가 콘솔 없는 이전 자동 인증 버전입니다.','이전 B는 서버 사전 배정이 필요하며, 새 KEY 입력 방식은 아직 운영 게시되지 않았습니다.','새 버전 배포에서 KEY 입력을 복원한 B를 빌드·서명·게시한 뒤 A를 다시 발급하세요. 기존 A 버전은 유지할 수 있습니다.','deploy'],
 WORKSPACE_LICENSE_RESERVED:['다른 A에 연결된 라이선스입니다.','아직 유효한 다른 발급 A 또는 실행이 이 라이선스를 사용합니다.','중복 배정하지 말고 다른 사용 전 라이선스를 선택하세요.','licenses'],
 WORKSPACE_CONFLICT:['화면을 연 뒤 서버 값이 바뀌었습니다.','이전 미리보기나 메모 revision은 적용되지 않았습니다.','새로고침한 뒤 같은 내용을 확인하고 다시 적용하세요.','refresh'],
 WORKSPACE_PLAN_EXPIRED:['작업 미리보기가 만료되었습니다.','실행은 시작하지 않았습니다.','작업 대상을 다시 미리본 뒤 실행하세요.','refresh'],
 WORKSPACE_STORAGE_REFERENCED:['사용 중인 배포 파일은 정리할 수 없습니다.','운영·발급 A·실행·되돌리기·시험 기록에서 참조합니다.','저장공간 화면의 보존 이유를 확인하세요.','storage'],
 WORKSPACE_SAVE_FAILED:['서버 작업을 저장하지 못했습니다.','완료로 처리하지 않았습니다.','서버 저장공간·쓰기 권한을 확인하고 같은 작업을 다시 조회하세요.','jobs'],
 WORKSPACE_RESTART_REQUIRED:['서버 저장 결과 확인이 필요합니다.','저장 중 장애로 메모리 상태만 신뢰할 수 없습니다.','서버 로그와 디스크를 확인하고 정상 재시작 후 작업 상태를 조회하세요.','jobs'],
 WORKSPACE_JOB_CAPACITY:['작업함 보관 한도에 도달했습니다.','새 작업은 시작하지 않았습니다.','진행 중 작업 완료를 확인하세요. 보관 한도(1,000개)에 도달한 경우 원본 라이선스를 삭제하지 말고 서버 작업 보관 정책을 검토하세요.','jobs'],
 SECURITY_AUDIT_UNAVAILABLE:['서버 감사 기록을 저장하지 못했습니다.','변경 작업은 보류되었습니다.','서버 디스크·감사 폴더 권한을 확인하세요.','security'],
 SECURITY_POLICY_CONFLICT:['정책 revision이 변경되었습니다.','이전 미리보기는 사용할 수 없습니다.','현재 정책을 새로 읽고 다시 미리보세요.','security'],
 SECURITY_OPERATIONS_CONFLICT:['배포 운영 상태가 변경되었습니다.','선택 당시 revision과 현재 서버 값이 다릅니다.','배포 후보와 정책을 새로고침해 다시 검증하세요.','deploy'],
 SECURITY_BUILD_CONTRACT_REQUIRED:['이 빌드의 검사 규격이 없습니다.','현재 정책은 정상 빌드 규격을 요구합니다.','실제 정상 실행에서 확인한 규격을 해당 파일 해시에 등록하세요.','security'],
 SECURITY_TEST_EVIDENCE_REQUIRED:['선택 배포 조합의 시험 기록이 없습니다.','현재 정책은 해당 A/B 또는 A/B/O 조합의 실제 시험 결과를 요구합니다.','실행한 시험 로그로 해당 조합의 기록을 등록하세요.','security'],
 BOOTSTRAP_OVERLAY_NOT_READY:['승인된 O 실행 파일이 없습니다.','현재 실행에 GameOverlay 후보가 연결되지 않았습니다.','O의 배포 승인을 확인하고 A/B/O 조합을 게시한 뒤 새 A를 발급하세요.','deploy'],
 BOOTSTRAP_NOT_READY:['운영 A/B 조합이 없습니다.','후보 등록만으로 운영 게시되지는 않습니다.','새 버전 배포에서 A/B를 검증한 뒤 게시하세요.','deploy'],
 BOOTSTRAP_INPUT_INVALID:['실행 파일 요청의 입력값을 확인해 주세요.','요청의 구성요소·버전·파일명 또는 입력 형식이 올바르지 않습니다.','등록 시 A/B/O 구분, 숫자 버전(예: 1.0.0), EXE 파일명을 확인하세요.','deploy'],
 BOOTSTRAP_UPLOAD_BUSY:['다른 파일을 검증하고 있습니다.','서버가 앞선 업로드를 처리 중입니다.','잠시 후 같은 파일로 다시 시도하세요.','deploy'],
 BOOTSTRAP_LAUNCHER_USED:['이미 실행된 A입니다.','일회용 실행 파일은 다시 사용할 수 없습니다.','새 A를 발급하세요. KEY는 B 콘솔에서 별도로 입력하며, 사용된 KEY는 재사용할 수 없습니다.','licenses'],
 BOOTSTRAP_PE_INVALID:['지원하는 실행 파일이 아닙니다.','Windows 64비트 GUI 실행 파일 검증에 실패했습니다.','현재 프로젝트의 정상 Win64 Release 템플릿을 선택하세요.','deploy'],
 BOOTSTRAP_TEMPLATE_PERSONALIZED:['발급된 A가 아니라 원본 템플릿이 필요합니다.','선택 파일에는 사용자 발급 정보가 붙어 있습니다.','빌드 폴더의 GameLauncher.exe 원본을 선택하세요.','deploy'],
 DESKTOP_KEY_USED:['이미 사용된 라이선스입니다.','사용 이력을 초기화하지 않았습니다.','사용 전 라이선스를 선택하거나 새로 발급하세요.','licenses'],
 DESKTOP_MACHINE_BLOCKED:['이 PC의 재사용이 제한되어 있습니다.','서버의 기존 일회용 PC 정책이 적용되었습니다.','PC 상세에서 기존 이력을 확인한 후 관리자가 판단하세요.','licenses'],
 ADMIN_SESSION_EXPIRED:['관리자 로그인이 만료되었습니다.','작업을 승인하지 않았습니다.','관리자 웹에 다시 로그인하세요.','login'],
 CSRF_FAILED:['현재 로그인 정보로 요청을 확인하지 못했습니다.','작업을 실행하지 않았습니다.','같은 관리자 웹을 새로고침하거나 다시 로그인하세요.','refresh']
};
function Explain(code){
 if(typeof code!=='string'||!/^[-A-Z0-9_]{1,80}$/.test(code))code='REQUEST_FAILED';
 const r=rows[code];return {code,title:r?.[0]||'요청을 완료하지 못했습니다.',current:r?.[1]||'해당 작업의 완료를 확인하지 못했습니다.',next:r?.[2]||'서버 상태를 새로고침하고 상세 오류 코드를 확인하세요.',action:r?.[3]||'refresh'};
}
module.exports={Explain};
