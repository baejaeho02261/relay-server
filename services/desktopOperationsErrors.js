'use strict';
// Public administrator guidance only. Never reflect tokens, PEMs or arbitrary errors.
const rows={
 AUTH_FAILED:['로그인 정보를 확인하세요.','선택한 권한과 비밀번호로 인증하지 못했습니다.','권한과 비밀번호를 확인한 뒤 다시 로그인하세요.','login'],
 ROLE_NOT_CONFIGURED:['선택한 로그인 권한이 설정되지 않았습니다.','해당 권한의 서버 로그인 설정을 사용할 수 없습니다.','사용할 권한의 서버 비밀번호 설정을 확인하세요.','login'],
 AUTH_RATE_LIMITED:['로그인 시도 횟수를 초과했습니다.','반복된 인증 실패로 로그인이 일시 제한되었습니다.','잠시 기다린 뒤 권한과 비밀번호를 확인하고 다시 로그인하세요.','login'],
 ORIGIN_NOT_ALLOWED:['접속 주소를 확인하지 못했습니다. (ORIGIN_NOT_ALLOWED)','브라우저 주소와 서버의 관리자 웹 주소가 일치하지 않습니다.','정식 관리자 웹 주소로 접속하고 서버의 WEB_ADMIN_PUBLIC_ORIGIN 또는 프록시 설정을 확인하세요.','login'],
 SECURITY_RELEASE_SIGNATURE:['배포 승인 서명을 확인하지 못했습니다.','공개키 등록·A/B/O 구분·버전·파일 내용 중 하나가 일치하지 않습니다.','신뢰 서명자 목록과 선택한 실행 파일·플러그인/승인 JSON을 확인하세요.','security'],
 OVERLAY_PLUGIN_APPROVAL_REQUIRED:['오버레이 승인 JSON을 선택하세요.','현재 서버 정책은 플러그인 배포 승인 서명을 요구합니다.','선택한 GameOverlayPlugin.bin과 동일한 버전을 O 구분으로 서명한 승인 JSON을 함께 선택하세요.','security'],
 OVERLAY_PLUGIN_APPROVAL_INVALID:['오버레이 승인 JSON 형식을 확인하세요.','키 식별자·서명 또는 선언된 승인 정보의 형식이 올바르지 않습니다.','기존 배포 서명 도구가 생성한 O 승인 JSON 원본을 선택하세요. 내용을 직접 수정하지 마세요.','security'],
 OVERLAY_PLUGIN_SIGNER_UNTRUSTED:['오버레이 서명 공개키가 등록되어 있지 않습니다.','승인 JSON의 keyId와 일치하는 공개키를 현재 서버에서 찾지 못했습니다.','기존 신뢰 서명자의 키로 다시 서명하거나, 사용할 공개키를 관리자 신뢰 서명자 목록에 등록하세요. 비밀키는 업로드하지 마세요.','security'],
 OVERLAY_PLUGIN_SIGNATURE_INVALID:['오버레이 승인 서명이 일치하지 않습니다.','등록된 키로 O 구분·입력 버전·업로드 파일의 서명을 검증하지 못했습니다.','최종 빌드한 GameOverlayPlugin.bin을 입력 버전과 O 구분으로 다시 서명하고 해당 승인 JSON을 선택하세요.','security'],
 OVERLAY_PLUGIN_APPROVAL_COMPONENT_MISMATCH:['오버레이용 O 승인 JSON을 선택하세요.','선택한 승인 JSON의 구분이 O가 아닙니다.','A/B 승인 JSON 대신 GameOverlayPlugin.bin을 O 구분으로 서명한 승인 JSON을 선택하세요.','security'],
 OVERLAY_PLUGIN_APPROVAL_VERSION_MISMATCH:['오버레이 버전과 승인 버전이 다릅니다.','입력한 후보 버전이 승인 JSON에 기록된 버전과 일치하지 않습니다.','승인 JSON과 같은 버전을 입력하거나 원하는 버전으로 파일을 다시 서명하세요.','security'],
 OVERLAY_PLUGIN_APPROVAL_HASH_MISMATCH:['오버레이 파일과 승인 JSON이 다릅니다.','업로드한 파일의 SHA-256이 승인 JSON의 파일 해시와 일치하지 않습니다.','승인 JSON과 짝인 최종 GameOverlayPlugin.bin을 선택하세요. 재빌드했다면 다시 서명하세요.','security'],
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
 SECURITY_TEST_EVIDENCE_REQUIRED:['선택 A/B의 시험 기록이 없습니다.','현재 정책은 해당 조합의 실제 시험 결과를 요구합니다.','실행한 시험 로그로 해당 조합의 기록을 등록하세요.','security'],
 BOOTSTRAP_NOT_READY:['운영 A/B 조합이 없습니다.','후보 등록만으로 운영 게시되지는 않습니다.','새 버전 배포에서 A/B를 검증한 뒤 게시하세요.','deploy'],
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
 const pluginMessage=require('./desktopOverlayPlugin').messages[code];
 const r=rows[code]||(pluginMessage?[pluginMessage,'플러그인 작업을 완료하거나 표시를 승인하지 않았습니다.','오버레이 설정에서 현재 파일·서명·운영 게시 상태를 확인하고 다시 시도하세요.','refresh']:null);return {code,title:r?.[0]||'요청을 완료하지 못했습니다.',current:r?.[1]||'해당 작업의 완료를 확인하지 못했습니다.',next:r?.[2]||'서버 상태를 새로고침하고 상세 오류 코드를 확인하세요.',action:r?.[3]||'refresh'};
}
module.exports={Explain};
