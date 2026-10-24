"""Real Chromium + production administrator JS, mocked API. Not an HTTP/Windows test.
Requires an operator test environment with Playwright and Chromium; no production dependency.
"""
import json, os, pathlib
from playwright.sync_api import sync_playwright
ROOT=pathlib.Path(__file__).resolve().parents[2]
HTML='''<!doctype html><meta charset="utf-8"><style>.hidden,[hidden]{display:none!important}label{display:block}textarea,input{display:block}#modal{position:absolute;inset:0;background:white;overflow:auto}</style><main id="content"></main><div id="modal" class="hidden"><h1 id="modal-title"></h1><div id="modal-body"></div><button id="modal-confirm">확인</button><button id="modal-cancel">취소</button></div>'''
SETUP=r'''
window.calls=[];window.errors=[];window.toasts=[];window.rejectUpload=true;
window.addEventListener('unhandledrejection',e=>errors.push(String(e.reason)));
const content=document.getElementById('content'),modalEl=document.getElementById('modal'),modalBody=document.getElementById('modal-body'),modalTitle=document.getElementById('modal-title'),modalConfirm=document.getElementById('modal-confirm'),modalCancel=document.getElementById('modal-cancel');
let session={csrf:'TEST_ADMIN_SESSION',role:'admin'},currentView='desktop-licenses';
function roleIsAdmin(){return session?.role==='admin';}
function esc(x){return String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function fmtTime(x){return String(x);}
function toast(x){toasts.push(String(x));}
async function renderCurrent(){}
function downloadJson(){}
function setViewLoading(){}
let aid='A'.repeat(24),bid='B'.repeat(24);
window.listing={active:{A:aid,B:bid},candidates:[{id:aid,component:'A',version:'1.0.0',hashVersion:3,sha512:'1'.repeat(128),active:true},{id:bid,component:'B',version:'1.0.0',hashVersion:3,sha512:'2'.repeat(128),active:true}],operations:{revision:1}};
window.mock=async(p,o={})=>{
 if(p==='/api/desktop/bootstrap/security-operations')return structuredClone(listing);
 if(p.startsWith('/api/desktop/bootstrap/artifacts?')){if(rejectUpload){rejectUpload=false;throw Object.assign(Error('서버 승인 서명을 확인하세요.'),{code:'TEST_SIGNATURE_REJECTED'});}return{artifact:{id:'A_candidate'},disposition:'CANDIDATE',activeUnchanged:true};}
 if(p.endsWith('/preview-pair'))return{preview:{eligible:true,aId:aid,bId:bid,operationsRevision:1,policyRevision:2,reasons:[]}};
 if(p.endsWith('/activate'))return{ok:true};
 if(p==='/api/desktop/workspace/summary')return{asOf:1,versions:[],issued:1,started:1,downloaded:1,claimed:1,authorized:1,medianStartToClaimMs:10,p95StartToClaimMs:10};
 if(p==='/api/desktop/workspace/jobs')return o.method==='POST'?{id:'c'.repeat(32)}:{items:[]};
 if(p==='/api/desktop/workspace/jobs/preview')return{planId:'d'.repeat(48),count:1,items:[{label:'사용자 001'}]};
 if(p==='/api/desktop/workspace/storage')return{asOf:1,pending:false,bytes:0,items:[]};
 if(p==='/api/desktop/workspace/deployment-note')return{saved:true};
 if(p.startsWith('/api/desktop/workspace/licenses?'))return{items:[{id:'C'.repeat(24),label:'빠른 목록',status:'AVAILABLE',issuedAt:1,metadata:{note:'',tags:[]}}],counts:{AVAILABLE:1,USED:0,REVOKED:0,ALL:1},total:1,filteredCount:1,page:0,pageSize:25,pages:1};
 if(p.startsWith('/api/desktop/workspace/licenses/'))return{license:{id:'C'.repeat(24),label:'<img src=x onerror="errors.push(1)">',status:'USED',machineId:'F'.repeat(64),machineBlocked:true,machinePolicy:{source:'SINGLE_USE'}},metadata:{revision:0,note:'<script>bad</script>',tags:['one']},timeline:[],flows:[]};
 if(p==='/api/desktop/machines')return{items:[],counts:{}};
 if(p==='/api/desktop/bootstrap')return{artifacts:[],launchers:[],sessions:[],active:{},counts:{}};
 throw Error('UNMOCKED: '+p);
};
async function api(p,o={}){calls.push({path:p,method:o.method||'GET',body:o.body,headers:o.headers,rawSize:o.rawBody?.size});return mock(p,o);}
'''
reports=[]
def test(name,fn):
    fn();reports.append(name);print('PASS',name,flush=True)
with sync_playwright() as p:
    browser=p.chromium.launch(executable_path=os.getenv('CHROMIUM','/usr/bin/chromium'),args=['--no-sandbox'])
    page=browser.new_page(viewport={'width':1280,'height':900})
    def fresh():
        global page
        page.close();page=browser.new_page(viewport={'width':1280,'height':900})
        page.set_content(HTML)
        page.add_script_tag(content=SETUP)
        # about:blank may lack randomUUID; use browser randomness for request
        # IDs. These UI tests do not replace the real server signature tests.
        page.add_script_tag(content="if(!crypto.randomUUID)crypto.randomUUID=()=>[...crypto.getRandomValues(new Uint8Array(16))].map(x=>x.toString(16).padStart(2,'0')).join('');")
        for f in ['scripts/interface/peace.admin-modal.js','scripts/desktop/peace.admin-desktop-licenses.js','scripts/desktop/peace.admin-desktop-workflow.js']:
            page.add_script_tag(content=(ROOT/'public'/f).read_text())
    def openfn(code,selector):
        page.evaluate('(code)=>{window.testPending=eval(code).catch(e=>errors.push(String(e)));}',code)
        page.wait_for_selector(selector)
    def close():
        page.click('#modal-cancel');page.wait_for_timeout(60);assert not page.evaluate('errors'),page.evaluate('errors')
    fresh()
    def deployment_panel():
        page.evaluate("content.innerHTML=desktopBootstrapMarkup({artifacts:{},launchers:[],sessions:[]})")
        assert 'A / B / O 실행 파일 배포' in page.locator('#desktop-bootstrap-panel').inner_text()
        for component in ['A','B','O']:
            assert page.locator('[data-desktop-action="artifact-upload"][data-component="'+component+'"]').count()==1
        assert page.locator('#desktop-launcher-create').count()==1
        assert page.locator('[data-desktop-action="main-registration"]').count()==0
        assert page.evaluate('typeof showDesktopMainRegistration')=='undefined'
        assert not page.evaluate("calls.some(x=>x.method==='POST')")
    test('A/B/O registration and one-time issuance have one restored panel',deployment_panel)
    def candidate_error():
        openfn("showDesktopArtifactUpload('A')",'#desktop-artifact-file')
        page.locator('#desktop-artifact-file').set_input_files({'name':'A.exe','mimeType':'application/octet-stream','buffer':b'MZ-public-test-fixture'})
        page.locator('[data-modal-field="version"]').fill('91.2.3')
        page.click('#modal-confirm')
        page.wait_for_function("document.getElementById('desktop-artifact-status').textContent.includes('서버 승인 서명을 확인하세요')")
        assert page.locator('#desktop-artifact-file').evaluate('(input)=>input.files[0].name')=='A.exe'
        assert page.locator('[data-modal-field="version"]').input_value()=='91.2.3'
        assert page.locator('#modal').is_visible()
        assert not page.evaluate("calls.some(x=>x.path.endsWith('/activate'))")
    test('Server rejection preserves the selected executable and version for correction',candidate_error)
    def candidate_retry():
        page.click('#modal-confirm')
        page.wait_for_selector('#modal',state='hidden')
        uploads=page.evaluate("calls.filter(x=>x.path.includes('/artifacts?'))")
        assert len(uploads)==2
        assert uploads[0]['path']==uploads[1]['path']
        assert uploads[0]['rawSize']==uploads[1]['rawSize']
        assert not page.evaluate("calls.some(x=>x.path.endsWith('/activate'))")
    test('Restored upload retries the same candidate without operational publication',candidate_retry)
    fresh()
    def separate_categories():
        openfn('showDesktopExecutableProtection()','#desktop-protection-modal')
        assert page.locator('[data-protection-candidate]').count()==3
        assert page.locator('#desktop-protection-modal input[type="file"]').count()==0
        assert page.locator('#desktop-baseline-pin').count()==0
        assert page.locator('#desktop-custom-selected').count()==1
        assert page.locator('#desktop-pack-selected').count()==1
        close()
        assert page.locator('[data-protection-candidate]').count()==0
        openfn('showDesktopReleaseSafety()','#desktop-release-safety')
        assert page.locator('#desktop-baseline-pin').count()==1
        assert page.locator('#desktop-retire-submit').count()==1
        assert page.locator('#desktop-custom-selected').count()==0
        assert page.locator('#desktop-release-safety input[type="file"]').count()==0
        assert not page.evaluate("calls.some(x=>x.method==='POST')")
    test('Release safety and packing/encryption are distinct read-only entry surfaces',separate_categories)
    close();fresh()
    def independent():
        page.evaluate("()=>{const base=mock;mock=async(p,o)=>{if(p.endsWith('/summary'))throw Object.assign(Error('통계 조회 실패'),{problem:{title:'통계 조회 실패',current:'이 영역 조회 실패',next:'재시도',code:'TEST',action:'refresh'}});return base(p,o);};}")
        openfn("showDesktopWorkspace('jobs')",'#desktop-workspace-modal')
        page.wait_for_selector('#desktop-quality-result [role=alert]',state='attached')
        assert page.locator('#desktop-job-preview').is_visible()
        assert '등록한 작업' in page.locator('#desktop-jobs-list').inner_text()
    test('A failed quality panel does not block the job panel',independent)
    def jobs():
        page.click('#desktop-job-preview');page.wait_for_function("!document.getElementById('desktop-job-commit').disabled")
        assert not page.evaluate("calls.some(x=>x.path==='/api/desktop/workspace/jobs'&&x.method==='POST')")
        page.locator('#desktop-job-count').fill('2');assert page.locator('#desktop-job-commit').is_disabled()
        page.click('#desktop-job-preview');page.wait_for_function("!document.getElementById('desktop-job-commit').disabled")
        page.click('#desktop-job-commit');page.wait_for_function("calls.some(x=>x.path==='/api/desktop/workspace/jobs'&&x.method==='POST')")
        assert len(page.evaluate("calls.filter(x=>x.path==='/api/desktop/workspace/jobs'&&x.method==='POST')"))==1
    test('Job preview is non-mutating, edits invalidate it and commit is explicit',jobs)
    def stoppoll():
        close();n=page.evaluate('calls.length');page.wait_for_timeout(2700);assert page.evaluate('calls.length')==n
    test('Closing workspace stops browser polling, not server jobs',stoppoll)
    fresh()
    def detail():
        openfn("showDesktopUnifiedDetail('"+'C'*24+"')",'#desktop-unified-detail')
        assert page.locator('#desktop-unified-detail img').count()==0
        assert page.locator('#desktop-unified-detail script').count()==0
        assert page.locator('#desktop-machine-action').is_visible()
        assert page.locator('#desktop-meta-note').input_value()=='<script>bad</script>'
    test('Unified detail escapes metadata and keeps the existing PC unblock action',detail)
    def cas():
        page.evaluate("()=>{const base=mock;mock=async(p,o)=>{if(p.endsWith('/metadata')){if(o.body.expectedRevision!==0)throw Error('BAD REV');return{revision:1};}return base(p,o);};}")
        page.locator('#desktop-meta-note').fill('새 메모');page.click('#desktop-meta-save');page.wait_for_function("document.getElementById('desktop-meta-status').textContent.includes('저장했습니다')")
        assert page.evaluate("calls.find(x=>x.path.endsWith('/metadata')).body.expectedRevision")==0
    test('Metadata save carries the server revision',cas)
    close();fresh()
    def fastlist():
        page.evaluate("()=>{const base=mock;mock=async(p,o)=>{if(p==='/api/desktop/bootstrap')return new Promise(()=>{});if(p==='/api/desktop/machines')throw Error('machine panel unavailable');return base(p,o);};}")
        openfn('renderDesktopLicenses()','#desktop-license-search')
        page.wait_for_function("document.getElementById('content').textContent.includes('빠른 목록')")
        assert page.locator('[data-license-select]').count()==1
    test('License rows render without waiting for a stalled independent panel',fastlist)
    def selection():
        page.locator('[data-license-select]').check()
        assert page.evaluate('desktopSelectedLicenses.size')==1
        page.evaluate("session={csrf:'NEW_ADMIN_SESSION',role:'admin'};desktopWorkflowOwner();")
        assert page.evaluate('desktopSelectedLicenses.size')==0
    test('Browser selection is session-bound RAM and is cleared on session change',selection)
    fresh()
    def launcher_form():
        openfn('createDesktopLauncher()','[data-modal-field="label"]')
        assert page.locator('[data-modal-field="licenseId"]').count()==0
        assert page.evaluate('calls.length')==0
        assert 'KEY' in page.locator('#modal-body').inner_text()
    test('A issuance form opens without fetching or requiring available licenses',launcher_form)
    def launcher_cancel():
        close()
        assert not page.evaluate("calls.some(x=>x.method==='POST')")
    test('Cancelling A issuance creates neither A nor a license',launcher_cancel)
    def launcher_submit():
        page.evaluate("()=>{const old=mock;mock=async(p,o)=>p==='/api/desktop/bootstrap/launchers'?{launcherId:'A'.repeat(24),downloadName:'a'.repeat(32)+'.exe',downloadUrl:'/api/desktop/bootstrap/launchers/'+('A'.repeat(24))+'/download',expiresAt:1}:old(p,o);}")
        openfn('createDesktopLauncher()','[data-modal-field="label"]')
        page.locator('[data-modal-field="label"]').fill('콘솔 사용자')
        page.click('#modal-confirm')
        page.wait_for_selector('#desktop-launcher-download')
        body=page.evaluate("calls.find(x=>x.path==='/api/desktop/bootstrap/launchers').body")
        assert set(body)=={'requestId','label'}
        assert body['label']=='콘솔 사용자'
        assert 'KEY' in page.locator('#modal-body').inner_text()
        assert '입력창 없이' not in page.locator('#modal-body').inner_text()
        close()
    test('A issuance submits only its request ID and label; receipt explains KEY input',launcher_submit)
    assert not page.evaluate('errors'),page.evaluate('errors')
    test('No unhandled promise rejection in the exercised administrator paths',lambda:None)
    browser.close()
print(json.dumps({'passed':len(reports),'tests':reports,'scope':'Chromium production JS + mock API; not Windows/real server integration or signature validation'},ensure_ascii=False))
