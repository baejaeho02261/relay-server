'use strict';
(() => {
  // Fragment never enters a request URL. Remove it before any async operation.
  let fragment = location.hash;
  try { history.replaceState(null, '', location.pathname); }
  catch (_) { document.getElementById('diagnostic-status').textContent = '링크 주소를 안전하게 지울 수 없습니다. 이 창을 닫고 다시 열어주세요.'; return; }
  let token = '';
  try { const params = new URLSearchParams(fragment.slice(1)); if ([...params.keys()].length === 1) token = params.get('token') || ''; } catch (_) {}
  fragment = '';
  const validToken = /^[A-F0-9]{24}\.[a-f0-9]{64}$/.test(token);
  const $ = id => document.getElementById(id);
  const ui = {status:$('diagnostic-status'), consent:$('capture-consent'), capture:$('capture-display'), file:$('capture-file'), panel:$('preview-panel'), canvas:$('capture-preview'), size:$('preview-size'), sendConsent:$('send-consent'), send:$('capture-send'), retry:$('capture-retry'), cancel:$('capture-cancel'), fields:$('redaction-fields'), mask:$('redact-apply')};
  const limits = {bytes:2097152, width:4096, height:4096, pixels:4194304, outputWidth:1920, outputHeight:1080};
  let phase = 'CHECKING', generation = 0, stream = null, video = null, image = null, controller = null;
  let deadline = 0, expiryTimer = null, mediaTimer = null, waitCancel = null, drag = null, pending = null;
  const urls = new Set();
  function status(text) { ui.status.textContent = text; }
  function stopTracks(value) { if (value) for (const track of value.getTracks()) { try { track.stop(); } catch (_) {} } }
  function releaseMedia() {
    clearTimeout(mediaTimer); mediaTimer = null;
    if (waitCancel) { const cancel = waitCancel; waitCancel = null; cancel(); }
    stopTracks(stream); stream = null;
    if (video) { video.onloadeddata = null; video.onerror = null; try { video.pause(); } catch (_) {} video.srcObject = null; video.remove(); video = null; }
    if (image) { image.onload = null; image.onerror = null; image.removeAttribute('src'); image = null; }
    for (const url of urls) URL.revokeObjectURL(url); urls.clear();
  }
  function releaseImage() {
    // Resetting dimensions clears the canvas backing store. No original copy remains for undo.
    ui.canvas.width = 0; ui.canvas.height = 0; ui.panel.hidden = true; ui.size.textContent = '';
    ui.file.value = ''; ui.sendConsent.checked = false; drag = null; pending = null;
  }
  function current(id) { return id === generation && token && phase !== 'CLOSED' && phase !== 'DONE' && performance.now() < deadline; }
  function controls() {
    const ready = phase === 'READY' || phase === 'PREVIEW';
    ui.consent.disabled = !ready;
    ui.capture.disabled = !ready || !ui.consent.checked || !isSecureContext || !navigator.mediaDevices?.getDisplayMedia;
    ui.file.disabled = !ready || !ui.consent.checked;
    ui.sendConsent.disabled = phase !== 'PREVIEW';
    ui.send.disabled = phase !== 'PREVIEW' || !ui.sendConsent.checked || drag !== null;
    ui.fields.disabled = phase !== 'PREVIEW';
    ui.retry.hidden = phase !== 'RETRY'; ui.retry.disabled = phase !== 'RETRY';
    ui.cancel.disabled = !['CAPTURING','LOADING','PREVIEW','SENDING','RETRY'].includes(phase);
  }
  function clearWork(next = 'READY') {
    generation++; if (controller) controller.abort(); controller = null;
    releaseMedia(); releaseImage(); phase = next; controls();
  }
  function closePage() { clearTimeout(expiryTimer); token = ''; clearWork('CLOSED'); ui.consent.checked = false; }
  function expire() { closePage(); status('이 링크의 사용 시간이 끝났습니다. 운영자에게 새 진단 링크를 요청하세요.'); }
  function checkAvailable() {
    if (!token || performance.now() >= deadline) { expire(); return false; }
    return true;
  }
  async function request(path, options) {
    const abort = new AbortController(); controller = abort;
    const timer = setTimeout(() => abort.abort(), 30000);
    try {
      const response = await fetch(path, {...options, headers:{Authorization:'Bearer '+token, ...options.headers}, credentials:'omit', cache:'no-store', redirect:'error', referrerPolicy:'no-referrer', signal:abort.signal});
      if (!response.ok) throw new Error('REQUEST_FAILED');
      return await response.json();
    } finally { clearTimeout(timer); if (controller === abort) controller = null; }
  }
  function done() {
    clearTimeout(expiryTimer); clearWork('DONE'); token = ''; ui.consent.checked = false;
    status('이미지 한 장을 접수했습니다. 이 링크는 사용 완료되었습니다. 브라우저의 미리보기는 지웠습니다. 창을 닫아도 됩니다.');
  }
  function showPreview(source, width, height, id) {
    if (!current(id)) return;
    if (!Number.isInteger(width) || !Number.isInteger(height) || width < 1 || height < 1 || width > 16384 || height > 16384 || width * height > 67108864) throw new Error('IMAGE_BOUNDS');
    const scale = Math.min(1, limits.outputWidth / width, limits.outputHeight / height);
    ui.canvas.width = Math.max(1, Math.floor(width * scale)); ui.canvas.height = Math.max(1, Math.floor(height * scale));
    const context = ui.canvas.getContext('2d', {alpha:false}); if (!context) throw new Error('CANVAS_FAILED');
    context.fillStyle = '#000'; context.fillRect(0, 0, ui.canvas.width, ui.canvas.height);
    context.drawImage(source, 0, 0, ui.canvas.width, ui.canvas.height); // Exactly one source frame.
    ui.panel.hidden = false; ui.sendConsent.checked = false;
    ui.size.textContent = `${ui.canvas.width} × ${ui.canvas.height} 픽셀 · 아직 전송하지 않았습니다.`;
    for (const id of ['redact-x','redact-width']) $(id).max = String(ui.canvas.width);
    for (const id of ['redact-y','redact-height']) $(id).max = String(ui.canvas.height);
    phase = 'PREVIEW'; controls(); status('화면 공유를 종료했습니다. 미리보기를 확인하고 민감한 내용을 가린 뒤 별도로 전송하세요.');
  }
  function waitForVideo(element) {
    return new Promise((resolve, reject) => {
      let settled = false;
      function finish(error) { if (settled) return; settled = true; element.onloadeddata = null; element.onerror = null; waitCancel = null; error ? reject(error) : resolve(); }
      waitCancel = () => finish(new Error('CANCELLED'));
      element.onloadeddata = () => finish(); element.onerror = () => finish(new Error('VIDEO_FAILED'));
      if (element.readyState >= 2 && element.videoWidth > 0) finish();
    });
  }
  async function capture() {
    if (!['READY','PREVIEW'].includes(phase) || !ui.consent.checked || !checkAvailable()) return;
    if (!isSecureContext || !navigator.mediaDevices?.getDisplayMedia) { status('이 브라우저에서는 화면 선택을 사용할 수 없습니다. PNG 파일을 직접 선택하세요.'); return; }
    clearWork('CAPTURING'); const id = generation;
    status('브라우저에서 촬영할 화면을 직접 선택하세요. 선택 뒤 한 장만 촬영합니다.');
    let acquired = null;
    try {
      // Must run in this user click, before any await (transient activation).
      const selected = navigator.mediaDevices.getDisplayMedia({video:true, audio:false});
      acquired = await selected;
      if (!current(id)) { stopTracks(acquired); return; }
      stream = acquired;
      const tracks = acquired.getVideoTracks();
      if (tracks.length !== 1 || tracks[0].readyState === 'ended') throw new Error('VIDEO_FAILED');
      // Audio was never requested. Stop any unexpected track before decoding.
      for (const track of acquired.getTracks()) if (track !== tracks[0]) track.stop();
      video = document.createElement('video'); video.muted = true; video.playsInline = true; video.srcObject = acquired;
      const element = video;
      mediaTimer = setTimeout(() => { if (current(id)) { clearWork(); status('화면을 읽는 시간이 초과되었습니다. 공유를 종료했습니다. 다시 선택하거나 PNG를 사용하세요.'); } }, 10000);
      const ready = waitForVideo(element);
      const playing = element.play(); if (playing?.catch) playing.catch(() => { if (current(id) && waitCancel) waitCancel(); });
      await ready;
      if (!current(id)) return;
      showPreview(element, element.videoWidth, element.videoHeight, id);
    } catch (_) { if (current(id)) { clearWork(); status('화면 선택이 취소되었거나 한 장을 읽지 못했습니다. 전송하지 않았습니다. 다시 선택하거나 PNG를 사용하세요.'); } }
    finally { stopTracks(acquired); if (id === generation) releaseMedia(); }
  }
  function pngSize(buffer) {
    const bytes = new Uint8Array(buffer), view = new DataView(buffer);
    const signature = [137,80,78,71,13,10,26,10];
    if (bytes.length < 33 || signature.some((value,index) => bytes[index] !== value) || view.getUint32(8) !== 13 || String.fromCharCode(...bytes.slice(12,16)) !== 'IHDR' || bytes[24] !== 8 || ![2,6].includes(bytes[25]) || bytes[26] || bytes[27] || bytes[28]) throw new Error('PNG_REQUIRED');
    const width = view.getUint32(16), height = view.getUint32(20);
    if (!width || !height || width > limits.width || height > limits.height || width * height > limits.pixels) throw new Error('IMAGE_BOUNDS');
    return {width, height};
  }
  async function chooseFile() {
    const file = ui.file.files?.[0];
    if (!file || !['READY','PREVIEW'].includes(phase) || !ui.consent.checked || !checkAvailable()) { ui.file.value = ''; return; }
    clearWork('LOADING'); const id = generation;
    try {
      if (file.type !== 'image/png' || file.size < 33 || file.size > limits.bytes) throw new Error('PNG_REQUIRED');
      const size = pngSize(await file.slice(0,33).arrayBuffer()); if (!current(id)) return;
      const url = URL.createObjectURL(file); urls.add(url); image = new Image(); const element = image;
      await new Promise((resolve,reject) => {
        let settled = false;
        function finish(error) { if (settled) return; settled = true; waitCancel = null; element.onload = null; element.onerror = null; error ? reject(error) : resolve(); }
        waitCancel = () => finish(new Error('CANCELLED'));
        element.onload = () => finish(); element.onerror = () => finish(new Error('PNG_REQUIRED'));
        mediaTimer = setTimeout(() => finish(new Error('IMAGE_TIMEOUT')), 10000); element.src = url;
      });
      if (!current(id)) return;
      if (element.naturalWidth !== size.width || element.naturalHeight !== size.height) throw new Error('IMAGE_BOUNDS');
      showPreview(element, size.width, size.height, id);
      status('PNG를 브라우저에서 다시 그렸습니다. 미리보기와 가리기를 확인한 뒤 전송하세요. 원본 파일 이름과 부가 정보는 보내지 않습니다.');
    } catch (_) { if (current(id)) { clearWork(); status('PNG를 읽지 못했습니다. 2 MiB 이하, 각 변 4096 픽셀 이하, 총 4,194,304 픽셀 이하의 일반 RGB/RGBA PNG를 선택하세요.'); } }
    finally { if (id === generation) releaseMedia(); }
  }
  function redact(x,y,width,height) {
    if (phase !== 'PREVIEW' || !checkAvailable()) return;
    if (![x,y,width,height].every(Number.isInteger) || x < 0 || y < 0 || width < 1 || height < 1 || x + width > ui.canvas.width || y + height > ui.canvas.height) { status('가릴 영역을 이미지 안의 정수 좌표와 크기로 지정하세요.'); return; }
    const context = ui.canvas.getContext('2d'); context.fillStyle = '#000'; context.fillRect(x,y,width,height);
    ui.sendConsent.checked = false; pending = null; controls(); status('선택 영역을 검게 가렸습니다. 바뀐 이미지를 다시 확인한 뒤 전송 동의를 선택하세요.');
  }
  function point(event) { const rect = ui.canvas.getBoundingClientRect(); if (!rect.width || !rect.height) return null; return {x:Math.max(0,Math.min(ui.canvas.width,Math.floor((event.clientX-rect.left)*ui.canvas.width/rect.width))), y:Math.max(0,Math.min(ui.canvas.height,Math.floor((event.clientY-rect.top)*ui.canvas.height/rect.height)))}; }
  async function send(retry = false) {
    if ((!retry && (phase !== 'PREVIEW' || !ui.sendConsent.checked || drag !== null)) || (retry && phase !== 'RETRY') || !checkAvailable()) return;
    phase = 'SENDING'; controls(); const id = generation;
    try {
      if (!retry) {
        const blob = await new Promise(resolve => ui.canvas.toBlob(resolve, 'image/png'));
        if (!current(id)) return;
        if (!blob || blob.type !== 'image/png' || blob.size > limits.bytes || blob.size < 33) { phase = 'PREVIEW'; ui.sendConsent.checked = false; controls(); status('전송 이미지가 2 MiB를 넘거나 PNG 변환에 실패했습니다. 취소 후 더 작은 프로그램 창이나 PNG를 선택하세요.'); return; }
        pending = {blob, requestId:crypto.randomUUID()};
      }
      if (!pending) throw new Error('NO_IMAGE');
      status('확인한 이미지 한 장을 전송하고 있습니다.');
      const result = await request('/api/diagnostic-capture/upload', {method:'POST', headers:{'Content-Type':'image/png','X-Diagnostic-Consent':'1','X-Diagnostic-Request':pending.requestId}, body:pending.blob});
      if (result.ok !== true) throw new Error('REQUEST_FAILED');
      if (current(id)) done();
    } catch (_) { if (current(id)) { phase = 'RETRY'; controls(); status('전송 결과를 확인하지 못했습니다. 이미 접수되었을 수 있습니다. 같은 전송 결과 다시 확인을 누르면 먼저 접수 상태를 확인합니다. 새 이미지를 자동으로 보내지 않습니다.'); } }
  }
  async function retry() {
    if (phase !== 'RETRY' || !pending || !checkAvailable()) return;
    phase = 'SENDING'; controls(); const id = generation;
    try {
      const result = await request('/api/diagnostic-capture/status', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
      if (!current(id)) return;
      if (result.ok === true && result.status === 'UPLOADED') { done(); return; }
      if (result.ok === true && result.status === 'RECEIVING') { phase = 'RETRY'; controls(); status('서버가 기존 전송을 처리하고 있습니다. 잠시 후 같은 전송 결과 다시 확인을 눌러주세요. 이미지를 추가로 보내지 않았습니다.'); return; }
      if (result.ok !== true || result.status !== 'AVAILABLE') throw new Error('STATUS_FAILED');
      phase = 'RETRY'; await send(true); // Same explicit retry click, same id and immutable PNG.
    } catch (_) { if (current(id)) { phase = 'RETRY'; controls(); status('접수 상태를 확인하지 못했습니다. 링크가 만료되었거나 취소되었을 수 있습니다. 운영자에게 확인하세요.'); } }
  }
  ui.consent.addEventListener('change', () => { if (!ui.consent.checked) clearWork(); controls(); });
  ui.sendConsent.addEventListener('change', controls);
  ui.capture.addEventListener('click', capture); ui.file.addEventListener('change', chooseFile);
  ui.send.addEventListener('click', () => send()); ui.retry.addEventListener('click', retry);
  ui.cancel.addEventListener('click', () => { const sending = phase === 'SENDING' || phase === 'RETRY'; clearWork(); ui.consent.checked = false; controls(); status(sending ? '브라우저 작업과 미리보기를 지웠습니다. 서버에 이미 도착했는지는 운영자에게 확인하세요.' : '촬영 작업과 로컬 미리보기를 지웠습니다. 이미지를 전송하지 않았습니다.'); });
  ui.mask.addEventListener('click', () => redact(...['redact-x','redact-y','redact-width','redact-height'].map(id => Number($(id).value))));
  ui.canvas.addEventListener('pointerdown', event => { if (phase !== 'PREVIEW' || event.button !== 0 || event.isPrimary === false) return; const start = point(event); drag = start && {...start,pointerId:event.pointerId}; if (drag) { ui.sendConsent.checked = false; controls(); } try { ui.canvas.setPointerCapture(event.pointerId); } catch (_) {} });
  ui.canvas.addEventListener('pointerup', event => { const start = drag, end = point(event); if (!start || start.pointerId !== event.pointerId) return; drag = null; controls(); if (!end) return; redact(Math.min(start.x,end.x),Math.min(start.y,end.y),Math.abs(end.x-start.x),Math.abs(end.y-start.y)); });
  ui.canvas.addEventListener('pointercancel', event => { if (drag && drag.pointerId === event.pointerId) { drag = null; controls(); } });
  addEventListener('pagehide', closePage);
  addEventListener('pageshow', event => { if (event.persisted) { closePage(); status('이전 화면의 진단 데이터는 지웠습니다. 운영자가 보낸 링크를 다시 열어주세요.'); } });
  if (!validToken || !isSecureContext || top !== self) { token = ''; phase = 'CLOSED'; controls(); status('유효한 진단 링크를 HTTPS 새 창에서 열어주세요. 운영자에게 링크를 다시 요청할 수 있습니다.'); return; }
  (async () => {
    const id = generation, requestedAt = performance.now();
    try {
      const result = await request('/api/diagnostic-capture/status', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
      if (id !== generation || !token) return;
      const remaining = result.expiresAt - result.serverTime;
      if (result.ok !== true || !['AVAILABLE','RECEIVING','UPLOADED'].includes(result.status) || !Number.isSafeInteger(result.expiresAt) || !Number.isSafeInteger(result.serverTime) || result.serverTime < 0 || remaining <= 0 || remaining > 600000 || result.consentVersion !== 1 || result.maxPngBytes !== limits.bytes || result.maxWidth !== limits.width || result.maxHeight !== limits.height || result.maxPixels !== limits.pixels || result.retentionHours !== 24) throw new Error('STATUS_FAILED');
      // Server time supplies the bounded remaining window. Anchor before the
      // request so network delay never adds time; a PC wall-clock change cannot
      // extend it. This local hint never overrides the server's expiry checks.
      deadline = requestedAt + remaining;
      if (performance.now() >= deadline) throw new Error('STATUS_FAILED');
      if (result.status === 'UPLOADED') { done(); return; }
      if (result.status === 'RECEIVING') { closePage(); status('이 링크의 기존 전송을 서버에서 처리하고 있습니다. 새 촬영을 시작하지 않습니다. 잠시 후 링크를 다시 열거나 운영자에게 접수를 확인하세요.'); return; }
      expiryTimer = setTimeout(expire, Math.max(1, deadline-performance.now())); phase = 'READY'; controls();
      status('진단 링크가 확인되었습니다. 동의 후 화면 또는 PNG를 선택하세요. 전송은 미리보기 뒤에 별도로 진행합니다.');
    } catch (_) { if (id === generation) { closePage(); status('진단 링크를 사용할 수 없습니다. 만료·취소·사용 완료 여부를 운영자에게 확인하세요.'); } }
  })();
})();
