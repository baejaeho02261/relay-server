'use strict';

let adminMainModal = null;
const adminIsolatedModals = new Set();
let adminModalSequence = 0;

function captureAdminModalOwner() {
  const owner = adminMainModal;
  return owner ? () => owner.active : null;
}
function closeAdminModals() {
  for (const child of [...adminIsolatedModals]) child.close(null);
  if (adminMainModal) adminMainModal.close(null);
}

function openModal(options) {
  // Reauthentication has its own surface; never replace a live upload or
  // deployment form, its event handlers, or the promise waiting for it.
  const isolated = options.isolated === true;
  if (!isolated) closeAdminModals();
  const previousFocus = document.activeElement;
  const parent = isolated ? adminMainModal : null;
  let surface = modalEl;
  if (isolated) {
    surface = document.createElement('div');
    surface.className = 'modal modal-isolated hidden';
    const titleId = 'isolated-modal-title-' + (++adminModalSequence);
    surface.innerHTML = `<div class="modal-backdrop" data-modal-close></div><div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="${titleId}" tabindex="-1"><div class="modal-head"><h3 id="${titleId}" data-modal-title></h3><button type="button" class="icon-btn" aria-label="닫기" data-modal-close>×</button></div><div class="modal-body" data-modal-body></div><div class="modal-actions"><button type="button" class="ghost" data-modal-cancel>취소</button><button type="button" class="primary" data-modal-confirm>확인</button></div></div>`;
    document.body.append(surface);
    if (parent) { modalEl.inert = true; modalEl.setAttribute('aria-hidden', 'true'); }
  }
  const title = isolated ? surface.querySelector('[data-modal-title]') : modalTitle;
  const body = isolated ? surface.querySelector('[data-modal-body]') : modalBody;
  const confirm = isolated ? surface.querySelector('[data-modal-confirm]') : modalConfirm;
  const cancel = isolated ? surface.querySelector('[data-modal-cancel]') : modalCancel;
  return new Promise(resolve => {
    title.textContent = options.title || '확인';
    const fields = options.fields || [];let active=true;confirm.disabled=false;
    body.innerHTML = `${options.message ? `<p>${esc(options.message)}</p>` : ''}${options.html || ''}${fields.map(f => {
      if (f.type === 'section') return `<h3 class="modal-section">${esc(f.label)}</h3>`;
      if (f.type === 'textarea') return `<label>${esc(f.label)}<textarea ${f.readOnly?'readonly aria-readonly="true"':''} data-modal-field="${esc(f.name)}" placeholder="${esc(f.placeholder || '')}">${esc(f.value || '')}</textarea></label>`;
      if (f.type === 'select') return `<label>${esc(f.label)}<select data-modal-field="${esc(f.name)}">${(f.options || []).map(o => `<option value="${esc(o.value ?? o)}" ${String(o.value ?? o)===String(f.value ?? '')?'selected':''}>${esc(o.label ?? o)}</option>`).join('')}</select></label>`;
      if (f.type === 'password') return `<label>${esc(f.label)}<div class="password-input-row"><input data-modal-field="${esc(f.name)}" type="password" value="${esc(f.value || '')}" placeholder="${esc(f.placeholder || '')}" inputmode="${esc(f.inputmode || 'numeric')}" autocomplete="${esc(f.autocomplete || 'new-password')}" maxlength="${Number(f.maxLength || 8)}"><button type="button" data-modal-reveal="${esc(f.name)}">보기</button></div></label>`;
      return `<label>${esc(f.label)}<input ${f.readOnly?'readonly aria-readonly="true"':''} data-modal-field="${esc(f.name)}" type="${esc(f.type || 'text')}" value="${esc(f.value || '')}" placeholder="${esc(f.placeholder || '')}"></label>`;
    }).join('')}`;
    confirm.textContent = options.confirmLabel || '확인';
    confirm.className = options.danger ? 'danger' : 'primary';
    surface.classList.remove('hidden');
    surface.setAttribute('aria-hidden', 'false');

    const lifecycle = {active:true,close:null};
    const close = value => {
      if (!active) return;
      active=false;lifecycle.active=false;
      if (!isolated) for (const child of [...adminIsolatedModals]) child.close(null);
      body.onchange=null;confirm.disabled=false;
      body.querySelectorAll('[data-modal-field]').forEach(el => { if (fields.some(f => f.name === el.dataset.modalField && f.type === 'password')) el.value = ''; });
      surface.classList.add('hidden');
      surface.setAttribute('aria-hidden', 'true');
      confirm.onclick = null;
      cancel.onclick = null;
      body.onclick = null;
      surface.querySelectorAll('[data-modal-close]').forEach(x => x.onclick = null);
      surface.removeEventListener('keydown', onKeyDown);
      if (isolated) {
        adminIsolatedModals.delete(lifecycle);
        surface.remove();
        if (parent?.active) { modalEl.inert = false; modalEl.setAttribute('aria-hidden', 'false'); }
      } else if (adminMainModal === lifecycle) {
        adminMainModal = null;
        modalEl.inert = false;
      }
      if (previousFocus?.isConnected && (!isolated || !parent || parent.active)) previousFocus.focus();
      resolve(value);
    };
    lifecycle.close = close;
    if (isolated) adminIsolatedModals.add(lifecycle); else adminMainModal = lifecycle;
    const onKeyDown = event => {
      if (event.key === 'Escape') { event.preventDefault();event.stopPropagation();close(null);return; }
      if (event.key !== 'Tab') return;
      const controls = [...surface.querySelectorAll('button,input,select,textarea,a[href],[tabindex]')].filter(el => !el.disabled && el.tabIndex >= 0 && !el.closest('[hidden]'));
      if (!controls.length) return;
      const first = controls[0], last = controls[controls.length-1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault();last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault();first.focus(); }
    };
    surface.addEventListener('keydown', onKeyDown);
    cancel.onclick = () => close(null);
    surface.querySelectorAll('[data-modal-close]').forEach(x => x.onclick = () => close(null));
    body.onclick = event => {
      const reveal = event.target.closest('[data-modal-reveal]');
      if (!reveal) return;
      const input = body.querySelector(`[data-modal-field="${CSS.escape(reveal.dataset.modalReveal)}"]`);
      if (!input) return;
      const visible = input.type === 'text';
      input.type = visible ? 'password' : 'text';
      reveal.textContent = visible ? '보기' : '숨기기';
      input.focus();
    };
    confirm.onclick = () => {
      if(!active)return;
      const values = {};
      body.querySelectorAll('[data-modal-field]').forEach(el => values[el.dataset.modalField] = el.value);
      close(values);
    };
    const first = body.querySelector('input:not([type=hidden]):not([readonly]),textarea:not([readonly]),select');
    setTimeout(() => { if (active && (isolated || !adminIsolatedModals.size)) (first || confirm).focus(); }, 20);
  });
}
