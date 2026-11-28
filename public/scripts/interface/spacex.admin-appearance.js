'use strict';

const adminSpacePalettes = new Set(['pure-black', 'blue-starlink', 'mint-orbit', 'violet-nebula',
  'amber-nova', 'eclipse', 'aurora', 'pulsar', 'deep-space', 'supernova']);
const adminAppearanceFonts = new Set(['orbitron', 'consolas', 'spacemono', 'sora', 'oxanium']);
const adminAppearanceColors = new Map([
  ['default', ['Theme default', '']],
  ['ice-blue', ['Ice Blue', '#94ccff']],
  ['ion-cyan', ['Ion Cyan', '#7be7f1']],
  ['nebula-violet', ['Nebula Violet', '#c8a5ff']],
  ['pulsar-pink', ['Pulsar Pink', '#fca2e2']],
  ['solar-amber', ['Solar Amber', '#ffcc91']],
  ['aurora-green', ['Aurora Green', '#91ecbd']],
  ['starlight', ['Starlight', '#edf1f7']],
]);
const adminLocaleTags = new Set(adminAppearanceLocaleOptions.map(([tag]) => tag));
const adminMotionStorageKey = 'spacex-admin-motion';
const adminAppearanceRoot = document.documentElement;
const adminAppearanceFields = new Map([
  ['space-palette', ['spacex-palette', adminSpacePalettes, 'pure-black']],
  ['appearance-font', ['spacex-admin-font', adminAppearanceFonts, 'orbitron']],
  ['appearance-checkbox', ['spacex-admin-checkbox', adminAppearanceColors, 'default']],
  ['appearance-text', ['spacex-admin-text', adminAppearanceColors, 'default']],
  ['appearance-language', ['spacex-admin-language', adminLocaleTags, 'ko-KR']],
]);
const adminAppearanceValues = new Map();

// Display preferences are scoped to this browser.
function readAdminAppearance(key) {
  try { return localStorage.getItem(key); } catch (_) { return null; }
}
function writeAdminAppearance(key, value) {
  try { localStorage.setItem(key, value); } catch (_) {}
}

function adminAppearanceLanguage() {
  const tag = adminAppearanceRoot.lang;
  return Object.keys(adminAppearanceCaptions).find(prefix =>
    tag === prefix || tag.startsWith(prefix + '-')) || 'en';
}
function syncAdminAppearanceCaptions() {
  const captions = adminAppearanceCaptions[adminAppearanceLanguage()];
  document.querySelectorAll('[data-appearance-caption]').forEach(element => {
    element.textContent = captions[Number(element.dataset.appearanceCaption)];
  });
}
function setAdminAppearance(id, value) {
  const [key, choices, fallback] = adminAppearanceFields.get(id);
  const selected = choices.has(value) ? value : fallback;
  adminAppearanceValues.set(id, selected);
  switch (id) {
    case 'space-palette': adminAppearanceRoot.dataset.spacePalette = selected; break;
    case 'appearance-font': adminAppearanceRoot.dataset.appearanceFont = selected; break;
    case 'appearance-checkbox':
      adminAppearanceRoot.style.setProperty('--admin-checkbox', adminAppearanceColors.get(selected)[1]);
      break;
    case 'appearance-text':
      adminAppearanceRoot.style.setProperty('--admin-ink', adminAppearanceColors.get(selected)[1]);
      break;
    case 'appearance-language': adminAppearanceRoot.lang = selected; break;
  }
  const control = document.getElementById(id);
  if (control) control.value = selected;
  writeAdminAppearance(key, selected);
  if (id === 'appearance-language') {
    syncAdminAppearanceCaptions();
    document.dispatchEvent(new Event('spacex:appearance-language'));
  }
}
function setAdminPalette(value) {
  setAdminAppearance('space-palette', value);
}
function setAdminTheme(theme) {
  const selected = theme === 'light' ? 'light' : 'dark';
  adminAppearanceRoot.dataset.theme = selected;
  adminAppearanceRoot.style.colorScheme = selected;
  writeAdminAppearance('relay-admin-theme', selected);
  const button = document.getElementById('theme-toggle');
  if (button) {
    const korean = adminAppearanceLanguage() === 'ko';
    const label = selected === 'dark' ? (korean ? '라이트 모드' : 'Light mode') : (korean ? '다크 모드' : 'Dark mode');
    button.querySelector('[data-theme-label]').textContent = label;
    button.setAttribute('aria-pressed', String(selected === 'dark'));
  }
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.content = selected === 'dark' ? '#000000' : '#e9edf7';
}
function setAdminMotion(paused) {
  adminAppearanceRoot.dataset.motion = paused ? 'paused' : 'running';
  writeAdminAppearance(adminMotionStorageKey, adminAppearanceRoot.dataset.motion);
  document.querySelectorAll('[data-motion-toggle]').forEach(button => {
    const korean = adminAppearanceLanguage() === 'ko';
    const label = paused ? (korean ? '애니메이션 켜기' : 'Enable animations') : (korean ? '애니메이션 끄기' : 'Disable animations');
    button.querySelector('[data-motion-label]').textContent = label;
    button.setAttribute('aria-label', label);
    button.setAttribute('aria-pressed', String(paused));
  });
}
function setAdminStars(hidden) {
  adminAppearanceRoot.dataset.stars = hidden ? 'hidden' : 'visible';
  writeAdminAppearance('spacex-admin-stars', adminAppearanceRoot.dataset.stars);
  const control = document.getElementById('appearance-stars');
  if (control) control.checked = hidden;
}
function fillAdminAppearanceSelect(id, rows) {
  const select = document.getElementById(id);
  if (!select) return;
  select.replaceChildren(...Array.from(rows, ([value, label]) => new Option(label, value)));
}
function syncAdminAppearanceButtons() {
  setAdminTheme(adminAppearanceRoot.dataset.theme);
  setAdminMotion(adminAppearanceRoot.dataset.motion === 'paused');
}

for (const [id, [key]] of adminAppearanceFields) setAdminAppearance(id, readAdminAppearance(key));
setAdminTheme(readAdminAppearance('relay-admin-theme'));
setAdminMotion((readAdminAppearance(adminMotionStorageKey) ?? readAdminAppearance('cozy-admin-motion')) === 'paused' ||
  window.matchMedia?.('(prefers-reduced-motion: reduce)').matches);
setAdminStars(readAdminAppearance('spacex-admin-stars') === 'hidden');

document.addEventListener('DOMContentLoaded', () => {
  const colors = Array.from(adminAppearanceColors, ([value, [label]]) => [value, label]);
  fillAdminAppearanceSelect('appearance-checkbox', colors);
  fillAdminAppearanceSelect('appearance-text', colors);
  fillAdminAppearanceSelect('appearance-language', adminAppearanceLocaleOptions);
  for (const [id, value] of adminAppearanceValues) setAdminAppearance(id, value);
  syncAdminAppearanceButtons();
  setAdminStars(adminAppearanceRoot.dataset.stars === 'hidden');
});
document.addEventListener('click', event => {
  if (event.target.closest('#theme-toggle')) setAdminTheme(adminAppearanceRoot.dataset.theme === 'dark' ? 'light' : 'dark');
  if (event.target.closest('[data-motion-toggle]')) setAdminMotion(adminAppearanceRoot.dataset.motion !== 'paused');
  const settings = document.getElementById('appearance-settings');
  if (settings?.open && !settings.contains(event.target)) settings.open = false;
});
document.addEventListener('keydown', event => {
  const settings = document.getElementById('appearance-settings');
  if (event.key !== 'Escape' || !settings?.open || !settings.contains(event.target)) return;
  settings.open = false;
  settings.querySelector('summary')?.focus();
});
document.addEventListener('change', ({target}) => {
  if (adminAppearanceFields.has(target.id)) {
    setAdminAppearance(target.id, target.value);
    if (target.id === 'appearance-language') syncAdminAppearanceButtons();
  }
  if (target.id === 'appearance-stars') setAdminStars(target.checked);
});
