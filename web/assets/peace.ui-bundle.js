'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require("../../config/peace.runtime-configuration");
const PUBLIC_DIR = path.resolve(MODULE_RESOURCE_ROOT, '..', 'public');
const FILES = [
  "index.html",
  "styles/admin.css",
  "styles/admin-theme.css",
  "styles/admin-appearance.css",
  "scripts/interface/peace.admin-appearance.js",
  "styles/admin-controls.css",
  "styles/admin-workspace.css",
  "scripts/interface/peace.admin-controls.js",
  "styles/admin-navigation.css",
  "scripts/interface/peace.admin-i18n.js",
  "scripts/application/peace.admin.js",
  "scripts/interface/peace.admin-navigation.js",
  "scripts/pages/peace.admin-pages-monitoring.js",
  "scripts/application/peace.admin-terminal.js",
  "scripts/pages/peace.admin-pages-traffic.js",
  "scripts/pages/peace.admin-pages-danger.js",
  "scripts/pages/peace.admin-pages-access.js",
  "scripts/pages/peace.admin-pages-reports.js",
  "scripts/actions/peace.admin-pages-devices.js",
  "scripts/pages/peace.admin-pages-deployment.js",
  "scripts/pages/peace.admin-pages-security.js",
  "scripts/pages/peace.admin-pages-operations.js",
  "scripts/actions/peace.admin-actions-access.js",
  "scripts/actions/peace.admin-actions-operations.js",
  "scripts/actions/peace.admin-actions-traffic.js",
  "scripts/actions/peace.admin-actions-devices.js",
  "scripts/actions/peace.admin-actions-policy.js",
  "scripts/actions/peace.admin-actions-system.js",
  "scripts/interface/peace.admin-modal.js",
  "scripts/actions/peace.admin-device-actions.js",
  "scripts/actions/peace.admin-actions.js",
  "icons/game.svg",
  "icons/icon.svg",
  "icons/favicon.svg",
  "icons/favicon.ico",
  "icons/icon-192.png",
  "icons/icon-512.png",
  "manifest.json",
  "scripts/interface/peace.admin-palette.js",
  "scripts/desktop/peace.admin-desktop-licenses.js",
  "scripts/desktop/peace.admin-desktop-security.js",
  "scripts/desktop/peace.admin-desktop-server-state.js",
  "scripts/desktop/peace.admin-desktop-workflow.js",
  "scripts/desktop/peace.admin-desktop-packed-release.js",
  "styles/admin-desktop.css",
  "scripts/pages/peace.admin-pages-production.js",
  "peace.service-worker.js",
  "ui-refresh.html",
  "scripts/application/peace.ui-refresh.js"
];
const ManifestPath = path.join(MODULE_RESOURCE_ROOT, "assets/ui-bundle.json");
function Hash(name, directory = PUBLIC_DIR) {
  // Git on Windows may convert text line endings without changing the UI.
  const source = /\.(?:png|ico)$/i.test(name)
    ? fs.readFileSync(path.join(directory, name))
    : fs.readFileSync(path.join(directory, name), 'utf8').replace(/\r\n/g, '\n');
  return crypto.createHash('sha256').update(source).digest('hex');
}
function Generate(directory = PUBLIC_DIR) {
  return { webAdminVersion: config.WEB_ADMIN_VERSION, uiRevision: config.WEB_UI_REVISION,
    files: Object.fromEntries(FILES.map(name => [name, Hash(name, directory)])) };
}
function Check(directory = PUBLIC_DIR) {
  const issues = [];
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(ManifestPath, 'utf8'));
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest))
      throw new Error('INVALID_UI_MANIFEST');
  }
  catch (_) { issues.push("web/assets/ui-bundle.json"); }
  if (manifest) {
    if (manifest.uiRevision !== config.WEB_UI_REVISION || manifest.webAdminVersion !== config.WEB_ADMIN_VERSION)
      issues.push("web/assets/ui-bundle.json (version)");
    for (const name of FILES) {
      try { if (Hash(name, directory) !== (manifest.files || {})[name]) issues.push(`public/${name}`); }
      catch (_) { issues.push(`public/${name}`); }
    }
  }
  return { ready: issues.length === 0, webAdminVersion: config.WEB_ADMIN_VERSION,
    uiRevision: config.WEB_UI_REVISION, issues };
}
function Unavailable(res, isHead = false) {
  // This fallback is independent of public/index.html and its obsolete JS.
  const html = '<!doctype html><html lang="ko"><meta charset="utf-8"><title>웹 화면 업데이트 확인</title><h1>웹 화면 파일을 확인해주세요.</h1><p>서버와 웹 화면 파일의 버전이 일치하지 않습니다. 현재 배포본의 public 폴더 전체를 교체하고 재배포해주세요.</p><p>기존 운영 데이터는 삭제하지 마세요.</p><a href="/ui-refresh">웹 화면 새로 불러오기</a></html>';
  res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Retry-After': '30' });
  res.end(isHead ? undefined : html);
}
module.exports = { Check, Generate, Unavailable, FILES, ManifestPath };
