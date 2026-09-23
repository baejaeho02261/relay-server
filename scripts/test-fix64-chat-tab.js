'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const native = path.resolve(__dirname, '../../MoaPlayApp_Android64');
const source = fs.readFileSync(path.join(native, 'MoaPlayDirectMessages.pas'), 'utf8').replace(/^\uFEFF/, '');
const bridge = fs.readFileSync(path.join(native, 'MoaPlayApp.Member.DirectMessages.inc'), 'utf8').replace(/^\uFEFF/, '');
function routine(text, name) {
  const starts = [...text.matchAll(/^(?:constructor|destructor|procedure|function)\s+([\w.]+)/gm)];
  const index = starts.findIndex(x => x[1] === name);
  assert.ok(index >= 0, name);
  return text.slice(starts[index].index, starts[index + 1]?.index ?? text.length).replace(/\{[\s\S]*?\}/g, '');
}
// Execute the production route/search/visibility procedures. The small parser
// deliberately accepts only syntax these routines use and rejects unknown input.
function compile(text, name) {
  let body = routine(text, 'TMoaPlayDirectMessages.' + name);
  body = body.slice(body.search(/\bbegin\b/i));
  const pattern = /\s+|:=|<>|<=|>=|'(?:''|[^'])*'|\d+|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*|[=<>();,]/gy;
  const tokens = []; let offset = 0;
  while (offset < body.length) {
    pattern.lastIndex = offset; const match = pattern.exec(body);
    assert.ok(match, 'unsupported Pascal: ' + body.slice(offset, offset + 60));
    offset = pattern.lastIndex; if (!/^\s+$/.test(match[0])) tokens.push(match[0]);
  }
  let pos = 0;
  const is = word => tokens[pos]?.toLowerCase() === word;
  const take = word => { assert.equal(tokens[pos]?.toLowerCase(), word); pos++; };
  const get = (ctx, name) => name.split('.').reduce((value, part) => value[part], ctx);
  function put(ctx, name, value) { const parts = name.split('.'), field = parts.pop(); parts.reduce((o, p) => o[p], ctx)[field] = value; }
  function call(ctx, name, args) {
    if (name.toLowerCase() === 'assigned') return args[0] != null;
    if (name.toLowerCase() === 'trim') return String(args[0]).trim();
    const parts = name.split('.'), field = parts.pop(), owner = parts.reduce((o, p) => o[p], ctx);
    assert.equal(typeof owner[field], 'function', name); return owner[field](...args);
  }
  function atom() {
    if (is('not')) { pos++; const value = atom(); return ctx => !value(ctx); }
    if (is('(')) { pos++; const value = expression(); take(')'); return value; }
    const token = tokens[pos++]; assert.ok(token);
    if (token.startsWith("'")) return () => token.slice(1, -1).replace(/''/g, "'");
    if (/^\d+$/.test(token)) return () => Number(token);
    if (/^(true|false|nil)$/i.test(token)) return () => token.toLowerCase() === 'nil' ? null : token.toLowerCase() === 'true';
    if (is('(')) {
      pos++; const args = [];
      if (!is(')')) { args.push(expression()); while (is(',')) { pos++; args.push(expression()); } }
      take(')'); return ctx => call(ctx, token, args.map(fn => fn(ctx)));
    }
    return ctx => get(ctx, token);
  }
  function compare() {
    let left = atom();
    if (['=', '<>', '<', '>', '<=', '>='].includes(tokens[pos])) {
      const operator = tokens[pos++], right = atom(), first = left;
      left = ctx => { const a = first(ctx), b = right(ctx); return operator === '=' ? a === b : operator === '<>' ? a !== b : operator === '<' ? a < b : operator === '>' ? a > b : operator === '<=' ? a <= b : a >= b; };
    }
    return left;
  }
  function and() { let value = compare(); while (is('and')) { pos++; const first = value, second = compare(); value = ctx => first(ctx) && second(ctx); } return value; }
  function expression() { let value = and(); while (is('or')) { pos++; const first = value, second = and(); value = ctx => first(ctx) || second(ctx); } return value; }
  const EXIT = Symbol('exit');
  function statement() {
    if (is('begin')) { pos++; const statements = []; while (!is('end')) { statements.push(statement()); if (is(';')) pos++; } take('end'); return ctx => { for (const fn of statements) if (fn(ctx) === EXIT) return EXIT; }; }
    if (is('if')) { pos++; const condition = expression(); take('then'); const yes = statement(); let no; if (is('else')) { pos++; no = statement(); } return ctx => condition(ctx) ? yes(ctx) : no?.(ctx); }
    if (is('exit')) { pos++; return () => EXIT; }
    const field = tokens[pos++]; assert.match(field, /^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$/);
    if (is(':=')) { pos++; const value = expression(); return ctx => { put(ctx, field, value(ctx)); }; }
    const args = [];
    if (is('(')) { pos++; if (!is(')')) { args.push(expression()); while (is(',')) { pos++; args.push(expression()); } } take(')'); }
    return ctx => call(ctx, field, args.map(fn => fn(ctx)));
  }
  const run = statement(); if (is(';')) pos++; assert.equal(pos, tokens.length, 'consume complete production routine'); return run;
}
const prepare = compile(source, 'PrepareRoute'), search = compile(source, 'SearchChanged'), searchTick = compile(source, 'SearchTick'), folder = compile(source, 'SetFolder'), visible = compile(source, 'GetVisible'), back = compile(source, 'Back');
function state() {
  const ctx = {
    FRenderBusy: false, FSearch: { Text: '', promptUpdates: 0, RefreshPrompt() { this.promptUpdates++; } }, FQuery: '', FFolder: 'messages', FListOffset: 20,
    FReadBusy: true, FReadAction: 'dm', FReadInvalidated: true, FList: { items: [{ id: 'old' }] }, FPage: { Visible: true }, FMenu: { Visible: false }, FConfirm: { Visible: false },
    FSignature: 'old', FDirty: false, FRoutePending: false, FSearchTimer: { Enabled: false }, FNextPoll: 100, FListMode: true,
    FCard: { Visible: true }, FHost: { Visible: true }, FDeleteID: '', paints: 0, headerUpdates: 0, fetches: 0, shown: 0,
    draft: '보내지 않은 메시지', searchIdentity: null,
    FreeAndNil() { this.FList = null; }, PrepareRoute() { prepare(this); }, UpdateListHeader() { this.headerUpdates++; }, QueuePaint() { this.paints++; },
    Fetch() { this.fetches++; }, ShowList() { this.shown++; this.FListMode = true; }
  };
  ctx.searchIdentity = ctx.FSearch;
  Object.defineProperty(ctx, 'Visible', { get() { visible(this); return this.Result; } }); return ctx;
}
let ctx = state();
for (const value of ['  ', 'M', 'Mo', 'Moa', 'Moa 한글 ']) { ctx.FSearch.Text = value; search(ctx); }
assert.equal(ctx.FQuery, 'Moa 한글'); assert.equal(ctx.FListOffset, 0); assert.equal(ctx.fetches, 0, 'keystrokes are coalesced before the network request');
assert.equal(ctx.FPage.Visible, false, 'old query rows hide before another response can arrive');
assert.equal(ctx.FSearch, ctx.searchIdentity, 'IME editor survives every search change'); assert.equal(ctx.draft, '보내지 않은 메시지');
assert.equal(ctx.FSearchTimer.Enabled, true); searchTick(ctx); assert.equal(ctx.fetches, 1); assert.equal(ctx.FSearchTimer.Enabled, false);
const before = ctx.paints; search(ctx); assert.equal(ctx.paints, before, 'same trimmed query does not invalidate layout');
ctx.Value = 'requests'; folder(ctx); assert.equal(ctx.FFolder, 'requests'); assert.equal(ctx.fetches, 2); assert.equal(ctx.FListOffset, 0); assert.equal(ctx.FQuery, 'Moa 한글');
folder(ctx); assert.equal(ctx.fetches, 2, 'same tab does not reset the current request');
ctx.Value = 'all'; folder(ctx); assert.equal(ctx.FFolder, 'requests', 'UI cannot fake requests by querying the all-thread folder');
ctx.FHost.Visible = false; assert.equal(ctx.Visible, false, 'a hidden host cannot pause normal app polling indefinitely'); searchTick(ctx); assert.equal(ctx.fetches, 2);
ctx.FHost.Visible = true; ctx.FListMode = false; back(ctx); assert.equal(ctx.shown, 1); assert.equal(ctx.draft, '보내지 않은 메시지');
back(ctx); assert.equal(ctx.shown, 1, 'root list does not hide the entire embedded tab');
ctx.FMenu.Visible = true; back(ctx); assert.equal(ctx.FMenu.Visible, false); assert.equal(ctx.shown, 1);
// Reordering a response from search or tab changes must not mutate active data.
const reply = routine(source, 'TMoaPlayDirectMessages.Reply');
const stale = /if Assigned\(Data\) and \(\(([\s\S]*?)\)\) then begin Obj\.Free;Exit;end;/.exec(reply);
assert.ok(stale, 'response identity guard before pending-state changes');
const reject = new Function('Data', 'FFolder', 'FQuery', 'FListOffset', 'DMTxt', 'DMNum', 'return ((' + stale[1].replace(/<>/g, '!==').replace(/\bor\b/g, '||') + '));');
const txt = (o, key, fallback = '') => o[key] ?? fallback, num = (o, key) => o[key] ?? 0;
for (const mode of ['messages', 'requests']) for (const query of ['', 'ABC', '한글']) for (const page of [0, 20]) {
  const data = { folder: mode, q: query, offset: page };
  assert.equal(reject(data, mode, query, page, txt, num), false);
  assert.equal(reject(data, mode === 'messages' ? 'requests' : 'messages', query, page, txt, num), true);
  assert.equal(reject(data, mode, query + 'x', page, txt, num), true);
  assert.equal(reject(data, mode, query, page + 20, txt, num), true);
}
assert.ok(reply.indexOf("DMTxt(Data,'folder'") < reply.indexOf('WasPending:='), 'stale list cannot clear a newer request state');
assert.match(routine(source, 'TMoaPlayDirectMessages.Fetch'), /Body\.AddPair\('folder',FFolder\);Body\.AddPair\('q',FQuery\)/);
assert.match(routine(source, 'TMoaPlayDirectMessages.RenderThread'), /DMBool\(Thread,'requestIncoming'\)[\s\S]*'accept'/);
assert.match(routine(source, 'TMoaPlayDirectMessages.Click'), /SendRequest\('dm\.accept',Body,True\)/, 'accept uses the same durable mutation lane');
assert.match(routine(source, 'TMoaPlayDirectMessages.RenderSuggestions'), /DMArr\(FList,'suggestions'\)/, 'recommendations use real server profiles');
assert.match(routine(source, 'TMoaPlayDirectMessages.RenderSuggestions'), /'follow\|'/);
assert.match(routine(bridge, 'TMoaPlayForm.HubRenderChats'), /\.Attach\(FHubChatHost\)/);
assert.doesNotMatch(bridge, /\.Attach\(FFinalPanel\)/, 'no full-screen overlay parent');
assert.match(routine(bridge, 'TMoaPlayForm.HubDirectMessagesAction'), /FDashboardActiveTab:=3;HubNavigate\('chats'\)/);
assert.match(routine(bridge, 'TMoaPlayForm.HubDirectMessagesResize'), /FHubChatHost\.AbsoluteToLocal/, 'keyboard coordinates account for embedded titlebar offset');
assert.match(routine(source, 'TMoaPlayDirectMessages.LayoutWindow'), /FHeader\.Visible:=not FListMode/, 'list has no duplicate titlebar');
assert.doesNotMatch(routine(source, 'TMoaPlayDirectMessages.Render'), /FreeAndNil\(FSearch\)|FreeAndNil\(FInput\)/);
// Verify the visibility test detects the original detached-overlay guard.
const badVisible = compile(source.replace(' and Assigned(FHost) and FHost.Visible', ''), 'GetVisible');
ctx.FHost.Visible = false; badVisible(ctx); assert.equal(ctx.Result, true); visible(ctx); assert.equal(ctx.Result, false);
for (const text of [source, bridge]) assert.ok(!text.replace(/\r\n/g, '').includes('\n'), 'native CRLF');
console.log('FIX64 chat tab PASS: production search/tab/debounce/visibility/back state, stale response isolation, embedded host and keyboard mapping, retained composer, real requests/acceptance and follow recommendations.');
