'use strict';
// Native source contracts and row geometry; FMX rendering requires the RAD build.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const dir = path.join(__dirname, '../../MoaPlayApp_Android64');
const read = name => fs.readFileSync(path.join(dir, name), 'utf8');
const feed = read('MoaPlayApp.Member.Feed.inc');
const shop = read('MoaPlayApp.Member.Shop.inc');
const social = read('MoaPlayApp.Member.Social.inc');
const compose = read('MoaPlayApp.Member.Compose.inc');
const tools = read('MoaPlayApp.Member.PostTools.inc');
const dashboard = read('MoaPlayApp.Dashboard.inc');
const actions = read('MoaPlayApp.Member.Actions.inc');
const flow = read('MoaPlayApp.Member.Flow.inc');
const identity = read('MoaPlayProviderMark.pas');
function method(source, name) {
  const re = new RegExp('(?:function|procedure) TMoaPlayForm\\.' + name + '\\b');
  const at = source.search(re); assert(at >= 0, name + ' must exist');
  const body = source.slice(at); const next = body.slice(10).search(/\n(?:function|procedure) TMoaPlayForm\./);
  return next < 0 ? body : body.slice(0, next + 10);
}
const status = method(feed, 'HubPostStatusRow');
assert.match(status, /Box\.HitTest:=False;Box\.AutoCapture:=False/);
assert.match(status, /L\.HitTest:=False/);
assert(!/Hub(?:Button|Reaction|IconButton)\(/.test(status), 'display chips must not recreate social action controls');
for (const key of ['comments', 'reposts', 'shares']) assert(status.includes("'" + key + "'"));
assert.match(status, /HubVerifiedProvider\(Author\)/);
assert.match(identity, /accountLinked/); assert.match(identity, /accountVerified/);
const fill = method(feed, 'HubFillPostCard');
assert.match(fill, /HubProviderMark\(Header,Author,L,Available\)/);
assert.match(fill, /HubPostStatusRow\(C,Post,Y\)/);
assert(!/post\.toggle|HubPostToggle/.test(fill), 'body stays expanded');
const open = method(feed, 'HubPostOpen');
assert.match(open, /HubUseFeedItem\(Kind,ID\)/);
assert.match(open, /FHubCommentTokenPostID:='';HubNavigate\('comments','',ID\)/);
assert.match(method(feed, 'HubPostCard'), /C\.OnOpen:=HubPostOpen/);
assert.match(method(feed, 'HubPostHold'), /HubUseFeedItem\('REPOST_TICKET',ID\)/);
assert(!method(feed, 'HubPostHold').includes("HubSendSocial('repost.set'"), 'hold must use the same purchase redemption path');
const use = method(shop, 'HubUseFeedItem');
for (const id of ['COMMENT_TICKET', 'REPOST_TICKET', 'SHARE_TICKET']) {
  assert(shop.includes("'" + id + "'"), id + ' registered');
}
assert.match(use, /not FState\.Connected or not MemberAccessReady/);
assert.match(use, /FHubCommentTokenPostID:=PostID/);
assert.match(use, /HubSendSocial\('repost.set',Body\)/);
assert.match(use, /HubOpenPostShare\(PostID,'',0\)/);
const shareSelection=use.split("if Kind='SHARE_TICKET' then begin")[1].split('end;')[0];
assert(!shareSelection.includes("FHubFeedItemKind:=''"), 'dismissing recipient sheet must preserve the visible selection mode');
assert.match(tools,/procedure HubDeactivateSheetScopes[\s\S]*TMoaPlayTouchScope\(Node.TagObject\).Enabled:=False/);
assert.match(tools,/HubDeactivateSheetScopes\(FHubOverlay.Children\[I\]\);[\s\S]*Visible:=False/);
assert.match(social,/HubDeactivateSheetScopes\(FHubOverlay\);FHubOverlay.Visible:=False/);
const shareAck=flow.split("else if Action='post.share' then begin")[1].split("else if Action='bookmark.set'")[0];
assert.match(shareAck,/FHubFeedItemKind:='';if FHubView='feed' then begin FHubLocalRender:=True;HubRender/);


assert(!/TJSONNumber\.Create\([^)]*-1|inventory.*AddPair/i.test(use), 'only the server spends inventory');
assert.match(social, /FHubFeedItemKind:=ID;FDashboardActiveTab:=2;HubNavigate\('feed'\)/);
assert.match(dashboard, /FHubCommentBar\.Visible:=.*FHubCommentTokenPostID=FHubPostID/);
assert.match(actions, /FHubCommentTokenPostID<>FHubPostID/);
assert.match(flow, /if NewView<>'feed' then FHubFeedItemKind:=''/);
assert.match(flow, /Action='comment\.create'.*FHubCommentTokenPostID=ReplyPostID.*FHubCommentTokenPostID:=''/);
assert.match(tools, /Body\.AddPair\('id',ItemID\);Body\.AddPair\('memberId',Parts\[2\]\)/);
assert.match(tools, /HubCloseOverlay\(nil\);HubSendSocial\('post.share',Body\)/);
// Title/body text and the first attachment icon have the same local X = 12.
assert.match(compose, /FHubMemo\.SetBounds\(12,4,Box\.Width-24,48\)/);
assert.match(compose, /Tools\.SetBounds\(12,0,C\.Width-24,44\)/);
assert.match(compose, /AddMemberSvg\(B,B,Icon,0,12,20,20\)/);
assert.match(compose, /Attachment\('gif','GIF','post.gif',0\)/);
// Exercise the same variable-width chip flow with wide/narrow text, font sizes,
// compact counts and long account-label translations. The row may wrap; it must
// never overlap the preceding chip or escape either card inset.
let cases = 0;
for (const width of [216, 240, 280, 296, 320, 360, 414, 480, 632]) {
  for (const scale of [1, 1.15, 1.3, 1.5, 2]) {
    for (const sizes of [[30, 32, 62, 32], [40, 60, 94, 66], [62, 108, 130, 110], [0, 42, 60, 45]]) {
      const limit = width - 32; let x = 16, y = 4, previous = null;
      for (const size of sizes.filter(Boolean)) {
        const w = Math.min(limit, Math.max(58, size * scale + 38));
        if (x > 16 && x + w > width - 16) { x = 16; y += 34; previous = null; }
        assert(x >= 16 && x + w <= width - 16 + 0.0001);
        if (previous) assert(x >= previous.end + 6);
        previous = { end: x + w }; x += w + 6;
      }
      assert(y + 28 <= 134, 'at most four rows'); cases++;
    }
  }
}
console.log('PASS feed/shop native contracts; ' + cases + ' responsive chip layouts.');
