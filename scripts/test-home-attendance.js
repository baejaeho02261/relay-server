'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moa-fix75-attendance-'));
process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const s=require('../services/member/store'),rewards=require('../services/member/rewards'),home=require('../services/member/home');
const realNow=Date.now,now=Date.parse('2026-09-28T03:00:00.000Z'),day=offset=>rewards.Day(now+offset*86400000);
const completed=data=>data.stampDays.filter(row=>row.completed).map(row=>row.day);
try{
 Date.now=()=>now;
 const p=s.Account({installationDeviceKey:'FIX75_ATTENDANCE_DATES'});p.points=7;p.balance=8300;p.eventSpins=2;
 let view=rewards.Attendance(p,now);
 assert.equal(view.stampDays.length,30);assert.equal(view.stampDays[0].day,day(0));assert.equal(view.stampDays[0].today,true);assert.equal(view.stampCompleted,0);
 assert.equal(new Set(view.stampDays.map(row=>row.day)).size,30,'every visible date is unique');
 p.attendance={day:day(0),at:now,count:80,streak:5,days:[day(-4),day(0),day(0),day(1),'bad-date']};
 const before=JSON.stringify(p);view=rewards.Attendance(p,now);
 assert.equal(view.streak,5);assert.deepEqual(completed(view),[day(-4),day(0)],'missing historical records never become fake completed stamps');
 assert.equal(view.stampCompleted,2);assert.equal(view.stampDays[4].today,true);assert.equal(JSON.stringify(p),before,'projection does not repair or mutate member history');
 assert.equal(view.stampDays[5].completed,false,'future history entry cannot complete a future stamp');
 p.attendance={day:day(-1),at:now-86400000,count:6,streak:6,days:Array.from({length:6},(_,i)=>day(i-6))};
 view=rewards.Attendance(p,now);assert.equal(view.checked,false);assert.equal(view.stampDays[6].today,true);assert.equal(view.stampCompleted,6);
 const points=p.points,balance=p.balance,spins=p.eventSpins;
 const first=s.Atomic(()=>rewards.Check(p)),second=s.Atomic(()=>rewards.Check(p));
 assert.equal(first.attendance.checked,true);assert.equal(first.attendance.stampDays[6].completed,true);assert.equal(first.attendance.stampDays[6].today,true);
 assert.equal(first.attendance.stampCompleted,7);assert.equal(second.attendance.stampCompleted,7);assert.equal(p.attendance.count,7,'duplicate check does not create another attendance');
 assert.equal(p.points,points+rewards.Rules().attendancePoints,'reward is retained and credited once');assert.equal(p.balance,balance);assert.equal(p.eventSpins,spins);
 assert.equal(Object.values(s.DB().pointLedger).filter(row=>row.accountId===p.id&&row.kind==='ATTENDANCE').length,1);
 const homeBefore=JSON.stringify(s.DB()),summary=home.Read(p);
 assert.deepEqual(summary.attendance.stampDays,second.attendance.stampDays,'home and stamp screen receive the same attendance state');assert.deepEqual(summary.catalog,require('../services/member/commerce').Catalog({summary:true},p).items,'home uses the canonical discovery projection including density-aware gallery media');assert.equal(JSON.stringify(s.DB()),homeBefore,'home attendance is read-only');
 const legacy=s.Account({installationDeviceKey:'FIX75_LEGACY_DAY_ONLY'});legacy.attendance={day:day(-1),at:now-86400000,count:2,streak:2};
 assert.deepEqual(completed(rewards.Attendance(legacy,now)),[day(-1)]);
 const legacyChecked=s.Atomic(()=>rewards.Check(legacy));
 assert.deepEqual(completed(legacyChecked.attendance),[day(-1),day(0)],'a new check-in preserves the old confirmed date when legacy days is absent');
 assert.deepEqual(legacy.attendance.days,[day(-1),day(0)]);assert.equal(legacyChecked.attendance.streak,3);
 assert.equal(legacyChecked.attendance.stampDays[0].completed,false,'the unknown earlier streak day is still not fabricated');
 legacy.attendance.days=[day(-1),day(-1),'2026-02-30','not-a-day',day(1)];legacy.attendance.day=day(-1);
 const recovered=s.Atomic(()=>rewards.Check(legacy));assert.deepEqual(recovered.attendance.days,[day(-1),day(0)],'persisted dates are valid, unique and never in the future');
 p.attendance={day:day(-1),at:now-86400000,count:30,streak:30,days:Array.from({length:30},(_,i)=>day(i-30))};
 view=rewards.Attendance(p,now);assert.equal(view.stampDays[0].today,true);assert.equal(view.stampCompleted,0,'next book starts clear after thirty completed days');
 p.attendance.day=day(-2);view=rewards.Attendance(p,now);assert.equal(view.streak,0);assert.equal(view.stampCompleted,0,'broken streak does not paint old completion onto a new book');
 // KST midnight is authoritative, even when the handset timezone differs.
 p.attendance={day:'2026-09-28',at:Date.parse('2026-09-28T14:59:59Z'),count:1,streak:1,days:['2026-09-28']};
 assert.equal(rewards.Attendance(p,Date.parse('2026-09-28T14:59:59Z')).checked,true);
 view=rewards.Attendance(p,Date.parse('2026-09-28T15:00:00Z'));assert.equal(view.checked,false);assert.equal(view.stampDays[1].day,'2026-09-29');assert.equal(view.stampDays[1].today,true);
 const native=path.resolve(__dirname,'../../MoaPlayApp_Android64');
 const ui=fs.readFileSync(path.join(native,'MoaPlayApp.Member.Home.inc'),'utf8'),stamp=fs.readFileSync(path.join(native,'MoaPlayApp.Member.Rewards.inc'),'utf8'),rank=fs.readFileSync(path.join(native,'MoaPlayApp.Member.History.inc'),'utf8');
 const my=ui.slice(ui.indexOf("Card:=StartCard('MY'"),ui.indexOf("Detail:=MemberFormat('연속"));
 assert.ok(my.includes("WalletPanel:=HubTextAction(Card"));assert.ok(my.includes("HubTextAction(WalletPanel,'','home.toggle|wallet'"));
 assert.ok(my.includes("HubTextAction(WalletPanel,'','points',12,62,WalletPanel.Width-24,58)"));assert.ok(!my.includes("'wheel'"));
 assert.ok(my.includes('WalletPanel.Height:=132'));assert.ok(my.includes('FinishRow(WalletPanel)'),'expanded wallet owns point balance and contributes its full height');
 const attendance=ui.slice(ui.indexOf("Card:=StartCard('출석 체크'"),ui.indexOf("Card:=StartCard('출석 랭킹'"));
 assert.ok(attendance.includes("HubButton(Card,Title,'attendance'"));assert.ok(!attendance.includes('attendance.check'));assert.ok(!attendance.includes("'wheel'"));
 const ranking=ui.slice(ui.indexOf("Card:=StartCard('출석 랭킹'"),ui.indexOf("Card:=StartCard('새로운 소식'"));
 for(const key of ['online','todayPosts','todayComments']){assert.ok(ranking.includes("HubNumber(Counts,'"+key+"')"));assert.ok(!attendance.includes("HubNumber(Counts,'"+key+"')"));}
 assert.ok(ui.includes('Button.Height:=HubFillGameCard(Button,Item,16);FinishRow(Button)'),'home discovery uses the shared renderer inside its own section');
 // Evaluate the actual layout expressions against wrapped native text heights,
 // including four/six-line translated titles on 280px cards.
 const expr=(name,args)=>new Function(...args,'return '+stamp.match(new RegExp(name+':=([^;]+)'))[1].replace(/\bMax\(/gu,'Math.max('));
 const detailY=expr('DetailY',['TitleH']),streakY=expr('StreakY',['DetailY','DetailH']),heroH=expr('HeroH',['StreakY']);
 for(const titleHeight of [28,56,84,112,168])for(const detailHeight of [16,32,48]){
  const subtitleTop=detailY(titleHeight),streakTop=streakY(subtitleTop,detailHeight),posterHeight=heroH(streakTop);
  assert.ok(subtitleTop>=58+titleHeight+16);assert.ok(streakTop>=subtitleTop+detailHeight+14);assert.ok(posterHeight+12>=streakTop+22+12);
 }
 assert.ok(stamp.includes('TitleH:=HubAttendanceTextHeight(Title,TitleW,TitleSize,True)'));assert.ok(stamp.includes('HubLabel(C,Title,30,58,TitleW,TitleH,TitleSize)'));
 const section=stamp.slice(stamp.indexOf('function HubAttendanceSectionTitle'),stamp.indexOf('procedure HubAttendancePoster'));
 assert.ok(section.includes('HubAttendanceTextHeight(Title,Card.Width-124,15,True)'));assert.ok(section.includes('HubLabel(Card,Title,42,Top,Card.Width-124,Result,15)'));
 assert.ok(stamp.includes("Completed:=HubBool(Day,'completed')"));assert.ok(stamp.includes('if Completed then HubAttendanceDoneStamp'));assert.ok(!stamp.includes('I<Completed'),'done stamps do not infer completion from index or streak');
 assert.ok(rank.includes('DiscSize:=Min(18,Size);Inset:=(Size-DiscSize)/2'));assert.ok(rank.includes('Disc.SetBounds(X+Inset,Y+Inset,DiscSize,DiscSize)'),'every rank marker keeps the original center with a smaller circle');
 for(const name of ['MoaPlayApp.Member.Home.inc','MoaPlayApp.Member.Rewards.inc','MoaPlayApp.Member.History.inc']){
  const bytes=fs.readFileSync(path.join(native,name));assert.equal(bytes.subarray(0,3).toString('hex'),'efbbbf');assert.ok(!bytes.toString('utf8').replace(/\r\n/gu,'').includes('\n'),name+' keeps CRLF');
 }
 console.log('FIX75 HOME/ATTENDANCE PASS: nested wallet tiles, separate stamp shortcut, ranking counts, identical discovery renderer geometry, centered smaller rank discs, dated actual-only completion stamps, KST rollover, reward/retry integrity, read-only shared state.');
}finally{Date.now=realNow;fs.rmSync(dir,{recursive:true,force:true});}
