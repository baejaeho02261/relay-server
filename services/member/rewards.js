'use strict';
const s=require('./store');
const Day=at=>new Date(at+9*3600000).toISOString().slice(0,10);
const IsDay=value=>typeof value==='string'&&/^\d{4}-\d{2}-\d{2}$/u.test(value)&&Number.isFinite(Date.parse(value+'T00:00:00.000Z'))&&new Date(value+'T00:00:00.000Z').toISOString().slice(0,10)===value;
const defaults={revision:1,attendanceDays:7,attendancePoints:100};
function Rules(){
 const raw=s.DB().settings.rewards||defaults;
 // Only active attendance/exchange settings are projected. Legacy wheel
 // settings remain untouched until an administrator saves the active form.
 return {revision:raw.revision||1,attendanceDays:raw.attendanceDays||7,attendancePoints:raw.attendancePoints||100,
  pointExchange:require('./points').Rules(raw.pointExchange),...(raw.updatedAt?{updatedAt:raw.updatedAt,updatedBy:raw.updatedBy}: {})};
}
function Wallet(p){return {points:p.points||0};}
function Credit(p,amount,kind,reference){
 const key=p.id+':'+kind+':'+reference,old=s.DB().pointLedger[key];if(old)return old;
 const balance=(p.points||0)+amount;if(!Number.isSafeInteger(balance)||balance<0||balance>100000000)s.Fail('POINT_BALANCE_INVALID');
 p.points=balance;
 const row={id:s.Id('PNT'),accountId:p.id,amount,balance,kind,reference,at:Date.now()};s.DB().pointLedger[key]=row;return row;
}
function Attendance(p,now=Date.now()){
 const r=Rules(),a=p.attendance||{},day=Day(now),streak=[day,Day(now-86400000)].includes(a.day)?a.streak||0:0;
 const cycle=streak>0?((streak-1)%r.attendanceDays)+1:0;
 // A stamp is proof of a recorded check-in, not a guess from the streak count.
 // The current thirty-day book follows the streak, independently of rewards.
 const checked=a.day===day,stampGoal=30;
 let bookPosition=streak>0?((streak-1)%stampGoal)+1:0;
 if(!checked&&bookPosition===stampGoal)bookPosition=0;
 const confirmed=new Set((Array.isArray(a.days)?a.days:[]).filter(value=>IsDay(value)&&value<=day));
 if(IsDay(a.day)&&a.day<=day)confirmed.add(a.day);
 const todayAt=Date.parse(day+'T00:00:00.000Z');
 const offset=bookPosition>0?bookPosition-(checked?1:0):0;
 const stampDays=Array.from({length:stampGoal},(_,index)=>{
  const stampDay=new Date(todayAt+(index-offset)*86400000).toISOString().slice(0,10);
  return {number:index+1,day:stampDay,completed:confirmed.has(stampDay),today:stampDay===day};
 });
 return {day,checked:a.day===day,count:a.count||0,streak,at:a.at||0,days:a.days||[],cycle,
  stampDays,stampGoal,stampCompleted:stampDays.filter(row=>row.completed).length,
  goal:r.attendanceDays,rewardPoints:r.attendancePoints,rewardEvery:r.attendanceDays,points:p.points||0};
}
function Check(p){
 const now=Date.now(),day=Day(now),old=p.attendance||{},r=Rules();let reward=null;
 if(old.day!==day){
  // Legacy accounts may only have their last confirmed day. Preserve that
  // proof on the first new check-in without inventing other streak dates.
  const days=[...new Set([...(Array.isArray(old.days)?old.days:[]),old.day,day].filter(value=>IsDay(value)&&value<=day))].sort().slice(-90);
  p.attendance={day,at:now,count:(old.count||0)+1,streak:old.day===Day(now-86400000)?(old.streak||0)+1:1,
   days};
  if(p.attendance.streak%r.attendanceDays===0)reward=Credit(p,r.attendancePoints,'ATTENDANCE',day);
 }
 return {...Read(p),reward};
}
function History(p,body={}){
 return s.Page(Object.values(s.DB().pointLedger).filter(x=>x.accountId===p.id).sort((a,b)=>b.at-a.at||b.id.localeCompare(a.id)),body,20);
}
function Read(p,body={}){return {rules:Rules(),wallet:Wallet(p),attendance:Attendance(p),history:History(p,body),profile:s.PublicProfile(p,true)};}
function SaveRules(body,actor){
 const previous=Rules();if(body.revision!==previous.revision)s.Fail('CONTENT_CHANGED');
 if(Object.keys(body).some(key=>!['action','revision','attendanceDays','attendancePoints','pointExchange'].includes(key)))s.Fail('INPUT_INVALID');
 const attendanceDays=s.Money(body.attendanceDays,1,31),attendancePoints=s.Money(body.attendancePoints,1,100000);
 const pointExchange=require('./points').Validate(body.pointExchange,previous.pointExchange);
 return s.Atomic(()=>{s.DB().settings.rewards={attendanceDays,attendancePoints,pointExchange,revision:previous.revision+1,updatedAt:Date.now(),updatedBy:actor};return Rules();});
}
function Admin(body={}){
 const rows=Object.values(s.DB().pointLedger).sort((a,b)=>b.at-a.at||b.id.localeCompare(a.id));
 return {rules:Rules(),...s.Page(rows.map(x=>({...x,member:s.ProfileById(x.accountId)?s.PublicProfile(s.ProfileById(x.accountId)):{id:'',nickname:'탈퇴 회원'}})),body,30)};
}
module.exports={Day,Rules,Wallet,Credit,Attendance,Check,History,Read,SaveRules,Admin};
