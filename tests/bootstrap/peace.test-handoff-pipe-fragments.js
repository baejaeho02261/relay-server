'use strict';

// Source-contract checks for the Windows probe and production helpers. The
// anonymous pipes, Delphi compiler, and Windows thread scheduler are NOT_RUN here.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const nativeRoot = path.resolve(__dirname, '../../../Railway');
const read = relative => fs.readFileSync(path.join(nativeRoot, relative), 'utf8');
const handoff = read('Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas');
const probe = read('Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc');
const entry = read('Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeProbe.dpr');
const project = read('Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeProbe.dproj');
const props = read('Cozy.Tests/Cozy.Build/Cozy.ManualProbe.props');
const section = (text, start, end) => {
  const a = text.indexOf(start), b = text.indexOf(end, a + start.length);
  assert.ok(a >= 0 && b > a, `Missing source section: ${start}`);
  return text.slice(a, b);
};
let passed = 0;
function check(name, action) { action(); passed++; console.log('PASS ' + name); }

check('the production last read and EOF cannot finish an expired absolute budget', () => {
  const exact = section(handoff, 'procedure ReadExact(', 'procedure RequirePipeEnd(');
  assert.match(exact, /ReadFile\([\s\S]*?Check\(Remaining\(Deadline\) > 0,[\s\S]*?Inc\(Offset/);
  const eof = section(handoff, 'procedure RequirePipeEnd(', 'procedure WritePublicFrame(');
  assert.match(eof, /repeat\s+Check\(Remaining\(Deadline\) > 0,[\s\S]*?PeekNamedPipe/);
  assert.match(eof, /ErrorCode = ERROR_BROKEN_PIPE[\s\S]*?Check\(Remaining\(Deadline\) > 0,[\s\S]*?Exit;/);
  assert.doesNotMatch(exact + eof, /Deadline\s*:=/);
});

check('ReadHello publishes validated outputs atomically and wipes failed output', () => {
  const hello = section(handoff, 'function ReadHello(', 'function Transcript(');
  assert.match(hello, /Result := nil; ChildKeyID := ''; Nonce := ''; Wrapping := nil;/);
  assert.equal((hello.match(/ReadExact\([^;]+Deadline\);/g) || []).length, 2);
  assert.match(hello, /RequirePipeEnd\(Pipe, Deadline\);[\s\S]*?CandidateKeyID := DevicePublicKeyID\(Signing\);[\s\S]*?Check\(Remaining\(Deadline\) > 0,[\s\S]*?ChildKeyID := CandidateKeyID/);
  assert.match(hello, /except\s+WipeBytes\(Result\); WipeBytes\(Wrapping\);\s+WipeText\(ChildKeyID\); WipeText\(Nonce\);\s+raise;/);
  assert.match(hello, /finally\s+WipeText\(Signing\); WipeText\(CandidateKeyID\); WipeText\(CandidateNonce\);\s+WipeBytes\(CandidateWrapping\);/);
  assert.doesNotMatch(hello, /Deadline\s*:=/);
});

check('fragment writers use explicit bounded context and cancellable delays', () => {
  assert.match(probe, /THandoffProbeFragmentWriter = class/);
  assert.match(probe, /Length\(Wire\) <= 4096/);
  assert.match(probe, /CreatePipe\(ReadPipe, WritePipe, nil, MaxHandoffBytes\)/);
  assert.match(probe, /WaitForSingleObject\(Writer.CancelEvent, Writer.GapMs\)/);
  assert.match(probe, /WaitForSingleObject\(Writer.CancelEvent, Writer.HoldOpenMs\)/);
  assert.match(probe, /BeginThread\(nil, 0, WriteHandoffProbeFragments, Writer, 0, ThreadID\)/);
  assert.doesNotMatch(probe, /CreateAnonymousThread|TThread\.Create|reference to|TerminateThread|CreateProcess/);
});

check('writer start gate arms a single reader deadline before later fragments', () => {
  const writer = section(probe, 'function WriteHandoffProbeFragments(', 'function HandoffProbeByteFragments(');
  assert.match(writer, /SetEvent\(Writer.FirstWriteEvent\)[\s\S]*?WaitForMultipleObjects\(2, @StartHandles\[0\], False, 3000\)/);
  const run = section(probe, 'procedure RunHandoffFragmentCase(', 'function RunFragmentedHandoffPipeContracts:');
  assert.match(run, /WaitForSingleObject\(Writer.FirstWriteEvent, 2000\)[\s\S]*?Deadline := StartedAt \+ BudgetMs;\s+Check\(SetEvent\(Writer.ContinueEvent\)/);
  assert.equal((run.match(/Deadline\s*:=/g) || []).length, 1);
  assert.match(run, /ReadHello\(ReadPipe, 0, Deadline, KeyID, Nonce, Wrapping\)/);
  assert.match(run, /ReadHandoffProbeFrame\(ReadPipe, Length\(Expected\), Deadline\)/);
});

check('all exceptions cancel and join before shared memory or handles are released', () => {
  const run = section(probe, 'procedure RunHandoffFragmentCase(', 'function RunFragmentedHandoffPipeContracts:');
  assert.match(run, /finally[\s\S]*?SetEvent\(Writer.CancelEvent\);\s+Joined := WaitForSingleObject\(WriterThread, 2000\) = WAIT_OBJECT_0;[\s\S]*?if not Joined then Halt\(86\);/);
  assert.match(run, /if \(WriterThread <> 0\) and not Joined then[\s\S]*?WaitForSingleObject\(WriterThread, 2000\) <> WAIT_OBJECT_0 then Halt\(86\);[\s\S]*?Close\(WriterThread\); Writer.Free;/);
  assert.match(run, /GetExitCodeThread\(WriterThread, ExitStatus\) and \(ExitStatus = 0\)/);
  assert.match(run, /Writer.PipeClosed and \(Writer.Pipe = 0\)/);
  for (const handle of ['WriterThread', 'Writer.CancelEvent', 'Writer.FirstWriteEvent', 'Writer.ContinueEvent', 'ReadPipe'])
    assert.ok(run.includes(`CloseHandoffProbeHandle(${handle});`), handle);
  assert.match(run, /WipeBytes\(Writer.Bytes\);[\s\S]*?PROBE_FRAGMENT_REMAINDER/);
  assert.match(run, /Length\(Output\) = 0[\s\S]*?Length\(Wrapping\) = 0[\s\S]*?KeyID = ''[\s\S]*?Nonce = ''[\s\S]*?PROBE_FRAGMENT_PARTIAL_OUTPUT/);
});

check('two-phase reads use real helpers and protect both buffer boundaries', () => {
  const frame = section(probe, 'function ReadHandoffProbeFrame(', 'procedure RunHandoffFragmentCase(');
  assert.match(frame, /ReadExact\(Pipe, Candidate, 4, 4, Deadline\);\s+ReadExact\(Pipe, Candidate, 8, Count - 4, Deadline\);\s+RequirePipeEnd\(Pipe, Deadline\);/);
  assert.match(frame, /Candidate\[I\] = \$A5[\s\S]*?Candidate\[Count \+ 4 \+ I\] = \$A5/);
  assert.match(frame, /except\s+WipeBytes\(Result\);\s+raise;/);
  assert.match(frame, /finally\s+WipeBytes\(Candidate\);/);
});

check('Windows cases cover every small-frame cut, actual hello bytes and maximum frame', () => {
  const cases = section(probe, 'function RunFragmentedHandoffPipeContracts:', 'function RunHandoffPipeContracts:');
  assert.match(cases, /for Cut := 1 to Length\(Input\) - 1 do/);
  assert.match(cases, /SetLength\(Changed, 4096\);[\s\S]*?RunHandoffFragmentCase\(Changed, Changed, HandoffProbeByteFragments\(Length\(Changed\)\)/);
  assert.match(cases, /Hello := BuildHello\(0, Device, Cipher, Nonce\);[\s\S]*?RunHandoffFragmentCase\(Hello, Hello, HandoffProbeByteFragments\(Length\(Hello\)\)/);
  assert.match(cases, /for Cut := SizeOf\(TChildHelloHeader\) - 1 to SizeOf\(TChildHelloHeader\) \+ 1 do/);
  assert.match(probe, /PROBE_PUBLIC_FRAME_OVERSIZE_ACCEPTED/);
});

check('Windows negative cases cover delayed overflow, truncation, EOF and shared budget', () => {
  const cases = section(probe, 'function RunFragmentedHandoffPipeContracts:', 'function RunHandoffPipeContracts:');
  assert.match(cases, /25, 0, 80, False, True/);
  assert.match(cases, /0, 500, 80, False, True/);
  assert.match(cases, /30, 0, 3000, False, True/);
  assert.match(cases, /RequirePipeEnd\(ReadPipe, GetTickCount64\)/);
  assert.match(cases, /Copy\(Hello, 0, SizeOf\(TChildHelloHeader\) - 1\)/);
  assert.match(cases, /Copy\(Hello, 0, Length\(Hello\) - 1\)/);
  assert.match(cases, /60, 0, 80, True, True/);
  assert.match(cases, /Header.Nonce\[63\] := Ord\('G'\)/);
});

check('the existing Windows entry and project include the real test-only unit', () => {
  assert.match(handoff, /\{\$IFDEF GAME_HANDOFF_CONTRACT_TESTS\}\s*\{\$I \.\.\\\.\.\\Cozy.Tests\\Cozy.Handoff\\Cozy.HandoffPipeContracts.inc\}/);
  assert.match(entry, /\{\$IFNDEF GAME_HANDOFF_CONTRACT_TESTS\}/);
  assert.match(entry, /SealApiPointerStorage;/);
  assert.match(entry, /RunHandoffPipeContracts/);
  assert.match(project, /<TestOnlyDefine>GAME_HANDOFF_CONTRACT_TESTS<\/TestOnlyDefine>/);
  assert.match(props, /Cozy.Source\\Cozy.Handoff/);
  assert.match(props, /Cozy.Tests\\Cozy.Handoff/);
  assert.match(probe, /Inc\(Result, RunFragmentedHandoffPipeContracts\)/);
});

console.log(`Handoff fragmented-pipe source contracts: ${passed} passed; Delphi/Windows runtime NOT_RUN.`);
