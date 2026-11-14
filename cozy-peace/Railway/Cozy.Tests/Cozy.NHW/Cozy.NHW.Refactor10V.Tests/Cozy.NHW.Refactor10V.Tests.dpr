program CozyNHW_Refactor10V_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build this project with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_HARDENING_TESTS}
  {$MESSAGE FATAL 'Open the Refactor10V DPROJ; test defines must apply to every unit.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5_TESTS}
  {$MESSAGE FATAL 'NHW_NATIVE5_TESTS is required.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5B_TESTS}
  {$MESSAGE FATAL 'NHW_NATIVE5B_TESTS is required.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5D_TESTS}
  {$MESSAGE FATAL 'NHW_NATIVE5D_TESTS is required.'}
{$ENDIF}

uses
  Winapi.Windows, System.SysUtils, System.Classes, System.Generics.Collections,
  Cozy.NHW.Types, Cozy.NHW.Native, Cozy.NHW.WinPointers,
  Cozy.NHW.Handles, Cozy.NHW.HandleSnapshot.Decoder,
  Cozy.NHW.Process, Cozy.NHW.ProcessList.Decoder,
  Cozy.NHW.RegistryNative,
  Cozy.NHW.ETWNative, Cozy.NHW.ETW.PropertyDecoders,
  Cozy.NHW.NetworkNative, Cozy.NHW.NetworkSnapshot.Decoders,
  Cozy.NHW.SelfNative,
  Cozy.NHW.ExceptionNative, Cozy.NHW.ExceptionRules,
  Cozy.NHW.IPCNative, Cozy.NHW.IPCSnapshot.Decoder,
  Cozy.NHW.ThreadOriginNative, Cozy.NHW.ThreadOrigin.Rules,
  Cozy.NHW.StackNative;

type
  TExistingGroup = function(out Failure: string; out Checks: Integer): Boolean;
  TExceptionCapture = function(out Snapshot: TExceptionImageState): Boolean;
  TSelfCapture = function(out Digest: UInt64; out Entries: Cardinal): Boolean;
  TRegistryOpen = function(const NativePath: string): THandle;

var
  NewChecks, InheritedChecks, Groups: Integer;

procedure Check(Value: Boolean; const Name: string);
begin
  Inc(NewChecks);
  if not Value then raise Exception.Create(Name);
end;

procedure Existing(const Name: string; Test: TExistingGroup);
var Failure: string; Count: Integer;
begin
  Failure := ''; Count := 0;
  if not Test(Failure, Count) then raise Exception.Create(Name + ': ' + Failure);
  Inc(InheritedChecks, Count);
end;

procedure Done(const Name: string);
begin
  Inc(Groups);
  Writeln('PASS: ', Name);
end;

procedure TestHandles;
var
  Data: TBytes;
  Holders: TDictionary<string, TTargetHolder>;
  Observed: TList<TObservedHandle>;
  Tokens: TList<TObservedTokenHandle>;
  Total: NativeUInt;
  TokenOK, ThreadOK: Boolean;
  Reason: string;
begin
  Existing('handle parser fixtures', TestHandleHardening);
  Holders := nil; Observed := nil; Tokens := nil;
  try
    Holders := TDictionary<string, TTargetHolder>.Create;
    Observed := TList<TObservedHandle>.Create;
    Tokens := TList<TObservedTokenHandle>.Create;
    Observed.Add(Default(TObservedHandle));
    Tokens.Add(Default(TObservedTokenHandle));
    Data := nil;
    Check(not ParseHandleSnapshot(Data, 10, 20, 30, nil, False,
      Holders, Observed, 0, Tokens, TokenOK, ThreadOK, Total, Reason), 'truncated handle snapshot');
    Check((Observed.Count = 0) and (Tokens.Count = 0) and (Holders.Count = 0), 'parser clears failed observations');
    Check((Total = 0) and not TokenOK and not ThreadOK, 'sub-snapshot status clears');
    Check(Reason <> '', 'parser preserves error reason');
    Check(not RealReference(0), 'zero is not a reference');
    Check(not RealReference(THandle(High(NativeUInt))), 'pseudo handle is not a reference');
    Check(RealReference(20), 'ordinary numeric reference retained');
  finally
    Tokens.Free; Observed.Free; Holders.Free;
  end;
  Done('Handles: acquisition/decoder boundary');
end;

procedure TestProcess;
var
  Data: TBytes;
  Candidates: TList<TProcessCandidate>;
  C: TProcessCandidate;
  Reason: string;
  PID: Cardinal;
  Matches: Integer;
begin
  Existing('process decoder fixtures', TestProcessHardening);
  Candidates := TList<TProcessCandidate>.Create;
  try
    C := Default(TProcessCandidate); C.PID := 7; C.Created := 123;
    Candidates.Add(C); Data := nil;
    Check(not CollectNameCandidates(Data, 'test.exe', Candidates, Reason), 'missing native process response');
    Check(Candidates.Count = 0, 'failed decode discards partial candidates');
    Check(Reason <> '', 'process decoder reason retained');
    Check(not FindTargetByName('', PID, Matches, Reason), 'public facade rejects empty name before native fetch');
    Check((PID = 0) and (Matches = 0), 'invalid name has no published identity');
  finally
    Candidates.Free;
  end;
  Done('Process: OS lifetime/list decoder boundary');
end;

procedure TestRegistry;
var OpenEntry: TRegistryOpen; H: THandle;
begin
  Existing('registry parser/layout fixtures', TestRegistryHardening);
  OpenEntry := NativeOpenRegistryKey;
  Check(Assigned(OpenEntry), 'registry open signature');
  Check(OpenEntry('') = 0, 'empty registry path rejected');
  Check(OpenEntry('relative') = 0, 'relative registry path rejected');
  Check(OpenEntry('\Registry\Machine' + #0 + 'tail') = 0, 'embedded null path rejected');
  H := 0; NativeCloseRegistry(H);
  Check(H = 0, 'no-op close preserves zero ownership');
  Done('RegistryNative: argument/lifetime contracts');
end;

procedure TestETW;
var B: TBytes; V: Cardinal; Wide: UInt64; S: string;
begin
  Existing('ETW property acquisition fixtures', TestETWNativeHardening);
  SetLength(B, 4); V := 42; Move(V, B[0], 4);
  Check(DecodeEtwUInt(B, V) and (V = 42), 'standalone DWORD decoder');
  SetLength(B, 8); Wide := UInt64(High(Cardinal)); Move(Wide, B[0], 8);
  Check(DecodeEtwUInt(B, V) and (V = High(Cardinal)), 'standalone bounded QWORD');
  Wide := UInt64(High(Cardinal)) + UInt64(1); Move(Wide, B[0], 8);
  Check(not DecodeEtwUInt(B, V) and (V = 0), 'overflow is not truncation');
  SetLength(B, 3); V := 99;
  Check(not DecodeEtwUInt(B, V) and (V = 0), 'unsupported scalar length');
  SetLength(B, 4); PWord(@B[0])^ := Ord('A'); PWord(@B[2])^ := 0;
  Check(DecodeEtwText(B, S) and (S = 'A'), 'standalone UTF16 payload');
  PWord(@B[0])^ := $D800;
  Check(not DecodeEtwText(B, S) and (S = ''), 'incomplete surrogate rejected');
  Done('ETWNative: TDH acquisition/payload decoder boundary');
end;

procedure TestNetwork;
var Data: TBytes; Routes: TStringList; R: PIpForwardRow; S: string;
begin
  Existing('network acquisition fixtures', TestNetworkNativeHardening);
  Routes := TStringList.Create;
  try
    Check(SizeOf(TIpForwardRow) = 56, 'moved route ABI retained');
    SetLength(Data, 4 + SizeOf(TIpForwardRow)); FillChar(Data[0], Length(Data), 0);
    PCardinal(@Data[0])^ := 1;
    R := PIpForwardRow(@Data[4]); R^.NextHop := 1; R^.IfIndex := 2; R^.Metric1 := 3;
    Check(ParseDefaultRoutes(Data, Cardinal(Length(Data)), Routes), 'standalone route table');
    Check((Routes.Count = 1) and (Routes[0] = '00000001:2:3'), 'route key unchanged');
    Check(not ParseDefaultRoutes(Data, 4, Routes) and (Routes.Count = 0), 'truncated route table clears output');
    SetLength(Data, 2); PWord(@Data[0])^ := Ord('X');
    Check(DecodeRegString(Data, 2, S) and (S = 'X'), 'bounded registry string');
    Check(not DecodeRegString(Data, 1, S) and (S = ''), 'odd registry string rejected');
    Data := nil;
    Check(DecodeRegString(Data, 0, S) and (S = ''), 'empty registry scalar preserved');
  finally Routes.Free; end;
  Done('NetworkNative: source-specific acquisition/payload decoding');
end;

procedure TestSelf;
var Capture: TSelfCapture; Digest: UInt64; Valid: Boolean;
begin
  // This existing group uses synthetic PE images in ordinary local memory.
  // It exercises the extracted directory and IAT walk through the old entry.
  Existing('self IAT/fingerprint fixtures', TestSelfNativeHardening);
  Capture := CaptureSelfIAT;
  Check(Assigned(Capture), 'self-IAT facade signature retained');
  Check(not CallbackFingerprint(0, 0, 0, Digest, Valid), 'missing required callback');
  Check((Digest = 0) and not Valid, 'failure outputs remain empty');
  Check(not ExecutableImageAddress(0), 'zero address is not executable-image evidence');
  Done('SelfNative: PE directory/IAT hashing stages');
end;

procedure TestException;
var Capture: TExceptionCapture; Entry: TNHWRuntimeFunction; Bytes: Cardinal;
begin
  Capture := CaptureExceptionImage;
  Check(Assigned(Capture), 'exception capture facade signature');
  Check(not IsReadableLocalRange(0, 1), 'invalid local range');
  Check(not IsReadableLocalRange(High(NativeUInt) - 1, 8), 'overflowing local span');
  Entry := Default(TNHWRuntimeFunction);
  Entry.BeginAddress := $100; Entry.EndAddress := $200; Entry.UnwindData := $300;
  Check(ExceptionRangeValid(Entry, $1000, 0, False), 'runtime entry bounds contract');
  Entry.EndAddress := $100;
  Check(not ExceptionRangeValid(Entry, $1000, 0, False), 'empty runtime entry rejected');
  Check(ExceptionUnwindHeaderValid(1, 0, $300, $1000, Bytes), 'unwind header minimum size');
  Check(Bytes = 4, 'unwind header base width');
  // Compile/link and pure contract checks, NOT exhaustive execution of the
  // native .pdata walk. The static audit compares both extracted stage bodies.
  Done('ExceptionNative: capture interface and metadata rule contracts');
end;

procedure TestIPC;
var Data: TBytes; Count: NativeUInt;
begin
  Existing('IPC probe verification fixtures', TestIPCNativeHardening);
  Check(ClassifyNativeType('Event') = ikEvent, 'event classification');
  Check(ClassifyNativeType('mutant') = ikMutex, 'case-insensitive mutex classification');
  Check(ClassifyNativeType('Unrelated') = ikNone, 'unknown type remains unclassified');
  Check(OpaqueKey(7, $10000) = '7:0000000000010000', 'opaque key format');
  SetLength(Data, IPC_HEADER_BYTES); FillChar(Data[0], Length(Data), 0);
  Check(IPCSnapshotShape(Data, 0), 'empty header shape accepted');
  Count := 1; Move(Count, Data[0], SizeOf(Count));
  Check(not IPCSnapshotShape(Data, 1), 'missing entry payload rejected');
  Done('IPCNative: probe ownership/response matching boundary');
end;

procedure TestThreadOrigin;
var
  A, B: Cozy.NHW.ThreadOriginNative.TThreadOriginRegion;
  C: Cozy.NHW.ThreadOrigin.Rules.TThreadOriginRegion;
  M: Cozy.NHW.ThreadOrigin.Rules.TMemoryBasicInformation64;
begin
  Existing('thread origin fixtures', TestThreadOriginHardening);
  M := Default(Cozy.NHW.ThreadOrigin.Rules.TMemoryBasicInformation64);
  M.BaseAddress := Pointer(NativeUInt($10000)); M.AllocationBase := M.BaseAddress;
  M.RegionSize := $1000; M.State := NT_MEM_COMMIT;
  M.Protect := NT_PAGE_EXECUTE_READ; M.RegionType := NT_MEM_PRIVATE;
  Check(NormalizeStartRegion(0, $10010, M, SizeOf(M), C), 'standalone region normalizer');
  A := C; B := A; C := A;
  Check((A.StartAddress = $10010) and (C.StartAddress = A.StartAddress), 'facade is an exact type alias');
  Check(Cozy.NHW.ThreadOriginNative.IsPrivateExecutableStart(A) =
    Cozy.NHW.ThreadOrigin.Rules.IsPrivateExecutableStart(C), 'facade/rules classify identically');
  Check(not Cozy.NHW.ThreadOriginNative.IsThreadRegionChanged(A, B), 'same region unchanged');
  B.Protect := NT_PAGE_EXECUTE_READWRITE;
  Check(Cozy.NHW.ThreadOriginNative.IsThreadRegionChanged(A, B), 'committed protection difference');
  Check(Cozy.NHW.ThreadOriginNative.IsExecutableProtection(NT_PAGE_EXECUTE_READ) =
    Cozy.NHW.ThreadOrigin.Rules.IsExecutableProtection(NT_PAGE_EXECUTE_READ), 'protection facade forwards');
  Done('ThreadOriginNative: normalized data and exact aliases');
end;

procedure TestStack;
var S: TNativeStackSnapshot;
begin
  Existing('stack metadata fixtures', TestStackNativeHardening);
  S := Default(TNativeStackSnapshot); S.Known := True; S.StackBase := $30000;
  Check(not QueryNativeThreadStack(0, 0, S), 'invalid handles do not query stack');
  Check(not S.Known and not S.BoundsValid, 'invalid input clears stack status');
  Check((S.StackBase = 0) and (S.CreateTime = 0), 'no stale stack identity');
  Check((S.ReservedBytes = 0) and (S.CommittedBytes = 0), 'no partial reservation result');
  // Fake region/TIB responses are covered by the existing group. Full real
  // stack-walk races and new nested stage success require Windows validation.
  Done('StackNative: query stages and failure contracts');
end;

begin
  NewChecks := 0; InheritedChecks := 0; Groups := 0;
  try
    // Isolated single-threaded tests. Some existing groups temporarily replace
    // API pointers and restore them. Never run the monitoring engine in here.
    ResolveWinPointers;
    ResolveNativeAPIs;
    TestHandles;
    TestProcess;
    TestRegistry;
    TestETW;
    TestNetwork;
    TestSelf;
    TestException;
    TestIPC;
    TestThreadOrigin;
    TestStack;
    Writeln('PASS: Refactor10V groups=', Groups, ' new-checks=', NewChecks,
      ' inherited-checks=', InheritedChecks);
    Writeln('This does not certify every OS path, timing or concurrency equivalence.');
  except
    on E: Exception do
    begin
      Writeln('FAIL: ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
