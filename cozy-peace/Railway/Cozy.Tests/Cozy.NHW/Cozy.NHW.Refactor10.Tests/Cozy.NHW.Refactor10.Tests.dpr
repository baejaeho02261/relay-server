program CozyNHW_Refactor10_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Open this project with Delphi Win64.'}
{$ENDIF}
uses
  Winapi.Windows, System.SysUtils, System.Generics.Collections,
  Cozy.NHW.Types, Cozy.NHW.Logging, Cozy.NHW.Engine,
  Cozy.NHW.ETW, Cozy.NHW.ETWTypes, Cozy.NHW.ETWNative, Cozy.NHW.ETW.Decoder,
  Cozy.NHW.Security, Cozy.NHW.Security.Snapshot,
  Cozy.NHW.Registry, Cozy.NHW.Registry.EvidenceReader,
  Cozy.NHW.ExportNative, Cozy.NHW.ExportRules, Cozy.NHW.PERules,
  Cozy.NHW.Export.ImageReader, Cozy.NHW.Export.DelayReader,
  Cozy.NHW.FileNative, Cozy.NHW.FileMetadata.Decoders,
  Cozy.NHW.PECodeIntegrity, Cozy.NHW.PECodeDigest,
  Cozy.NHW.AllocationGuard, Cozy.NHW.WaitChain,
  Cozy.NHW.DualObserver, Cozy.NHW.Observer.Protocol;

type
  TRunContract = procedure(const Opt: TOptions);
  TExportContract = function(const Bases: array of NativeUInt;
    out Snapshot: TExportSnapshot): Boolean;
  TCodeContract = function(Module: HMODULE;
    out Digest: Cozy.NHW.PECodeIntegrity.TCodeImageDigest): Boolean;
var
  Checks, Groups: Integer;

procedure Check(Value: Boolean; const MessageText: string);
begin
  Inc(Checks);
  if not Value then raise Exception.Create(MessageText);
end;

procedure FinishGroup(const Name: string);
begin
  Inc(Groups);
  Writeln('PASS: ', Name);
end;

procedure TestEngineContract;
var Entry: TRunContract;
begin
  Entry := Cozy.NHW.Engine.Run;
  Check(Assigned(Entry), 'Run keeps its original public signature');
  Check(SizeOf(TDetectionKinds) > 0, 'detection contract links unchanged');
  // Compile/link contract only: never enter the infinite monitoring loop here.
  FinishGroup('Engine public contract');
end;

procedure TestETWDecoder;
var Event: TKernelEvent; Rec: TEtwEventRecord;
begin
  Check(Cozy.NHW.ETW.Decoder.NormalPath(' a/b ') = 'A\B', 'ETW path normalization');
  Check(Cozy.NHW.ETW.Decoder.PathEndsWith('C:/X/App.exe', '\X\APP.EXE'), 'ETW suffix');
  Check(not Cozy.NHW.ETW.Decoder.PathEndsWith('C:\X\App.exe', ''), 'empty suffix rejected');
  Check(Cozy.NHW.ETW.Decoder.RegistryRelevant(
    '\Registry\Machine\Software\Microsoft\Windows\CurrentVersion\Policies\X', ''), 'registry policy selector');
  Check(not Cozy.NHW.ETW.Decoder.RegistryRelevant('\Registry\Machine\Unrelated\X', ''), 'unrelated registry selector');
  Rec := Default(TEtwEventRecord);
  Check(not TryDecodeKernelEvent(@Rec, 0, '', '', Event), 'target zero is not decoded');
  Check(not TryDecodeKernelEvent(@Rec, 99, '', '', Event), 'unrecognized provider is not decoded');
  FinishGroup('ETW parser boundaries');
end;

procedure TestSecurityEvidence;
var B: TBytes; H: UInt64; Identity: string; M: TSecurityMonitor;
begin
  Check(not TryDaclBufferSignature(nil, 0, H), 'empty security buffer');
  Check(H = 0, 'failed descriptor output cleared');
  SetLength(B, 20);
  B[0] := 1;
  PWord(@B[2])^ := $8004;
  Check(TryDaclBufferSignature(B, Length(B), H), 'self-relative null DACL');
  PCardinal(@B[16])^ := 19;
  Check(not TryDaclBufferSignature(B, Length(B), H), 'out of range DACL');
  Check(ThreadSecurityIdentity(17, 21, Identity) and (Identity = 'T:17:21'), 'thread epoch key');
  Check(not ThreadSecurityIdentity(17, 0, Identity), 'unknown epoch rejected');
  Check(TokenModificationRights(TOKEN_QUERY_RIGHT) = 0, 'query remains non-modifying');
  Check(TokenModificationRights(TOKEN_ADJUST_PRIVILEGES_RIGHT) = TOKEN_ADJUST_PRIVILEGES_RIGHT, 'modification mask preserved');
  M := TSecurityMonitor.Create;
  try M.Reset; finally M.Free; end;
  FinishGroup('Security collector and monitor');
end;

procedure TestRegistryEvidence;
var A, B: TList<string>; H: UInt64; S: TRegistryEvidenceState;
    E: TRegistryEvidence; D: TDetectionKinds;
begin
  A := nil; B := nil;
  try
    A := TList<string>.Create; B := TList<string>.Create;
    A.Add('B'); A.Add('A'); B.Add('A'); B.Add('B');
    H := CanonicalHash(A);
    Check(H = CanonicalHash(B), 'registry canonical order');
    B.Add('C'); Check(H <> CanonicalHash(B), 'registry distinct entries');
  finally B.Free; A.Free; end;
  S.Reset; E := Default(TRegistryEvidence); E.ValuesKnown := True; E.ValuesHash := 7;
  D := []; S.Observe(E, True, D); Check(D = [], 'registry baseline silent');
  E.ValuesHash := 8; S.Observe(E, False, D); Check(dkRegistryValue in D, 'registry existing value signal');
  D := []; E.ValuesKnown := False; S.Observe(E, False, D); Check(D = [], 'unknown registry evidence silent');
  FinishGroup('Registry collection/state separation');
end;

procedure TestExportReaders;
var I: TImageInfo; Address: NativeUInt; Entry: TExportContract;
begin
  Entry := CaptureExportSnapshot;
  Check(Assigned(Entry), 'export facade signature');
  I := Default(TImageInfo); I.Base := $10000; I.Size := $1000;
  Check(WithinImage(I, $FFF, 1), 'last image byte');
  Check(not WithinImage(I, $FFF, 2), 'image overrun rejected');
  Check(MapAddress(I, 16, 4, Address) and (Address = $10010), 'RVA mapping');
  Check(not MapAddress(I, $1000, 1, Address) and (Address = 0), 'invalid RVA output zero');
  I.Base := High(NativeUInt) - 1;
  Check(not MapAddress(I, 2, 1, Address), 'address addition overflow rejected');
  Check(SizeOf(TDelayDescriptor) = 32, 'delay descriptor layout unchanged');
  FinishGroup('Export/delay reader contracts');
end;

procedure TestFileDecoders;
var B: TBytes; Name: string; Hash: UInt64;
begin
  Check(not DecodeFileName(nil, Name) and (Name = ''), 'empty filename response');
  SetLength(B, 8); PCardinal(@B[0])^ := 4;
  PWord(@B[4])^ := Ord('a'); PWord(@B[6])^ := Ord('b');
  Check(DecodeFileName(B, Name) and (Name = 'ab'), 'UTF16 filename');
  PCardinal(@B[0])^ := 3; Check(not DecodeFileName(B, Name), 'odd filename length');
  Check(not DecodeStreamSet(nil, Hash) and (Hash = 0), 'incomplete stream set');
  Check(not DecodeLinkNames(nil, Hash) and (Hash = 0), 'incomplete link set');
  SetLength(B, 20); FillChar(B[0], Length(B), 0); B[0] := 1; PWord(@B[2])^ := $8004;
  Check(DecodeFileDacl(B, Length(B), Hash), 'null file DACL');
  PCardinal(@B[16])^ := 100;
  Check(not DecodeFileDacl(B, Length(B), Hash) and (Hash = 0), 'bad file DACL output');
  FinishGroup('File metadata pure decoders');
end;

procedure TestCodeDigestContract;
var A, B: Cozy.NHW.PECodeIntegrity.TCodeImageLayout;
    D: Cozy.NHW.PECodeIntegrity.TCodeImageDigest; Entry: TCodeContract;
begin
  Entry := Cozy.NHW.PECodeIntegrity.CaptureExecutableCodeDigest;
  Check(Assigned(Entry), 'code digest facade signature');
  Check(SizeOf(Cozy.NHW.PECodeIntegrity.TCodeImageLayout) = SizeOf(Cozy.NHW.PECodeDigest.TCodeImageLayout), 'layout alias identity');
  A := Default(Cozy.NHW.PECodeIntegrity.TCodeImageLayout);
  A.ModuleBase := $10000; A.SectionCount := 1; A.Sections[0].RVA := $1000;
  A.Sections[0].Bytes := 128; B := A;
  Check(SameCodeLayout(A, B), 'same layout');
  Inc(B.Sections[0].Bytes); Check(not SameCodeLayout(A, B), 'section change');
  Check(not Cozy.NHW.PECodeIntegrity.CaptureExecutableCodeDigest(0, D), 'invalid image rejected');
  Check(not D.Valid and (D.BytesHashed = 0), 'failed digest unavailable');
  FinishGroup('PE digest/monitor contract');
end;

procedure TestAllocationPhases;
var A, B: TAllocationSample; Signals: TAllocationSignals; M: TVirtualAllocationGuard;
begin
  A := Default(TAllocationSample); A.Base := $10000; B := A;
  Check(AllocationSamplesEqual(A, B), 'equal allocation');
  B.ReservedBytes := 1024*1024;
  Signals := AnalyzeAllocationTransition(A, B, False);
  Check(asAllocation in Signals, 'new allocation threshold preserved');
  B := A; B.CommittedBytes := 64*1024;
  Signals := AnalyzeAllocationTransition(A, B, True);
  Check(asCommit in Signals, 'commit threshold preserved');
  A := B; B.ExecutableBytes := 4096;
  Check(asExecute in AnalyzeAllocationTransition(A, B, True), 'protection transition preserved');
  B.Base := $20000;
  Check(AnalyzeAllocationTransition(A, B, True) = [], 'different reservations not compared');
  M := TVirtualAllocationGuard.Create;
  try M.Reset; Check(not M.ObservationFailed, 'allocation reset'); finally M.Free; end;
  FinishGroup('Allocation phase interfaces');
end;

procedure TestWaitChainLifecycle;
var M: TWaitChainMonitor; S: TWaitState; C: TContentionState;
begin
  S := Default(TWaitState); C := Default(TContentionState);
  Check((S.LastTick = 0) and not S.CycleEmitted, 'wait state contract');
  Check((C.LastRoot = 0) and (C.LastTick = 0), 'contention state contract');
  M := TWaitChainMonitor.Create;
  try Check(M <> nil, 'request pool construction'); finally M.Free; end;
  // No Reset/Examine: no native WCT collection is requested by this test.
  FinishGroup('WaitChain construction/retirement boundaries');
end;

procedure TestObserverProtocol;
var Shared: Cozy.NHW.DualObserver.TObserverShared; Value: UInt64;
begin
  Check(SizeOf(Cozy.NHW.DualObserver.TObserverShared) = SizeOf(Cozy.NHW.Observer.Protocol.TObserverShared), 'observer record alias identity');
  Shared := Default(Cozy.NHW.DualObserver.TObserverShared);
  Check((NativeUInt(@Shared.ProofRevision) and 7) = 0, 'proof revision alignment');
  Check((NativeUInt(@Shared.OwnerTick) and 7) = 0, 'heartbeat alignment');
  Check(Cozy.NHW.DualObserver.ObserverIdentityMatches(7, 11, 7, 11), 'observer facade identity');
  Check(not Cozy.NHW.DualObserver.ObserverIdentityMatches(7, 11, 7, 12), 'observer different epoch');
  Check(not Cozy.NHW.Observer.Protocol.ObserverIdentityMatches(0, 11, 0, 11), 'zero owner rejected');
  Value := 0; ObserverStore64(Value, 123); Check(ObserverLoad64(Value) = 123, 'protocol atomic store/read');
  Shared.StopFlag := 0; Check(not ObserverStopped(@Shared), 'stop flag clear');
  Shared.StopFlag := 1; Check(ObserverStopped(@Shared), 'stop flag set');
  FinishGroup('Observer protocol and facade');
end;

begin
  Checks := 0; Groups := 0;
  try
    TestEngineContract;
    TestETWDecoder;
    TestSecurityEvidence;
    TestRegistryEvidence;
    TestExportReaders;
    TestFileDecoders;
    TestCodeDigestContract;
    TestAllocationPhases;
    TestWaitChainLifecycle;
    TestObserverProtocol;
    Writeln('PASS: Refactor10 groups=', Groups, ' assertions=', Checks);
    Writeln('Compatibility/leaf checks only. Run all existing regression projects and Windows observation separately.');
  except
    on E: Exception do begin Writeln('FAIL: ', E.Message); ExitCode := 1; end;
  end;
end.
