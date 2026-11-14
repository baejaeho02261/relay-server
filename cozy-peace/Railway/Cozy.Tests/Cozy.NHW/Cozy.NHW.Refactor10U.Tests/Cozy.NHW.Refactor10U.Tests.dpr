program CozyNHW_Refactor10U_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build this project with Delphi Win64.'}
{$ENDIF}

uses
  Winapi.Windows, System.SysUtils, System.Classes, System.Generics.Collections,
  Cozy.NHW.Types, Cozy.NHW.Logging, Cozy.NHW.Native, Cozy.NHW.PERules, Cozy.NHW.PENative,
  Cozy.NHW.AsyncGuard, Cozy.NHW.AsyncRules,
  Cozy.NHW.Lifecycle, Cozy.NHW.Lifecycle.Snapshot,
  Cozy.NHW.PathNative, Cozy.NHW.PathSnapshot.Decoders,
  Cozy.NHW.CaptureNative, Cozy.NHW.CaptureRules, Cozy.NHW.CaptureSnapshot.Decoders,
  Cozy.NHW.AllocationNative, Cozy.NHW.MappingGuard, Cozy.NHW.ProtectionGuard,
  Cozy.NHW.HeapTLS, Cozy.NHW.HeapTLSRules,
  Cozy.NHW.Scheduler, Cozy.NHW.Scheduler.Rules,
  Cozy.NHW.NamespaceNative, Cozy.NHW.Namespace.Decoders;

type
  TPEContract = function(out Snapshot: TPEImageSnapshot): Boolean;
  TThreadSnapshotContract = function(PID: Cardinal;
    Parents: Cozy.NHW.Lifecycle.TProcessParentMap;
    Threads: Cozy.NHW.Lifecycle.TThreadSampleMap): Boolean;

var
  Checks, Groups: Integer;

procedure Check(Condition: Boolean; const MessageText: string);
begin
  Inc(Checks);
  if not Condition then raise Exception.Create(MessageText);
end;

procedure GroupDone(const Name: string);
begin
  Inc(Groups);
  Writeln('PASS: ', Name);
end;

procedure TestPEStagesContract;
var Entry: TPEContract; S: TPEImageSnapshot;
begin
  Entry := Cozy.NHW.PENative.CapturePEImage;
  Check(Assigned(Entry), 'mapped PE public signature retained');
  S := Default(TPEImageSnapshot);
  Check(not S.Header.Available and not S.TLSDirectory.Available, 'unavailable default snapshot');
  Check(PERangeInImage($100, 16, $1000), 'bounded RVA remains valid');
  Check(not PERangeInImage($1000, 1, $1000), 'out-of-image RVA remains invalid');
  Check(not PERangeInImage(High(Cardinal), 8, $1000), 'overflowing RVA remains invalid');
  // Compile/link and pure boundary checks only. Existing PE smoke tests cover
  // the current image. No claim is made that this executes every PE stage.
  GroupDone('PENative public contract and PE bounds');
end;

procedure TestAsyncLifetimeContract;
var M: TAsyncGuardMonitor; D: TDetectionKinds;
begin
  M := TAsyncGuardMonitor.Create;
  try
    D := [];
    M.Examine(True, 1000, False, D);
    Check(D = [], 'no initialized probes during baseline');
    M.Examine(False, 2000, False, D);
    Check(D = [], 'uninitialized optional probes stay silent');
    Check(ExpectedCompletion(7, 7, 8, 8, nil), 'owned packet comparator');
    Check(not ExpectedCompletion(8, 7, 8, 8, nil), 'different key comparator');
    Check(WorkCountersConsistent(3, 2), 'work accounting contract');
    Check(not WorkCountersConsistent(2, 3), 'unexpected completion count');
  finally
    M.Free;
  end;
  // No Reset here: no completion port/work/timer is started by this group.
  GroupDone('AsyncGuard lifetime and public comparisons');
end;

procedure TestLifecycleBoundaries;
var
  M: TLifecycleMonitor;
  Parents: Cozy.NHW.Lifecycle.TProcessParentMap;
  Threads: Cozy.NHW.Lifecycle.TThreadSampleMap;
  S: Cozy.NHW.Lifecycle.TThreadSample;
  AliasSample: Cozy.NHW.Lifecycle.Snapshot.TThreadSample;
  D: TDetectionKinds;
  Entry: TThreadSnapshotContract;
begin
  M := nil; Parents := nil; Threads := nil;
  try
    M := TLifecycleMonitor.Create;
    Parents := Cozy.NHW.Lifecycle.TProcessParentMap.Create;
    Threads := Cozy.NHW.Lifecycle.TThreadSampleMap.Create;
    Entry := Cozy.NHW.Lifecycle.ReadSystemThreadSnapshot;
    Check(Assigned(Entry), 'native snapshot facade signature');
    S := Default(Cozy.NHW.Lifecycle.TThreadSample); S.ThreadID := 10; S.StartAddress := $10000;
    AliasSample := S; S := AliasSample;
    Check(S.ThreadID = 10, 'snapshot type alias is assignment compatible');
    Parents.Add(42, 1); Threads.Add(10, S);
    Check(not Entry(0, Parents, Threads), 'zero target rejected without native fetch');
    Check((Parents.Count = 0) and (Threads.Count = 0), 'invalid input clears outputs');
    Threads.Add(10, S); D := [];
    M.ExamineThreads(Threads, 1000, True, False, D);
    Check(D = [], 'startup seeds without a signal');
    S.ThreadID := 11; S.StartAddress := $20000; Threads.Add(11, S);
    M.ExamineThreads(Threads, 2000, False, True, D);
    Check((dkThreadCreation in D) and (dkLifecycle in D), 'new thread correlated with access');
    D := []; M.ExamineThreads(Threads, 2200, False, False, D);
    Check(D = [], 'same thread collection is silent');
    Threads.Remove(11); D := [];
    M.ExamineThreads(Threads, 2400, False, False, D);
    Check((dkThreadExit in D) and (dkLifecycle in D), 'confirmed exit correlation preserved');
    M.InvalidateThreadBaseline; D := [];
    M.ExamineThreads(Threads, 2600, False, False, D);
    Check(D = [], 'invalidation does not imply all threads exited');
  finally
    Threads.Free; Parents.Free; M.Free;
  end;
  GroupDone('Lifecycle snapshot facade and state phases');
end;

procedure TestPathDecoders;
var
  Data: TBytes;
  A: PAdapterPrefix;
  P: PProtocolInfo;
  DNS, Interfaces, Providers: TStringList;
  Name: string;
begin
  DNS := nil; Interfaces := nil; Providers := nil;
  try
    DNS := TStringList.Create; Interfaces := TStringList.Create; Providers := TStringList.Create;
    Check(SizeOf(TAdapterPrefix) = 112, 'adapter x64 prefix unchanged');
    Check(SizeOf(TDnsNode) = 32, 'DNS node x64 layout unchanged');
    Check(SizeOf(TProtocolInfo) = 628, 'Winsock record layout unchanged');
    SetLength(Data, SizeOf(TAdapterPrefix) + 4); FillChar(Data[0], Length(Data), 0);
    A := PAdapterPrefix(@Data[0]); A^.Length := SizeOf(TAdapterPrefix); A^.OperStatus := 1;
    A^.AdapterName := PAnsiChar(@Data[SizeOf(TAdapterPrefix)]);
    A^.AdapterName[0] := AnsiChar('n'); A^.AdapterName[1] := AnsiChar('0');
    Check(ParseAdapterSnapshots(Data, DNS, Interfaces), 'bounded adapter response');
    Check((Interfaces.Count = 1) and (Interfaces[0] = 'n0:1'), 'interface key preserved');
    Check((DNS.Count = 1) and (DNS[0] = 'n0:<none>'), 'empty DNS set preserved');
    Check(ReadBufferName(Data, A^.AdapterName, Name) and (Name = 'n0'), 'bounded ANSI name');
    A^.OperStatus := 8; DNS.Clear; Interfaces.Clear;
    Check(not ParseAdapterSnapshots(Data, DNS, Interfaces), 'invalid adapter status');
    Check(not TakeAdapterSnapshots(DNS, DNS), 'facade rejects aliased outputs');
    SetLength(Data, SizeOf(TProtocolInfo)); FillChar(Data[0], Length(Data), 0);
    P := PProtocolInfo(@Data[0]); P^.Chain.ChainLen := 0; P^.CatalogEntryId := 9;
    Check(ParseWinsockCatalog(Data, 1, Providers), 'catalog response decoder');
    Check(Providers.Count = 1, 'one protocol record');
    P^.Chain.ChainLen := 8;
    Check(not ParseWinsockCatalog(Data, 1, Providers), 'invalid chain count rejected');
    Check(not ParseWinsockCatalog(Data, 2, Providers), 'truncated catalog rejected');
    Check(not TakeNRPTSnapshot(nil), 'nil policy output rejected');
    Check(not TakeWinsockCatalogSnapshot(nil), 'nil provider output rejected');
  finally
    Providers.Free; Interfaces.Free; DNS.Free;
  end;
  GroupDone('Path source-specific decoders');
end;

procedure TestCaptureDecoders;
var
  Data: TBytes; P: ^TProcessPrefix; R: PTcpRowNative;
  Processes: Cozy.NHW.CaptureNative.TCaptureProcessList;
  PIDs: Cozy.NHW.CaptureNative.TCapturePIDSet;
  Path: string; Created: UInt64; F: TCaptureFamilies;
begin
  Processes := nil; PIDs := nil;
  try
    Processes := Cozy.NHW.CaptureNative.TCaptureProcessList.Create;
    PIDs := Cozy.NHW.CaptureNative.TCapturePIDSet.Create;
    Check(SizeOf(TProcessPrefix) = 88, 'process prefix layout');
    SetLength(Data, SizeOf(TProcessPrefix) + 4); FillChar(Data[0], Length(Data), 0);
    P := Pointer(@Data[0]); P^.UniqueProcessId := 42;
    P^.ImageName.Buffer := PWideChar(@Data[SizeOf(TProcessPrefix)]);
    P^.ImageName.Length := 4; P^.ImageName.MaximumLength := 4;
    P^.ImageName.Buffer[0] := 'a'; P^.ImageName.Buffer[1] := 'b';
    Check(ParseCaptureProcesses(Data, Processes), 'complete process response');
    Check((Processes.Count = 1) and (Processes[0].PID = 42), 'process list type alias');
    Check(Processes[0].Name = 'ab', 'process name copied');
    P^.ImageName.Length := 3;
    Check(not ParseCaptureProcesses(Data, Processes), 'odd UTF16 length rejected');
    Check(Processes.Count = 0, 'failure discards partial process result');
    SetLength(Data, 4 + SizeOf(TTcpRowNative)); FillChar(Data[0], Length(Data), 0);
    PCardinal(@Data[0])^ := 1; R := Pointer(@Data[4]); R^.State := 2; R^.OwnerPID := 42;
    Check(ParseCaptureListeners(Data, Cardinal(Length(Data)), PIDs), 'bounded listener table');
    Check(PIDs.ContainsKey(42), 'listener owner collected');
    R^.State := 5;
    Check(not ParseCaptureListeners(Data, Cardinal(Length(Data)), PIDs), 'non-listener rejected');
    Check(PIDs.Count = 0, 'failure discards partial listener result');
    Check(not InspectCaptureModules(0, Path, Created, F), 'invalid module target avoids native queries');
    Check((Path = '') and (Created = 0) and (F = []), 'module failure outputs clear');
  finally
    PIDs.Free; Processes.Free;
  end;
  GroupDone('Capture process/listener decoders and module facade');
end;

procedure TestMappingPhases;
var A, B: TMappingSample; M: TMappingGuard; S: TMappingSignals;
begin
  A := Default(TMappingSample); A.Base := $10000; A.RegionType := ALLOC_MEM_IMAGE;
  A.MappedBytes := $1000; A.ProbePage := $10000; B := A;
  Check(MappingSamplesEqual(A, B), 'same mapped sample');
  B.ExecutableBytes := $1000;
  Check(msExecutable in AnalyzeMappingTransition(A, B, True), 'executable transition');
  A.SharedKnown := True; A.Shared := True; B := A; B.Shared := False;
  S := AnalyzeMappingTransition(A, B, True);
  Check((msCOW in S) and (msPageSharing in S), 'same-page sharing transition');
  B.ProbePage := $20000; S := AnalyzeMappingTransition(A, B, True);
  Check(not (msCOW in S), 'different pages are not COW proof');
  M := TMappingGuard.Create;
  try M.BeginSweep; M.CancelSweep; M.Reset; finally M.Free; end;
  GroupDone('Mapping metadata and reconciliation contracts');
end;

procedure TestProtectionPhases;
var M: TProtectionGuard; R: TVirtualRegion; D: TDetectionKinds; I: Integer;
begin
  M := TProtectionGuard.Create;
  try
    R := Default(TVirtualRegion); R.BaseAddress := $10000; R.AllocationBase := $10000;
    R.Size := $1000; R.State := ALLOC_MEM_COMMIT; R.RegionType := ALLOC_MEM_PRIVATE; R.Protect := $04;
    for I := 1 to 2 do
    begin
      D := []; M.BeginSweep; M.ObserveRegion(R); M.EndSweep(UInt64(I) * 1000, D);
      Check(D = [], 'protection warmup remains silent');
    end;
    R.Protect := $20; D := []; M.BeginSweep; M.ObserveRegion(R); M.EndSweep(3000, D);
    Check(D = [], 'first changed protection is pending');
    M.BeginSweep; M.ObserveRegion(R); M.EndSweep(4000, D);
    Check(dkProtectTransition in D, 'second changed protection confirms');
    D := []; M.BeginSweep; M.ObserveRegion(R); M.CancelSweep;
    M.EndSweep(5000, D); Check(D = [], 'cancelled sweep does not commit');
    Check(ProtectionIsRW($04) and not ProtectionIsRW($104), 'guard bit remains significant');
    Check(ProtectionIsRX($20), 'RX rule unchanged');
  finally M.Free; end;
  GroupDone('Protection rule/state/cleanup phases');
end;

procedure TestHeapTLSLifetime;
var M: THeapTLSMonitor; D: TDetectionKinds; A, B: TArray<NativeUInt>;
begin
  A := TArray<NativeUInt>.Create(1, 2); B := Copy(A, 0, Length(A));
  Check(HeapTLSHeapsEqual(A, B), 'heap set comparator unchanged');
  B[1] := 3; Check(not HeapTLSHeapsEqual(A, B), 'heap set change');
  M := THeapTLSMonitor.Create;
  try
    M.Reset; D := []; M.Examine(True, 1000, False, D);
    Check(D = [], 'local TLS/FLS baseline is silent');
    M.Reset;
  finally M.Free; end;
  // Optional self-owned heap/TLS/FLS smoke; no external process is modified.
  GroupDone('HeapTLS same-thread setup/read/teardown');
end;

procedure TestScheduleRules;
var A, B: Cozy.NHW.Scheduler.TProcessScheduleState;
    X, Y: Cozy.NHW.Scheduler.TThreadScheduleState;
    AliasState: Cozy.NHW.Scheduler.Rules.TProcessScheduleState;
    D: TDetectionKinds; M: TSchedulerMonitor;
begin
  A := Default(Cozy.NHW.Scheduler.TProcessScheduleState); B := A;
  B.PriorityClass := $80;
  Check(Cozy.NHW.Scheduler.CompareProcessSchedule(A, B) = [], 'unknown process fields do not signal');
  A.ClassKnown := True; B.ClassKnown := True;
  D := Cozy.NHW.Scheduler.CompareProcessSchedule(A, B);
  Check(dkProcessPriority in D, 'process priority rule preserved');
  AliasState := B; B := AliasState;
  Check(D = Cozy.NHW.Scheduler.Rules.CompareProcessSchedule(A, B), 'facade and pure rule agree');
  X := Default(Cozy.NHW.Scheduler.TThreadScheduleState); Y := X;
  X.PriorityKnown := True; Y.PriorityKnown := True; Y.Priority := 1;
  Check(dkThreadPriority in Cozy.NHW.Scheduler.CompareThreadSchedule(X, Y), 'thread priority rule');
  Y.PriorityKnown := False;
  Check(Cozy.NHW.Scheduler.CompareThreadSchedule(X, Y) = [], 'unknown thread field excluded');
  M := TSchedulerMonitor.Create;
  try M.Reset; finally M.Free; end;
  GroupDone('Scheduler acquisition/comparator/state contract');
end;

procedure TestNamespaceDecoders;
var Data: TBytes; E: PNsDirectoryEntry; Entries: Cozy.NHW.NamespaceNative.TNamespaceEntries;
    Signature: UInt64; S: Cozy.NHW.NamespaceNative.TNamespaceEntry;
    AliasEntry: Cozy.NHW.Namespace.Decoders.TNamespaceEntry;
begin
  Entries := Cozy.NHW.NamespaceNative.TNamespaceEntries.Create;
  try
    Check(NamespaceLayoutsValid, 'namespace raw layouts unchanged');
    SetLength(Data, 80); FillChar(Data[0], Length(Data), 0);
    E := PNsDirectoryEntry(@Data[0]);
    E^.Name.Buffer := PWideChar(@Data[64]); E^.Name.Length := 2; E^.Name.MaximumLength := 2;
    E^.TypeName.Buffer := PWideChar(@Data[66]); E^.TypeName.Length := 2; E^.TypeName.MaximumLength := 2;
    E^.Name.Buffer[0] := 'A'; E^.TypeName.Buffer[0] := 'B';
    Check(ParseNamespacePage(Data, 68, Entries), 'bounded directory page and sentinel');
    Check(Entries.TryGetValue('A', S), 'directory key preserved');
    AliasEntry := S; S := AliasEntry;
    Check((S.Name = 'A') and (S.TypeName = 'B'), 'entry type alias');
    E^.Name.Length := 1;
    Check(not ParseNamespacePage(Data, 68, Entries), 'malformed counted Unicode rejected');
    Check(Entries.Count = 0, 'partial page output cleared');
    SetLength(Data, 20); FillChar(Data[0], Length(Data), 0); Data[0] := 1;
    PWord(@Data[2])^ := $8004;
    Check(ParseNamespaceDacl(Data, Cardinal(Length(Data)), Signature), 'self-relative null DACL');
    PCardinal(@Data[16])^ := 19;
    Check(not ParseNamespaceDacl(Data, Cardinal(Length(Data)), Signature), 'bad ACL offset');
    Check(Signature = 0, 'failed ACL parse clears signature');
    Check(not EnumerateNamespace('', Entries), 'invalid native path rejected');
  finally Entries.Free; end;
  GroupDone('Namespace parsing/OS boundary');
end;

begin
  Checks := 0; Groups := 0;
  try
    TestPEStagesContract;
    TestAsyncLifetimeContract;
    TestLifecycleBoundaries;
    TestPathDecoders;
    TestCaptureDecoders;
    TestMappingPhases;
    TestProtectionPhases;
    TestHeapTLSLifetime;
    TestScheduleRules;
    TestNamespaceDecoders;
    Writeln('PASS: Refactor10U groups=', Groups, ' checks=', Checks);
    ExitCode := 0;
  except
    on E: Exception do
    begin
      Writeln('FAIL: ', E.ClassName, ': ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
