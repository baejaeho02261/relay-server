unit Cozy.NHW.WriteWatch;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.SysUtils, System.Generics.Collections, Cozy.NHW.Types, Cozy.NHW.Logging;

type
  TWriteEpisode = record
    Tick: UInt64;
    PageIndex: Integer;
  end;

  TWriteWatchMonitor = class
  private
    // Last Examine only: known failed collection, not a throttled/pending pass.
    FObservationFailed: Boolean;
    FBase: Pointer;
    FRegionSize: NativeUInt;
    FPageSize: Cardinal;
    FEnabled: Boolean;
    FExpected: TBytes;
    FWasCorrupt: Boolean;
    FLastContentValid: Boolean;
    FWatchNeedsBaseline: Boolean;
    FLastPoll: UInt64;
    FLastFreshWrite: UInt64;
    FLastCorrelation: UInt64;
    FLastBurst: UInt64;
    FLastRepeat: UInt64;
    FEpisodes: TList<TWriteEpisode>;
    procedure PruneEpisodes(NowTick: UInt64);
    procedure RecordPages(DirtyMask: Cardinal; NowTick: UInt64;
      var Detected: TDetectionKinds);
    procedure BreakWriteCoverage;
    function TryCanaryChanged(out Changed: Boolean): Boolean;
    function RegionReadable: Boolean;
    procedure ClearWriteState;
    procedure InitializeWatchContents;
    procedure AppendDirtyPages(DirtyMask: Cardinal; NowTick: UInt64);
    procedure ReportWriteBurst(NowTick: UInt64; var Detected: TDetectionKinds);
    procedure ReportRepeatedWrites(DirtyMask: Cardinal; NowTick: UInt64;
      var Detected: TDetectionKinds);
    procedure ReportWriteCorrelation(NowTick: UInt64;
      var Detected: TDetectionKinds);
  public
    property ObservationFailed: Boolean read FObservationFailed;
    constructor Create;
    destructor Destroy; override;
    procedure Reset(TargetPID: Cardinal);
    function RegionAddress: NativeUInt;
    procedure ObserveHolder(const H: TTargetHolder;
      First, WasInactive, InBaseline: Boolean;
      PreviousRights: Cardinal; Tick: UInt64);
    procedure Examine(TargetPID: Cardinal; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE5I_TESTS}
function TestWriteWatch5I(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.WinPointers, Cozy.NHW.WriteRules,
  Cozy.NHW.WriteWatchNative, Cozy.NHW.AllocationNative, Cozy.NHW.NativeSafety;

type
  TWatchMemoryRead = function(Process: THandle; Address, Buffer: Pointer;
    Bytes: NativeUInt; var ReadBytes: NativeUInt): BOOL; stdcall;
{$IFDEF NHW_NATIVE5I_TESTS}
  TWatchCopyHook = function(Address, Buffer: Pointer; Bytes: NativeUInt;
    out ReadBytes: NativeUInt): Boolean;
  TWatchQueryHook = function(Process: THandle; Address: NativeUInt;
    out Region: TVirtualRegion): Boolean;
  TWatchDirtyHook = function(Base: Pointer; RegionSize: NativeUInt;
    PageSize: Cardinal; out DirtyMask: Cardinal): Boolean;
var
  WatchCopyHook: TWatchCopyHook;
  WatchQueryHook: TWatchQueryHook;
  WatchDirtyHook: TWatchDirtyHook;
{$ENDIF}

function CopyWatchMemory(Address, Buffer: Pointer; Bytes: NativeUInt;
  out ReadBytes: NativeUInt): Boolean;
var
  ReadPtr: TWatchMemoryRead;
begin
  ReadBytes := 0;
{$IFDEF NHW_NATIVE5I_TESTS}
  if Assigned(WatchCopyHook) then Exit(WatchCopyHook(Address, Buffer, Bytes, ReadBytes));
{$ENDIF}
  // Never dereference FBase here. Only our dedicated canary in this process
  // is copied through the OS, with both status and exact length checked.
  ReadPtr := TWatchMemoryRead(WinExport(WinModule('kernel32.dll'), 'ReadProcessMemory'));
  Result := False;
  if not Assigned(ReadPtr) then Exit;
  Result := ReadPtr(WinCurrentProcess, Address, Buffer, Bytes, ReadBytes);
end;

function QueryWatchRegion(Address: NativeUInt; out Region: TVirtualRegion): Boolean;
begin
  Region := Default(TVirtualRegion);
{$IFDEF NHW_NATIVE5I_TESTS}
  if Assigned(WatchQueryHook) then Exit(WatchQueryHook(WinCurrentProcess, Address, Region));
{$ENDIF}
  Result := QueryVirtualRegion(WinCurrentProcess, Address, Region);
end;

function QueryWatchDirty(Base: Pointer; RegionSize: NativeUInt;
  PageSize: Cardinal; out Mask: Cardinal): Boolean;
begin
  Mask := 0;
{$IFDEF NHW_NATIVE5I_TESTS}
  if Assigned(WatchDirtyHook) then Exit(WatchDirtyHook(Base, RegionSize, PageSize, Mask));
{$ENDIF}
  Result := QueryAndResetWriteWatch(Base, RegionSize, PageSize, Mask);
end;

constructor TWriteWatchMonitor.Create;
begin
  inherited Create;
  FEpisodes := TList<TWriteEpisode>.Create;
  FBase := nil;
end;

destructor TWriteWatchMonitor.Destroy;
begin
  ReleaseWriteWatchRegion(FBase);
  FEpisodes.Free;
  inherited Destroy;
end;

procedure TWriteWatchMonitor.ClearWriteState;
begin
  FEnabled := False;
  FRegionSize := 0;
  FPageSize := 0;
  SetLength(FExpected, 0);
  FWasCorrupt := False;
  FLastContentValid := False;
  FWatchNeedsBaseline := False;
  FLastPoll := 0;
  FLastFreshWrite := 0;
  FLastCorrelation := 0;
  FLastBurst := 0;
  FLastRepeat := 0;
  FEpisodes.Clear;
end;

procedure TWriteWatchMonitor.InitializeWatchContents;
var
  I: Integer;
begin
  // Initialize exactly once before arming the write watch. Normal monitoring
  // NEVER writes to this dedicated memory after initialization.
  SetLength(FExpected, Integer(FRegionSize));
  for I := 0 to Length(FExpected) - 1 do
    FExpected[I] := Byte((I * 17 + 91 + (I shr 5)) and $FF);
  Move(FExpected[0], PByte(FBase)^, Length(FExpected));
end;

procedure TWriteWatchMonitor.Reset(TargetPID: Cardinal);
var
  ResetMask: Cardinal;
begin
  FObservationFailed := False;
  ReleaseWriteWatchRegion(FBase);
  ClearWriteState;
  if TargetPID <> WinCurrentProcessId then Exit;
  if not CreateWriteWatchRegion(FBase, FRegionSize, FPageSize) then Exit;
  InitializeWatchContents;
  // Discard self-initialization as baseline. No attempt to infer an attacker.
  FEnabled := QueryAndResetWriteWatch(FBase, FRegionSize, FPageSize,
    ResetMask);
  if not FEnabled then
  begin
    ReleaseWriteWatchRegion(FBase);
    SetLength(FExpected, 0);
  end;
end;

function TWriteWatchMonitor.RegionAddress: NativeUInt;
begin
  if FEnabled then Result := NativeUInt(FBase)
  else Result := 0;
end;

procedure TWriteWatchMonitor.ObserveHolder(const H: TTargetHolder;
  First, WasInactive, InBaseline: Boolean;
  PreviousRights: Cardinal; Tick: UInt64);
begin
  if InBaseline then Exit;
  if not WriteCapable(H.IsThread, H.RightsUnion) then Exit;
  if NewlyWriteCapable(H.IsThread, First, WasInactive,
      PreviousRights, H.RightsUnion) then FLastFreshWrite := Tick;
end;

procedure TWriteWatchMonitor.BreakWriteCoverage;
begin
  FObservationFailed := True;
  FEpisodes.Clear;
  FLastFreshWrite := 0;
  FWatchNeedsBaseline := True;
  FLastContentValid := False;
  // FWasCorrupt is a committed content result, not a query-success flag.
  // A failed read must not pretend it observed clean contents.
end;

function TWriteWatchMonitor.TryCanaryChanged(out Changed: Boolean): Boolean;
var
  Buffer: array[0..16383] of Byte;
  Copied: NativeUInt;
begin
  Result := False;
  Changed := False;
  FLastContentValid := False;
  if (FBase = nil) or (Length(FExpected) = 0) or
     (FRegionSize > NativeUInt(SizeOf(Buffer))) or
     (FRegionSize <> NativeUInt(Length(FExpected))) or
     not NHWAddressSpan(NativeUInt(FBase), FRegionSize) then Exit;
  if not RegionReadable then Exit;
  FillChar(Buffer, SizeOf(Buffer), 0);
  try
    if not CopyWatchMemory(FBase, @Buffer[0], FRegionSize, Copied) then Exit;
    if Copied <> FRegionSize then Exit;
    // Re-check allocation/protection after copying. This reduces races but
    // is not an atomic snapshot of contents or an allocation-generation ID.
    if not RegionReadable then Exit;
    Changed := not CompareMem(@Buffer[0], @FExpected[0], Length(FExpected));
    FLastContentValid := True;
    Result := True;
  finally
    FillChar(Buffer, SizeOf(Buffer), 0);
  end;
end;

procedure TWriteWatchMonitor.PruneEpisodes(NowTick: UInt64);
var
  I: Integer;
begin
  for I := FEpisodes.Count - 1 downto 0 do
    if (NowTick < FEpisodes[I].Tick) or
       (NowTick - FEpisodes[I].Tick > WRITE_WINDOW_MS) then
      FEpisodes.Delete(I);
  while FEpisodes.Count > 128 do FEpisodes.Delete(0);
end;

procedure TWriteWatchMonitor.AppendDirtyPages(DirtyMask: Cardinal; NowTick: UInt64);
var
  I: Integer;
  Event: TWriteEpisode;
  PageMask: Cardinal;
begin
  for I := 0 to WRITE_WATCH_PAGE_COUNT - 1 do
  begin
    PageMask := Cardinal(1) shl I;
    if (DirtyMask and PageMask) = 0 then Continue;
    Event.Tick := NowTick;
    Event.PageIndex := I;
    FEpisodes.Add(Event);
  end;
  while FEpisodes.Count > 128 do FEpisodes.Delete(0);
end;

procedure TWriteWatchMonitor.ReportWriteBurst(NowTick: UInt64;
  var Detected: TDetectionKinds);
var
  I: Integer;
  RecentPages: Cardinal;
begin
  // A burst requires >= 3 DISTINCT changed pages within 2.5 seconds.
  // Re-reading the same dirty page is NOT a multi-page burst.
  RecentPages := 0;
  for I := 0 to FEpisodes.Count - 1 do
    if RecentWriteObservation(NowTick, FEpisodes[I].Tick,
        WRITE_BURST_WINDOW_MS) then
      RecentPages := RecentPages or
        (Cardinal(1) shl FEpisodes[I].PageIndex);
  if (CountSetBits(RecentPages) >= WRITE_BURST_PAGES) and
     ((FLastBurst = 0) or (NowTick - FLastBurst >= WRITE_SIGNAL_COOLDOWN_MS)) then
  begin
    Include(Detected, dkWriteBurst);
    FLastBurst := NowTick;
  end;
end;

procedure TWriteWatchMonitor.ReportRepeatedWrites(DirtyMask: Cardinal; NowTick: UInt64;
  var Detected: TDetectionKinds);
var
  I, J, SameCount: Integer;
  PageMask: Cardinal;
begin
  // A repeated write requires the SAME page dirty in >= 3 separate
  // GetWriteWatch+RESET observation cycles within 10 seconds.
  for I := 0 to WRITE_WATCH_PAGE_COUNT - 1 do
  begin
    PageMask := Cardinal(1) shl I;
    if (DirtyMask and PageMask) = 0 then Continue;
    SameCount := 0;
    for J := 0 to FEpisodes.Count - 1 do
      if FEpisodes[J].PageIndex = I then Inc(SameCount);
    if SameCount >= WRITE_REPEAT_EPISODES then
    begin
      if (FLastRepeat = 0) or
         (NowTick - FLastRepeat >= WRITE_SIGNAL_COOLDOWN_MS) then
      begin
        Include(Detected, dkRepeatedWrite);
        FLastRepeat := NowTick;
      end;
      Break;
    end;
  end;
end;

procedure TWriteWatchMonitor.ReportWriteCorrelation(NowTick: UInt64;
  var Detected: TDetectionKinds);
begin
  if RecentWriteObservation(NowTick, FLastFreshWrite,
      WRITE_CORRELATION_MS) and
     ((FLastCorrelation = 0) or
      (NowTick - FLastCorrelation >= WRITE_CORRELATION_COOLDOWN_MS)) then
  begin
    Include(Detected, dkWriteCorrelation);
    FLastCorrelation := NowTick;
  end;
end;

procedure TWriteWatchMonitor.RecordPages(DirtyMask: Cardinal; NowTick: UInt64;
  var Detected: TDetectionKinds);
begin
  if DirtyMask = 0 then Exit;
  Include(Detected, dkWriteWatch);
  PruneEpisodes(NowTick);
  AppendDirtyPages(DirtyMask, NowTick);

  ReportWriteBurst(NowTick, Detected);

  ReportRepeatedWrites(DirtyMask, NowTick, Detected);

  ReportWriteCorrelation(NowTick, Detected);
end;

function TWriteWatchMonitor.RegionReadable: Boolean;
var
  I: Integer;
  Region: TVirtualRegion;
  PageAddress: NativeUInt;
  Protection: Cardinal;
begin
  Result := False;
  if (FBase = nil) or (FPageSize <> 4096) or
     (FRegionSize <> NativeUInt(FPageSize) * WRITE_WATCH_PAGE_COUNT) or
     not NHWAddressSpan(NativeUInt(FBase), FRegionSize) then Exit;
  for I := 0 to WRITE_WATCH_PAGE_COUNT - 1 do
  begin
    PageAddress := NativeUInt(FBase) + NativeUInt(I) * FPageSize;
    if not QueryWatchRegion(PageAddress, Region) then Exit;
    if not NHWContainedSpan(Region.BaseAddress, Region.Size,
      PageAddress, FPageSize) then Exit;
    if (Region.AllocationBase <> NativeUInt(FBase)) or
       (Region.State <> ALLOC_MEM_COMMIT) or
       (Region.RegionType <> ALLOC_MEM_PRIVATE) or
       ((Region.Protect and $100) <> 0) then Exit;
    Protection := Region.Protect and $FF;
    if (Protection <> $02) and (Protection <> $04) and
       (Protection <> $08) and (Protection <> $20) and
       (Protection <> $40) and (Protection <> $80) then Exit;
  end;
  Result := True;
end;

procedure TWriteWatchMonitor.Examine(TargetPID: Cardinal; Tick: UInt64;
  var Detected: TDetectionKinds);
var
  DirtyMask: Cardinal;
  Changed, DirtyObserved, Corroborated: Boolean;
begin
  FObservationFailed := False;
  if not FEnabled or (TargetPID <> WinCurrentProcessId) then Exit;
  if (FLastPoll <> 0) and (Tick >= FLastPoll) and
     (Tick - FLastPoll < WRITE_WATCH_SAMPLE_MS) then Exit;
  if Tick < FLastPoll then BreakWriteCoverage;
  FLastPoll := Tick;
  FLastContentValid := False;
  DirtyMask := 0;
  DirtyObserved := False;
  try
    if not RegionReadable then begin BreakWriteCoverage; Exit; end;
    if QueryWatchDirty(FBase, FRegionSize, FPageSize, DirtyMask) then
    begin
      if FWatchNeedsBaseline then
        FWatchNeedsBaseline := False // discard dirty pages spanning a gap
      else
        DirtyObserved := DirtyMask <> 0;
    end
    else
      BreakWriteCoverage;
    // A dirty WriteWatch page alone is not proof of hostile writing.  Windows
    // and legitimate in-process components can cause dirty observations over
    // long runtimes.  Require independent evidence: changed canary contents or
    // a freshly observed external PROCESS_VM_WRITE-capable holder.
    if not TryCanaryChanged(Changed) then begin BreakWriteCoverage; Exit; end;
    Corroborated := Changed or RecentWriteObservation(Tick, FLastFreshWrite,
      WRITE_CORRELATION_MS);
    if DirtyObserved and Corroborated then
      RecordPages(DirtyMask, Tick, Detected);
    if Changed and not FWasCorrupt then Include(Detected, dkWriteIntegrity);
    FWasCorrupt := Changed;
  except
    BreakWriteCoverage;
    raise;
  end;
end;

{$IFDEF NHW_NATIVE5I_TESTS}
{$I Cozy.NHW.Native5I.WriteWatch.inc}
{$ENDIF}

end.
