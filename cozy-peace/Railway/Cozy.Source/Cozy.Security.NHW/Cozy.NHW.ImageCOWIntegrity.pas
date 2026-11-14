unit Cozy.NHW.ImageCOWIntegrity;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.Generics.Collections, Cozy.NHW.Logging;

type
  // v44: resident executable MEM_IMAGE pages formerly observed as shared.
  // Native5E preserves a cursor for each of the FOUR original module slots.
  TImageCOWMonitor = class
  private
    FInspectionAttempted: Boolean;
    FShared: TDictionary<NativeUInt, Byte>;
    FPending: TDictionary<NativeUInt, Byte>;
    FModuleBase: array[0..3] of NativeUInt;
    FCursor: array[0..3] of NativeUInt;
    FNextModule: Integer;
    FLastScan: UInt64;
    FLastReport: UInt64;
    FLastCodeChange: UInt64;
    FHaveBaseline: Boolean;
    procedure ClearPendingRange(First, Limit: NativeUInt);
  public
    property InspectionAttempted: Boolean read FInspectionAttempted;
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(Baseline: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

function IsConfirmedCOW(WasShared, IsShared: Boolean;
  Confirmations: Byte; CodeChangeRecent: Boolean): Boolean;

{$IFDEF NHW_NATIVE5E_TESTS}
function TestImageCOWHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, Cozy.NHW.AllocationNative, Cozy.NHW.WinPointers,
  Cozy.NHW.SignalCorrelation;

const
  PAGE_BYTES = 4096;
  MAX_IMAGE_SCAN_BYTES = 32 * 1024 * 1024;
  MAX_COW_PAGES_PER_SCAN = 384;
  MAX_COW_REGION_QUERIES = MAX_COW_PAGES_PER_SCAN * 4;
  COW_SCAN_PERIOD_MS = 6000;
  COW_REPORT_COOLDOWN_MS = 25000;
  CODE_CHANGE_WINDOW_MS = 16000;

type
  TWorkingSetInfo = record
    VirtualAddress: Pointer;
    Flags: NativeUInt;
  end;
  TQueryWorkingSetEx = function(ProcessHandle: THandle;
    Info: Pointer; Bytes: Cardinal): BOOL; stdcall;

var
  FQueryWS: TQueryWorkingSetEx = nil;
  FQueryResolved: Boolean = False;

{$IFDEF NHW_NATIVE5E_TESTS}
type
  TCOWModuleHook = function(Index: Integer): HMODULE;
  TCOWRegionHook = function(Address: NativeUInt;
    out Region: TVirtualRegion): Boolean;
var
  COWModuleHook: TCOWModuleHook = nil;
  COWRegionHook: TCOWRegionHook = nil;
{$ENDIF}

function COWModule(Index: Integer): HMODULE;
begin
{$IFDEF NHW_NATIVE5E_TESTS}
  if Assigned(COWModuleHook) then Exit(COWModuleHook(Index));
{$ENDIF}
  case Index of
    0: Result := HMODULE(HInstance);
    1: Result := WinModule('ntdll.dll');
    2: Result := WinModule('kernel32.dll');
    3: Result := WinModule('kernelbase.dll');
  else Result := 0;
  end;
end;

function COWRegion(Address: NativeUInt; out Region: TVirtualRegion): Boolean;
begin
  Region := Default(TVirtualRegion);
{$IFDEF NHW_NATIVE5E_TESTS}
  if Assigned(COWRegionHook) then Exit(COWRegionHook(Address, Region));
{$ENDIF}
  Result := QueryVirtualRegion(WinCurrentProcess, Address, Region);
end;

procedure ResolveWS;
var M: HMODULE;
begin
  if FQueryResolved then Exit;
  M := WinModule('kernel32.dll');
  FQueryWS := TQueryWorkingSetEx(WinExport(M, 'K32QueryWorkingSetEx'));
  if not Assigned(FQueryWS) then
  begin
    M := WinLoadLibrary('psapi.dll');
    FQueryWS := TQueryWorkingSetEx(WinExport(M, 'QueryWorkingSetEx'));
  end;
  FQueryResolved := True;
end;

function ReadSharedFlag(Address: NativeUInt; out IsShared: Boolean): Boolean;
var Info: TWorkingSetInfo;
begin
  Result := False;
  IsShared := False;
  ResolveWS;
  if not Assigned(FQueryWS) then Exit;
  Info := Default(TWorkingSetInfo);
  Info.VirtualAddress := Pointer(Address);
  if not FQueryWS(WinCurrentProcess, @Info, SizeOf(Info)) then Exit;
  // Valid must be set before interpreting Shared. Do not fault pages in.
  if (Info.Flags and 1) = 0 then Exit;
  IsShared := (Info.Flags and $8000) <> 0;
  Result := True;
end;

function IsConfirmedCOW(WasShared, IsShared: Boolean;
  Confirmations: Byte; CodeChangeRecent: Boolean): Boolean;
begin
  Result := WasShared and not IsShared and
    (Confirmations >= 2) and CodeChangeRecent;
end;

constructor TImageCOWMonitor.Create;
begin
  inherited Create;
  FShared := TDictionary<NativeUInt, Byte>.Create;
  FPending := TDictionary<NativeUInt, Byte>.Create;
  Reset;
end;

destructor TImageCOWMonitor.Destroy;
begin
  FPending.Free;
  FShared.Free;
  inherited Destroy;
end;

procedure TImageCOWMonitor.Reset;
var I: Integer;
begin
  FInspectionAttempted := False;
  FShared.Clear;
  FPending.Clear;
  for I := 0 to 3 do
  begin
    FModuleBase[I] := 0;
    FCursor[I] := 0;
  end;
  FNextModule := 0;
  FLastScan := 0;
  FLastReport := 0;
  FLastCodeChange := 0;
  FHaveBaseline := False;
end;

procedure TImageCOWMonitor.ClearPendingRange(First, Limit: NativeUInt);
var Pages: TArray<NativeUInt>; Page: NativeUInt;
begin
  if FPending.Count = 0 then Exit;
  Pages := FPending.Keys.ToArray;
  for Page in Pages do
    if (Page >= First) and (Page < Limit) then FPending.Remove(Page);
end;

procedure TImageCOWMonitor.Examine(Baseline: Boolean;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  Modules: array[0..3] of NativeUInt;
  CodeRecent, Changed: Boolean;
  Samples, Queries, FirstModule: Integer;

  procedure SynchronizeModuleSlots;
  var
    BasesChanged: Boolean;
    I, J: Integer;
  begin
    BasesChanged := False;
    for I := 0 to 3 do
    begin
      Modules[I] := NativeUInt(COWModule(I));
      if (Modules[I] < $10000) or
         (Modules[I] > High(NativeUInt) - NativeUInt(MAX_IMAGE_SCAN_BYTES)) or
         ((Modules[I] mod PAGE_BYTES) <> 0) then Modules[I] := 0;
      // Never sample one address twice through duplicate slots in one sweep.
      for J := 0 to I - 1 do
        if Modules[I] = Modules[J] then Modules[I] := 0;
      if Modules[I] <> FModuleBase[I] then BasesChanged := True;
    end;
    if BasesChanged then
    begin
      // An observed module-base change invalidates the old address-keyed
      // history. An unload/reload at the SAME base between scans is not proven.
      FShared.Clear;
      FPending.Clear;
      FHaveBaseline := False;
      for I := 0 to 3 do
      begin
        FModuleBase[I] := Modules[I];
        FCursor[I] := Modules[I];
      end;
    end;
  end;

  procedure ObserveResidentPage(Page: NativeUInt);
  var
    Prev, Pending: Byte;
    Shared: Boolean;
  begin
    Prev := 0;
    Pending := 0;
    if ReadSharedFlag(Page, Shared) then
    begin
      if not Baseline and FShared.TryGetValue(Page, Prev) and
         (Prev <> 0) and not Shared then
      begin
        if not FPending.TryGetValue(Page, Pending) then Pending := 0;
        if Pending < 2 then Inc(Pending);
        FPending.AddOrSetValue(Page, Pending);
        if IsConfirmedCOW(True, Shared, Pending,
          FHaveBaseline and CodeRecent) then Changed := True;
      end
      else FPending.Remove(Page);
      if Shared then FShared.AddOrSetValue(Page, 1)
      else if not FShared.ContainsKey(Page) then
        FShared.AddOrSetValue(Page, 0);
    end
    else FPending.Remove(Page); // residency/query failure is unknown
  end;

  procedure InspectRotatingModules;
  var
    ModuleBase, Cursor, Limit, StopAt, Page: NativeUInt;
    R: TVirtualRegion;
    I, Turn, ModuleSamples, Budget: Integer;
  begin
    for Turn := 0 to 3 do
    begin
      I := (FirstModule + Turn) mod 4;
      ModuleBase := Modules[I];
      if ModuleBase = 0 then Continue;
      Limit := ModuleBase + NativeUInt(MAX_IMAGE_SCAN_BYTES);
      Cursor := FCursor[I];
      if (Cursor < ModuleBase) or (Cursor >= Limit) or
         ((Cursor mod PAGE_BYTES) <> 0) then Cursor := ModuleBase;
      // Reserve work for later slots. Unused work is available to those
      // slots; rotating the first slot prevents a fixed ordering advantage.
      Budget := (MAX_COW_PAGES_PER_SCAN - Samples) div (4 - Turn);
      ModuleSamples := 0;
      while (Cursor < Limit) and (ModuleSamples < Budget) and
            (Queries < MAX_COW_REGION_QUERIES) do
      begin
        Inc(Queries);
        if not COWRegion(Cursor, R) then
        begin
          // An unknown region breaks candidate continuity. Move one page
          // ahead so an unreadable page cannot pin this cursor forever.
          FPending.Clear;
          Inc(Cursor, PAGE_BYTES); // Cursor < Limit; Limit itself was checked
          Break;
        end;
        if (R.Size = 0) or (R.BaseAddress > Cursor) or
           (R.BaseAddress > High(NativeUInt) - R.Size) then
        begin
          FPending.Clear;
          Inc(Cursor, PAGE_BYTES);
          Break;
        end;
        StopAt := R.BaseAddress + R.Size;
        if (StopAt <= Cursor) or ((StopAt mod PAGE_BYTES) <> 0) then
        begin
          FPending.Clear;
          Inc(Cursor, PAGE_BYTES);
          Break;
        end;
        if R.AllocationBase <> ModuleBase then
        begin
          Cursor := Limit; // reached this image's end; wrap next invocation
          Break;
        end;
        if StopAt > Limit then StopAt := Limit;
        if (R.RegionType = ALLOC_MEM_IMAGE) and RegionIsExecutable(R) then
        begin
          Page := Cursor;
          while (Page < StopAt) and (ModuleSamples < Budget) do
          begin
            Inc(Samples);
            Inc(ModuleSamples);
            ObserveResidentPage(Page);
            Inc(Page, PAGE_BYTES);
          end;
          Cursor := Page; // preserve the exact page on budget exhaustion
        end
        else
        begin
          ClearPendingRange(Cursor, StopAt);
          Cursor := StopAt;
        end;
      end;
      if Cursor >= Limit then FCursor[I] := ModuleBase
      else FCursor[I] := Cursor;
    end;
  end;

begin
  FInspectionAttempted := False;
  if (FLastScan <> 0) and (Tick < FLastScan) then
  begin
    FPending.Clear;
    FLastReport := 0;
    FLastCodeChange := 0;
  end;
  if dkPECodeIntegrity in Detected then FLastCodeChange := Tick;
  if (FLastScan <> 0) and (Tick >= FLastScan) and
     (Tick - FLastScan < COW_SCAN_PERIOD_MS) then Exit;
  FLastScan := Tick;
  FInspectionAttempted := True;
  SynchronizeModuleSlots;
  if Baseline then FPending.Clear;
  Samples := 0;
  Queries := 0;
  Changed := False;
  FirstModule := FNextModule;
  FNextModule := (FNextModule + 1) mod 4;
  CodeRecent := RecentSignal(FLastCodeChange, Tick, CODE_CHANGE_WINDOW_MS);
  try
    InspectRotatingModules;
  except
    FPending.Clear;
    raise;
  end;
  if Samples > 0 then FHaveBaseline := True;
  if Changed and not Baseline and ((FLastReport = 0) or
    ((Tick >= FLastReport) and
     (Tick - FLastReport >= COW_REPORT_COOLDOWN_MS))) then
  begin
    Include(Detected, dkImageCOWIntegrity);
    FLastReport := Tick;
  end;
end;

{$IFDEF NHW_NATIVE5E_TESTS}
{$I Cozy.NHW.Native5E.ImageCOW.inc}
{$ENDIF}

end.
