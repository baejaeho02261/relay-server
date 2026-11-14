unit Cozy.NHW.Namespace;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.Logging,
  Cozy.NHW.NamespaceNative;

const
  NAMESPACE_POLL_MS = 5000;
  NAMESPACE_BURST_WINDOW_MS = 10000;
  NAMESPACE_BURST_THRESHOLD = 5;

// The public diff helper is pure: it does not query Windows or output text.
function CompareNamespaceEntries(const Before, After: TNamespaceEntries;
  DeviceDirectory: Boolean; out Changes: Integer): TDetectionKinds;

type
  TNamespaceWatch = class
  private
    FPath: string;
    FIsDeviceDirectory: Boolean;
    FRestrictToNHW: Boolean;
    FEntries: TNamespaceEntries;
    FPrimed: Boolean;
    FDaclKnown: Boolean;
    FDaclSignature: UInt64;
  public
    constructor Create(const NativePath: string;
      DeviceDirectory, RestrictToNHW: Boolean);
    destructor Destroy; override;
    function Examine(out Changes, NHWChanges: Integer): TDetectionKinds;
  end;

  TNamespaceMonitor = class
  private
    FWatches: TObjectList<TNamespaceWatch>;
    FChangeHistory: TList<UInt64>;
    FLastTick: UInt64;
    FBurstActive: Boolean;
    procedure AddWatch(const Path: string;
      IsDevice, RestrictToNHW: Boolean);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset(TargetPID: Cardinal);
    procedure Examine(Tick: UInt64; var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE10M_TESTS}
function TestNamespace10M(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.WinPointers;

{$IFDEF NHW_NATIVE10M_TESTS}
{$I Cozy.NHW.Native10M.Namespace.Hooks.inc}
{$ENDIF}

function IsSymbolicLink(const Entry: TNamespaceEntry): Boolean;
begin
  Result := SameText(Entry.TypeName, 'SymbolicLink');
end;

function CompareNamespaceEntries(const Before, After: TNamespaceEntries;
  DeviceDirectory: Boolean; out Changes: Integer): TDetectionKinds;
var
  KV: TPair<string, TNamespaceEntry>;
  Previous: TNamespaceEntry;
  WasLink, IsLink: Boolean;
begin
  Result := [];
  Changes := 0;
  for KV in After do
  begin
    if not Before.TryGetValue(KV.Key, Previous) then
    begin
      Inc(Changes);
      Include(Result, dkNamespace);
      if DeviceDirectory and IsSymbolicLink(KV.Value) then
        Include(Result, dkDeviceMap);
      Continue;
    end;
    WasLink := IsSymbolicLink(Previous);
    IsLink := IsSymbolicLink(KV.Value);
    if not SameText(Previous.TypeName, KV.Value.TypeName) then
    begin
      Inc(Changes);
      Include(Result, dkObjectType);
      if DeviceDirectory and (WasLink or IsLink) then
        Include(Result, dkDeviceMap);
    end;
    if WasLink and IsLink and Previous.TargetKnown and
       KV.Value.TargetKnown and (not SameText(Previous.Target, KV.Value.Target)) then
    begin
      Inc(Changes);
      Include(Result, dkSymbolicLink);
      if DeviceDirectory then Include(Result, dkDeviceMap);
    end;
  end;
  for KV in Before do
    if not After.ContainsKey(KV.Key) then
    begin
      Inc(Changes);
      Include(Result, dkNamespace);
      if DeviceDirectory and IsSymbolicLink(KV.Value) then
        Include(Result, dkDeviceMap);
    end;
end;

constructor TNamespaceWatch.Create(const NativePath: string;
  DeviceDirectory, RestrictToNHW: Boolean);
begin
  inherited Create;
  FPath := NativePath;
  FIsDeviceDirectory := DeviceDirectory;
  FRestrictToNHW := RestrictToNHW;
  FEntries := TNamespaceEntries.Create;
  FPrimed := False;
  FDaclKnown := False;
end;

destructor TNamespaceWatch.Destroy;
begin
  FEntries.Free;
  inherited;
end;

function TNamespaceWatch.Examine(out Changes, NHWChanges: Integer): TDetectionKinds;
var
  Current, OldEntries: TNamespaceEntries;
  Old: TNamespaceEntry;
  Dacl: UInt64;
  HasDacl: Boolean;
  NeedRemove: TList<string>;
  NeedUpdate: TList<TPair<string, TNamespaceEntry>>;
  Entry: TNamespaceEntry;

  procedure FilterSelectedEntries;
  var
    K: string;
  begin
    if FRestrictToNHW then
    begin
      for K in Current.Keys do
        if (Pos('NHW.', K) <> 1) and
           (Pos('NATIVEHANDLEWATCH', K) <> 1) then
          NeedRemove.Add(K);
      for K in NeedRemove do Current.Remove(K);
    end;
    // There is no recursive scan of Device\NamedPipe or other IPC trees.
    if SameText(FPath, '\Device') then Current.Remove('NAMEDPIPE');
  end;

  procedure PreserveKnownLinkTargets;
  var
    KV, Update: TPair<string, TNamespaceEntry>;
  begin
    for KV in Current do
      if (not KV.Value.TargetKnown) and FEntries.TryGetValue(KV.Key, Old) and
         SameText(KV.Value.TypeName, Old.TypeName) and Old.TargetKnown then
      begin
        Entry := KV.Value;
        Entry.TargetKnown := True;
        Entry.Target := Old.Target;
        NeedUpdate.Add(TPair<string, TNamespaceEntry>.Create(KV.Key, Entry));
      end;
    for Update in NeedUpdate do
      Current.AddOrSetValue(Update.Key, Update.Value);
  end;

  procedure CommitCompletedSnapshot;
  begin
    OldEntries := FEntries;
    FEntries := Current;
    Current := OldEntries; // finally now frees the retired snapshot
    FPrimed := True;
    if HasDacl then
    begin
      FDaclKnown := True;
      FDaclSignature := Dacl;
    end;
  end;

begin
  Result := [];
  Changes := 0;
  NHWChanges := 0;
  Current := nil;
  NeedRemove := nil;
  NeedUpdate := nil;
  try
    Current := TNamespaceEntries.Create;
    NeedRemove := TList<string>.Create;
    NeedUpdate := TList<TPair<string, TNamespaceEntry>>.Create;
    if not EnumerateNamespace(FPath, Current) then Exit;
    FilterSelectedEntries;
    // Preserve the last successful target when a link query temporarily fails.
    // Never interpret inaccessible targets as removed/changed links.
    PreserveKnownLinkTargets;
    HasDacl := QueryNamespaceDacl(FPath, Dacl);
    if FPrimed then
    begin
      Result := CompareNamespaceEntries(FEntries, Current,
        FIsDeviceDirectory, Changes);
      // Only filtered NHW entries can contribute to the burst threshold.
      // Directory DACL changes are still detected, but do not count as NHW objects.
      if FRestrictToNHW then NHWChanges := Changes;
      if HasDacl then
      begin
        if FDaclKnown and (FDaclSignature <> Dacl) then
        begin
          Include(Result, dkObjectSecurity);
          Inc(Changes);
        end;
      end;
    end;
    // Commit only after enumeration, filtering, target preservation and diff
    // have all succeeded. Reference assignments do not allocate dictionary nodes.
    CommitCompletedSnapshot;
  finally
    NeedUpdate.Free;
    NeedRemove.Free;
    Current.Free;
  end;
end;

constructor TNamespaceMonitor.Create;
begin
  inherited Create;
  FWatches := TObjectList<TNamespaceWatch>.Create(True);
  FChangeHistory := TList<UInt64>.Create;
  FLastTick := 0;
  FBurstActive := False;
end;

destructor TNamespaceMonitor.Destroy;
begin
  FChangeHistory.Free;
  FWatches.Free;
  inherited;
end;

procedure TNamespaceMonitor.AddWatch(const Path: string;
  IsDevice, RestrictToNHW: Boolean);
var
  I: Integer;
begin
  for I := 0 to FWatches.Count - 1 do
    if SameText(FWatches[I].FPath, Path) then Exit;
  FWatches.Add(TNamespaceWatch.Create(Path, IsDevice, RestrictToNHW));
end;

procedure TNamespaceMonitor.Reset(TargetPID: Cardinal);
var
  SessionID: Cardinal;
begin
  FWatches.Clear;
  FChangeHistory.Clear;
  FLastTick := 0;
  FBurstActive := False;
  // Bounded, selected directories only. No recursive object traversal.
  AddWatch('\KnownDlls', False, False);
  AddWatch('\GLOBAL??', True, False);
  AddWatch('\??', True, False);
  AddWatch('\Device', False, False);
  AddWatch('\BaseNamedObjects', False, True);
  SessionID := 0;
  if WinProcessIdToSessionId(TargetPID, SessionID) then
    AddWatch('\Sessions\' + IntToStr(SessionID) + '\BaseNamedObjects',
      False, True);
end;

procedure TNamespaceMonitor.Examine(Tick: UInt64;
  var Detected: TDetectionKinds);
var
  I, J, Changes, NHWChanges, TotalChanges: Integer;
  NewKinds: TDetectionKinds;
begin
  if (FLastTick <> 0) and (Tick >= FLastTick) and
     (Tick - FLastTick < NAMESPACE_POLL_MS) then Exit;
  FLastTick := Tick;
  TotalChanges := 0;
  for I := 0 to FWatches.Count - 1 do
  begin
    // Unsupported/inaccessible directories do not erase previous baselines.
    try
      NewKinds := FWatches[I].Examine(Changes, NHWChanges);
      Detected := Detected + NewKinds;
      Inc(TotalChanges, NHWChanges);
    except
      // NT Object Manager interfaces are version sensitive.
      // An invalid/incomplete query is UNKNOWN, never a detection.
    end;
  end;
  while (FChangeHistory.Count > 0) and (Tick >= FChangeHistory[0]) and
        (Tick - FChangeHistory[0] > NAMESPACE_BURST_WINDOW_MS) do
    FChangeHistory.Delete(0);
  if TotalChanges > 16 then TotalChanges := 16;
  for J := 1 to TotalChanges do FChangeHistory.Add(Tick);
  if FChangeHistory.Count >= NAMESPACE_BURST_THRESHOLD then
  begin
    if not FBurstActive then Include(Detected, dkNamespaceBurst);
    FBurstActive := True;
  end
  else
    FBurstActive := False;
end;

{$IFDEF NHW_NATIVE10M_TESTS}
{$I Cozy.NHW.Native10M.Namespace.inc}
{$ENDIF}

end.
