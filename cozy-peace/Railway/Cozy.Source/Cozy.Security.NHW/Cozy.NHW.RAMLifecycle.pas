unit Cozy.NHW.RAMLifecycle;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

const
  NHW_RAM_STORE_LIMIT = 16;
  NHW_RAM_EVIDENCE_BUDGET = 1024 * 1024;

type
  TRAMPruneMethod = procedure(Tick: UInt64) of object;
  TRAMStoreState = record
    Registered: Boolean;
    ReservedBytes: NativeUInt;
    Prune: TRAMPruneMethod;
    Passes, Failures: UInt64;
  end;

  // Accounts for REGISTERED fixed-capacity evidence objects, not the entire
  // Delphi heap / OS buffers. Baselines and live handles are never evicted.
  // Register/unregister and maintenance are owned by the main scan thread.
  TRAMLifecycle = class
  private
    FStores: array[0..NHW_RAM_STORE_LIMIT - 1] of TRAMStoreState;
    FReserved, FLimit: NativeUInt;
    FLastMaintenance: UInt64;
    FHasMaintained, FCycleFailure: Boolean;
  public
    constructor Create(LimitBytes: NativeUInt = NHW_RAM_EVIDENCE_BUDGET);
    procedure Clear;
    function RegisterStore(ID: Integer; ReservedBytes: NativeUInt;
      Prune: TRAMPruneMethod): Boolean;
    procedure Maintain(Tick: UInt64; Force: Boolean = False);
    function StoreState(ID: Integer): TRAMStoreState;
    property ReservedBytes: NativeUInt read FReserved;
    property LimitBytes: NativeUInt read FLimit;
    property CycleFailure: Boolean read FCycleFailure;
  end;

implementation

uses System.SysUtils, Cozy.NHW.NativeSafety, Cozy.NHW.SensorFaultIsolation;

constructor TRAMLifecycle.Create(LimitBytes: NativeUInt);
begin
  inherited Create;
  FLimit := LimitBytes;
  Clear;
end;

procedure TRAMLifecycle.Clear;
begin
  // Unregister before freeing a source object; no dangling callback invokes.
  FillChar(FStores, SizeOf(FStores), 0);
  FReserved := 0;
  FLastMaintenance := 0;
  FHasMaintained := False;
  FCycleFailure := False;
end;

function TRAMLifecycle.RegisterStore(ID: Integer; ReservedBytes: NativeUInt;
  Prune: TRAMPruneMethod): Boolean;
begin
  Result := False;
  if (ID < 0) or (ID >= NHW_RAM_STORE_LIMIT) then Exit;
  if FStores[ID].Registered or (ReservedBytes = 0) or
    not Assigned(Prune) then Exit;
  if not NHWBufferSpan(FLimit, FReserved, ReservedBytes) then Exit;
  FStores[ID].Registered := True;
  FStores[ID].ReservedBytes := ReservedBytes;
  FStores[ID].Prune := Prune;
  FReserved := FReserved + ReservedBytes;
  Result := True;
end;

procedure TRAMLifecycle.Maintain(Tick: UInt64; Force: Boolean);
var I: Integer;
begin
  FCycleFailure := False;
  if not Force and FHasMaintained and (Tick >= FLastMaintenance) and
    (Tick - FLastMaintenance < 1000) then Exit;
  FHasMaintained := True;
  FLastMaintenance := Tick;
  for I := Low(FStores) to High(FStores) do
  begin
    if not FStores[I].Registered then Continue;
    try
      FStores[I].Prune(Tick);
      FStores[I].Passes := NHWSaturatingAdd(FStores[I].Passes, 1);
    except
      on E: Exception do
      begin
        FStores[I].Failures := NHWSaturatingAdd(FStores[I].Failures, 1);
        FCycleFailure := True;
        if NHWFatalSensorException(E) then raise;
        // Continue maintenance of unrelated stores. Do not fabricate success.
      end;
    end;
  end;
end;

function TRAMLifecycle.StoreState(ID: Integer): TRAMStoreState;
begin
  Result := Default(TRAMStoreState);
  if (ID >= 0) and (ID < NHW_RAM_STORE_LIMIT) then Result := FStores[ID];
end;

end.
