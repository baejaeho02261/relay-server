unit Cozy.NHW.MicroburstAccess;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows;

type
  TRecentRightsObservation = record
    OwnerPID: Cardinal;
    OwnerCreated: UInt64;
    Rights: Cardinal;
    Tick: UInt64;
    Used: Boolean;
  end;

  // Sampled capability observations, NOT an OpenProcess call trace.
  // One slot per PID+creation epoch; unknown identities are not correlated.
  TMicroburstAccess = class
  private
    FItems: array[0..63] of TRecentRightsObservation;
    FLastTick: UInt64;
    FHaveTick: Boolean;
  public
    constructor Create;
    procedure Reset;
    procedure ObserveNewEdge(OwnerPID, Rights: Cardinal; Tick: UInt64;
      OwnerCreated: UInt64 = 0);
    function Correlated(Tick: UInt64): Boolean;
  end;

{$IFDEF NHW_NATIVE10P_TESTS}
function TestMicroburstAccess10P(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10P_TESTS}
uses System.SysUtils;
{$ENDIF}

const MICROBURST_WINDOW_MS = 2000;

constructor TMicroburstAccess.Create;
begin inherited Create; Reset; end;

procedure TMicroburstAccess.Reset;
begin
  FillChar(FItems, SizeOf(FItems), 0);
  FLastTick := 0;
  FHaveTick := False;
end;

procedure ScanMicroburstSlots(Monitor: TMicroburstAccess;
  OwnerPID: Cardinal; OwnerCreated, Tick: UInt64;
  out Match, Empty, Oldest: Integer);
var I: Integer;
begin
  Match := -1;
  Empty := -1;
  Oldest := -1;
  for I := Low(Monitor.FItems) to High(Monitor.FItems) do
  begin
    if Monitor.FItems[I].Used then
    begin
      if (Tick < Monitor.FItems[I].Tick) or
         (Tick - Monitor.FItems[I].Tick > MICROBURST_WINDOW_MS) or
         ((Monitor.FItems[I].OwnerPID = OwnerPID) and
          (Monitor.FItems[I].OwnerCreated <> OwnerCreated)) then
        Monitor.FItems[I] := Default(TRecentRightsObservation);
    end;
    if not Monitor.FItems[I].Used then
    begin
      if Empty < 0 then Empty := I;
      Continue;
    end;
    if (Monitor.FItems[I].OwnerPID = OwnerPID) and
       (Monitor.FItems[I].OwnerCreated = OwnerCreated) then Match := I;
    if (Oldest < 0) then Oldest := I
    else if Monitor.FItems[I].Tick < Monitor.FItems[Oldest].Tick then Oldest := I;
  end;
end;

procedure StoreMicroburstEdge(Monitor: TMicroburstAccess; Slot: Integer;
  OwnerPID, Rights: Cardinal; OwnerCreated, Tick: UInt64);
begin
  Monitor.FItems[Slot] := Default(TRecentRightsObservation);
  Monitor.FItems[Slot].Used := True;
  Monitor.FItems[Slot].OwnerPID := OwnerPID;
  Monitor.FItems[Slot].OwnerCreated := OwnerCreated;
  Monitor.FItems[Slot].Rights := Rights;
  Monitor.FItems[Slot].Tick := Tick;
end;

procedure TMicroburstAccess.ObserveNewEdge(OwnerPID, Rights: Cardinal;
  Tick, OwnerCreated: UInt64);
var Match, Empty, Oldest: Integer;
begin
  if (OwnerPID = 0) or (Rights = 0) or (OwnerCreated = 0) then Exit;
  // Older delivery cannot rewrite newer identity/history. Reset belongs to
  // an explicit engine session/target reset, not a single delayed event.
  if FHaveTick and (Tick < FLastTick) then Exit;
  FHaveTick := True;
  FLastTick := Tick;
  ScanMicroburstSlots(Self, OwnerPID, OwnerCreated, Tick,
    Match, Empty, Oldest);
  if Match >= 0 then
  begin
    FItems[Match].Rights := FItems[Match].Rights or Rights;
    FItems[Match].Tick := Tick;
    Exit;
  end;
  if Empty >= 0 then Match := Empty else Match := Oldest;
  if Match < 0 then Exit;
  StoreMicroburstEdge(Self, Match, OwnerPID, Rights, OwnerCreated, Tick);
end;

function TMicroburstAccess.Correlated(Tick: UInt64): Boolean;
var I, Distinct: Integer;
begin
  Result := False;
  if FHaveTick and (Tick < FLastTick) then Exit;
  Distinct := 0;
  for I := Low(FItems) to High(FItems) do
    if FItems[I].Used and (Tick >= FItems[I].Tick) and
       (Tick - FItems[I].Tick <= MICROBURST_WINDOW_MS) then
    begin
      Inc(Distinct);
      if Distinct >= 2 then Exit(True);
    end;
end;

{$IFDEF NHW_NATIVE10P_TESTS}
{$I Cozy.NHW.Native10P.MicroburstAccess.inc}
{$ENDIF}

end.
