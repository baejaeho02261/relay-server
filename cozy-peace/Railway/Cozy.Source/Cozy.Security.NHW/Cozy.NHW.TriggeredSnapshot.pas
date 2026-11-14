unit Cozy.NHW.TriggeredSnapshot;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows;

type
  TTriggeredSnapshot = class
  private
    FRecentRelevant, FLastGrant, FLastAttempt, FReservationTick: UInt64;
    FHaveRelevant, FHaveGrant, FHaveAttempt, FReserved: Boolean;
  public
    constructor Create;
    procedure Reset;
    procedure SignalRelevant(Tick: UInt64);
    function CorroboratedTrigger(IndependentEvidence: Boolean;
      Tick: UInt64): Boolean;
    procedure CompleteAttempt(ReservationTick: UInt64; CaptureAttempted: Boolean);
  end;

{$IFDEF NHW_NATIVE10P_TESTS}
function TestTriggeredSnapshot10P(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10P_TESTS}
uses System.SysUtils;
{$ENDIF}

constructor TTriggeredSnapshot.Create;
begin inherited Create; Reset; end;

procedure TTriggeredSnapshot.Reset;
begin
  FRecentRelevant := 0;
  FLastGrant := 0;
  FLastAttempt := 0;
  FReservationTick := 0;
  FHaveRelevant := False;
  FHaveGrant := False;
  FHaveAttempt := False;
  FReserved := False;
end;

procedure TTriggeredSnapshot.SignalRelevant(Tick: UInt64);
begin
  if not FHaveRelevant or (Tick > FRecentRelevant) then
  begin FRecentRelevant := Tick; FHaveRelevant := True; end;
end;

function BeginTriggerObservation(Snapshot: TTriggeredSnapshot;
  Tick: UInt64): Boolean;
begin
  Result := True;
  if Snapshot.FHaveAttempt and (Tick < Snapshot.FLastAttempt) then
  begin
    Snapshot.Reset; // A new clock epoch needs fresh independent relevance.
    Result := False;
  end;
end;

function TriggerEvidenceFresh(Snapshot: TTriggeredSnapshot;
  IndependentEvidence: Boolean; Tick: UInt64): Boolean;
begin
  Result := IndependentEvidence and Snapshot.FHaveRelevant and
    (Tick >= Snapshot.FRecentRelevant) and
    (Tick - Snapshot.FRecentRelevant <= 3500);
end;

function TriggerRateAllowed(Snapshot: TTriggeredSnapshot;
  Tick: UInt64): Boolean;
begin
  Result := False;
  if Snapshot.FHaveGrant and (Tick >= Snapshot.FLastGrant) and
     (Tick - Snapshot.FLastGrant < 6000) then Exit;
  if Snapshot.FHaveAttempt and (Tick >= Snapshot.FLastAttempt) and
     (Tick - Snapshot.FLastAttempt < 1000) then Exit;
  Result := True;
end;

procedure ReserveTriggeredSnapshot(Snapshot: TTriggeredSnapshot;
  Tick: UInt64);
begin
  Snapshot.FLastAttempt := Tick;
  Snapshot.FHaveAttempt := True;
  Snapshot.FReservationTick := Tick;
  Snapshot.FReserved := True;
end;

function CompleteSnapshotReservation(Snapshot: TTriggeredSnapshot;
  ReservationTick: UInt64): Boolean;
begin
  Result := Snapshot.FReserved and
    (Snapshot.FReservationTick = ReservationTick);
  if Result then Snapshot.FReserved := False;
end;

function TTriggeredSnapshot.CorroboratedTrigger(IndependentEvidence: Boolean;
  Tick: UInt64): Boolean;
begin
  Result := False;
  if not BeginTriggerObservation(Self, Tick) then Exit;
  if not TriggerEvidenceFresh(Self, IndependentEvidence, Tick) then Exit;
  if not TriggerRateAllowed(Self, Tick) then Exit;
  ReserveTriggeredSnapshot(Self, Tick);
  Result := True;
end;

procedure TTriggeredSnapshot.CompleteAttempt(ReservationTick: UInt64;
  CaptureAttempted: Boolean);
begin
  if not CompleteSnapshotReservation(Self, ReservationTick) then Exit;
  if CaptureAttempted then
  begin
    // The API call counts even if capture/query/free fails: do not hammer PSS.
    FLastGrant := ReservationTick;
    FHaveGrant := True;
  end;
end;

{$IFDEF NHW_NATIVE10P_TESTS}
{$I Cozy.NHW.Native10P.TriggeredSnapshot.inc}
{$ENDIF}

end.
