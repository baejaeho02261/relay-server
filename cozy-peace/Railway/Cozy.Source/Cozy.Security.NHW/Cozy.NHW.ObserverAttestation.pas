unit Cozy.NHW.ObserverAttestation;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.DualObserver, Cozy.NHW.ObserverAuthenticator;

type
  TObserverAuthGrade = (oagUnknown, oagUnavailable,
    oagAuthenticated, oagStale);
  // v98: HMAC validates a current companion heartbeat and known session.
  // The key lives in pagefile-backed shared memory, so a hostile same-user
  // process that reads that mapping could forge it. NOT a trust boundary.
  TObserverAttestation = class
  private
    FGrade: TObserverAuthGrade;
    FLastAuthenticated: UInt64;
    FLastSequence: UInt64;
    FObserverPID: Cardinal;
    FOwnerCreated: UInt64;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(const Observer: TDualObserver;
      SelfTarget, StableTarget: Boolean; Tick: UInt64);
    property Grade: TObserverAuthGrade read FGrade;
    property LastSequence: UInt64 read FLastSequence;
    property LastAuthenticated: UInt64 read FLastAuthenticated;
  end;

{$IFDEF NHW_NATIVE10Q_TESTS}
function TestObserverAttestation10Q(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10Q_TESTS}
uses System.SysUtils;
type TAttestationRead10Q = function(Tick: UInt64;
  out Evidence: TObserverSessionEvidence; out Available: Boolean): Boolean;
var AttestationRead10Q: TAttestationRead10Q = nil;
{$ENDIF}

constructor TObserverAttestation.Create;
begin inherited Create; Reset; end;

procedure TObserverAttestation.Reset;
begin
  FGrade := oagUnknown;
  FLastAuthenticated := 0;
  FLastSequence := 0;
  FObserverPID := 0;
  FOwnerCreated := 0;
end;

function ReadObserverEvidence(const Observer: TDualObserver; Tick: UInt64;
  out Evidence: TObserverSessionEvidence; out Available: Boolean): Boolean;
begin
  Evidence := Default(TObserverSessionEvidence);
  Available := False;
  {$IFDEF NHW_NATIVE10Q_TESTS}
  if Assigned(AttestationRead10Q) then
    Exit(AttestationRead10Q(Tick, Evidence, Available));
  {$ENDIF}
  Result := Observer.SnapshotReport(Tick, Evidence, Available);
end;

procedure ApplyObserverEvidence(Monitor: TObserverAttestation;
  const Evidence: TObserverSessionEvidence; Tick: UInt64);
begin
  if (Evidence.State <> 1) or (Evidence.Sequence = 0) or
     (Evidence.ObservedTick = 0) or (Evidence.ObservedTick > Tick) then Exit;
  if (Monitor.FObserverPID <> Evidence.ObserverPID) or
     (Monitor.FOwnerCreated <> Evidence.OwnerCreated) then
  begin
    Monitor.FLastSequence := 0;
    Monitor.FLastAuthenticated := 0;
    Monitor.FObserverPID := Evidence.ObserverPID;
    Monitor.FOwnerCreated := Evidence.OwnerCreated;
  end;
  if (Evidence.Sequence < Monitor.FLastSequence) or
     (Evidence.ObservedTick < Monitor.FLastAuthenticated) then Exit;
  if Evidence.Sequence = Monitor.FLastSequence then
  begin
    if Evidence.ObservedTick = Monitor.FLastAuthenticated then
      Monitor.FGrade := oagAuthenticated;
    Exit; // duplicate health poll never manufactures a new observation time
  end;
  if (Monitor.FLastSequence <> 0) and
     (Evidence.ObservedTick <= Monitor.FLastAuthenticated) then Exit;
  Monitor.FGrade := oagAuthenticated;
  Monitor.FLastSequence := Evidence.Sequence;
  Monitor.FLastAuthenticated := Evidence.ObservedTick;
end;

procedure TObserverAttestation.Examine(const Observer: TDualObserver;
  SelfTarget, StableTarget: Boolean; Tick: UInt64);
var
  E: TObserverSessionEvidence;
  Available, Verified: Boolean;
begin
  FGrade := oagUnknown;
  if not SelfTarget or not StableTarget then
  begin Reset; Exit; end;
  if Observer = nil then
  begin FGrade := oagUnavailable; Exit; end;
  Verified := ReadObserverEvidence(Observer, Tick, E, Available);
  if not Available then
  begin FGrade := oagUnavailable; Exit; end;
  FGrade := oagStale;
  if not Verified then Exit;
  ApplyObserverEvidence(Self, E, Tick);
end;

{$IFDEF NHW_NATIVE10Q_TESTS}
{$I Cozy.NHW.Native10Q.ObserverAttestation.inc}
{$ENDIF}

end.
