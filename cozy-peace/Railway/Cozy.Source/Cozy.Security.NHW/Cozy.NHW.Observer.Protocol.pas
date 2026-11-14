unit Cozy.NHW.Observer.Protocol;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

{$A8}

interface

uses
  Winapi.Windows, Cozy.NHW.ObserverAuthenticator;

type
  TObserverShutdownStatus = record
    HadChild, ForcedTerminationRequested, ExitObserved: Boolean;
    AuthenticatedReportObserved: Boolean;
    ElapsedMs: UInt64;
  end;
  TObserverShared = record
    Magic: Cardinal;
    Version: Cardinal;
    OwnerPID: Cardinal;
    OwnerCreated: UInt64;
    OwnerTick: UInt64;
    ObserverPID: Cardinal;
    ObservedCreation: UInt64;
    ObserverTick: UInt64;
    State: Cardinal;
    StopFlag: Cardinal;
    // v98 additive authenticated heartbeat. Never persisted.
    SessionKey: TObserverSessionKey;
    ProofRevision: UInt64;
    ProofEvidence: TObserverSessionEvidence;
    ProofMAC: TObserverSessionMAC;
    ExpectedChildPID: Cardinal;
    ExpectedChildCreated: UInt64;
    LaunchClaimed: LongInt;
  end;
  PObserverShared = ^TObserverShared;

const
  OBSERVER_MAGIC = $4E485736; // 'NHW6'
  OBSERVER_VERSION = 3;
  OBSERVER_QUERY_LIMITED = $1000;
  OBSERVER_POLL_MS = 700;
  OBSERVER_STALE_MS = 8000;


function ObserverClockTick: UInt64; stdcall;
function QueryProcessCreation(H: THandle; out Creation: UInt64): Boolean;
function ObserverIdentityMatches(ExpectedPID: Cardinal;
  ExpectedCreated: UInt64; ActualPID: Cardinal;
  ActualCreated: UInt64): Boolean;
function ObserverLoad64(var Value: UInt64): UInt64;
procedure ObserverStore64(var Destination: UInt64; Value: UInt64);
function ObserverStopped(View: PObserverShared): Boolean;

implementation

uses
  System.SyncObjs;

function ObserverClockTick: UInt64; stdcall; external 'kernel32.dll' name 'GetTickCount64';

function QueryProcessCreation(H: THandle; out Creation: UInt64): Boolean;
var C, E, K, U: TFileTime;
begin
  Creation := 0;
  Result := (H <> 0) and Winapi.Windows.GetProcessTimes(H, C, E, K, U);
  if Result then
  begin
    Creation := (UInt64(C.dwHighDateTime) shl 32) or C.dwLowDateTime;
    Result := Creation <> 0;
  end;
end;

function ObserverIdentityMatches(ExpectedPID: Cardinal;
  ExpectedCreated: UInt64; ActualPID: Cardinal;
  ActualCreated: UInt64): Boolean;
begin
  Result := (ExpectedPID <> 0) and (ExpectedPID = ActualPID) and
    (ExpectedCreated <> 0) and (ExpectedCreated = ActualCreated);
end;

function ObserverLoad64(var Value: UInt64): UInt64;
begin
  Result := UInt64(TInterlocked.CompareExchange(PInt64(@Value)^, Int64(0), Int64(0)));
end;

procedure ObserverStore64(var Destination: UInt64; Value: UInt64);
begin
  TInterlocked.Exchange(PInt64(@Destination)^, Int64(Value));
end;

function ObserverStopped(View: PObserverShared): Boolean;
begin
  Result := TInterlocked.CompareExchange(PInteger(@View^.StopFlag)^, 0, 0) <> 0;
end;

end.
