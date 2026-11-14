unit Cozy.Api.Types;

{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Platform,

  {$IFDEF FPC}SysUtils{$ELSE}System.SysUtils{$ENDIF};

type
  EGameApi = class(Exception)
  private
    FCode: string;
    FRetryable: Boolean;
  public
    constructor Create(const ACode, AMessage: string;
      ARetryable: Boolean = False); reintroduce;
    property Code: string read FCode;
    property Retryable: Boolean read FRetryable;
  end;

  TLicenseState = record
    LicenseID: string;
    Status: string;
    DeviceID: string;
    LicenseLabel: string;
    IssuedAt: Int64;
    ActivatedAt: Int64;
    ExpiresAt: Int64;
    LeaseExpiresAt: Int64;
    ServerTime: Int64;
    Revision: Int64;
    VerifiedAtTick: UInt64;
    LeaseDeadlineTick: UInt64;
    function IsActive: Boolean;
    function RemainingLeaseSeconds: Integer;
    function RemainingLicenseSeconds: Int64;
  end;

{$IFDEF GAME_LICENSE_CONTRACT_TESTS}
{ Test-only clock. This API and its storage do not exist in application builds. }
procedure LicenseStateProbeSetTick(Tick: UInt64);
function LicenseStateProbeTickReads: Integer;
{$ENDIF}

implementation

{$IFNDEF GAME_LICENSE_CONTRACT_TESTS}
uses Cozy.Clock,
  Winapi.Windows,
  Cozy.WinApi, Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Api.Pointer;

{ Private API pointers: initialized before application code starts. }
{ POINTER WRAPPERS 1 BEGIN }
{ POINTER WRAPPERS 1 END }
{$ELSE}
var
  ProbeTick: UInt64;
  ProbeTickReads: Integer;

procedure LicenseStateProbeSetTick(Tick: UInt64);
begin
  ProbeTick := Tick;
  ProbeTickReads := 0;
end;

function LicenseStateProbeTickReads: Integer;
begin
  Result := ProbeTickReads;
end;

function CozyTick: UInt64;
begin
  Inc(ProbeTickReads);
  Result := ProbeTick;
end;
{$ENDIF}

constructor EGameApi.Create(const ACode, AMessage: string;
  ARetryable: Boolean);
begin
  inherited Create(AMessage);
  FCode := ACode;
  FRetryable := ARetryable;
end;

function LicenseStateIsActiveAt(const State: TLicenseState;
  NowTick: UInt64): Boolean;
const
  { Same bounded lease as TGameApi.ParseState; this record is only a local
    view of an already authenticated server response, never an authority. }
  MaxLeaseMilliseconds = 120000;
var
  ServerLease: UInt64;
begin
  Result := False;
  if (State.Status <> CozyText_Api_Types_USED_9d9f0b1d) or (State.LicenseID = '') or
    (State.DeviceID = '') or (State.VerifiedAtTick = 0) or
    (NowTick < State.VerifiedAtTick) or
    (State.LeaseDeadlineTick <= State.VerifiedAtTick) or
    (NowTick >= State.LeaseDeadlineTick) or (State.ServerTime <= 0) or
    (State.LeaseExpiresAt <= State.ServerTime) or (State.ExpiresAt < 0) then
    Exit;
  { Both timestamps are now positive and ordered, so subtraction cannot
    overflow. The local deadline may only shorten the authenticated lease. }
  ServerLease := UInt64(State.LeaseExpiresAt) - UInt64(State.ServerTime);
  if (ServerLease > MaxLeaseMilliseconds) or
    (State.LeaseDeadlineTick - State.VerifiedAtTick > ServerLease) then
    Exit;
  if (State.ExpiresAt <> 0) and
    ((State.ExpiresAt <= State.ServerTime) or
     (State.LeaseExpiresAt > State.ExpiresAt)) then
    Exit;
  Result := True;
end;

function TLicenseState.IsActive: Boolean;
begin
  { The key is consumed as soon as it is redeemed. Only the already-bound
    execution session can continue under its short server-verified lease. }
  Result := LicenseStateIsActiveAt(Self, CozyTick);
end;

function TLicenseState.RemainingLeaseSeconds: Integer;
var
  NowTick, Remaining: UInt64;
begin
  Result := 0;
  NowTick := CozyTick;
  if not LicenseStateIsActiveAt(Self, NowTick) then
    Exit;
  Remaining := LeaseDeadlineTick - NowTick;
  { No pre-rounding addition: malformed extreme values cannot wrap at +999.
    The validated maximum lease bounds this conversion to at most 120. }
  Result := Integer(Remaining div 1000);
  if Remaining mod 1000 <> 0 then Inc(Result);
end;

function TLicenseState.RemainingLicenseSeconds: Int64;
var
  Elapsed, Remaining: UInt64;
  NowTick: UInt64;
begin
  Result := 0;
  { Take one monotonic sample for both authorization and the displayed time. }
  NowTick := CozyTick;
  if not LicenseStateIsActiveAt(Self, NowTick) then
    Exit;
  if ExpiresAt = 0 then
    Exit(-1);
  Elapsed := NowTick - VerifiedAtTick;
  Remaining := UInt64(ExpiresAt) - UInt64(ServerTime);
  if Elapsed >= Remaining then
    Exit;
  Dec(Remaining, Elapsed);
  Result := Int64(Remaining div 1000);
  if Remaining mod 1000 <> 0 then Inc(Result);
end;


end.
