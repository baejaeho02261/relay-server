unit Cozy.NHW.StableIdentity;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.Generics.Collections, Cozy.NHW.Types;

type
  TStableActorState = record
    Created: UInt64;
    LastSeen: UInt64;
  end;

  // PID + creation time, never PID/handle alone. One engine-thread owner.
  TStableObjectIdentity = class
  private
    FActors: TDictionary<Cardinal, TStableActorState>;
    FTargetPID: Cardinal;
    FTargetCreation: UInt64;
    FLastActorReuse: UInt64;
    FLastActorTick: UInt64;
    FValidated: Boolean;
    procedure EvictOldestActor;
    function ValidateTargetHandle(Handle: THandle; PID: Cardinal;
      out Created: UInt64): Boolean;
    procedure UpdateActorState(PID: Cardinal; Created, Tick: UInt64;
      out Reused: Boolean);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    function ObserveTarget(Handle: THandle; PID: Cardinal): Boolean;
    procedure ObserveHolder(const H: TTargetHolder; Tick: UInt64);
    property TargetValidated: Boolean read FValidated;
    property TargetCreation: UInt64 read FTargetCreation;
    property LastActorReuse: UInt64 read FLastActorReuse;
  end;

function QueryCreationIdentity(Handle: THandle; out Created: UInt64): Boolean;
function SameProcessIdentity(PIDA: Cardinal; CreatedA: UInt64;
  PIDB: Cardinal; CreatedB: UInt64): Boolean;
{$IFDEF NHW_NATIVE5D_TESTS}
function TestStableIdentityHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, System.SyncObjs, Cozy.NHW.WinPointers;

const
  MAX_STABLE_ACTORS = 2048;

type
  TIdentityGetPID = function(Handle: THandle): Cardinal; stdcall;
{$IFDEF NHW_NATIVE5D_TESTS}
  TIdentityTestTimes = function(Handle: THandle; out C, E, K, U: TFileTime): BOOL;
{$ENDIF}
var
  IdentityResolveLock: TCriticalSection;
  IdentityGetPID: TIdentityGetPID = nil;
{$IFDEF NHW_NATIVE5D_TESTS}
  IdentityTestTimes: TIdentityTestTimes = nil;
{$ENDIF}

procedure ResolveIdentityPID;
var M: HMODULE;
begin
  IdentityResolveLock.Acquire;
  try
    if Assigned(IdentityGetPID) then Exit;
    M := WinModule('kernel32.dll');
    if M <> 0 then
      IdentityGetPID := TIdentityGetPID(WinExport(M, 'GetProcessId'));
  finally
    IdentityResolveLock.Release;
  end;
end;

function ReadIdentityTimes(Handle: THandle;
  out C, E, K, U: TFileTime): BOOL;
begin
{$IFDEF NHW_NATIVE5D_TESTS}
  if Assigned(IdentityTestTimes) then
    Exit(IdentityTestTimes(Handle, C, E, K, U));
{$ENDIF}
  Result := WinGetProcessTimes(Handle, C, E, K, U);
end;

function QueryCreationIdentity(Handle: THandle; out Created: UInt64): Boolean;
var C, E, K, U: TFileTime;
begin
  Result := False;
  Created := 0;
  if Handle = 0 then Exit;
  // -1 is the legitimate current-process pseudo handle, not rejected here.
  C := Default(TFileTime);
  E := Default(TFileTime);
  K := Default(TFileTime);
  U := Default(TFileTime);
  if not ReadIdentityTimes(Handle, C, E, K, U) then Exit;
  Created := (UInt64(C.dwHighDateTime) shl 32) or UInt64(C.dwLowDateTime);
  Result := Created <> 0;
end;

function SameProcessIdentity(PIDA: Cardinal; CreatedA: UInt64;
  PIDB: Cardinal; CreatedB: UInt64): Boolean;
begin
  Result := (PIDA <> 0) and (PIDA = PIDB) and
    (CreatedA <> 0) and (CreatedA = CreatedB);
end;

constructor TStableObjectIdentity.Create;
begin
  inherited Create;
  FActors := TDictionary<Cardinal, TStableActorState>.Create;
  Reset;
end;

destructor TStableObjectIdentity.Destroy;
begin
  FActors.Free;
  inherited Destroy;
end;

procedure TStableObjectIdentity.Reset;
begin
  FActors.Clear;
  FTargetPID := 0;
  FTargetCreation := 0;
  FLastActorReuse := 0;
  FLastActorTick := 0;
  FValidated := False;
end;

function TStableObjectIdentity.ValidateTargetHandle(Handle: THandle;
  PID: Cardinal; out Created: UInt64): Boolean;
begin
  Result := False;
  Created := 0;
  if (Handle = 0) or (PID = 0) then Exit;
  ResolveIdentityPID;
  if not Assigned(IdentityGetPID) then Exit;
  if IdentityGetPID(Handle) <> PID then Exit;
  if not QueryCreationIdentity(Handle, Created) then Exit;
  // Recheck the handle-to-PID relation before binding a baseline identity.
  Result := IdentityGetPID(Handle) = PID;
end;

function TStableObjectIdentity.ObserveTarget(Handle: THandle;
  PID: Cardinal): Boolean;
var Created: UInt64;
begin
  Result := False;
  FValidated := False;
  if not ValidateTargetHandle(Handle, PID, Created) then Exit;
  if FTargetPID = 0 then
  begin
    FTargetPID := PID;
    FTargetCreation := Created;
  end;
  Result := SameProcessIdentity(FTargetPID, FTargetCreation, PID, Created);
  FValidated := Result;
end;

procedure TStableObjectIdentity.EvictOldestActor;
var
  Pair: TPair<Cardinal, TStableActorState>;
  OldestPID: Cardinal;
  OldestTick: UInt64;
begin
  OldestPID := 0;
  OldestTick := High(UInt64);
  for Pair in FActors do
    if (OldestPID = 0) or (Pair.Value.LastSeen < OldestTick) or
       ((Pair.Value.LastSeen = OldestTick) and (Pair.Key < OldestPID)) then
    begin
      OldestPID := Pair.Key;
      OldestTick := Pair.Value.LastSeen;
    end;
  // Never mutate the dictionary during enumeration.
  if OldestPID <> 0 then FActors.Remove(OldestPID);
end;

procedure TStableObjectIdentity.UpdateActorState(PID: Cardinal;
  Created, Tick: UInt64; out Reused: Boolean);
var
  Old, Current: TStableActorState;
begin
  Reused := False;
  if FActors.TryGetValue(PID, Old) then
    Reused := Old.Created <> Created
  else if FActors.Count >= MAX_STABLE_ACTORS then
    EvictOldestActor;
  Current.Created := Created;
  Current.LastSeen := Tick;
  FActors.AddOrSetValue(PID, Current);
end;

procedure TStableObjectIdentity.ObserveHolder(const H: TTargetHolder;
  Tick: UInt64);
var
  Reused: Boolean;
begin
  if (H.PID <= 4) or (H.CreateTime = 0) then Exit;
  // Engine observations use a monotonic clock. Do not let a late record
  // overwrite a newer identity or make a recently used entry look old.
  if Tick < FLastActorTick then Exit;
  UpdateActorState(H.PID, H.CreateTime, Tick, Reused);
  FLastActorTick := Tick;
  if Reused then FLastActorReuse := Tick;
end;

{$IFDEF NHW_NATIVE5D_TESTS}
{$I Cozy.NHW.Native5D.StableIdentity.inc}
{$ENDIF}

initialization
  IdentityResolveLock := TCriticalSection.Create;
finalization
  IdentityResolveLock.Free;
end.
