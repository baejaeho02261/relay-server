unit Cozy.NHW.SelectedRegressionV109;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

function ValidateSelectedV109(out Failure: string): Boolean;

implementation

uses
  Winapi.Windows, System.SysUtils, System.Generics.Collections,
  Cozy.NHW.Types, Cozy.NHW.Logging,
  Cozy.NHW.HandleSharingEvidence, Cozy.NHW.APCStyleEvidence, Cozy.NHW.SensorTamperHealth;

procedure AssertCheck(Pass: Boolean; const Description: string);
begin
  if not Pass then raise Exception.Create(Description);
end;

procedure AddHandle(const List: TList<TObservedHandle>;
  PID: Cardinal; Obj, HandleNum: NativeUInt; Rights: Cardinal;
  ThreadObject: Boolean = False);
var H: TObservedHandle;
begin
  H := Default(TObservedHandle);
  H.OwnerPID := PID;
  H.ObjectIdentity := Obj;
  H.HandleValue := HandleNum;
  H.GrantedAccess := Rights;
  H.IsThread := ThreadObject;
  List.Add(H);
end;

procedure CheckSharingRules;
var Prior, Current: TSharingHandle;
begin
  Prior := Default(TSharingHandle);
  Current := Default(TSharingHandle);
  Prior.PID := 101;
  Prior.Created := 1000;
  Prior.ObjectIdentity := $CAFE;
  Prior.AccessMask := ACCESS_VM_WRITE;
  Current := Prior;
  Current.PID := 102;
  Current.Created := 2000;
  AssertCheck(NHWPotentialSharedHandle(Prior, Current, True),
    'v101: same-object high-rights shared pattern');
  AssertCheck(not NHWPotentialSharedHandle(Prior, Current, False),
    'v101: prior must still be present');
  Current.AccessMask := ACCESS_QUERY_LIMITED;
  AssertCheck(not NHWPotentialSharedHandle(Prior, Current, True),
    'v101: query-only must not trigger');
end;

procedure CheckSharingSequence(M: THandleSharingEvidence;
  Entries: TList<TObservedHandle>; Ages: TDictionary<Cardinal, UInt64>);
var K: TDetectionKinds;
begin
  Ages.Add(101, 1000);
  Ages.Add(102, 2000);
  AddHandle(Entries, 101, $CAFE, $11, ACCESS_VM_WRITE);
  K := [];
  M.Examine(Entries, Ages, True, True, True, 1000, K);
  AssertCheck(K = [], 'v101: baseline not reported');
  AddHandle(Entries, 102, $CAFE, $22, ACCESS_VM_WRITE);
  K := [];
  M.Examine(Entries, Ages, True, False, False, 1500, K);
  AssertCheck(not (dkHandleSharingEvidence in K),
    'v101: first observation is only candidate');
  K := [];
  M.Examine(Entries, Ages, True, False, False, 1800, K);
  AssertCheck(dkHandleSharingEvidence in K,
    'v101: sustained two-owner handle appearance');
  K := [];
  M.Examine(Entries, Ages, True, False, False, 2100, K);
  AssertCheck(not (dkHandleSharingEvidence in K),
    'v101: unchanged handle does not repeatedly report');
  Ages.AddOrSetValue(102, 3000);
  K := [];
  M.Examine(Entries, Ages, True, False, False, 2600, K);
  AssertCheck(not (dkHandleSharingEvidence in K),
    'v101: PID reuse is not carried across epochs');
  Entries.Clear;
  AddHandle(Entries, 101, $CAFE, $11, ACCESS_VM_WRITE);
  AddHandle(Entries, 102, $CAFE, $22, ACCESS_VM_WRITE, True);
  K := [];
  M.Examine(Entries, Ages, False, False, False, 3000, K);
  AssertCheck(not (dkHandleSharingEvidence in K),
    'v101: incomplete thread snapshot ignored');
end;

procedure TestSharing;
var
  M: THandleSharingEvidence;
  Entries: TList<TObservedHandle>;
  Ages: TDictionary<Cardinal, UInt64>;
begin
  M := THandleSharingEvidence.Create;
  Entries := TList<TObservedHandle>.Create;
  Ages := TDictionary<Cardinal, UInt64>.Create;
  try
    CheckSharingRules;
    CheckSharingSequence(M, Entries, Ages);
  finally
    Ages.Free;
    Entries.Free;
    M.Free;
  end;
end;

procedure CheckAPCPreconditions(M: TAPCStyleEvidence; const H: TTargetHolder);
var K: TDetectionKinds;
begin
  K := [];
  M.ObserveThreadRights(H, True, False, 1000);
  M.Examine(True, True, False, 2000, K);
  AssertCheck(not (dkAPCStyleEvidence in K),
    'v104: capability alone is insufficient');
  K := [dkPECodeIntegrity];
  M.Examine(False, True, False, 2200, K);
  AssertCheck(not (dkAPCStyleEvidence in K),
    'v104: external target must be excluded');
  K := [dkPECodeIntegrity];
  M.Examine(True, False, False, 2300, K);
  AssertCheck(not (dkAPCStyleEvidence in K),
    'v104: incomplete thread snapshot ignored');
  K := [dkPECodeIntegrity];
  M.Examine(True, True, False, 2400, K);
  AssertCheck(not (dkAPCStyleEvidence in K),
    'v104: Native5J requires fresh rights after an observation gap');
end;

procedure CheckAPCConfirmation(M: TAPCStyleEvidence; const H: TTargetHolder);
var K: TDetectionKinds;
begin
  M.ObserveThreadRights(H, True, False, 2450);
  K := [dkPECodeIntegrity];
  M.Examine(True, True, False, 2500, K);
  AssertCheck(dkAPCStyleEvidence in K,
    'v104: fresh context rights + independent self integrity impact');
  K := [dkPECodeIntegrity];
  M.Examine(True, True, False, 2600, K);
  AssertCheck(not (dkAPCStyleEvidence in K),
    'v104: cooldown');
  M.Reset;
  K := [dkPECodeIntegrity];
  M.ObserveThreadRights(H, True, True, 3000);
  M.Examine(True, True, False, 3100, K);
  AssertCheck(not (dkAPCStyleEvidence in K),
    'v104: baseline access is not evidence');
  AssertCheck(not NHWAPCIndependentImpact([dkThreadStart, dkThread]),
    'v104: normal thread start is insufficient');
end;

procedure TestAPC;
var
  M: TAPCStyleEvidence;
  H: TTargetHolder;
begin
  M := TAPCStyleEvidence.Create;
  try
    H := Default(TTargetHolder);
    H.PID := 110;
    H.CreateTime := 444;
    H.IsThread := True;
    H.RightsUnion := THREAD_SET_CONTEXT_RIGHT;
    CheckAPCPreconditions(M, H);
    CheckAPCConfirmation(M, H);
  finally
    M.Free;
  end;
end;

procedure CheckSensorTraceLoss(M: TSensorTamperHealth);
var K: TDetectionKinds;
begin
  K := [];
  M.Observe(False, False, True, True, False, 0, 500,
    500, 1000, K);
  AssertCheck(K = [], 'v109: unavailable ETW is not tampering');
  K := [];
  M.Observe(True, False, True, True, False, 0, 500,
    500, 1500, K);
  K := [];
  M.Observe(False, False, True, True, False, 0, 500,
    500, 2000, K);
  M.Observe(False, False, True, True, False, 0, 500,
    500, 2500, K);
  AssertCheck(K = [], 'v109: one/two missing samples not reported');
  M.Observe(False, False, True, True, False, 0, 500,
    500, 3000, K);
  AssertCheck(dkObservationUncertain in K,
    'v109: sustained formerly-ready ETW loss warned');
  AssertCheck(M.LastReason = shTraceStopped,
    'v109: reason differentiates trace loss');
  K := [];
  M.Observe(False, False, True, True, False, 0, 500,
    500, 3500, K);
  AssertCheck(K = [], 'v109: warning deduplicated');
end;

procedure CheckSensorSnapshotGap(M: TSensorTamperHealth);
var K: TDetectionKinds;
begin
  K := [];
  M.Observe(False, False, True, False, False, 0, 100,
    500, 1000, K);
  M.Observe(False, False, True, False, False, 0, 100,
    500, 1500, K);
  M.Observe(False, False, True, False, False, 0, 100,
    500, 2000, K);
  AssertCheck(dkObservationUncertain in K,
    'v109: repeated native snapshot gap warned');
end;

procedure CheckSensorDisabledWatch(M: TSensorTamperHealth);
var K: TDetectionKinds;
begin
  K := [];
  M.Observe(False, False, False, False, False, 0, 100,
    500, 1000, K);
  AssertCheck(K = [], 'v109: disabled thread watch is not a gap');
end;

procedure TestSensorHealth;
var M: TSensorTamperHealth;
begin
  M := TSensorTamperHealth.Create;
  try
    CheckSensorTraceLoss(M);
    M.Reset;
    CheckSensorSnapshotGap(M);
    M.Reset;
    CheckSensorDisabledWatch(M);
  finally
    M.Free;
  end;
end;

function ValidateSelectedV109(out Failure: string): Boolean;
begin
  Result := False;
  Failure := '';
  try
    TestSharing;
    TestAPC;
    TestSensorHealth;
    Result := True;
  except
    on E: Exception do Failure := E.Message;
  end;
end;

end.
