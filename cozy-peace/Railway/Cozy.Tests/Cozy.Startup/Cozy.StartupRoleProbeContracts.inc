{ Local startup-only fixture: uses the exact product unit closure/resources,
  then exits. This is not the final issued EXE, a server session, or a full
  A/B/O workflow test. No application entry point is called. }
procedure StartupProbeCheck(Value: Boolean; const Code: string);
begin
  if not Value then raise EInvalidOpException.Create(Code);
end;
procedure RunStartupRoleProbe(Role: TGameComponentRole);
var Other: TGameComponentRole; Observation: TNativeStartupObservation;
begin
  for Other := Low(TGameComponentRole) to High(TGameComponentRole) do
  begin
    Observation := CaptureNativeStartupObservation(Other);
    StartupProbeCheck((Observation.State = nssNotRun) and
      not NativeStartupObservationComplete(Observation), CozyText_StartupRoleProbeContracts_STARTUP_ALREADY_OBSERVED_6e31b880);
  end;
  SealApiPointerStorage;
  RequireNativeStartup(Role);
  Observation := CaptureNativeStartupObservation(Role);
  StartupProbeCheck((Observation.Role = Role) and
    NativeStartupObservationComplete(Observation), CozyText_StartupRoleProbeContracts_STARTUP_ROLE_GATE_INCOMPLETE_05acaaa7);
  for Other := Low(TGameComponentRole) to High(TGameComponentRole) do
    if Other <> Role then
    begin
      Observation := CaptureNativeStartupObservation(Other);
      StartupProbeCheck((Observation.State = nssNotRun) and
        not NativeStartupObservationComplete(Observation), CozyText_StartupRoleProbeContracts_STARTUP_OTHER_ROLE_NOT_RUN_128f7cf4);
    end;
end;
