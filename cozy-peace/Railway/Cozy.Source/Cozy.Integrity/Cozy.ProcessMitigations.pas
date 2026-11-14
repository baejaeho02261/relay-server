unit Cozy.ProcessMitigations;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity,
 System.JSON, System.Generics.Collections;
type
  TMitigationObservation = record
    RequestedMode, ProfileId: string;
    StrictSetAttempted, StrictSetSucceeded, ImageSetAttempted, ImageSetSucceeded: Boolean;
    StrictSetError, ImageSetError: Cardinal;
    SetAttempted, SetSucceeded, DynamicQueried, CfgQueried,
      StrictHandleQueried, ImageLoadQueried: Boolean;
    SetError, DynamicError, CfgError, StrictHandleError, ImageLoadError,
      DynamicFlags, CfgFlags, StrictHandleFlags, ImageLoadFlags: Cardinal;
    function ToJSON: TJSONObject;
  end;
procedure CollectProcessMitigations(const RequestedMode: string;
  out DynamicCodeState, CfgState: string); overload;
procedure CollectProcessMitigations(const RequestedMode: string;
  out DynamicCodeState, CfgState: string; out Observation: TMitigationObservation); overload;
function MitigationProfileReadback(const Settings: TJSONObject;
  const Observation: TMitigationObservation): string;
procedure SetMitigationGpuIdentity(const Fingerprint: string);
function CollectMitigationEnvironment(const Stage: string): TJSONObject;
procedure CollectProcessMitigationsProfile(const RequestedMode: string; Profile: TJSONObject;
  out DynamicCodeState, CfgState: string; out Observation: TMitigationObservation);
implementation
uses Winapi.Windows, System.SysUtils, Cozy.Api.Pointer, Cozy.Api.ROR13, Cozy.Platform.ExportResolver, System.SyncObjs;
type
  TGetMitigation = function(Process: THandle; Policy: Integer;
    Buffer: Pointer; Size: NativeUInt): BOOL; stdcall;
  TSetMitigation = function(Policy: Integer; Buffer: Pointer;
    Size: NativeUInt): BOOL; stdcall;
  TGetError = function: DWORD; stdcall;
var ApiSlot_GetMitigation, ApiSlot_SetMitigation, ApiSlot_Error,
  ApiSlot_RtlGetVersion: TEncodedApiPointer;
  GpuIdentityState: Integer;
  GpuIdentityBytes: array[0..127] of AnsiChar;
function LastError: Cardinal;
var P: TGetError;
begin P := TGetError(DecodeApiPointer(ApiSlot_Error)); Result := P(); end;
function QueryFlags(Policy: Integer; out Flags, Error: Cardinal): Boolean;
var Target: TGetMitigation;
begin
  Flags := 0; Error := ERROR_CALL_NOT_IMPLEMENTED; Result := False;
  if not ApiSlot_GetMitigation.IsBound then Exit;
  Target := TGetMitigation(DecodeApiPointer(ApiSlot_GetMitigation));
  Result := Target(THandle(High(NativeUInt)), Policy, @Flags, SizeOf(Flags));
  if Result then Error := 0 else begin Error := LastError; Flags := 0; end;
end;
function TMitigationObservation.ToJSON: TJSONObject;
  procedure Number(const Name: string; Value: Cardinal);
  begin Result.AddPair(Name, TJSONNumber.Create(Int64(Value))); end;
begin
  Result := TJSONObject.Create;
  try
    if ProfileId <> '' then
    begin
      Number(CozyText_ProcessMitigations_version_c34f5063, 2); Result.AddPair(CozyText_ProcessMitigations_profileId_e43f0d58, ProfileId);
      Result.AddPair(CozyText_ProcessMitigations_strictSetAttempted_d03b0cf9, TJSONBool.Create(StrictSetAttempted));
      Result.AddPair(CozyText_ProcessMitigations_strictSetSucceeded_b1c09cb3, TJSONBool.Create(StrictSetSucceeded)); Number(CozyText_ProcessMitigations_strictSetError_2a465b77, StrictSetError);
      Result.AddPair(CozyText_ProcessMitigations_imageSetAttempted_c2def5f0, TJSONBool.Create(ImageSetAttempted));
      Result.AddPair(CozyText_ProcessMitigations_imageSetSucceeded_44d1cb21, TJSONBool.Create(ImageSetSucceeded)); Number(CozyText_ProcessMitigations_imageSetError_62fcf216, ImageSetError);
    end else Number(CozyText_ProcessMitigations_version_c34f5063, 1);
    Result.AddPair(CozyText_ProcessMitigations_requestedMode_79edd7c7, RequestedMode);
    Result.AddPair(CozyText_ProcessMitigations_setAttempted_8934568a, TJSONBool.Create(SetAttempted));
    Result.AddPair(CozyText_ProcessMitigations_setSucceeded_3f0f06b8, TJSONBool.Create(SetSucceeded)); Number(CozyText_ProcessMitigations_setError_0efd2633, SetError);
    Result.AddPair(CozyText_ProcessMitigations_dynamicQueried_5f2fc34b, TJSONBool.Create(DynamicQueried)); Number(CozyText_ProcessMitigations_dynamicFlags_0990226f, DynamicFlags); Number(CozyText_ProcessMitigations_dynamicError_0ef7d9e2, DynamicError);
    Result.AddPair(CozyText_ProcessMitigations_cfgQueried_ab21b824, TJSONBool.Create(CfgQueried)); Number(CozyText_ProcessMitigations_cfgFlags_f9e53859, CfgFlags); Number(CozyText_ProcessMitigations_cfgError_c961cdab, CfgError);
    Result.AddPair(CozyText_ProcessMitigations_strictHandleQueried_89d8df29, TJSONBool.Create(StrictHandleQueried)); Number(CozyText_ProcessMitigations_strictHandleFlags_9f12a821, StrictHandleFlags); Number(CozyText_ProcessMitigations_strictHandleError_a95ceeaf, StrictHandleError);
    Result.AddPair(CozyText_ProcessMitigations_imageLoadQueried_823f566e, TJSONBool.Create(ImageLoadQueried)); Number(CozyText_ProcessMitigations_imageLoadFlags_1eb10dbe, ImageLoadFlags); Number(CozyText_ProcessMitigations_imageLoadError_d5ffc9ba, ImageLoadError);
  except Result.Free; raise; end;
end;
procedure CollectProcessMitigations(const RequestedMode: string;
  out DynamicCodeState, CfgState: string);
var Observation: TMitigationObservation;
begin CollectProcessMitigations(RequestedMode, DynamicCodeState, CfgState, Observation); end;
procedure CollectProcessMitigations(const RequestedMode: string;
  out DynamicCodeState, CfgState: string; out Observation: TMitigationObservation);
var Flags, Error: Cardinal; Target: TSetMitigation;
begin
  if (RequestedMode <> CozyText_ProcessMitigations_observe_e9515b64) and (RequestedMode <> CozyText_ProcessMitigations_prohibit_5eed27c9) then
    raise EArgumentException.Create(CozyText_ProcessMitigations_Unknown_process_mitigation_policy_1380e5f4);
  Observation := Default(TMitigationObservation); Observation.RequestedMode := RequestedMode;
  DynamicCodeState := CozyText_ProcessMitigations_UNAVAILABLE_5188398f; CfgState := CozyText_ProcessMitigations_UNAVAILABLE_5188398f;
  if RequestedMode = CozyText_ProcessMitigations_prohibit_5eed27c9 then
  begin
    if not QueryFlags(2, Flags, Error) or ((Flags and $7) <> $1) then
    begin
      if ApiSlot_SetMitigation.IsBound then
      begin
        Flags := $1; Target := TSetMitigation(DecodeApiPointer(ApiSlot_SetMitigation));
        Observation.SetAttempted := True;
        Observation.SetSucceeded := Target(2, @Flags, SizeOf(Flags));
        if not Observation.SetSucceeded then Observation.SetError := LastError;
      end
      else Observation.SetError := ERROR_CALL_NOT_IMPLEMENTED;
    end;
  end;
  { Re-query every observation; a TRUE setter never substitutes for this read. }
  Observation.DynamicQueried := QueryFlags(2, Observation.DynamicFlags, Observation.DynamicError);
  if Observation.DynamicQueried then
    if (Observation.DynamicFlags and $7) = $1 then DynamicCodeState := CozyText_ProcessMitigations_PROHIBITED_8d6e2d37
    else DynamicCodeState := CozyText_ProcessMitigations_ALLOWED_7a85e477;
  Observation.CfgQueried := QueryFlags(7, Observation.CfgFlags, Observation.CfgError);
  if Observation.CfgQueried then
    if (Observation.CfgFlags and $1) <> 0 then CfgState := CozyText_ProcessMitigations_ENABLED_04c730e5 else CfgState := CozyText_ProcessMitigations_DISABLED_fdb30d3f;
  { Diagnostic only until the Windows/GPU compatibility matrix is approved.
    Never turn on new strict-handle/image restrictions on untested machines. }
  Observation.StrictHandleQueried := QueryFlags(3, Observation.StrictHandleFlags, Observation.StrictHandleError);
  Observation.ImageLoadQueried := QueryFlags(10, Observation.ImageLoadFlags, Observation.ImageLoadError);
end;
function MitigationProfileReadback(const Settings: TJSONObject;
  const Observation: TMitigationObservation): string;
var Mask: Integer; NeedsStrict, NeedsCfg: Boolean; Mode: string;
  function QueryUnavailable(Queried: Boolean; Error: Cardinal): Boolean;
  begin
    Result := not Queried and ((Error = ERROR_CALL_NOT_IMPLEMENTED) or
      (Error = ERROR_NOT_SUPPORTED) or (Error = ERROR_INVALID_PARAMETER));
  end;
begin
  { A setter's success is never proof. This helper reads only the independent
    observations; it does not enable policy, relax a policy or authorize work. }
  Result := CozyText_ProcessMitigations_FAIL_ceeb6559;
  if Settings = nil then Exit;
  if not (Settings.GetValue(CozyText_ProcessMitigations_dynamicCode_51e126a5) is TJSONString) or
     not (Settings.GetValue(CozyText_ProcessMitigations_strictHandles_b0d34cf9) is TJSONBool) or
     not (Settings.GetValue(CozyText_ProcessMitigations_requireCfg_d5d7eeb0) is TJSONBool) or
     not (Settings.GetValue(CozyText_ProcessMitigations_imageLoadMask_ea6c4eed) is TJSONNumber) then Exit;
  Mode := Settings.GetValue<string>(CozyText_ProcessMitigations_dynamicCode_51e126a5, '');
  if (Mode <> CozyText_ProcessMitigations_observe_e9515b64) and (Mode <> CozyText_ProcessMitigations_prohibit_5eed27c9) then Exit;
  Mask := Settings.GetValue<Integer>(CozyText_ProcessMitigations_imageLoadMask_ea6c4eed, -1);
  if (Mask < 0) or (Mask > 7) or (Observation.RequestedMode <> Mode) then Exit;
  NeedsStrict := Settings.GetValue<Boolean>(CozyText_ProcessMitigations_strictHandles_b0d34cf9, False);
  NeedsCfg := Settings.GetValue<Boolean>(CozyText_ProcessMitigations_requireCfg_d5d7eeb0, False);
  if ((Mode = CozyText_ProcessMitigations_prohibit_5eed27c9) and QueryUnavailable(Observation.DynamicQueried, Observation.DynamicError)) or
     (NeedsStrict and QueryUnavailable(Observation.StrictHandleQueried, Observation.StrictHandleError)) or
     ((Mask <> 0) and QueryUnavailable(Observation.ImageLoadQueried, Observation.ImageLoadError)) or
     (NeedsCfg and QueryUnavailable(Observation.CfgQueried, Observation.CfgError)) then
    Exit(CozyText_ProcessMitigations_UNSUPPORTED_df6a4eb5);
  if (Mode = CozyText_ProcessMitigations_prohibit_5eed27c9) and (not Observation.DynamicQueried or
      ((Observation.DynamicFlags and 7) <> 1)) then Exit;
  if NeedsStrict and (not Observation.StrictHandleQueried or
      ((Observation.StrictHandleFlags and 3) <> 3)) then Exit;
  if (Mask <> 0) and (not Observation.ImageLoadQueried or
      ((Observation.ImageLoadFlags and Cardinal(Mask)) <> Cardinal(Mask))) then Exit;
  if NeedsCfg and (not Observation.CfgQueried or
      ((Observation.CfgFlags and 1) = 0)) then Exit;
  Result := CozyText_ProcessMitigations_PASS_ecca96d4;
end;
function MitigationGpuIdentity: string;
var I: Integer;
begin
  Result := CozyText_ProcessMitigations_unknown_a0c0259e;
  if TInterlocked.CompareExchange(GpuIdentityState, 2, 2) <> 2 then Exit;
  SetLength(Result, Length(GpuIdentityBytes));
  for I := 0 to High(GpuIdentityBytes) do Result[I+1] := Char(GpuIdentityBytes[I]);
end;
procedure SetMitigationGpuIdentity(const Fingerprint: string);
var I, Prior: Integer;
begin
  if (Fingerprint = '') or (Fingerprint = CozyText_ProcessMitigations_unknown_a0c0259e) then
  begin
    if TInterlocked.CompareExchange(GpuIdentityState, 2, 2) = 2 then raise EInvalidOpException.Create(CozyText_ProcessMitigations_MITIGATION_GPU_UNAVAILABLE_be82e4fb);
    Exit;
  end;
  if Length(Fingerprint) <> Length(GpuIdentityBytes) then raise EArgumentException.Create(CozyText_ProcessMitigations_MITIGATION_GPU_INVALID_2b2e4323);
  for I := 1 to Length(Fingerprint) do if not CharInSet(Fingerprint[I], ['0'..'9','a'..'f']) then raise EArgumentException.Create(CozyText_ProcessMitigations_MITIGATION_GPU_INVALID_2b2e4323);
  Prior := TInterlocked.CompareExchange(GpuIdentityState, 1, 0);
  if Prior <> 0 then
  begin
    if (Prior <> 2) or (MitigationGpuIdentity <> Fingerprint) then raise EInvalidOpException.Create(CozyText_ProcessMitigations_MITIGATION_GPU_CHANGED_4f74c16f);
    Exit;
  end;
  for I := 0 to High(GpuIdentityBytes) do GpuIdentityBytes[I] := AnsiChar(Fingerprint[I+1]);
  TInterlocked.Exchange(GpuIdentityState, 2);
end;
function CollectMitigationEnvironment(const Stage: string): TJSONObject;
type
  TNativeVersion = record
    Size, Major, Minor, Build, Platform: Cardinal;
    ServicePack: array[0..127] of WideChar;
  end;
  TRtlGetVersion = function(var Info: TNativeVersion): LongInt; stdcall;
var Info: TNativeVersion; Target: TRtlGetVersion;
begin
  Result := nil; Info := Default(TNativeVersion); Info.Size := SizeOf(Info);
  { The existing optional Windows target is registered before the DPR seals
    API storage. Runtime calls use that immutable slot, like mitigation APIs. }
  if not ApiSlot_RtlGetVersion.IsBound then Exit;
  Target := TRtlGetVersion(DecodeApiPointer(ApiSlot_RtlGetVersion));
  if (Target(Info) < 0) or (Info.Build < 10240) then Exit;
  Result := TJSONObject.Create;
  try
    Result.AddPair(CozyText_ProcessMitigations_architecture_361d9e38, CozyText_ProcessMitigations_x64_b1dcc85b);
    Result.AddPair(CozyText_ProcessMitigations_windowsBuild_2ed24838, TJSONNumber.Create(Int64(Info.Build)));
    if (Stage = 'O') or (Stage = 'B') then Result.AddPair(CozyText_ProcessMitigations_gpuIdentitySha512_7f2f89ea, MitigationGpuIdentity)
    else Result.AddPair(CozyText_ProcessMitigations_gpuIdentitySha512_7f2f89ea, CozyText_ProcessMitigations_none_61098ac7);
  except Result.Free; raise; end;
end;
procedure CollectProcessMitigationsProfile(const RequestedMode: string; Profile: TJSONObject;
  out DynamicCodeState, CfgState: string; out Observation: TMitigationObservation);
var Flags, Error, Mask: Cardinal; Id, Mode: string; Strict: Boolean;
  procedure EnableBits(Policy: Integer; Bits: Cardinal; out Attempted, Succeeded: Boolean; out SetError: Cardinal);
  var Target: TSetMitigation; Existing, QueryError, Wanted: Cardinal;
  begin
    Attempted := False; Succeeded := False; SetError := 0;
    if Bits = 0 then Exit;
    if not QueryFlags(Policy, Existing, QueryError) then begin SetError := QueryError; Exit; end;
    if (Existing and Bits) = Bits then Exit;
    if not ApiSlot_SetMitigation.IsBound then begin SetError := ERROR_CALL_NOT_IMPLEMENTED; Exit; end;
    Wanted := Existing or Bits; Target := TSetMitigation(DecodeApiPointer(ApiSlot_SetMitigation));
    Attempted := True; Succeeded := Target(Policy, @Wanted, SizeOf(Wanted));
    if not Succeeded then SetError := LastError;
  end;
begin
  if Profile = nil then begin CollectProcessMitigations(RequestedMode, DynamicCodeState, CfgState, Observation); Exit; end;
  { Validate every field before irreversible mitigation setters. CFG enablement is
    compiler/loader-owned: no attempt to turn on CFG by patching a PE flag. }
  if (Profile.Count <> 6) or (Profile.GetValue<Integer>(CozyText_ProcessMitigations_version_c34f5063, 0) <> 1) or
     not (Profile.GetValue(CozyText_ProcessMitigations_strictHandles_b0d34cf9) is TJSONBool) or
     not (Profile.GetValue(CozyText_ProcessMitigations_requireCfg_d5d7eeb0) is TJSONBool) or
     not (Profile.GetValue(CozyText_ProcessMitigations_imageLoadMask_ea6c4eed) is TJSONNumber) then
    raise EArgumentException.Create(CozyText_ProcessMitigations_MITIGATION_PROFILE_INVALID_e11e67e1);
  Id := Profile.GetValue<string>(CozyText_ProcessMitigations_id_300b076b, ''); Mode := Profile.GetValue<string>(CozyText_ProcessMitigations_dynamicCode_51e126a5, '');
  if (Length(Id) <> 128) or (Mode <> RequestedMode) then raise EArgumentException.Create(CozyText_ProcessMitigations_MITIGATION_PROFILE_INVALID_e11e67e1);
  for Flags := 1 to Length(Id) do if not CharInSet(Id[Flags], ['0'..'9', 'a'..'f']) then raise EArgumentException.Create(CozyText_ProcessMitigations_MITIGATION_PROFILE_INVALID_e11e67e1);
  Error := Profile.GetValue<Integer>(CozyText_ProcessMitigations_imageLoadMask_ea6c4eed, -1);
  if Error > 7 then raise EArgumentException.Create(CozyText_ProcessMitigations_MITIGATION_PROFILE_INVALID_e11e67e1);
  Mask := Error; Strict := Profile.GetValue<Boolean>(CozyText_ProcessMitigations_strictHandles_b0d34cf9, False);
  CollectProcessMitigations(RequestedMode, DynamicCodeState, CfgState, Observation);
  Observation.ProfileId := Id;
  if Strict then EnableBits(3, 3, Observation.StrictSetAttempted, Observation.StrictSetSucceeded, Observation.StrictSetError);
  EnableBits(10, Mask, Observation.ImageSetAttempted, Observation.ImageSetSucceeded, Observation.ImageSetError);
  Observation.StrictHandleQueried := QueryFlags(3, Observation.StrictHandleFlags, Observation.StrictHandleError);
  Observation.ImageLoadQueried := QueryFlags(10, Observation.ImageLoadFlags, Observation.ImageLoadError);
end;
procedure BindOptionalMitigations;
var Address, ModuleBase: Pointer;
begin
  BindApiPointer(ApiSlot_Error, RequireProcAddressHash64(CozyText_ProcessMitigations_kernel32_dll_7308f4c6, HASH_GetLastError));
  ModuleBase := GetModuleBase64(CozyText_ProcessMitigations_kernel32_dll_7308f4c6);
  Address := GetProcAddressHash64(ModuleBase, HASH_GetProcessMitigationPolicy);
  if Address <> nil then BindApiPointer(ApiSlot_GetMitigation, Address);
  Address := GetProcAddressHash64(ModuleBase, HASH_SetProcessMitigationPolicy);
  if Address <> nil then BindApiPointer(ApiSlot_SetMitigation, Address);
  Address := GetProcAddressHash64(GetModuleBase64(CozyText_ProcessMitigations_ntdll_dll_9e78643f), HASH_RtlGetVersion);
  if Address <> nil then BindApiPointer(ApiSlot_RtlGetVersion, Address);
end;
initialization
  BindOptionalMitigations;
end.
