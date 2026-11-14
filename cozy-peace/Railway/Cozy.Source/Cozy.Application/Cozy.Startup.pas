unit Cozy.Startup;

{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}

interface
{ Cozy central text imports. }
uses
  Cozy.Strings.Application;


{ Local initialization diagnostics only. Server authorization is separate. }
type
  TGameComponentRole = (gcrLauncher, gcrConnect, gcrOverlay);

function StartupAlgorithmsValid: Boolean;
{$IFNDEF FPC}
type
  TNativeStartupState = (nssNotRun, nssFailed, nssPassed);
  TNativeStartupCheck = (nscAbi, nscSealedPointers, nscRoleApis,
    nscRoleResources, nscAlgorithms);
  TNativeStartupChecks = set of TNativeStartupCheck;
  TNativeStartupObservation = record
    Version: Cardinal;
    Role: TGameComponentRole;
    State: TNativeStartupState;
    CompletedChecks: TNativeStartupChecks;
    FailureStage: Integer;
  end;
{ Diagnostic memory only: the latest completed local gate attempt for this
  process. NOT_RUN is not a success. Copies cannot authorize a server session,
  attest another process or replace execution of the final product files. }
function CaptureNativeStartupObservation(Role: TGameComponentRole): TNativeStartupObservation;
function NativeStartupObservationComplete(const Value: TNativeStartupObservation): Boolean;
procedure RequireNativeStartup(Role: TGameComponentRole;
  FailureStage: PInteger = nil);
{$ENDIF}

implementation

uses
  {$IFDEF FPC}SysUtils,{$ELSE}System.SysUtils, System.SyncObjs, Winapi.Windows, Cozy.WinApi,
  Cozy.Api.Pointer, Cozy.Api.ROR13, Cozy.Platform.ExportResolver,{$ENDIF}
  Cozy.Hashes.SelfTest;

{$IFNDEF FPC}
type
  TStartupApiContract = record
    ModuleName: string;
    ProcName: AnsiString; { Nonempty only for the explicit named clock contract. }
    ProcHash, Copies: Cardinal;
    Optional: Boolean;
  end;
  TStartupApiContracts = array of TStartupApiContract;
  TStartupFindResource = function(Module: HMODULE; Name, Kind: PWideChar): HRSRC; stdcall;
  TStartupSizeResource = function(Module: HMODULE; Resource: HRSRC): DWORD; stdcall;
var
  ApiSlot_FindResourceW, ApiSlot_SizeofResource: TEncodedApiPointer;
  StartupObservations: array[TGameComponentRole] of Int64;

procedure ValidateStartupRole(Role: TGameComponentRole);
begin
  case Role of
    gcrLauncher, gcrConnect, gcrOverlay: Exit;
  else raise EArgumentException.Create(CozyText_Startup_STARTUP_ROLE_INVALID_1f6d4366);
  end;
end;

function CaptureNativeStartupObservation(Role: TGameComponentRole): TNativeStartupObservation;
var EncodedState: Int64; Check: TNativeStartupCheck;
begin
  ValidateStartupRole(Role);
  EncodedState := TInterlocked.CompareExchange(StartupObservations[Role], Int64(0), Int64(0));
  Result.Version := 1; Result.Role := Role;
  Result.State := TNativeStartupState(EncodedState and $FF);
  Result.CompletedChecks := [];
  for Check := Low(TNativeStartupCheck) to High(TNativeStartupCheck) do
    if (EncodedState and (Int64(1) shl (8 + Ord(Check)))) <> 0 then
      Include(Result.CompletedChecks, Check);
  Result.FailureStage := Integer(EncodedState shr 16);
end;

function NativeStartupObservationComplete(const Value: TNativeStartupObservation): Boolean;
begin
  Result := (Value.Version = 1) and (Value.State = nssPassed) and
    (Value.FailureStage = 0) and
    (Value.CompletedChecks = [nscAbi, nscSealedPointers, nscRoleApis,
      nscRoleResources, nscAlgorithms]) and
    ((Value.Role = gcrLauncher) or (Value.Role = gcrConnect) or
      (Value.Role = gcrOverlay));
end;

procedure PublishStartupObservation(const Value: TNativeStartupObservation);
var EncodedState: Int64; Check: TNativeStartupCheck;
begin
  { One native atomic POD value; no allocation, lock, output or cleanup can
    replace the gate's original success/failure. Readers see only a complete
    attempt, retaining the last completed result while another attempt runs.
    No authorization/gate decision reads this diagnostic value. }
  EncodedState := Int64(Ord(Value.State)) or (Int64(Value.FailureStage) shl 16);
  for Check := Low(TNativeStartupCheck) to High(TNativeStartupCheck) do
    if Check in Value.CompletedChecks then
      EncodedState := EncodedState or (Int64(1) shl (8 + Ord(Check)));
  TInterlocked.Exchange(StartupObservations[Value.Role], EncodedState);
end;

procedure SetApiContract(var Item: TStartupApiContract; const ModuleName: string;
  ProcHash, Copies: Cardinal; Optional: Boolean);
begin
  Item.ModuleName := ModuleName; Item.ProcName := ''; Item.ProcHash := ProcHash;
  Item.Copies := Copies; Item.Optional := Optional;
end;

function NamedClockApiAllowed(const Name: AnsiString): Boolean;
const
  { Public API identities. No lookup hash or hidden-name decoding is used for
    these documented clock/wait functions. }
  Allowed: array[0..6] of AnsiString = (
    CozyText_Startup_QueryPerformanceCounter_30a9b4de, CozyText_Startup_QueryPerformanceFrequency_e20f096d, CozyText_Startup_CreateEventW_1ae52b29,
    CozyText_Startup_WaitForSingleObject_3f62d502, CozyText_Startup_CloseHandle_c3dc71c0, CozyText_Startup_GetLastError_6b283b78, CozyText_Startup_SetLastError_4fbcb022);
var I: Integer;
begin
  Result := False;
  for I := Low(Allowed) to High(Allowed) do
    if Name = Allowed[I] then Exit(True);
end;

procedure SetNamedApiContract(var Item: TStartupApiContract;
  const ModuleName: string; const ProcName: AnsiString; Copies: Cardinal);
begin
  if (ModuleName <> CozyText_Startup_kernel32_dll_66c5ad2a) or not NamedClockApiAllowed(ProcName) or
    (Copies <> 1) then
    raise EInvalidOpException.Create(CozyText_Startup_STARTUP_NAMED_API_CONTRACT_INVALID_1dd2b5f4);
  Item.ModuleName := ModuleName; Item.ProcName := ProcName; Item.ProcHash := 0;
  Item.Copies := Copies; Item.Optional := False;
end;

{$I Cozy.Startup.ApiContracts.inc}

{$IFDEF GAME_PRODUCT_FAULT_TESTS}
procedure AppendProductFaultApiContract(var Items: TStartupApiContracts);
var First: Integer;
begin
  { Independent expected identities for the isolated fault unit's eight bindings.
    Production's generated role multiset remains unchanged. Do not derive these
    targets from the actual bound slots: that would hide an incorrect binding. }
  First := Length(Items);
  SetLength(Items, First + 8);
  SetApiContract(Items[First + 0], CozyText_Startup_kernel32_dll_66c5ad2a, HASH_GetEnvironmentVariableW, 1, False);
  SetApiContract(Items[First + 1], CozyText_Startup_kernel32_dll_66c5ad2a, HASH_GetFileAttributesW, 1, False);
  SetApiContract(Items[First + 2], CozyText_Startup_kernel32_dll_66c5ad2a, HASH_CreateFileW, 1, False);
  SetApiContract(Items[First + 3], CozyText_Startup_kernel32_dll_66c5ad2a, HASH_GetFileInformationByHandle, 1, False);
  SetApiContract(Items[First + 4], CozyText_Startup_kernel32_dll_66c5ad2a, HASH_ReadFile, 1, False);
  SetApiContract(Items[First + 5], CozyText_Startup_kernel32_dll_66c5ad2a, HASH_WriteFile, 1, False);
  SetApiContract(Items[First + 6], CozyText_Startup_kernel32_dll_66c5ad2a, HASH_CloseHandle, 1, False);
  SetApiContract(Items[First + 7], CozyText_Startup_kernel32_dll_66c5ad2a, HASH_GetCurrentProcessId, 1, False);
end;
{$ENDIF}

procedure ValidateRoleApis(Role: TGameComponentRole);
var Items: TStartupApiContracts; Targets: TArray<Pointer>;
  I, J, Count: Integer; Address: Pointer; Module: HMODULE;
begin
  FillRoleApiContract(Role, Items);
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
  AppendProductFaultApiContract(Items);
{$ENDIF}
  Count := 0;
  for I := 0 to High(Items) do Inc(Count, Items[I].Copies);
  SetLength(Targets, Count); Count := 0;
  for I := 0 to High(Items) do
  begin
    if Items[I].ProcName <> '' then
    begin
      if (Items[I].ProcHash <> 0) or Items[I].Optional or
        (Items[I].ModuleName <> CozyText_Startup_kernel32_dll_66c5ad2a) or
        not NamedClockApiAllowed(Items[I].ProcName) or (Items[I].Copies <> 1) then
        raise EInvalidOpException.Create(CozyText_Startup_STARTUP_NAMED_API_CONTRACT_INVALID_1dd2b5f4);
      { Independent, documented loader query. Never derive expected targets
        from the slots being checked and never compare an import thunk. These
        two loader queries are bootstrap validation, not application calls. }
      Module := Winapi.Windows.GetModuleHandleW(PWideChar(Items[I].ModuleName));
      if Module = 0 then
        raise EInvalidOpException.Create(CozyText_Startup_STARTUP_NAMED_API_UNAVAILABLE_28efb48d);
      Address := Winapi.Windows.GetProcAddress(Module, PAnsiChar(Items[I].ProcName));
      if Address = nil then
        raise EInvalidOpException.Create(CozyText_Startup_STARTUP_NAMED_API_UNAVAILABLE_28efb48d);
    end
    else
    begin
      if Items[I].ProcHash = 0 then
        raise EInvalidOpException.Create(CozyText_Startup_STARTUP_API_CONTRACT_INVALID_3199bdc2);
      if Items[I].Optional then
        Address := OptionalSystemProcAddressHash64(Items[I].ModuleName, Items[I].ProcHash)
      else Address := RequireProcAddressHash64(Items[I].ModuleName, Items[I].ProcHash);
      if Address = nil then Continue;
    end;
    RetainApiTargetModule(Address);
    for J := 1 to Integer(Items[I].Copies) do
    begin Targets[Count] := Address; Inc(Count); end;
  end;
  SetLength(Targets, Count);
  if not ApiPointerTargetsMatch(Targets) then
    raise EInvalidOpException.Create(CozyText_Startup_STARTUP_ROLE_API_CONTRACT_MISMATCH_de54f668);
end;

procedure RequireResource(Kind, Name: Word; Minimum, Maximum: DWORD);
var FindTarget: TStartupFindResource; SizeTarget: TStartupSizeResource;
  Resource: HRSRC; Count: DWORD;
begin
  FindTarget := TStartupFindResource(DecodeApiPointer(ApiSlot_FindResourceW));
  SizeTarget := TStartupSizeResource(DecodeApiPointer(ApiSlot_SizeofResource));
  Resource := FindTarget(HInstance, PWideChar(NativeUInt(Name)), PWideChar(NativeUInt(Kind)));
  if Resource = 0 then raise EInvalidOpException.Create(CozyText_Startup_STARTUP_RESOURCE_MISSING_0e42e980);
  Count := SizeTarget(HInstance, Resource);
  if (Count < Minimum) or (Count > Maximum) then
    raise EInvalidOpException.Create(CozyText_Startup_STARTUP_RESOURCE_SIZE_INVALID_4dcf2375);
end;

procedure ValidateRoleResources(Role: TGameComponentRole);
begin
  { The actual .rc contract: process manifest + VERSIONINFO in every role;
    Launcher also carries its public issuer trust in read-only RCDATA.
    Overlay additionally distributes upstream ImGui's MIT license in RCDATA.
    A personalized profile and B/O encrypted handoff are validated by their
    role bootstrap before any server session; they are not PE resources. }
  RequireResource(24, 1, 32, 65536);
  RequireResource(16, 1, 52, 65536);
  if Role = gcrLauncher then RequireResource(10, 311, 331, 331);
  if Role = gcrOverlay then RequireResource(10, 310, 100, 65536);
end;
{$ENDIF}

function StartupAlgorithmsValid: Boolean;
begin
  { Public algorithm self-test only; never a local authorization baseline. }
  Result := IntegrityAlgorithmsSelfTest;
end;

{$IFNDEF FPC}
procedure RequireNativeStartup(Role: TGameComponentRole; FailureStage: PInteger);
var Observation: TNativeStartupObservation;
  procedure Stage(Value: Integer);
  begin
    Observation.FailureStage := Value;
    if FailureStage <> nil then FailureStage^ := Value;
  end;
begin
  ValidateStartupRole(Role);
  Observation := Default(TNativeStartupObservation);
  Observation.Version := 1; Observation.Role := Role;
  Observation.State := nssFailed;
  { Called by each application entry point after all unit initialization and
    pointer sealing, before networking, key creation or user interface work.
    The observation records actual completed checks, never planned checks. }
  try
    Stage(31004);
    if not Win64ApiLayoutValid then
      raise EInvalidOpException.Create(CozyText_Startup_STARTUP_ABI_INVALID_120e5056);
    Include(Observation.CompletedChecks, nscAbi);
    Stage(31005);
    if not ApiPointerStorageIsSealed then
      raise EInvalidOpException.Create(CozyText_Startup_STARTUP_API_BINDINGS_INCOMPLETE_ad3e2cad);
    Include(Observation.CompletedChecks, nscSealedPointers);
    Stage(31006);
    ValidateRoleApis(Role);
    Include(Observation.CompletedChecks, nscRoleApis);
    Stage(31007);
    ValidateRoleResources(Role);
    Include(Observation.CompletedChecks, nscRoleResources);
    Stage(31008);
    if not StartupAlgorithmsValid then
      raise EInvalidOpException.Create(CozyText_Startup_STARTUP_ALGORITHM_SELF_TEST_FAILED_f60033c3);
    Include(Observation.CompletedChecks, nscAlgorithms);
    Observation.FailureStage := 0; Observation.State := nssPassed;
  finally PublishStartupObservation(Observation); end;
end;
{$ENDIF}

{$IFNDEF FPC}
initialization
  BindApiPointer(ApiSlot_FindResourceW, RequireProcAddressHash64(CozyText_Startup_kernel32_dll_66c5ad2a, HASH_FindResourceW));
  BindApiPointer(ApiSlot_SizeofResource, RequireProcAddressHash64(CozyText_Startup_kernel32_dll_66c5ad2a, HASH_SizeofResource));
{$ENDIF}
end.
