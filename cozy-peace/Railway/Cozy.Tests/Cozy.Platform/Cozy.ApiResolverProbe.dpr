program Cozy_ApiResolverProbe;

{$APPTYPE CONSOLE}
{$POINTERMATH ON}
{$R+}
{$Q+}

uses
{ Cozy central text imports. }
  Cozy.Strings.Application in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Application.pas',
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Identity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Identity.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.License in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.License.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Network in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Network.pas',
  Cozy.Strings.Overlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Overlay.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Protection in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Protection.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
{$IF (Defined(GAME_HANDOFF_CONTRACT_TESTS))}
  Cozy.Strings.TestsHandoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsHandoff.pas',
{$ENDIF}
{$IF (Defined(GAME_DEVICE_IDENTITY_PROBE))}
  Cozy.Strings.TestsIdentity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsIdentity.pas',
{$ENDIF}
{$IF ((Defined(GAME_RELAY_SOCKET_CONTRACT_TESTS))) or (((Defined(GAME_NATIVE_ABI_TESTS))) or ((Defined(GAME_TLS_CONTRACT_TESTS))))}
  Cozy.Strings.TestsNetwork in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsNetwork.pas',
{$ENDIF}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',

  Winapi.Windows, System.SysUtils,
  Cozy.WinApi, Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Api.Pointer, Cozy.Api.Guid,
  Cozy.License.Session, Cozy.Launcher;

{ Merely linking both entry units validates all API initialization sections.
  RunLicenseClient/RunLauncher are NEVER called: no server connection, license
  request, file deletion, downloaded program, or application UI is started. }

var
  CheckedExports: Integer;

procedure Check(Condition: Boolean; const MessageText: string);
begin
  if not Condition then raise Exception.Create(MessageText);
end;

procedure CheckExport(const Dll: string; const Name: AnsiString;
  ExpectedHash: Cardinal);
var
  Actual, Expected: Pointer;
  Slot: TEncodedApiPointer;
  Module: HMODULE;
  Directory: array[0..32767] of WideChar;
  Count: DWORD;
  FullPath: string;
begin
  Check(ApiHashROR13(Name) = ExpectedHash, CozyText_ApiResolverProbe_ROR13_constant_aef6a7f1 + string(Name));
  Actual := RequireProcAddressHash64(Dll, ExpectedHash);
  Slot := Default(TEncodedApiPointer);
  BindApiPointer(Slot, Actual);
  Check(Slot.IsBound, CozyText_ApiResolverProbe_Encoded_slot_bound_ad0872fd);
  Check(DecodeApiPointer(Slot) = Actual, CozyText_ApiResolverProbe_Encoded_pointer_round_trip_22551e2e);
  Check(Actual = RequireProcAddress64(Dll, Name), CozyText_ApiResolverProbe_Named_compatibility_path_6ebf3a84);
  Count := Winapi.Windows.GetSystemDirectoryW(@Directory[0], Length(Directory));
  Check((Count > 0) and (Count < Cardinal(Length(Directory))), CozyText_ApiResolverProbe_System_directory_37ecff5c);
  SetString(FullPath, PWideChar(@Directory[0]), Integer(Count));
  FullPath := IncludeTrailingPathDelimiter(FullPath) + Dll;
  Module := Winapi.Windows.LoadLibraryExW(PWideChar(FullPath), 0, $00000800);
  Check(Module <> 0, CozyText_ApiResolverProbe_Load_a4889b80 + Dll);
  try
    Expected := Pointer(Winapi.Windows.GetProcAddress(Module, PAnsiChar(Name)));
    Check((Actual <> nil) and (Actual = Expected), Dll + '!' + string(Name));
  finally
    Winapi.Windows.FreeLibrary(Module);
  end;
  Inc(CheckedExports);
end;

procedure Put16(var Bytes: TBytes; Offset: Integer; Value: Word);
begin
  Move(Value, Bytes[Offset], SizeOf(Value));
end;

procedure Put32(var Bytes: TBytes; Offset: Integer; Value: Cardinal);
begin
  Move(Value, Bytes[Offset], SizeOf(Value));
end;

function SyntheticImage: TBytes;
const
  ExportName: AnsiString = CozyText_ApiResolverProbe_ProbeExport_61dd8380;
begin
  SetLength(Result, $1000);
  FillChar(Result[0], Length(Result), 0);
  Put16(Result, $00, $5A4D);
  Put32(Result, $3C, $80);
  Put32(Result, $80, $4550);
  Put16(Result, $84, $8664);
  Put16(Result, $94, $F0);
  Put16(Result, $98, $20B);
  Put32(Result, $D0, $1000);    { SizeOfImage }
  Put32(Result, $104, 16);     { NumberOfRvaAndSizes }
  Put32(Result, $108, $200);   { Export RVA }
  Put32(Result, $10C, $100);   { Export size }
  Put32(Result, $200 + 16, 1); { Ordinal base }
  Put32(Result, $200 + 20, 1); { One function }
  Put32(Result, $200 + 24, 1); { One name }
  Put32(Result, $200 + 28, $400);
  Put32(Result, $200 + 32, $410);
  Put32(Result, $200 + 36, $420);
  Put32(Result, $400, $800);   { Merely a data address; NEVER executed }
  Put32(Result, $410, $430);
  Put16(Result, $420, 0);
  Move(ExportName[1], Result[$430], Length(ExportName));
end;

procedure TestMalformedImages;
var
  Bytes: TBytes;
  Base: Pointer;
begin
  Bytes := SyntheticImage;
  Base := @Bytes[0];
  Check(GetProcAddress64(Base, CozyText_ApiResolverProbe_ProbeExport_61dd8380) = Pointer(PByte(Base) + $800),
    CozyText_ApiResolverProbe_Synthetic_named_export_33f4812f);
  Check(GetProcAddress64(Base, CozyText_ApiResolverProbe_probeexport_627ceab9) = nil, CozyText_ApiResolverProbe_Case_sensitive_export_1438972d);
  Check(GetProcAddress64(Base, CozyText_ApiResolverProbe_MissingExport_d322ebf3) = nil, CozyText_ApiResolverProbe_Missing_export_82ed6b8f);
  Check(GetProcAddress64(nil, CozyText_ApiResolverProbe_ProbeExport_61dd8380) = nil, CozyText_ApiResolverProbe_Nil_module_8f794eb7);
  Check(GetProcAddress64(Base, '') = nil, CozyText_ApiResolverProbe_Empty_name_2a921e63);
  Check(GetProcAddress64(Base, AnsiString(CozyText_ApiResolverProbe_ProbeExport_junk_e7e1e73a)) = nil,
    CozyText_ApiResolverProbe_Embedded_NUL_182a8284);

  Put32(Bytes, $200 + 24, 0);
  Check(GetProcAddress64(Base, CozyText_ApiResolverProbe_ProbeExport_61dd8380) = nil, CozyText_ApiResolverProbe_Zero_names_d3264362);
  Put32(Bytes, $200 + 24, 1);
  Put32(Bytes, $200 + 20, 0);
  Check(GetProcAddress64(Base, CozyText_ApiResolverProbe_ProbeExport_61dd8380) = nil, CozyText_ApiResolverProbe_Zero_functions_7c382bc2);
  Put32(Bytes, $200 + 20, 1);
  Put16(Bytes, $420, 1);
  Check(GetProcAddress64(Base, CozyText_ApiResolverProbe_ProbeExport_61dd8380) = nil, CozyText_ApiResolverProbe_Ordinal_outside_EAT_b0c6c210);
  Put16(Bytes, $420, 0);
  Put32(Bytes, $400, 0);
  Check(GetProcAddress64(Base, CozyText_ApiResolverProbe_ProbeExport_61dd8380) = nil, CozyText_ApiResolverProbe_Zero_function_RVA_53e97969);
  Put32(Bytes, $400, $1000);
  Check(GetProcAddress64(Base, CozyText_ApiResolverProbe_ProbeExport_61dd8380) = nil, CozyText_ApiResolverProbe_Function_outside_image_ac70a32f);
  Put32(Bytes, $400, $800);
  Put32(Bytes, $200 + 32, $FFF);
  Check(GetProcAddress64(Base, CozyText_ApiResolverProbe_ProbeExport_61dd8380) = nil, CozyText_ApiResolverProbe_Name_table_outside_image_9f0b16fd);
  Put32(Bytes, $200 + 32, $410);
  Put32(Bytes, $410, $FFD);
  Check(GetProcAddress64(Base, CozyText_ApiResolverProbe_ProbeExport_61dd8380) = nil, CozyText_ApiResolverProbe_Name_crosses_image_end_3b1c3a47);
  Put32(Bytes, $410, $430);
  Put32(Bytes, $10C, 39);
  Check(GetProcAddress64(Base, CozyText_ApiResolverProbe_ProbeExport_61dd8380) = nil, CozyText_ApiResolverProbe_Truncated_directory_90569b3f);
  Put32(Bytes, $10C, $100);
  Put32(Bytes, $104, 0);
  Check(GetProcAddress64(Base, CozyText_ApiResolverProbe_ProbeExport_61dd8380) = nil, CozyText_ApiResolverProbe_No_data_directories_4934b6da);
  Put32(Bytes, $104, 16);
  Put16(Bytes, $98, $10B);
  Check(GetProcAddress64(Base, CozyText_ApiResolverProbe_ProbeExport_61dd8380) = nil, CozyText_ApiResolverProbe_PE32_rejected_cb98b89e);
  Put16(Bytes, $98, $20B);
  Put16(Bytes, $84, $14C);
  Check(GetProcAddress64(Base, CozyText_ApiResolverProbe_ProbeExport_61dd8380) = nil, CozyText_ApiResolverProbe_x86_rejected_57efc813);
  Put16(Bytes, $84, $8664);
  Put32(Bytes, $3C, $FFFFFFFF);
  Check(GetProcAddress64(Base, CozyText_ApiResolverProbe_ProbeExport_61dd8380) = nil, CozyText_ApiResolverProbe_Negative_NT_offset_4684974d);
  Put32(Bytes, $3C, $80);
  Put32(Bytes, $80, 0);
  Check(GetProcAddress64(Base, CozyText_ApiResolverProbe_ProbeExport_61dd8380) = nil, CozyText_ApiResolverProbe_Bad_PE_signature_b865c2b3);
  Put32(Bytes, $80, $4550);
  Put16(Bytes, $00, 0);
  Check(GetProcAddress64(Base, CozyText_ApiResolverProbe_ProbeExport_61dd8380) = nil, CozyText_ApiResolverProbe_Bad_DOS_signature_6d5f5042);
end;

procedure TestMalformedHashImages;
var
  Bytes: TBytes;
  Base: Pointer;
begin
  Bytes := SyntheticImage;
  Base := @Bytes[0];
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = Pointer(PByte(Base) + $800),
    CozyText_ApiResolverProbe_Synthetic_hashed_export_12fc7ca3);
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_probeexport_627ceab9)) = nil, CozyText_ApiResolverProbe_Case_sensitive_export_1438972d);
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_MissingExport_d322ebf3)) = nil, CozyText_ApiResolverProbe_Missing_export_82ed6b8f);
  Check(GetProcAddressHash64(nil, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = nil, CozyText_ApiResolverProbe_Nil_module_8f794eb7);

  Put32(Bytes, $200 + 24, 0);
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = nil, CozyText_ApiResolverProbe_Zero_names_d3264362);
  Put32(Bytes, $200 + 24, 1);
  Put32(Bytes, $200 + 20, 0);
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = nil, CozyText_ApiResolverProbe_Zero_functions_7c382bc2);
  Put32(Bytes, $200 + 20, 1);
  Put16(Bytes, $420, 1);
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = nil, CozyText_ApiResolverProbe_Ordinal_outside_EAT_b0c6c210);
  Put16(Bytes, $420, 0);
  Put32(Bytes, $400, 0);
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = nil, CozyText_ApiResolverProbe_Zero_function_RVA_53e97969);
  Put32(Bytes, $400, $1000);
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = nil, CozyText_ApiResolverProbe_Function_outside_image_ac70a32f);
  Put32(Bytes, $400, $800);
  Put32(Bytes, $200 + 32, $FFF);
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = nil, CozyText_ApiResolverProbe_Name_table_outside_image_9f0b16fd);
  Put32(Bytes, $200 + 32, $410);
  Put32(Bytes, $410, $FFD);
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = nil, CozyText_ApiResolverProbe_Name_crosses_image_end_3b1c3a47);
  Put32(Bytes, $410, $430);
  Put32(Bytes, $10C, 39);
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = nil, CozyText_ApiResolverProbe_Truncated_directory_90569b3f);
  Put32(Bytes, $10C, $100);
  Put32(Bytes, $104, 0);
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = nil, CozyText_ApiResolverProbe_No_data_directories_4934b6da);
  Put32(Bytes, $104, 16);
  Put16(Bytes, $98, $10B);
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = nil, CozyText_ApiResolverProbe_PE32_rejected_cb98b89e);
  Put16(Bytes, $98, $20B);
  Put16(Bytes, $84, $14C);
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = nil, CozyText_ApiResolverProbe_x86_rejected_57efc813);
  Put16(Bytes, $84, $8664);
  Put32(Bytes, $3C, $FFFFFFFF);
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = nil, CozyText_ApiResolverProbe_Negative_NT_offset_4684974d);
  Put32(Bytes, $3C, $80);
  Put32(Bytes, $80, 0);
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = nil, CozyText_ApiResolverProbe_Bad_PE_signature_b865c2b3);
  Put32(Bytes, $80, $4550);
  Put16(Bytes, $00, 0);
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = nil, CozyText_ApiResolverProbe_Bad_DOS_signature_6d5f5042);
end;

procedure TestROR13;
const
  CollisionA: AnsiString = CozyText_ApiResolverProbe_ProbemhCdNONDi_7675a931;
  CollisionB: AnsiString = CozyText_ApiResolverProbe_ProbeiZoHNPUnw_0ac8ffd0;
  CollisionHash: Cardinal = $B7123054;
var
  Bytes: TBytes;
  Base: Pointer;
begin
  Check(ApiHashROR13('') = 0, CozyText_ApiResolverProbe_ROR13_empty_vector_b3c1c55d);
  Check(ApiHashROR13(CozyText_ApiResolverProbe_LoadLibraryA_987cd39d) = $EC0E4E8E, CozyText_ApiResolverProbe_ROR13_rotate_then_add_vector_9859f5e7);
  Check(ApiHashROR13(CozyText_ApiResolverProbe_GetProcAddress_c68d4544) = $7C0DFCAA, CozyText_ApiResolverProbe_ROR13_second_vector_2de3a86d);
  Check(ApiHashROR13Byte($FFFFFFFF, 1) = 0, CozyText_ApiResolverProbe_ROR13_32_bit_wrap_under_Q_R_7690f3c6);
  Check(ApiHashROR13('A') <> ApiHashROR13('a'), CozyText_ApiResolverProbe_ROR13_case_sensitivity_13add41f);
  Check((ApiHashROR13(CollisionA) = CollisionHash) and
    (ApiHashROR13(CollisionB) = CollisionHash), CozyText_ApiResolverProbe_True_collision_fixture_2f671708);

  Bytes := SyntheticImage;
  Base := @Bytes[0];
  Put32(Bytes, $200 + 20, 2);
  Put32(Bytes, $200 + 24, 2);
  Put32(Bytes, $404, $810);
  Put32(Bytes, $414, $470);
  Put16(Bytes, $422, 1);
  FillChar(Bytes[$430], $40, 0);
  Move(CollisionA[1], Bytes[$430], Length(CollisionA));
  Move(CollisionB[1], Bytes[$470], Length(CollisionB));
  Check(GetProcAddressHash64(Base, CollisionHash) = nil,
    CozyText_ApiResolverProbe_Ambiguous_hash_must_fail_rather_than_choosing_ei_d8135225);
  Put32(Bytes, $200 + 24, 1);
  Check(GetProcAddressHash64(Base, CollisionHash) = Pointer(PByte(Base) + $800),
    CozyText_ApiResolverProbe_The_same_hash_resolves_when_unambiguous_5eaade2a);

  Bytes := SyntheticImage;
  Base := @Bytes[0];
  Bytes[$430] := 0;
  Check(GetProcAddressHash64(Base, 0) = nil, CozyText_ApiResolverProbe_An_empty_export_name_is_invalid_9331d190);
  Put32(Bytes, $410, $FFD);
  FillChar(Bytes[$FFD], 3, Ord('X'));
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_XXX_033c3ba7)) = nil,
    CozyText_ApiResolverProbe_An_export_name_must_terminate_inside_its_image_811a39dc);

  Bytes := SyntheticImage;
  Base := @Bytes[0];
  Put32(Bytes, $400, $2F0);
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = nil,
    CozyText_ApiResolverProbe_Empty_forwarder_is_not_executable_fceb5e99);
  FillChar(Bytes[$2F0], $10, Ord('X'));
  Check(GetProcAddressHash64(Base, ApiHashROR13(CozyText_ApiResolverProbe_ProbeExport_61dd8380)) = nil,
    CozyText_ApiResolverProbe_Unterminated_forwarder_is_rejected_9aed3a0a);
end;

procedure TestGuidCalls;
var
  First, Second, Empty: TGUID;
  Status: LongInt;
begin
  Check(SizeOf(TGUID) = 16, CozyText_ApiResolverProbe_GUID_ABI_size_49d2c2f8);
  Check(SizeOf(LongInt) = 4, CozyText_ApiResolverProbe_HRESULT_ABI_size_07009417);
  Empty := Default(TGUID);
  First := Empty;
  Second := Empty;
  Status := WindowsApiCreateGUID(First);
  Check(Status = 0, CozyText_ApiResolverProbe_First_GUID_creation_HRESULT_6c7c4248);
  Status := WindowsApiCreateGUID(Second);
  Check(Status = 0, CozyText_ApiResolverProbe_Second_GUID_creation_HRESULT_23398cb1);
  Check(not CompareMem(@First, @Empty, SizeOf(TGUID)), CozyText_ApiResolverProbe_First_GUID_is_nonzero_ed0e163b);
  Check(not CompareMem(@Second, @Empty, SizeOf(TGUID)), CozyText_ApiResolverProbe_Second_GUID_is_nonzero_310b828c);
  Check(not CompareMem(@First, @Second, SizeOf(TGUID)), CozyText_ApiResolverProbe_Fresh_GUID_per_request_dfe0f5cc);
  Check(Length(GUIDToString(First)) = 38, CozyText_ApiResolverProbe_Existing_GUID_string_format_72933a02);
end;

procedure TestBenignCalls;
var
  Tick: TApiGetTickCount64;
  CreateAnEvent: TApiCreateEventW;
  SignalEvent: TApiSetEvent;
  WaitOne: TApiWaitForSingleObject;
  CloseAnEvent: TApiCloseHandle;
  LastError: TApiGetLastError;
  Event: THandle;
  BeforeTick, NowTick, AfterTick: UInt64;
begin
  Tick := TApiGetTickCount64(RequireProcAddressHash64(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, HASH_GetTickCount64));
  CreateAnEvent := TApiCreateEventW(RequireProcAddressHash64(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, HASH_CreateEventW));
  SignalEvent := TApiSetEvent(RequireProcAddressHash64(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, HASH_SetEvent));
  WaitOne := TApiWaitForSingleObject(RequireProcAddressHash64(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, HASH_WaitForSingleObject));
  CloseAnEvent := TApiCloseHandle(RequireProcAddressHash64(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, HASH_CloseHandle));
  LastError := TApiGetLastError(RequireProcAddressHash64(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, HASH_GetLastError));
  BeforeTick := Winapi.Windows.GetTickCount64;
  NowTick := Tick();
  AfterTick := Winapi.Windows.GetTickCount64;
  Check((NowTick >= BeforeTick) and (NowTick <= AfterTick), CozyText_ApiResolverProbe_Tick_ABI_946b98ad);
  Event := CreateAnEvent(nil, True, False, nil);
  Check(Event <> 0, CozyText_ApiResolverProbe_CreateEvent_ABI_e5f0f5ba);
  try
    Check(WaitOne(Event, 0) = WAIT_TIMEOUT, CozyText_ApiResolverProbe_Unsignalled_event_0cffe34e);
    Check(SignalEvent(Event), CozyText_ApiResolverProbe_SetEvent_ABI_5fc13f08);
    Check(WaitOne(Event, 0) = WAIT_OBJECT_0, CozyText_ApiResolverProbe_Signalled_event_19b35b7d);
  finally
    CloseAnEvent(Event);
  end;
  Winapi.Windows.SetLastError(12345);
  Check(LastError() = 12345, CozyText_ApiResolverProbe_Last_error_state_is_preserved_by_the_bound_call_4a51e6fa);
end;

begin
  try
    Check(GetPEB64 <> nil, CozyText_ApiResolverProbe_PEB_e8394237);
    Check(GetModuleBase64(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6) =
      Pointer(Winapi.Windows.GetModuleHandleW(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6)), CozyText_ApiResolverProbe_PEB_module_94f229c0);
    Check(GetModuleBase64(CozyText_ApiResolverProbe_KERNEL32_DLL_d763e7ef) = GetModuleBase64(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6),
      CozyText_ApiResolverProbe_Module_name_is_case_insensitive_9b232034);
    Check(GetModuleBase64('') = nil, CozyText_ApiResolverProbe_Empty_module_name_fbbfd6d1);
    Check(GetModuleBase64(CozyText_ApiResolverProbe_GameConnect_Probe_NotLoaded_dll_0fe8ef3b) = nil,
      CozyText_ApiResolverProbe_Absent_module_c3d10ca9);
    TestMalformedImages;
    TestMalformedHashImages;
    TestROR13;
    TestBenignCalls;
    TestGuidCalls;
    CheckExport(CozyText_ApiResolverProbe_advapi32_dll_59db4bbc, CozyText_ApiResolverProbe_RegCloseKey_b1d6fbcb, HASH_RegCloseKey);
    CheckExport(CozyText_ApiResolverProbe_advapi32_dll_59db4bbc, CozyText_ApiResolverProbe_RegOpenKeyExW_6dc59b4f, HASH_RegOpenKeyExW);
    CheckExport(CozyText_ApiResolverProbe_advapi32_dll_59db4bbc, CozyText_ApiResolverProbe_RegQueryValueExW_b11d4359, HASH_RegQueryValueExW);
    CheckExport(CozyText_ApiResolverProbe_bcrypt_dll_cba11fd8, CozyText_ApiResolverProbe_BCryptCloseAlgorithmProvider_c312e7eb, HASH_BCryptCloseAlgorithmProvider);
    CheckExport(CozyText_ApiResolverProbe_bcrypt_dll_cba11fd8, CozyText_ApiResolverProbe_BCryptCreateHash_5710eef6, HASH_BCryptCreateHash);
    CheckExport(CozyText_ApiResolverProbe_bcrypt_dll_cba11fd8, CozyText_ApiResolverProbe_BCryptDecrypt_6dedff78, HASH_BCryptDecrypt);
    CheckExport(CozyText_ApiResolverProbe_bcrypt_dll_cba11fd8, CozyText_ApiResolverProbe_BCryptDestroyHash_d0731052, HASH_BCryptDestroyHash);
    CheckExport(CozyText_ApiResolverProbe_bcrypt_dll_cba11fd8, CozyText_ApiResolverProbe_BCryptDestroyKey_a29fb2e5, HASH_BCryptDestroyKey);
    CheckExport(CozyText_ApiResolverProbe_bcrypt_dll_cba11fd8, CozyText_ApiResolverProbe_BCryptEncrypt_f8dad3b2, HASH_BCryptEncrypt);
    CheckExport(CozyText_ApiResolverProbe_bcrypt_dll_cba11fd8, CozyText_ApiResolverProbe_BCryptFinishHash_c9cf1231, HASH_BCryptFinishHash);
    CheckExport(CozyText_ApiResolverProbe_bcrypt_dll_cba11fd8, CozyText_ApiResolverProbe_BCryptGenRandom_0041fc76, HASH_BCryptGenRandom);
    CheckExport(CozyText_ApiResolverProbe_bcrypt_dll_cba11fd8, CozyText_ApiResolverProbe_BCryptGenerateSymmetricKey_58114969, HASH_BCryptGenerateSymmetricKey);
    CheckExport(CozyText_ApiResolverProbe_bcrypt_dll_cba11fd8, CozyText_ApiResolverProbe_BCryptHashData_1c77e54e, HASH_BCryptHashData);
    CheckExport(CozyText_ApiResolverProbe_bcrypt_dll_cba11fd8, CozyText_ApiResolverProbe_BCryptImportKeyPair_74e11e54, HASH_BCryptImportKeyPair);
    CheckExport(CozyText_ApiResolverProbe_bcrypt_dll_cba11fd8, CozyText_ApiResolverProbe_BCryptOpenAlgorithmProvider_a09788dd, HASH_BCryptOpenAlgorithmProvider);
    CheckExport(CozyText_ApiResolverProbe_bcrypt_dll_cba11fd8, CozyText_ApiResolverProbe_BCryptSetProperty_72b665b4, HASH_BCryptSetProperty);
    CheckExport(CozyText_ApiResolverProbe_crypt32_dll_a85a2101, CozyText_ApiResolverProbe_CertFreeCertificateContext_34756410, HASH_CertFreeCertificateContext);
    CheckExport(CozyText_ApiResolverProbe_crypt32_dll_a85a2101, CozyText_ApiResolverProbe_CertVerifyTimeValidity_522eb795, HASH_CertVerifyTimeValidity);
    CheckExport(CozyText_ApiResolverProbe_crypt32_dll_a85a2101, CozyText_ApiResolverProbe_CryptHashCertificate2_0ef4f936, HASH_CryptHashCertificate2);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_CancelSynchronousIo_f42db104, HASH_CancelSynchronousIo);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_CloseHandle_e7cc93ce, HASH_CloseHandle);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_CreateEventW_2dbf549a, HASH_CreateEventW);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_CreateFileW_b588d2cb, HASH_CreateFileW);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_CreatePipe_0033eb8c, HASH_CreatePipe);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_CreateProcessW_7bce8476, HASH_CreateProcessW);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_DeleteProcThreadAttributeList_1f4567e7, HASH_DeleteProcThreadAttributeList);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_DuplicateHandle_46a40dce, HASH_DuplicateHandle);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_FlushFileBuffers_650f7a7f, HASH_FlushFileBuffers);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetComputerNameW_01c7ad6a, HASH_GetComputerNameW);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetCurrentProcess_a73a8b1e, HASH_GetCurrentProcess);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetCurrentProcessId_30b0083c, HASH_GetCurrentProcessId);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetExitCodeThread_1aee9b51, HASH_GetExitCodeThread);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetFileAttributesW_d0f4fbf3, HASH_GetFileAttributesW);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetFileInformationByHandle_caa180ac, HASH_GetFileInformationByHandle);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetFileType_404ee75e, HASH_GetFileType);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetFinalPathNameByHandleW_55914794, HASH_GetFinalPathNameByHandleW);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetFullPathNameW_4e513857, HASH_GetFullPathNameW);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetHandleInformation_8a27f47a, HASH_GetHandleInformation);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetLastError_5db0468e, HASH_GetLastError);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetModuleFileNameW_179efedc, HASH_GetModuleFileNameW);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetModuleHandleW_a3a4fb8b, HASH_GetModuleHandleW);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetProcessId_10749a2f, HASH_GetProcessId);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetStdHandle_f69eca2f, HASH_GetStdHandle);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetSystemFirmwareTable_bd98e326, HASH_GetSystemFirmwareTable);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetSystemTimeAsFileTime_5df41580, HASH_GetSystemTimeAsFileTime);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetTickCount64_c0c742c5, HASH_GetTickCount64);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GlobalLock_df550056, HASH_GlobalLock);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GlobalSize_d34cf8ca, HASH_GlobalSize);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GlobalUnlock_32ae00ab, HASH_GlobalUnlock);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_InitializeProcThreadAttributeList_bb125778, HASH_InitializeProcThreadAttributeList);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_MultiByteToWideChar_24dff365, HASH_MultiByteToWideChar);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_PeekNamedPipe_35864c70, HASH_PeekNamedPipe);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_QueryFullProcessImageNameW_8d096b68, HASH_QueryFullProcessImageNameW);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_ReadFile_327ede75, HASH_ReadFile);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_SetEvent_3bf8ed73, HASH_SetEvent);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_SetFileInformationByHandle_7103ba3b, HASH_SetFileInformationByHandle);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_SetHandleInformation_b0f9b9d9, HASH_SetHandleInformation);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_Sleep_e50c7a65, HASH_Sleep);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_TerminateProcess_648a61c4, HASH_TerminateProcess);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_UpdateProcThreadAttribute_309c0c77, HASH_UpdateProcThreadAttribute);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_VirtualQuery_6ccf5e42, HASH_VirtualQuery);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_WaitForMultipleObjects_b2925e7f, HASH_WaitForMultipleObjects);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_WaitForSingleObject_43d3cf34, HASH_WaitForSingleObject);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_WriteFile_c70d362f, HASH_WriteFile);
    CheckExport(CozyText_ApiResolverProbe_ncrypt_dll_6778f61d, CozyText_ApiResolverProbe_NCryptCreatePersistedKey_5b626e7c, HASH_NCryptCreatePersistedKey);
    CheckExport(CozyText_ApiResolverProbe_ncrypt_dll_6778f61d, CozyText_ApiResolverProbe_NCryptExportKey_56c24f72, HASH_NCryptExportKey);
    CheckExport(CozyText_ApiResolverProbe_ncrypt_dll_6778f61d, CozyText_ApiResolverProbe_NCryptFinalizeKey_db1aa492, HASH_NCryptFinalizeKey);
    CheckExport(CozyText_ApiResolverProbe_ncrypt_dll_6778f61d, CozyText_ApiResolverProbe_NCryptFreeObject_a607d349, HASH_NCryptFreeObject);
    CheckExport(CozyText_ApiResolverProbe_ncrypt_dll_6778f61d, CozyText_ApiResolverProbe_NCryptImportKey_1245c23e, HASH_NCryptImportKey);
    CheckExport(CozyText_ApiResolverProbe_ncrypt_dll_6778f61d, CozyText_ApiResolverProbe_NCryptOpenStorageProvider_005407e5, HASH_NCryptOpenStorageProvider);
    CheckExport(CozyText_ApiResolverProbe_ncrypt_dll_6778f61d, CozyText_ApiResolverProbe_NCryptSetProperty_bfb000c9, HASH_NCryptSetProperty);
    CheckExport(CozyText_ApiResolverProbe_ncrypt_dll_6778f61d, CozyText_ApiResolverProbe_NCryptSignHash_fa72aa94, HASH_NCryptSignHash);
    CheckExport(CozyText_ApiResolverProbe_psapi_dll_acb2b276, CozyText_ApiResolverProbe_EnumProcessModulesEx_a4630cbf, HASH_EnumProcessModulesEx);
    CheckExport(CozyText_ApiResolverProbe_psapi_dll_acb2b276, CozyText_ApiResolverProbe_GetModuleFileNameExW_3c8af2b1, HASH_GetModuleFileNameExW);
    CheckExport(CozyText_ApiResolverProbe_secur32_dll_7aa89676, CozyText_ApiResolverProbe_AcquireCredentialsHandleW_008878c9, HASH_AcquireCredentialsHandleW);
    CheckExport(CozyText_ApiResolverProbe_secur32_dll_7aa89676, CozyText_ApiResolverProbe_DecryptMessage_924d9719, HASH_DecryptMessage);
    CheckExport(CozyText_ApiResolverProbe_secur32_dll_7aa89676, CozyText_ApiResolverProbe_DeleteSecurityContext_ab8d2094, HASH_DeleteSecurityContext);
    CheckExport(CozyText_ApiResolverProbe_secur32_dll_7aa89676, CozyText_ApiResolverProbe_EncryptMessage_96b2d9d7, HASH_EncryptMessage);
    CheckExport(CozyText_ApiResolverProbe_secur32_dll_7aa89676, CozyText_ApiResolverProbe_FreeContextBuffer_6de5e0d8, HASH_FreeContextBuffer);
    CheckExport(CozyText_ApiResolverProbe_secur32_dll_7aa89676, CozyText_ApiResolverProbe_FreeCredentialsHandle_987de409, HASH_FreeCredentialsHandle);
    CheckExport(CozyText_ApiResolverProbe_secur32_dll_7aa89676, CozyText_ApiResolverProbe_InitializeSecurityContextW_3786f0d4, HASH_InitializeSecurityContextW);
    CheckExport(CozyText_ApiResolverProbe_secur32_dll_7aa89676, CozyText_ApiResolverProbe_QueryContextAttributesW_212320da, HASH_QueryContextAttributesW);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_CloseClipboard_26e77aa6, HASH_CloseClipboard);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_GetClipboardData_4dd98675, HASH_GetClipboardData);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_IsClipboardFormatAvailable_7aa5447c, HASH_IsClipboardFormatAvailable);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_OpenClipboard_11530e31, HASH_OpenClipboard);
    CheckExport(CozyText_ApiResolverProbe_ws2_32_dll_7d82e8f5, CozyText_ApiResolverProbe_WSACleanup_39ed8e55, HASH_WSACleanup);
    CheckExport(CozyText_ApiResolverProbe_ws2_32_dll_7d82e8f5, CozyText_ApiResolverProbe_WSAGetLastError_e312568f, HASH_WSAGetLastError);
    CheckExport(CozyText_ApiResolverProbe_ws2_32_dll_7d82e8f5, CozyText_ApiResolverProbe_WSAStartup_32938ed9, HASH_WSAStartup);
    CheckExport(CozyText_ApiResolverProbe_ws2_32_dll_7d82e8f5, CozyText_ApiResolverProbe_closesocket_50ce5fe2, HASH_closesocket);
    CheckExport(CozyText_ApiResolverProbe_ws2_32_dll_7d82e8f5, CozyText_ApiResolverProbe_connect_55290721, HASH_connect);
    CheckExport(CozyText_ApiResolverProbe_ws2_32_dll_7d82e8f5, CozyText_ApiResolverProbe_gethostbyname_ae916a72, HASH_gethostbyname);
    CheckExport(CozyText_ApiResolverProbe_ws2_32_dll_7d82e8f5, CozyText_ApiResolverProbe_getsockopt_174b7cab, HASH_getsockopt);
    CheckExport(CozyText_ApiResolverProbe_ws2_32_dll_7d82e8f5, CozyText_ApiResolverProbe_htons_272e8bcc, HASH_htons);
    CheckExport(CozyText_ApiResolverProbe_ws2_32_dll_7d82e8f5, CozyText_ApiResolverProbe_ioctlsocket_a1e13fc2, HASH_ioctlsocket);
    CheckExport(CozyText_ApiResolverProbe_ws2_32_dll_7d82e8f5, CozyText_ApiResolverProbe_recv_dabae229, HASH_recv);
    CheckExport(CozyText_ApiResolverProbe_ws2_32_dll_7d82e8f5, CozyText_ApiResolverProbe_select_d1c2e67d, HASH_select);
    CheckExport(CozyText_ApiResolverProbe_ws2_32_dll_7d82e8f5, CozyText_ApiResolverProbe_send_ed2b74ef, HASH_send);
    CheckExport(CozyText_ApiResolverProbe_ws2_32_dll_7d82e8f5, CozyText_ApiResolverProbe_setsockopt_09cffd5b, HASH_setsockopt);
    CheckExport(CozyText_ApiResolverProbe_ws2_32_dll_7d82e8f5, CozyText_ApiResolverProbe_shutdown_608a955f, HASH_shutdown);
    CheckExport(CozyText_ApiResolverProbe_ws2_32_dll_7d82e8f5, CozyText_ApiResolverProbe_socket_6d16326b, HASH_socket);
    { DYNAMIC LOADER PROBE BEGIN }
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetProcAddress_c68d4544, HASH_GetProcAddress);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetModuleHandleExW_84756011, HASH_GetModuleHandleExW);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetSystemDirectoryW_adf5631f, HASH_GetSystemDirectoryW);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_LoadLibraryExW_c90d9c26, HASH_LoadLibraryExW);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_FreeLibrary_b03b43d0, HASH_FreeLibrary);
    { DYNAMIC LOADER PROBE END }
    { POINTER CODEC PROBE BEGIN }
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_EncodePointer_8fadec2c, HASH_EncodePointer);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_DecodePointer_285f262c, HASH_DecodePointer);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_SetLastError_06b9963d, HASH_SetLastError);
    { POINTER CODEC PROBE END }
    CheckExport(CozyText_ApiResolverProbe_ole32_dll_ce729cab, CozyText_ApiResolverProbe_CoCreateGuid_7b6f8a0a, HASH_CoCreateGuid);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_VirtualAlloc_c5405b6b, HASH_VirtualAlloc);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_VirtualProtect_b7a47155, HASH_VirtualProtect);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_VirtualFree_c0dc580a, HASH_VirtualFree);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetProcessMitigationPolicy_7e01196e, HASH_GetProcessMitigationPolicy);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_SetProcessMitigationPolicy_25f1fd5c, HASH_SetProcessMitigationPolicy);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_RegisterClassExW_e4ab9c77, HASH_RegisterClassExW);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_UnregisterClassW_f60bd4a8, HASH_UnregisterClassW);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_CreateWindowExW_88147b5b, HASH_CreateWindowExW);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_DefWindowProcW_bcb92986, HASH_DefWindowProcW);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_DestroyWindow_fb8285b3, HASH_DestroyWindow);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_ShowWindow_d3f93e4b, HASH_ShowWindow);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_PeekMessageW_89496c0b, HASH_PeekMessageW);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_MsgWaitForMultipleObjectsEx_ca2ef08e, HASH_MsgWaitForMultipleObjectsEx);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_TranslateMessage_b942796a, HASH_TranslateMessage);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_DispatchMessageW_437b758b, HASH_DispatchMessageW);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_GetClientRect_5c6a9aff, HASH_GetClientRect);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_BeginPaint_4748a65d, HASH_BeginPaint);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_EndPaint_20af3df4, HASH_EndPaint);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_LoadCursorW_7c2d5385, HASH_LoadCursorW);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_SetCursor_4a127743, HASH_SetCursor);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_SetCapture_5dbb17ab, HASH_SetCapture);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_GetCapture_7996ede3, HASH_GetCapture);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_ReleaseCapture_8178965b, HASH_ReleaseCapture);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_GetCursorPos_ab728e9a, HASH_GetCursorPos);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_GetWindowRect_a8164467, HASH_GetWindowRect);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_SetWindowPos_900fc334, HASH_SetWindowPos);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_GetDpiForWindow_2acc536d, HASH_GetDpiForWindow);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_MonitorFromWindow_82d84b2f, HASH_MonitorFromWindow);
    CheckExport(CozyText_ApiResolverProbe_user32_dll_b313d1a8, CozyText_ApiResolverProbe_GetMonitorInfoW_514daacd, HASH_GetMonitorInfoW);
    CheckExport(CozyText_ApiResolverProbe_kernel32_dll_4e3bc2f6, CozyText_ApiResolverProbe_GetCurrentThreadId_4e6f4770, HASH_GetCurrentThreadId);
    Check(CheckedExports = 140, CozyText_ApiResolverProbe_Export_test_count_2c1e88f8);
    SealApiPointerStorage;
    Check(ApiPointerStorageIsSealed, CozyText_ApiResolverProbe_API_arena_is_sealed_after_all_bindings_a9ab4559);
    Writeln(CozyText_ApiResolverProbe_PASS_f556dfe7, CheckedExports, CozyText_ApiResolverProbe_exports_match_the_Windows_loader_eb224bcb);
    Writeln(CozyText_ApiResolverProbe_PASS_ROR13_constants_collision_rejection_malform_1ba32c8f);
    Writeln(CozyText_ApiResolverProbe_No_application_workflow_or_server_connection_was_0de573db);
    ExitCode := 0;
  except
    on E: Exception do
    begin
      Writeln(CozyText_ApiResolverProbe_FAIL_19e153f7, E.ClassName, CozyText_ApiResolverProbe_Text_fab10c54, E.Message);
      ExitCode := 1;
    end;
  end;
end.
