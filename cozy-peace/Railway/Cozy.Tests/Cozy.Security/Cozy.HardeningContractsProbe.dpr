program Cozy_HardeningContractsProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Identity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Identity.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Overlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Overlay.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
  Cozy.Strings.TestsSecurity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsSecurity.pas',
 Winapi.Windows, System.SysUtils, System.Classes, System.IOUtils, System.JSON,
  Cozy.Measurement, Cozy.Integrity, Cozy.ProtocolJson, Cozy.Overlay.State,
  Cozy.ModuleInventory, Cozy.CodeIntegrity;
procedure Require(Value: Boolean; const Name: string);
begin if not Value then raise Exception.Create(CozyText_HardeningContractsProbe_HARDENING_PROBE_85d59f65 + Name); end;
procedure Status(Expected: TMeasurementStatus; const Work: TProc; const Name: string);
var Rejected: Boolean;
begin
  Rejected := False;
  try Work(); except on E: EMeasurement do begin Require(E.Status = Expected, Name + CozyText_HardeningContractsProbe_wrong_status_2f9630ee); Rejected := True; end; end;
  Require(Rejected, Name + CozyText_HardeningContractsProbe_accepted_5ca538b3); WriteLn(CozyText_HardeningContractsProbe_PASS_3ad6f8f9, Name);
end;
procedure JsonAndState;
const Invalid: array[0..11] of string = (CozyText_HardeningContractsProbe_JsonFixture_c7282ffd, CozyText_HardeningContractsProbe_JsonFixture_b68ecaab,
  CozyText_HardeningContractsProbe_JsonFixture_be3e708c, CozyText_HardeningContractsProbe_JsonFixture_afd1e590, CozyText_HardeningContractsProbe_JsonFixture_299ab5bc, CozyText_HardeningContractsProbe_JsonFixture_78b45de0,
  CozyText_HardeningContractsProbe_JsonFixture_736bbd61, CozyText_HardeningContractsProbe_JsonFixture_cdc0251a, CozyText_HardeningContractsProbe_JsonFixture_12aee432, CozyText_HardeningContractsProbe_JsonFixture_8de94da7,
  CozyText_HardeningContractsProbe_JsonFixture_0423f79a, CozyText_HardeningContractsProbe_JsonFixture_eb26c36a);
var I, J: Integer; Obj: TJSONObject; Rejected, Expected: Boolean; Current: TOverlayState;
  Bytes: UTF8String; Text: string;
begin
  for I := Low(Invalid) to High(Invalid) do begin
    Obj := nil; Rejected := False;
    try Obj := ParseProtocolObject(Invalid[I], 4096); except on E: EConvertError do Rejected := True; end;
    Obj.Free; Require(Rejected, CozyText_HardeningContractsProbe_strict_JSON_26af187a + IntToStr(I));
  end;
  Obj := ParseProtocolObject(CozyText_HardeningContractsProbe_JsonFixture_ad28054e, 4096);
  Obj.Free;
  SetLength(Bytes, 2); Bytes[1] := AnsiChar($C0); Bytes[2] := AnsiChar($AF);
  Rejected := False; try Text := DecodeProtocolUTF8(Bytes); except on E: EConvertError do Rejected := True; end;
  Require(Rejected, CozyText_HardeningContractsProbe_overlong_UTF8_3bc47666);
  for I := Ord(Low(TOverlayState)) to Ord(High(TOverlayState)) do
    for J := Ord(Low(TOverlayState)) to Ord(High(TOverlayState)) do begin
      Expected := ((I = 0) and ((J = 1) or (J = 4))) or
        ((I = 1) and ((J = 2) or (J = 4))) or ((I = 2) and ((J = 3) or (J = 4))) or
        ((I = 3) and (J = 4)) or ((I = 4) and (J = 5));
      Require(OverlayCanTransition(TOverlayState(I), TOverlayState(J)) = Expected, CozyText_HardeningContractsProbe_state_matrix_664dd8f1);
      Current := TOverlayState(I); Rejected := False;
      try OverlayTransition(Current, TOverlayState(J));
      except on E: EInvalidOpException do begin
        Require(E.Message = CozyText_HardeningContractsProbe_OVERLAY_STATE_TRANSITION_INVALID_cc05d4a3, CozyText_HardeningContractsProbe_transition_error_code_bfbb0f60);
        Rejected := True;
      end; end;
      Require(Rejected <> Expected, CozyText_HardeningContractsProbe_transition_result_9d010fb8);
      if Rejected then Require(Current = TOverlayState(I), CozyText_HardeningContractsProbe_rejected_transition_mutated_state_b1679653);
    end;
  Require(OverlayNextRenewal(1000, 121000, 100) = 31000, CozyText_HardeningContractsProbe_long_lease_c9c88f66);
  Require(OverlayNextRenewal(1000, 5000, 500) = 3000, CozyText_HardeningContractsProbe_short_lease_a6f50e0f);
  Require(OverlayNextRenewal(1000, 2000, 500) = 1000, CozyText_HardeningContractsProbe_immediate_renewal_4d0596d4);
  Rejected := False; try OverlayNextRenewal(2000, 2000, 0);
  except on E: EInvalidOpException do begin
    Require(E.Message = CozyText_HardeningContractsProbe_OVERLAY_LEASE_EXPIRED_04786cd2, CozyText_HardeningContractsProbe_lease_error_code_6ff59961);
    Rejected := True;
  end; end;
  Require(Rejected, CozyText_HardeningContractsProbe_expired_lease_dfc46a97);
  Require(OverlayGraphicsFailure(Integer($8007000E), CozyText_HardeningContractsProbe_CREATE_d99e0519) = CozyText_HardeningContractsProbe_OVERLAY_GRAPHICS_OUT_OF_MEMORY_46ff7b8b, CozyText_HardeningContractsProbe_OOM_76bcf97c);
  Require(OverlayGraphicsFailure(Integer($887A0005), CozyText_HardeningContractsProbe_PRESENT_8f9f35ad) = CozyText_HardeningContractsProbe_OVERLAY_GRAPHICS_DEVICE_LOST_5c9cd7b1, CozyText_HardeningContractsProbe_device_lost_6102366b);
  Require(OverlayGraphicsFailure(-1, CozyText_HardeningContractsProbe_RESIZE_0fdaf193) = CozyText_HardeningContractsProbe_OVERLAY_GRAPHICS_RESIZE_FAILED_af42921c, CozyText_HardeningContractsProbe_resize_11afbc57);
  WriteLn(CozyText_HardeningContractsProbe_PASS_strict_JSON_UTF8_all_36_lifecycle_edges_lea_b64d21b0);
end;
procedure ReparseContract(const LinkPath, Target: string; const Digest: TImageDigest);
type TCreateLink = function(LinkName, TargetName: PWideChar; Flags: DWORD): Byte; stdcall;
var CreateLink: TCreateLink; H: THandle; Image: TImageIntegrity; Rejected: Boolean; Error: DWORD;
begin
  CreateLink := TCreateLink(GetProcAddress(GetModuleHandle(CozyText_HardeningContractsProbe_kernel32_dll_d00139ee), CozyText_HardeningContractsProbe_CreateSymbolicLinkW_6204ea6c));
  if not Assigned(CreateLink) then begin WriteLn(CozyText_HardeningContractsProbe_SKIP_reparse_probe_API_unavailable_17d58ae8); Exit; end;
  if CreateLink(PWideChar(LinkPath), PWideChar(Target), 2) = 0 then
    if CreateLink(PWideChar(LinkPath), PWideChar(Target), 0) = 0 then begin
      Error := GetLastError;
      if Error = ERROR_PRIVILEGE_NOT_HELD then begin
        WriteLn(CozyText_HardeningContractsProbe_SKIP_reparse_probe_enable_Developer_Mode_or_syml_6f432b79); Exit;
      end;
      raise Exception.Create(CozyText_HardeningContractsProbe_Reparse_fixture_creation_failed_ff56a661 + UIntToStr(Error));
    end;
  H := INVALID_HANDLE_VALUE; Image := nil;
  try
    H := CreateFile(PChar(LinkPath), GENERIC_READ, FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE,
      nil, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, 0);
    Require(H <> INVALID_HANDLE_VALUE, CozyText_HardeningContractsProbe_open_reparse_node_not_target_d03e64fa);
    Rejected := False;
    try Image := TImageIntegrity.Create(H, Digest.SHA512, Digest.CRC64);
    except on E: EImageIntegrity do Rejected := True; end;
    Require(Rejected, CozyText_HardeningContractsProbe_reparse_node_entered_a_pinned_image_measurement_539212fd);
    WriteLn(CozyText_HardeningContractsProbe_PASS_reparse_point_rejection_at_retained_image_b_afb06632);
  finally Image.Free; if H <> INVALID_HANDLE_VALUE then CloseHandle(H); DeleteFile(PChar(LinkPath)); end;
end;

procedure FileContracts;
var Root, Active, Moved, FileName: string; Guid: TGUID; Data, Other: TBytes;
  Handle, AliasHandle, ReaderHandle: THandle; Position, EndPosition: Int64;
  Digest, Again: TImageDigest; Budget: TMeasurementBudget; Pinned: TImageIntegrity;
  Reader: TThread; ReaderFailed: Boolean; I: Integer; Count: DWORD; One: Byte;
begin
  CreateGUID(Guid); Root := TPath.Combine(TPath.GetTempPath, CozyText_HardeningContractsProbe_GameMeasurement_ac1aabf4 + GUIDToString(Guid));
  Active := TPath.Combine(Root, CozyText_HardeningContractsProbe_active_15f2df72); Moved := TPath.Combine(Root, CozyText_HardeningContractsProbe_moved_fae4eed5);
  ForceDirectories(Active); FileName := TPath.Combine(Active, CozyText_HardeningContractsProbe_sample_bin_c3672683);
  SetLength(Data, 131073); for I := 0 to High(Data) do Data[I] := Byte(I mod 251);
  Other := TBytes.Create(7, 8, 9); TFile.WriteAllBytes(FileName, Data);
  Handle := INVALID_HANDLE_VALUE; AliasHandle := 0; ReaderHandle := 0; Pinned := nil; Reader := nil;
  try
    Handle := CreateFile(PChar(FileName), GENERIC_READ or GENERIC_WRITE,
      FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    Require(Handle <> INVALID_HANDLE_VALUE, CozyText_HardeningContractsProbe_open_file_36c8887d);
    Require(DuplicateHandle(GetCurrentProcess, Handle, GetCurrentProcess, @AliasHandle, 0, False, DUPLICATE_SAME_ACCESS), CozyText_HardeningContractsProbe_duplicate_332b360d);
    Position := 37; Require(SetFilePointerEx(Handle, Position, nil, FILE_BEGIN), CozyText_HardeningContractsProbe_set_position_78c5cf07);
    Digest := IntegrityHashHandle(Handle);
    Position := 0; Require(SetFilePointerEx(AliasHandle, Position, @EndPosition, FILE_CURRENT) and (EndPosition = 37), CozyText_HardeningContractsProbe_hash_altered_shared_position_737b054b);
    Require(SetFilePointerEx(Handle, Position, nil, FILE_BEGIN), CozyText_HardeningContractsProbe_reset_position_c55aa70a);
    ReaderFailed := False;
    Reader := TThread.CreateAnonymousThread(procedure
      var J: Integer; B: Byte; ReadCount: DWORD;
      begin
        for J := 1 to 256 do begin
          if not ReadFile(AliasHandle, B, 1, ReadCount, nil) or (ReadCount <> 1) or (B <> Byte((J - 1) mod 251)) then ReaderFailed := True;
          Sleep(1);
        end;
      end);
    Reader.FreeOnTerminate := False; Reader.Start;
    Again := IntegrityHashHandle(Handle); Reader.WaitFor; FreeAndNil(Reader);
    Require(not ReaderFailed and (Again.SHA512 = Digest.SHA512), CozyText_HardeningContractsProbe_concurrent_duplicate_read_e5edc82e);
    Require(SetFilePointerEx(Handle, Position, @EndPosition, FILE_CURRENT) and (EndPosition = 256), CozyText_HardeningContractsProbe_concurrent_position_568811bd);
    WriteLn(CozyText_HardeningContractsProbe_PASS_original_duplicate_shared_position_and_simu_15766a9a);
    Budget := TMeasurementBudget.Start(1, 30000);
    Status(msCoverageInsufficient, procedure begin Again := IntegrityHashHandle(Handle, Budget); end, CozyText_HardeningContractsProbe_byte_budget_32bab082);
    Budget := TMeasurementBudget.Start(1024 * 1024, 30000, function: Boolean begin Result := True; end);
    Status(msCancelled, procedure begin Again := IntegrityHashHandle(Handle, Budget); end, CozyText_HardeningContractsProbe_cancel_budget_c53d8658);
    Budget := TMeasurementBudget.Start(1024 * 1024, 1); Sleep(2);
    Status(msDeadlineExceeded, procedure begin Again := IntegrityHashHandle(Handle, Budget); end, CozyText_HardeningContractsProbe_deadline_budget_34c2b245);
    Pinned := TImageIntegrity.Create(Handle, Digest.SHA512, Digest.CRC64);
    Require(MoveFile(PChar(FileName), PChar(FileName + CozyText_HardeningContractsProbe_renamed_189b5718)), CozyText_HardeningContractsProbe_rename_pinned_file_2dc960f5);
    TFile.WriteAllBytes(FileName, Other);
    Again := Pinned.VerifyNow; Require(Again.SHA512 = Digest.SHA512, CozyText_HardeningContractsProbe_pathname_replacement_followed_3a66ce79);
    Require(MoveFile(PChar(Active), PChar(Moved)), CozyText_HardeningContractsProbe_rename_parent_32a04a4a); ForceDirectories(Active);
    TFile.WriteAllBytes(FileName, Other);
    Again := Pinned.VerifyNow; Require(Again.SHA512 = Digest.SHA512, CozyText_HardeningContractsProbe_parent_replacement_followed_a2f816cf);
    WriteLn(CozyText_HardeningContractsProbe_PASS_pinned_file_rename_replacement_and_parent_p_17b7c60c);
    ReparseContract(TPath.Combine(Active, CozyText_HardeningContractsProbe_linked_bin_426c5d9d), TPath.Combine(Moved, CozyText_HardeningContractsProbe_sample_bin_renamed_ab8e2e89), Digest);
    Position := 0; Require(SetFilePointerEx(Handle, Position, nil, FILE_BEGIN), CozyText_HardeningContractsProbe_set_mutation_position_15db5c3a);
    One := Data[0] xor $FF; Require(WriteFile(Handle, One, 1, Count, nil) and (Count = 1), CozyText_HardeningContractsProbe_write_mutation_76e425c1);
    Require(FlushFileBuffers(Handle), CozyText_HardeningContractsProbe_flush_mutation_d0b54c41);
    Status(msChanged, procedure begin Again := Pinned.VerifyNow; end, CozyText_HardeningContractsProbe_changed_file_distinct_status_806a0946);
    ReaderHandle := OpenMeasurementHandle(Handle);
    Budget := TMeasurementBudget.Start(1024, 30000, function: Boolean
      begin CloseMeasurementHandle(ReaderHandle); Result := False; end);
    Status(msReadError, procedure begin Count := ReadMeasurementAt(ReaderHandle, 0, @One, 1, Budget); end, CozyText_HardeningContractsProbe_read_handle_failure_distinct_status_1a60d74b);
    WriteLn(CozyText_HardeningContractsProbe_NOT_RUN_kernel_slow_I_O_fault_injection_see_comp_1d643cac);
  finally
    if Reader <> nil then begin Reader.WaitFor; Reader.Free; end;
    Pinned.Free; CloseMeasurementHandle(ReaderHandle); CloseMeasurementHandle(AliasHandle); CloseMeasurementHandle(Handle);
    if TDirectory.Exists(Root) then TDirectory.Delete(Root, True);
  end;
end;
procedure RetainedOwnInventory;
var Root, CopyPath, Name: string; Guid: TGUID; H: THandle; Image: TImageIntegrity;
  Plan: TCodeIntegrity; Digest: TImageDigest; Snapshot, Row: TJSONObject;
  Rows: TJSONArray; Position: Int64; Changed: Byte; Written: DWORD;
  function OwnRow: TJSONObject;
  var Index: Integer; Candidate: TJSONObject;
  begin
    Result := nil; Rows := Snapshot.GetValue<TJSONArray>(CozyText_HardeningContractsProbe_modules_3b152eee);
    for Index := 0 to Rows.Count - 1 do
    begin
      Candidate := TJSONObject(Rows.Items[Index]);
      if SameText(Candidate.GetValue<string>(CozyText_HardeningContractsProbe_name_6c5d132e), Name) then
      begin
        Require(Result = nil, CozyText_HardeningContractsProbe_duplicate_own_inventory_row_eff32df4);
        Result := Candidate;
      end;
    end;
    Require(Result <> nil, CozyText_HardeningContractsProbe_own_inventory_row_missing_68780b23);
  end;
begin
  { The retained copy has the same PE bytes as this running probe. Replacing
    its name or mutating its bytes lets this test distinguish fresh held-file
    measurements from accidental reopening of the still-readable probe EXE. }
  CreateGUID(Guid); Root := TPath.Combine(TPath.GetTempPath, CozyText_HardeningContractsProbe_GameOwnInventory_4b8ff380 + GUIDToString(Guid));
  ForceDirectories(Root); CopyPath := TPath.Combine(Root, CozyText_HardeningContractsProbe_retained_exe_85514913);
  TFile.Copy(ParamStr(0), CopyPath); Name := ExtractFileName(ParamStr(0));
  H := INVALID_HANDLE_VALUE; Image := nil; Plan := nil; Snapshot := nil;
  try
    H := CreateFile(PChar(CopyPath), GENERIC_READ or GENERIC_WRITE,
      FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    Require(H <> INVALID_HANDLE_VALUE, CozyText_HardeningContractsProbe_open_retained_own_fixture_372dd770);
    Digest := IntegrityHashHandle(H); Image := TImageIntegrity.Create(H, Digest.SHA512, Digest.CRC64);
    Plan := TCodeIntegrity.Create(H);
    Require(MoveFile(PChar(CopyPath), PChar(CopyPath + CozyText_HardeningContractsProbe_renamed_189b5718)), CozyText_HardeningContractsProbe_rename_retained_own_fixture_ae84e0e0);
    TFile.WriteAllBytes(CopyPath, TBytes.Create(1, 2, 3));
    Snapshot := CollectModuleInventoryJSON(nil, Image, Plan); Row := OwnRow;
    Require(Row.GetValue<string>(CozyText_HardeningContractsProbe_status_b0d4d2bf) = CozyText_HardeningContractsProbe_UNVERIFIED_BASELINE_bf5c9a55, CozyText_HardeningContractsProbe_retained_own_file_status_399edbea);
    Require(Row.GetValue<string>(CozyText_HardeningContractsProbe_codeStatus_5ae65f34) = CozyText_HardeningContractsProbe_MATCH_LOCAL_FILE_c0e24f41, CozyText_HardeningContractsProbe_retained_own_code_status_d9605696);
    Require(Row.GetValue<string>(CozyText_HardeningContractsProbe_fileSha512_97bce501) = Digest.SHA512, CozyText_HardeningContractsProbe_retained_own_digest_79e83369);
    FreeAndNil(Snapshot);
    Position := 0; Require(SetFilePointerEx(H, Position, nil, FILE_BEGIN), CozyText_HardeningContractsProbe_seek_retained_mutation_de7069c6);
    Changed := 0; Require(WriteFile(H, Changed, 1, Written, nil) and (Written = 1), CozyText_HardeningContractsProbe_mutate_retained_file_d6337f50);
    Require(FlushFileBuffers(H), CozyText_HardeningContractsProbe_flush_retained_mutation_e80dd4f6);
    Snapshot := CollectModuleInventoryJSON(nil, Image, Plan); Row := OwnRow;
    Require(Row.GetValue<string>(CozyText_HardeningContractsProbe_status_b0d4d2bf) = CozyText_HardeningContractsProbe_FILE_CHANGED_7c4806be, CozyText_HardeningContractsProbe_retained_mutation_was_hidden_by_path_reopen_38692d3e);
    Require(Row.GetValue<string>(CozyText_HardeningContractsProbe_fileSha512_97bce501) = '', CozyText_HardeningContractsProbe_failed_retained_row_reused_old_digest_6562176d);
    Require(Snapshot.GetValue<string>(CozyText_HardeningContractsProbe_coverage_5239c623) = CozyText_HardeningContractsProbe_PARTIAL_064ea338, CozyText_HardeningContractsProbe_failed_retained_row_claimed_full_coverage_7cff23a1);
    WriteLn(CozyText_HardeningContractsProbe_PASS_retained_own_image_inventory_rename_replace_5d5086b5);
  finally
    Snapshot.Free; Plan.Free; Image.Free; CloseMeasurementHandle(H);
    if TDirectory.Exists(Root) then TDirectory.Delete(Root, True);
  end;
end;

begin
  try JsonAndState; FileContracts; RetainedOwnInventory;
  except on E: Exception do begin WriteLn(E.ClassName, CozyText_HardeningContractsProbe_Text_b8c6e1e4, E.Message); Halt(1); end; end;
end.
