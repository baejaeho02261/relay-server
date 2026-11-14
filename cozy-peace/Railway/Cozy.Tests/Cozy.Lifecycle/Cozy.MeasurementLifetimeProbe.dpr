program Cozy_MeasurementLifetimeProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Identity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Identity.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsLifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsLifecycle.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
 Winapi.Windows, System.SysUtils, System.Classes, System.IOUtils,
  System.SyncObjs, System.JSON, Cozy.Measurement, Cozy.Integrity, Cozy.CodeIntegrity, Cozy.ModuleInventory;
procedure Require(Value: Boolean; const Name: string);
begin if not Value then raise Exception.Create(Name); end;
procedure RunRace(IsCode: Boolean);
var FileName: string; H: THandle; Image: TImageIntegrity; Code: TCodeIntegrity;
  Digest: TImageDigest; Budget: TMeasurementBudget; Worker, Closer: TThread;
  Entered, Resume, Closed: TEvent; Calls, Cancelled: Integer;
begin
  Image := nil; Code := nil; Worker := nil; Closer := nil;
  Entered := TEvent.Create(nil, True, False, '');
  Resume := TEvent.Create(nil, True, False, ''); Closed := TEvent.Create(nil, True, False, '');
  FileName := ParamStr(0); H := CreateFile(PChar(FileName), GENERIC_READ,
    FILE_SHARE_READ or FILE_SHARE_DELETE, nil, OPEN_EXISTING, 0, 0);
  Require(H <> INVALID_HANDLE_VALUE, CozyText_MeasurementLifetimeProbe_OPEN_SELF_eddb837d); Calls := 0; Cancelled := 0;
  try
    if IsCode then Code := TCodeIntegrity.Create(H)
    else begin Digest := IntegrityHashHandle(H); Image := TImageIntegrity.Create(H, Digest.SHA512, Digest.CRC64); end;
    Budget := TMeasurementBudget.Start(128 * 1024 * 1024, 10000,
      function: Boolean
      begin
        if TInterlocked.Increment(Calls) = 1 then
        begin Entered.SetEvent; Require(Resume.WaitFor(5000) = wrSignaled, CozyText_MeasurementLifetimeProbe_RESUME_TIMEOUT_0fcc24aa); end;
        Result := False;
      end);
    Worker := TThread.CreateAnonymousThread(procedure
      var LocalCode: TCodeIntegrityMeasurement; LocalFile: TImageDigest;
      begin
        try
          if IsCode then begin LocalCode := Code.MeasureNow(Budget); Require(LocalCode.Size > 0, CozyText_MeasurementLifetimeProbe_CODE_SIZE_19bf9afa); end
          else begin LocalFile := Image.VerifyNow(Budget); Require(LocalFile.Size > 0, CozyText_MeasurementLifetimeProbe_FILE_SIZE_db76ab99); end;
        except on E: EMeasurement do
          if E.Status = msCancelled then TInterlocked.Exchange(Cancelled, 1);
        end;
      end);
    Worker.FreeOnTerminate := False; Worker.Start;
    Require(Entered.WaitFor(5000) = wrSignaled, CozyText_MeasurementLifetimeProbe_ADMISSION_TIMEOUT_5419e9cc);
    Closer := TThread.CreateAnonymousThread(procedure
      begin if IsCode then Code.Free else Image.Free; Closed.SetEvent; end);
    Closer.FreeOnTerminate := False; Closer.Start;
    Require(Closed.WaitFor(30) = wrTimeout, CozyText_MeasurementLifetimeProbe_DESTROY_RELEASED_ACTIVE_OWNER_482a9df2);
    Resume.SetEvent;
    Require(Closed.WaitFor(5000) = wrSignaled, CozyText_MeasurementLifetimeProbe_DRAIN_TIMEOUT_2aa67254);
    Worker.WaitFor; Closer.WaitFor; Code := nil; Image := nil;
    Require(Cancelled = 1, CozyText_MeasurementLifetimeProbe_CLOSING_DID_NOT_CANCEL_MEASUREMENT_7da491b6);
  finally
    Resume.SetEvent;
    if Worker <> nil then Worker.WaitFor;
    if Closer <> nil then begin Closer.WaitFor; Code := nil; Image := nil; end;
    Worker.Free; Closer.Free; Image.Free; Code.Free;
    CloseHandle(H); Entered.Free; Resume.Free; Closed.Free;
  end;
end;
procedure MidCodeCancellation;
var H: THandle; Code: TCodeIntegrity; Calls: Integer; Budget: TMeasurementBudget;
  ResultCode: TCodeIntegrityMeasurement; Failed: Boolean;
begin
  H := CreateFile(PChar(ParamStr(0)), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, 0, 0);
  Require(H <> INVALID_HANDLE_VALUE, CozyText_MeasurementLifetimeProbe_OPEN_SELF_eddb837d); Code := nil;
  try
    Code := TCodeIntegrity.Create(H); Calls := 0; Failed := False;
    Budget := TMeasurementBudget.Start(128 * 1024 * 1024, 10000,
      function: Boolean begin Inc(Calls); Result := Calls >= 8; end);
    try ResultCode := Code.MeasureNow(Budget); Require(ResultCode.Size > 0, CozyText_MeasurementLifetimeProbe_CODE_SIZE_19bf9afa);
    except on E: EMeasurement do Failed := E.Status = msCancelled; end;
    Require(Failed and (Calls >= 8), CozyText_MeasurementLifetimeProbe_INTERNAL_CODE_CANCELLATION_1f1a9458);
  finally Code.Free; CloseHandle(H); end;
end;
procedure BoundedFileReads;
var FileName: string; H, ReadHandle, InvalidHandle: THandle;
  Input, Output: TBytes; Buffer: array[0..31] of Byte; I: Integer;
  Budget, Restricted: TMeasurementBudget; Failed: Boolean;
  procedure RejectRead(Offset: UInt64; Count: Cardinal; Status: TMeasurementStatus);
  var Rejected: Boolean; J: Integer;
  begin
    Rejected := False; FillChar(Buffer, SizeOf(Buffer), $A5);
    try ReadMeasurementAt(ReadHandle, Offset, @Buffer[0], Count, Restricted);
    except on E: EMeasurement do Rejected := E.Status = Status; end;
    Require(Rejected, CozyText_MeasurementLifetimeProbe_BOUNDED_READ_STATUS_3f1df03f);
    for J := 0 to High(Buffer) do Require(Buffer[J] = $A5, CozyText_MeasurementLifetimeProbe_FAILED_READ_PUBLISHED_BYTES_6cec40a7);
  end;
begin
  FileName := TPath.GetTempFileName; H := INVALID_HANDLE_VALUE; ReadHandle := 0;
  SetLength(Input, 200000); for I := 0 to High(Input) do Input[I] := Byte(I mod 251);
  try
    TFile.WriteAllBytes(FileName, Input);
    H := CreateFile(PChar(FileName), GENERIC_READ, FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE,
      nil, OPEN_EXISTING, 0, 0); Require(H <> INVALID_HANDLE_VALUE, CozyText_MeasurementLifetimeProbe_OPEN_READ_FIXTURE_0591c05b);
    Require(SetFilePointer(H, 17, nil, FILE_BEGIN) = 17, CozyText_MeasurementLifetimeProbe_SET_CALLER_OFFSET_11e3a5b7);
    Budget := TMeasurementBudget.Start(1000000, 10000); ReadHandle := OpenMeasurementHandle(H);
    Require(ReadMeasurementAt(ReadHandle, 40000, @Buffer[0], SizeOf(Buffer), Budget) = SizeOf(Buffer), CozyText_MeasurementLifetimeProbe_POSITIONAL_READ_HIGH_cf77515e);
    for I := 0 to High(Buffer) do Require(Buffer[I] = Input[40000+I], CozyText_MeasurementLifetimeProbe_POSITIONAL_READ_CONTENT_a563316f);
    Require(ReadMeasurementAt(ReadHandle, 3, @Buffer[0], SizeOf(Buffer), Budget) = SizeOf(Buffer), CozyText_MeasurementLifetimeProbe_POSITIONAL_READ_REVERSE_5dc6bc59);
    for I := 0 to High(Buffer) do Require(Buffer[I] = Input[3+I], CozyText_MeasurementLifetimeProbe_POSITIONAL_REVERSE_CONTENT_4a86c43d);
    Output := ReadMeasurementBytes(H, Budget);
    Require((Length(Output) = Length(Input)) and CompareMem(@Input[0], @Output[0], Length(Input)), CozyText_MeasurementLifetimeProbe_FULL_READ_CONTENT_336bd675);
    Require(SetFilePointer(H, 0, nil, FILE_CURRENT) = 17, CozyText_MeasurementLifetimeProbe_CALLER_FILE_POSITION_CHANGED_af074c42);
    FillChar(Buffer, SizeOf(Buffer), $A5);
    Require(ReadMeasurementAt(ReadHandle, UInt64(Length(Input)), @Buffer[0], SizeOf(Buffer), Budget) = 0, CozyText_MeasurementLifetimeProbe_READ_EOF_608478f7);
    for I := 0 to High(Buffer) do Require(Buffer[I] = $A5, CozyText_MeasurementLifetimeProbe_EOF_PUBLISHED_BYTES_d8450217);
    Restricted := Budget; Restricted.MaxBytes := 4; RejectRead(3, 2, msCoverageInsufficient);
    Restricted := Budget; Restricted.DeadlineTick := MeasurementTick; RejectRead(0, 1, msDeadlineExceeded);
    Restricted := TMeasurementBudget.Start(1000000, 10000, function: Boolean begin Result := True; end);
    RejectRead(0, 1, msCancelled);
    Restricted := Budget; Restricted.MaxBytes := High(UInt64);
    RejectRead(UInt64(High(Int64)), 1, msCoverageInsufficient);
    RejectRead(UInt64(High(Int64)) + 1, 1, msCoverageInsufficient);
    Failed := False;
    try ReadMeasurementAt(ReadHandle, 0, nil, 1, Budget); except on E: EArgumentException do Failed := True; end;
    Require(Failed, CozyText_MeasurementLifetimeProbe_NIL_READ_BUFFER_ACCEPTED_965efc69); Failed := False;
    try ReadMeasurementAt(ReadHandle, 0, @Buffer[0], 65537, Budget); except on E: EArgumentException do Failed := True; end;
    Require(Failed, CozyText_MeasurementLifetimeProbe_OVERSIZED_READ_ACCEPTED_63fd31e8); Failed := False;
    try InvalidHandle := OpenMeasurementHandle(0); CloseMeasurementHandle(InvalidHandle);
    except on E: EMeasurement do Failed := E.Status = msReadError; end;
    Require(Failed, CozyText_MeasurementLifetimeProbe_INVALID_SOURCE_HANDLE_ACCEPTED_964ad399);
    {$IFDEF GAME_MEASUREMENT_TESTS}
    Require(OutstandingMeasurementReadsForTest = 0, CozyText_MeasurementLifetimeProbe_READ_OWNER_REMAINED_dd27c819);
    Failed := False;
    try ExerciseDrainStartFailureForTest(ReadHandle);
    except on E: EMeasurement do Failed := E.Status = msReadError; end;
    Require(Failed, CozyText_MeasurementLifetimeProbe_DRAIN_START_FAILURE_NOT_EXERCISED_bba669a9);
    Require(OutstandingMeasurementReadsForTest = 0, CozyText_MeasurementLifetimeProbe_DRAIN_START_FAILURE_LEAKED_OWNER_f62cb4d6);
    {$ENDIF}
  finally
    CloseMeasurementHandle(ReadHandle); if H <> INVALID_HANDLE_VALUE then CloseHandle(H);
    if Length(Output) > 0 then FillChar(Output[0], Length(Output), 0);
    if Length(Input) > 0 then FillChar(Input[0], Length(Input), 0);
    TFile.Delete(FileName);
  end;
end;

procedure CancelledBundleTransfersNothing;
var H: THandle; Code: TCodeIntegrity; Calls: Integer; Budget: TMeasurementBudget;
  ResultCode: TCodeIntegrityMeasurement; Layers: TJSONObject; Failed, ObservedDigest: Boolean;
begin
  H := CreateFile(PChar(ParamStr(0)), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, 0, 0);
  Require(H <> INVALID_HANDLE_VALUE, CozyText_MeasurementLifetimeProbe_OPEN_BUNDLE_SELF_ded0d650); Code := nil; Layers := nil;
  try
    Code := TCodeIntegrity.Create(H); Calls := 0; Failed := False; ObservedDigest := False;
    ResultCode := Default(TCodeIntegrityMeasurement);
    Budget := TMeasurementBudget.Start(128 * 1024 * 1024, 10000,
      function: Boolean
      begin
        Inc(Calls);
        if ResultCode.SHA512 <> '' then ObservedDigest := True;
        Result := ObservedDigest;
      end);
    try Code.MeasureBundle(ResultCode, Layers, Budget);
    except on E: EMeasurement do Failed := E.Status = msCancelled; end;
    Require(Failed and ObservedDigest and (Calls > 0), CozyText_MeasurementLifetimeProbe_BUNDLE_CANCEL_AFTER_DIGEST_NOT_REPORTED_ea53eec2);
    Require((Layers = nil) and (ResultCode.SHA512 = '') and (ResultCode.Size = 0), CozyText_MeasurementLifetimeProbe_FAILED_BUNDLE_TRANSFERRED_OUTPUT_6e34ffbb);
  finally Layers.Free; Code.Free; CloseHandle(H); end;
end;

{$IFDEF GAME_MEASUREMENT_TESTS}
procedure DrainShutdownJoinsActualThread;
var Source, ReadHandle: THandle; Entered, Resume, Joined: TEvent; Closer: TThread;
  Budget: TMeasurementBudget; Buffer: Byte; Rejected: Boolean;
begin
  Source := CreateFile(PChar(ParamStr(0)), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, 0, 0);
  Require(Source <> INVALID_HANDLE_VALUE, CozyText_MeasurementLifetimeProbe_DRAIN_SHUTDOWN_SOURCE_87582578); ReadHandle := 0; Closer := nil;
  Entered := TEvent.Create(nil, True, False, ''); Resume := TEvent.Create(nil, True, False, '');
  Joined := TEvent.Create(nil, True, False, '');
  try
    ReadHandle := OpenMeasurementHandle(Source);
    StartMeasurementDrainForTest(ReadHandle, Entered.Handle, Resume.Handle);
    Require(Entered.WaitFor(1000) = wrSignaled, CozyText_MeasurementLifetimeProbe_DRAIN_TAIL_NOT_ENTERED_11b1f8ad);
    Require(OutstandingMeasurementReadsForTest = 0, CozyText_MeasurementLifetimeProbe_DRAIN_TAIL_COUNTER_NOT_ZERO_a5dcc709);
    Closer := TThread.CreateAnonymousThread(procedure
      begin FinalizeMeasurementDrainsForTest; Joined.SetEvent; end);
    Closer.FreeOnTerminate := False; Closer.Start;
    Require(Joined.WaitFor(40) = wrTimeout, CozyText_MeasurementLifetimeProbe_SHUTDOWN_ACCEPTED_COUNTER_BEFORE_THREAD_EXIT_22a20265);
    Resume.SetEvent;
    Require(Joined.WaitFor(1000) = wrSignaled, CozyText_MeasurementLifetimeProbe_DRAIN_SHUTDOWN_JOIN_FAILED_e22ef50c);
    Closer.WaitFor;
    Budget := TMeasurementBudget.Start(1024, 1000); Rejected := False;
    try ReadMeasurementAt(ReadHandle, 0, @Buffer, 1, Budget);
    except on E: EMeasurement do Rejected := E.Status = msCancelled; end;
    Require(Rejected, CozyText_MeasurementLifetimeProbe_MEASUREMENT_ADMISSION_AFTER_SHUTDOWN_148b76e1);
    Require(OutstandingMeasurementReadsForTest = 0, CozyText_MeasurementLifetimeProbe_REJECTED_SHUTDOWN_READ_LEAKED_532713fc);
  finally
    Resume.SetEvent;
    if Closer <> nil then Closer.WaitFor else FinalizeMeasurementDrainsForTest;
    Closer.Free; CloseMeasurementHandle(ReadHandle); CloseHandle(Source);
    Joined.Free; Resume.Free; Entered.Free;
  end;
end;
{$ENDIF}

procedure LoaderGenerationProbe(const FileName: string);
var BeforeGeneration, LoadedGeneration, AfterGeneration: Int64;
  Module: HMODULE; I: Integer;
begin
  Require(FileExists(FileName), CozyText_MeasurementLifetimeProbe_MODULE_GENERATION_FIXTURE_MISSING_567b0507);
  Require(ModuleLoaderGenerationStatus(BeforeGeneration) = CozyText_MeasurementLifetimeProbe_TRACKED_6a82df8a, CozyText_MeasurementLifetimeProbe_MODULE_GENERATION_UNAVAILABLE_2879aef6);
  Require(GetModuleHandle(PChar(FileName)) = 0, CozyText_MeasurementLifetimeProbe_MODULE_GENERATION_FIXTURE_ALREADY_LOADED_9f0a63fe);
  for I := 1 to 2 do
  begin
    Require(ModuleLoaderGenerationStatus(BeforeGeneration) = CozyText_MeasurementLifetimeProbe_TRACKED_6a82df8a, CozyText_MeasurementLifetimeProbe_MODULE_GENERATION_NOT_TRACKED_250469bb);
    Module := LoadLibraryEx(PChar(FileName), 0, LOAD_WITH_ALTERED_SEARCH_PATH);
    Require(Module <> 0, CozyText_MeasurementLifetimeProbe_MODULE_GENERATION_FIXTURE_LOAD_7c7bcde3);
    try
      Require(GetProcAddress(Module, CozyText_MeasurementLifetimeProbe_GameModuleGenerationFixture_53a22244) <> nil, CozyText_MeasurementLifetimeProbe_WRONG_MODULE_GENERATION_FIXTURE_887f440f);
      Require((ModuleLoaderGenerationStatus(LoadedGeneration) = CozyText_MeasurementLifetimeProbe_TRACKED_6a82df8a) and
        (LoadedGeneration > BeforeGeneration), CozyText_MeasurementLifetimeProbe_MODULE_LOAD_NOT_OBSERVED_3529a93f);
    finally Require(FreeLibrary(Module), CozyText_MeasurementLifetimeProbe_MODULE_GENERATION_FIXTURE_UNLOAD_bf4c98b4); end;
    Require((ModuleLoaderGenerationStatus(AfterGeneration) = CozyText_MeasurementLifetimeProbe_TRACKED_6a82df8a) and
      (AfterGeneration > LoadedGeneration), CozyText_MeasurementLifetimeProbe_MODULE_UNLOAD_NOT_OBSERVED_c28271e1);
    Require(GetModuleHandle(PChar(FileName)) = 0, CozyText_MeasurementLifetimeProbe_MODULE_GENERATION_FIXTURE_STILL_LOADED_abe785a5);
  end;
  Writeln(CozyText_MeasurementLifetimeProbe_PASS_actual_loader_load_unload_reload_generation_6ab1285c);
end;

begin
  try
    if (ParamCount = 2) and (ParamStr(1) = CozyText_MeasurementLifetimeProbe_loader_fixture_478e61ef) then LoaderGenerationProbe(ExpandFileName(ParamStr(2)))
    else
    begin
      Require(ParamCount = 0, CozyText_MeasurementLifetimeProbe_MEASUREMENT_PROBE_ARGUMENTS_0c31794a);
      RunRace(False); RunRace(True); MidCodeCancellation;
      BoundedFileReads; CancelledBundleTransfersNothing;
      {$IFDEF GAME_MEASUREMENT_TESTS}DrainShutdownJoinsActualThread;{$ENDIF}
      Writeln(CozyText_MeasurementLifetimeProbe_PASS_actual_retained_file_code_close_races_bound_ed5fdf8d);
    end;
  except on E: Exception do begin Writeln(E.ClassName, CozyText_MeasurementLifetimeProbe_Text_f08fecb2, E.Message); Halt(1); end; end;
end.
