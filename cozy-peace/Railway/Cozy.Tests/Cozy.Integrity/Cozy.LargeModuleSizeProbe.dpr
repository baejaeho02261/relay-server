program Cozy_LargeModuleSizeProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
{ TEST ONLY: bounded 80 MiB synthetic data-file/PE-parser test.
  No executable fixture is loaded or run, no foreign process is accessed,
  and no server is contacted. It is not an NVIDIA/O runtime-success test. }
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsIntegrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsIntegrity.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
 Winapi.Windows, System.SysUtils, System.Classes, System.IOUtils,
  Cozy.Measurement, Cozy.SelfImageHeaders, Cozy.CodeIntegrity;
const
{$I ..\..\Cozy.Source\Cozy.Integrity\Cozy.ModuleLimits.inc}
var Checks: Integer;
procedure Check(Value: Boolean; const Name: string);
begin
  if not Value then raise Exception.Create(Name);
  Inc(Checks); Writeln(CozyText_LargeModuleSizeProbe_JsonFixture_dea1c955, Name);
end;
procedure Clear(var B: TBytes);
begin
  if Length(B) > 0 then FillChar(B[0], Length(B), 0);
  B := nil;
end;
procedure Put16(var B: TBytes; At: Integer; Value: Word);
begin Move(Value, B[At], SizeOf(Value)); end;
procedure Put32(var B: TBytes; At: Integer; Value: Cardinal);
begin Move(Value, B[At], SizeOf(Value)); end;
procedure Put64(var B: TBytes; At: Integer; Value: UInt64);
begin Move(Value, B[At], SizeOf(Value)); end;
function Fixture: TBytes;
const PE = $80; Optional = PE + 24; TableAt = Optional + $F0;
  ImageBytes = 192 * 1024 * 1024;
begin
  SetLength(Result, 80 * 1024 * 1024 + 1024);
  Put16(Result, 0, $5A4D); Put32(Result, $3C, PE);
  Put32(Result, PE, $4550); Put16(Result, PE + 4, $8664);
  Put16(Result, PE + 6, 2); Put16(Result, PE + 20, $F0);
  Put16(Result, PE + 22, $2022); Put16(Result, Optional, $20B);
  Put32(Result, Optional + 16, $1000); Put32(Result, Optional + 20, $1000);
  Put64(Result, Optional + 24, UInt64($140000000));
  Put32(Result, Optional + 32, $1000); Put32(Result, Optional + 36, 512);
  Put32(Result, Optional + 56, ImageBytes); Put32(Result, Optional + 60, 512);
  Put32(Result, Optional + 108, 16);
  Put32(Result, TableAt + 8, 512); Put32(Result, TableAt + 12, $1000);
  Put32(Result, TableAt + 16, 512); Put32(Result, TableAt + 20, 512);
  Put32(Result, TableAt + 36, $60000020);
  Put32(Result, TableAt + 48, ImageBytes - $2000);
  Put32(Result, TableAt + 52, $2000);
  Put32(Result, TableAt + 56, 80 * 1024 * 1024);
  Put32(Result, TableAt + 60, 1024); Put32(Result, TableAt + 76, $40000040);
  FillChar(Result[512], 512, $90); Result[512] := $C3;
  Result[High(Result)] := $A5;
end;
procedure TestHeaders(const Bytes: TBytes);
var Plan: TSelfImageHeaderPlan; Rejected: Boolean;
begin
  Plan := Default(TSelfImageHeaderPlan); Rejected := False;
  try Plan.Initialize(Bytes); except on E: ESelfImageHeader do Rejected := True; end;
  Check(Rejected and not Plan.IsReady, CozyText_LargeModuleSizeProbe_DEFAULT_OWN_HEADER_LIMIT_STILL_REJECTS_07903148);
  Plan.InitializeBounded(Bytes, InventoryPeFileLimit, InventoryPeImageLimit);
  Check(Plan.IsReady and (Plan.ImageSize = 192 * 1024 * 1024),
    CozyText_LargeModuleSizeProbe_MODULE_HEADER_ACCEPTS_80_MIB_FILE_AND_192_MIB_IM_907e3603);
  Check((Plan.RangeCount > 0) and (Plan.ComparedBytes > 0), CozyText_LargeModuleSizeProbe_HEADER_RANGES_NOT_SKIPPED_6dd1a06f);
  Rejected := False;
  try Plan.InitializeBounded(Bytes, InventoryPeFileLimit + 1, InventoryPeImageLimit);
  except on E: ESelfImageHeader do Rejected := True; end;
  Check(Rejected and not Plan.IsReady, CozyText_LargeModuleSizeProbe_OVERSIZED_HEADER_LIMIT_REJECTED_0fb77d47);
end;
procedure TestFile(const Bytes: TBytes);
var FileName: string; Output, Input: TFileStream; Actual: TBytes;
  Budget: TMeasurementBudget; Plan: TCodeIntegrity; Rejected: Boolean;
  Measurement: TCodeIntegrityMeasurement;
begin
  FileName := ''; Output := nil; Input := nil; Plan := nil; Actual := nil;
  try
    FileName := TPath.GetTempFileName;
    Output := TFileStream.Create(FileName, fmCreate);
    Output.WriteBuffer(Bytes[0], Length(Bytes)); FreeAndNil(Output);
    Input := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
    Rejected := False;
    try
      Actual := ReadMeasurementBytes(Input.Handle,
        TMeasurementBudget.Start(InventoryPeFileLimit, 30000));
    except on E: EMeasurement do Rejected := E.Status = msCoverageInsufficient; end;
    Check(Rejected and (Length(Actual) = 0), CozyText_LargeModuleSizeProbe_DEFAULT_READER_64_MIB_CAP_STILL_REJECTS_019fcc80);
    Actual := ReadMeasurementBytesBounded(Input.Handle,
      TMeasurementBudget.Start(InventoryPeFileLimit, 30000), InventoryPeFileLimit);
    Check((Length(Actual) = Length(Bytes)) and
      CompareMem(@Actual[0], @Bytes[0], Length(Bytes)), CozyText_LargeModuleSizeProbe_EXPLICIT_MODULE_READ_ALL_80_MIB_BYTES_cddd11f2);
    Clear(Actual);
    Budget := TMeasurementBudget.Start(OwnPeFileLimit, 30000); Rejected := False;
    try Actual := ReadMeasurementBytesBounded(Input.Handle, Budget, InventoryPeFileLimit);
    except on E: EMeasurement do Rejected := E.Status = msCoverageInsufficient; end;
    Check(Rejected and (Length(Actual) = 0), CozyText_LargeModuleSizeProbe_CALLER_BYTE_BUDGET_NOT_WIDENED_a314fbba);
    Budget := TMeasurementBudget.Start(InventoryPeFileLimit, 30000,
      function: Boolean begin Result := True; end);
    Rejected := False;
    try Actual := ReadMeasurementBytesBounded(Input.Handle, Budget, InventoryPeFileLimit);
    except on E: EMeasurement do Rejected := E.Status = msCancelled; end;
    Check(Rejected and (Length(Actual) = 0), CozyText_LargeModuleSizeProbe_CANCELLED_READ_NEVER_PASSES_288d869c);
    Budget := TMeasurementBudget.Start(InventoryPeFileLimit, 30000);
    Budget.DeadlineTick := MeasurementTick; Rejected := False;
    try Actual := ReadMeasurementBytesBounded(Input.Handle, Budget, InventoryPeFileLimit);
    except on E: EMeasurement do Rejected := E.Status = msDeadlineExceeded; end;
    Check(Rejected and (Length(Actual) = 0), CozyText_LargeModuleSizeProbe_EXPIRED_DEADLINE_NEVER_RESTARTED_a0eca147);
    { Explicit-module DISK-PLAN ONLY. HInstance is an existing process module,
      not this fixture: NEVER call MeasureNow on this synthetic file plan. }
    Plan := TCodeIntegrity.Create(Input.Handle, HMODULE(HInstance),
      TMeasurementBudget.Start(InventoryPeFileLimit, 30000));
    Measurement := Plan.FileMeasurement;
    Check((Length(Measurement.SHA512) = 128) and (Measurement.Sections = 1) and
      (Measurement.Size > 512), CozyText_LargeModuleSizeProbe_DISK_CODE_PLAN_MEASURED_WITHOUT_EXECUTING_FIXTUR_4be2bce7);
    Check(Plan.ExportTableStatus = CozyText_LargeModuleSizeProbe_NO_EXPORTS_d21331ea, CozyText_LargeModuleSizeProbe_EMPTY_EXPORT_DIRECTORY_CLASSIFIED_0f7a98a1);
    FreeAndNil(Plan);
    Rejected := False;
    try Plan := TCodeIntegrity.Create(Input.Handle, 0,
      TMeasurementBudget.Start(InventoryPeFileLimit, 30000));
    except on E: EMeasurement do Rejected := E.Status = msCoverageInsufficient; end;
    Check(Rejected and (Plan = nil), CozyText_LargeModuleSizeProbe_OWN_CODE_PLAN_REMAINS_64_MIB_CAPPED_7294cf47);
  finally
    Plan.Free; Clear(Actual); Input.Free; Output.Free;
    if FileName <> '' then System.SysUtils.DeleteFile(FileName);
  end;
end;
var Bytes: TBytes;
begin
  try
    Bytes := Fixture;
    try TestHeaders(Bytes); TestFile(Bytes); finally Clear(Bytes); end;
    Writeln(CozyText_LargeModuleSizeProbe_PASS_a0474617, Checks, CozyText_LargeModuleSizeProbe_disk_fixture_checks_NOT_an_O_runtime_or_GPU_test_7d9ddf6d);
  except
    on E: Exception do begin Writeln(CozyText_LargeModuleSizeProbe_FAIL_8abfc18a, E.ClassName, CozyText_LargeModuleSizeProbe_Text_b39eaa82, E.Message); ExitCode := 1; end;
  end;
end.
