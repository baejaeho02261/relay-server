program Cozy_SelfIntegrityProbe;

{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}

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

  System.SysUtils, System.Classes, System.JSON,
  Cozy.SelfImageHeaders, Cozy.CodeIntegrity;

procedure Check(Condition: Boolean; const MessageText: string);
begin
  if not Condition then raise Exception.Create(MessageText);
end;

procedure Put16(var Bytes: TBytes; At: Integer; Value: Word);
begin
  Move(Value, Bytes[At], SizeOf(Value));
end;

procedure Put32(var Bytes: TBytes; At: Integer; Value: Cardinal);
begin
  Move(Value, Bytes[At], SizeOf(Value));
end;

function Fixture: TBytes;
const
  PE = $80;
  Optional = PE + 24;
  TableAt = Optional + 240;
var Index, At: Integer;
begin
  SetLength(Result, $1000);
  FillChar(Result[0], Length(Result), 0);
  Put16(Result, 0, $5A4D);
  Put32(Result, $3C, PE);
  Put32(Result, PE, $4550);
  Put16(Result, PE + 4, $8664);
  Put16(Result, PE + 6, 2);
  Put16(Result, PE + 20, 240);
  Put16(Result, PE + 22, $22);
  Put16(Result, Optional, $20B);
  Put32(Result, Optional + 16, $1000);
  Put32(Result, Optional + 20, $1000);
  Put32(Result, Optional + 32, $1000);
  Put32(Result, Optional + 36, $200);
  Put32(Result, Optional + 56, $4000);
  Put32(Result, Optional + 60, $400);
  Put32(Result, Optional + 108, 16);
  for Index := 0 to 1 do
  begin
    At := TableAt + Index * 40;
    Put32(Result, At + 8, $200);
    Put32(Result, At + 12, Cardinal(Index + 1) * $1000);
    Put32(Result, At + 16, $200);
    Put32(Result, At + 20, $400 + Cardinal(Index) * $200);
    if Index = 0 then Put32(Result, At + 36, $60000020)
    else Put32(Result, At + 36, $C0000040);
  end;
end;

function MatchesSnapshot(var Plan: TSelfImageHeaderPlan;
  const Snapshot: TBytes): Boolean;
var Index: Integer; At, Count: Cardinal;
begin
  Result := False;
  for Index := 0 to Plan.RangeCount - 1 do
  begin
    At := Plan.RangeOffset(Index);
    Count := Plan.RangeSize(Index);
    if UInt64(At) + Count > UInt64(Length(Snapshot)) then Exit;
    if not Plan.RangeMatches(Index, @Snapshot[NativeInt(At)], Count) then Exit;
  end;
  Result := True;
end;

procedure TestHeaderPlan;
const Optional = $80 + 24;
var
  Plan: TSelfImageHeaderPlan;
  Original, Changed: TBytes;
  Index, ByteIndex, Mutations: Integer;
  At: Cardinal;
  Raised: Boolean;
begin
  Plan := Default(TSelfImageHeaderPlan);
  Original := Fixture;
  Plan.Initialize(Original);
  Check(Plan.IsReady, CozyText_SelfIntegrityProbe_Plan_was_not_initialized_cadcb06c);
  Check(Plan.RangeCount = 14, CozyText_SelfIntegrityProbe_Unexpected_range_count_237d0d9c);
  Check(Plan.ComparedBytes = 216, CozyText_SelfIntegrityProbe_Unexpected_byte_count_8e5b82ab);
  Check(MatchesSnapshot(Plan, Original), CozyText_SelfIntegrityProbe_Unchanged_header_did_not_match_0bde33c9);
  Mutations := 0;
  for Index := 0 to Plan.RangeCount - 1 do
    for ByteIndex := 0 to Integer(Plan.RangeSize(Index)) - 1 do
    begin
      Changed := Copy(Original, 0, Length(Original));
      At := Plan.RangeOffset(Index) + Cardinal(ByteIndex);
      Changed[NativeInt(At)] := Changed[NativeInt(At)] xor $01;
      Check(not MatchesSnapshot(Plan, Changed), CozyText_SelfIntegrityProbe_Selected_byte_change_was_missed_daba73bd);
      Inc(Mutations);
    end;
  Changed := Copy(Original, 0, Length(Original));
  Changed[Optional + 24] := Changed[Optional + 24] xor $01; // ImageBase
  Changed[Optional + 64] := Changed[Optional + 64] xor $01; // checksum
  Changed[Optional + 2] := Changed[Optional + 2] xor $01;   // linker version
  Changed[$80 + 8] := Changed[$80 + 8] xor $01;             // timestamp
  Changed[Optional + 240] := Changed[Optional + 240] xor $01;// section name
  Changed[$500] := Changed[$500] xor $01;                  // not a header field
  Check(MatchesSnapshot(Plan, Changed), CozyText_SelfIntegrityProbe_Excluded_fields_affected_the_comparison_32917880);
  Check(not Plan.RangeMatches(0, nil, Plan.RangeSize(0)), CozyText_SelfIntegrityProbe_Nil_buffer_accepted_0dab3fb9);
  Check(not Plan.RangeMatches(0, @Original[0], 0), CozyText_SelfIntegrityProbe_Partial_buffer_accepted_a865f56f);
  Changed := Copy(Original, 0, Length(Original));
  Put32(Changed, $3C, $FFFFFFF0);
  Raised := False;
  try
    Plan.Initialize(Changed);
  except
    on E: ESelfImageHeader do Raised := True;
  end;
  Check(Raised and not Plan.IsReady, CozyText_SelfIntegrityProbe_Malformed_initialization_left_a_ready_plan_38b01cca);
  Plan.Initialize(Original);
  Check(MatchesSnapshot(Plan, Original), CozyText_SelfIntegrityProbe_Valid_reinitialization_failed_267ed247);
  Original[0] := 0;
  Check(not MatchesSnapshot(Plan, Original), CozyText_SelfIntegrityProbe_Baseline_aliases_the_input_buffer_f4a7c4bc);
  Writeln(CozyText_SelfIntegrityProbe_PASS_header_byte_buffer_tests_individual_changes_af3132fb, Mutations);
end;

function SameDigest(const A, B: TCodeIntegrityMeasurement): Boolean;
begin
  Result := (A.Algorithm = B.Algorithm) and (A.Size = B.Size) and
    (A.Sections = B.Sections) and (A.SHA512 = B.SHA512) and
    (A.CRC64 = B.CRC64) and (A.XXH3_128 = B.XXH3_128) and (A.Blake3 = B.Blake3);
end;

procedure TestLiveOwnImage;
const
  LayerNames: array[0..8] of string = (CozyText_SelfIntegrityProbe_ecma182_522b3882, CozyText_SelfIntegrityProbe_nvme_3f66e42b, CozyText_SelfIntegrityProbe_jones_1bda0b54, CozyText_SelfIntegrityProbe_xz_be74c1b4,
    CozyText_SelfIntegrityProbe_we_9bdadd7d, CozyText_SelfIntegrityProbe_iso_95ae5c2c, CozyText_SelfIntegrityProbe_crc32c_d5df9275, CozyText_SelfIntegrityProbe_crc16_arc_c918656f, CozyText_SelfIntegrityProbe_crc8_smbus_8a42f931);
var
  Input: TFileStream;
  Plan: TCodeIntegrity;
  Current, Expected: TCodeIntegrityMeasurement;
  Report, Layers: TJSONObject;
  Name: string;
begin
  Input := TFileStream.Create(ParamStr(0), fmOpenRead or fmShareDenyNone);
  try
    Plan := TCodeIntegrity.Create(Input.Handle);
    try
      Expected := Plan.FileMeasurement;
      Check(Length(Expected.SHA512) = 128, CozyText_SelfIntegrityProbe_SHA_512_must_have_128_hex_digits_040d42c3);
      Check(Length(Expected.XXH3_128) = 32, CozyText_SelfIntegrityProbe_XXH3_128_must_have_32_hex_digits_73f4973a);
      Check(Length(Expected.CRC64) = 16, CozyText_SelfIntegrityProbe_CRC64_width_changed_dbf2694c);
      Check(Length(Expected.Blake3) = 64, CozyText_SelfIntegrityProbe_BLAKE3_default_width_changed_89c38e0e);
      Report := Expected.ToJSON;
      try
        Check(Report.GetValue(CozyText_SelfIntegrityProbe_codeSha512_d26ef727) <> nil, CozyText_SelfIntegrityProbe_New_SHA_512_field_is_absent_76c81ccd);
        Check(Report.GetValue(CozyText_SelfIntegrityProbe_codeXxh3_128_ec113dfa) <> nil, CozyText_SelfIntegrityProbe_New_XXH3_128_field_is_absent_0270bb99);
        Check(Report.GetValue(CozyText_SelfIntegrityProbe_codeSha256_f7549fd5) = nil, CozyText_SelfIntegrityProbe_Legacy_SHA_256_field_leaked_into_measurement_278855eb);
        Check(Report.GetValue(CozyText_SelfIntegrityProbe_codeXxh64_a2df4edb) = nil, CozyText_SelfIntegrityProbe_Legacy_XXH64_field_leaked_into_measurement_a6204e0d);
      finally
        Report.Free;
      end;
      Layers := Plan.MeasureCrcLayersNow;
      try
        { Exercise real own-image PE/header/page measurement on Windows. The
          server still decides which build-dependent checker roles it accepts. }
        for Name in LayerNames do
          Check(Layers.GetValue(Name) is TJSONObject, CozyText_SelfIntegrityProbe_Missing_CRC_role_d354399d + Name);
      finally
        Layers.Free;
      end;
      Current := Plan.MeasureNow;
      Check(SameDigest(Expected, Current), CozyText_SelfIntegrityProbe_Own_live_code_differs_from_the_file_baseline_a9adefee);
      Current := Plan.MeasureNow;
      Check(SameDigest(Expected, Current), CozyText_SelfIntegrityProbe_Repeated_live_measurement_changed_c90bccbb);
    finally
      Plan.Free;
    end;
  finally
    Input.Free;
  end;
  Writeln(CozyText_SelfIntegrityProbe_PASS_live_own_image_and_repeated_normalized_code_1d4e9907);
end;

begin
  try
    TestHeaderPlan;
    TestLiveOwnImage;
    Writeln(CozyText_SelfIntegrityProbe_PASS_Cozy_SelfIntegrityProbe_5131c2e2);
  except
    on E: Exception do
    begin
      Writeln(CozyText_SelfIntegrityProbe_FAIL_7d84de5f, E.ClassName, CozyText_SelfIntegrityProbe_Text_9e2c4aff, E.Message);
      ExitCode := 1;
    end;
  end;
end.
