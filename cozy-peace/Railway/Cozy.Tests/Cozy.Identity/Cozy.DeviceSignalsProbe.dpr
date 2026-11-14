program Cozy_DeviceSignalsProbe;
{$IFDEF FPC}{$MODE DELPHI}{$ELSE}{$APPTYPE CONSOLE}{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Identity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Identity.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
  Cozy.Strings.TestsIdentity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsIdentity.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
 {$IFDEF FPC}SysUtils,{$ELSE}System.SysUtils, System.JSON, System.Generics.Collections,
  Cozy.DeviceSignals, Cozy.Measurement, Cozy.Api.Pointer, Cozy.Handoff.Crypto,{$ENDIF}
  Cozy.DeviceSignals.Core;
var Buffer, Raw, Key, Mac: TBytes; A, B: TDeviceSignalSet; Expected, Changed: string;
  Passed, I, N: Integer; Okay: Boolean;
procedure Require(Value: Boolean);
begin if not Value then raise Exception.Create(CozyText_DeviceSignalsProbe_DEVICE_SIGNAL_CONTRACT_26a4a875 + IntToStr(Passed + 1)); Inc(Passed); end;
procedure Put32(Offset: Integer; Value: Cardinal);
begin
  Buffer[Offset] := Byte(Value); Buffer[Offset+1] := Byte(Value shr 8);
  Buffer[Offset+2] := Byte(Value shr 16); Buffer[Offset+3] := Byte(Value shr 24);
end;
procedure Descriptor;
const Serial: AnsiString = CozyText_DeviceSignalsProbe_SERIAL_ABC_b7870ae9;
begin
  SetLength(Buffer, 128); FillChar(Buffer[0], Length(Buffer), 0);
  Put32(0,40); Put32(4,128); Put32(24,40); Move(Serial[1],Buffer[40],Length(Serial));
end;
{$IFNDEF FPC}
procedure NativeProbe;
var J: TJSONObject; Budget: TMeasurementBudget; Status: string;
begin
  SealApiPointerStorage;
  ConfigureDeviceSignalsRequest(False, '', '', '');
  Budget := TMeasurementBudget.Start(4096, 5000); J := CollectDeviceSignalsJSON(Budget);
  try
    Require(J.Count = 8); Require(J.GetValue<string>(CozyText_DeviceSignalsProbe_status_964a69ed) = CozyText_DeviceSignalsProbe_NOT_REQUESTED_001cb149);
    Require(J.GetValue<Integer>(CozyText_DeviceSignalsProbe_diskCount_521116f8) = 0); Require(J.GetValue<Integer>(CozyText_DeviceSignalsProbe_nicCount_b388c49b) = 0);
    Require(J.GetValue<string>(CozyText_DeviceSignalsProbe_scope_997860e5) = ''); Require(J.GetValue<string>(CozyText_DeviceSignalsProbe_digest_75ba87f9) = '');
  finally J.Free; end;
  if (ParamCount <> 1) or (ParamStr(1) <> CozyText_DeviceSignalsProbe_collect_hardware_8e1c9a4b) then
  begin Writeln(CozyText_DeviceSignalsProbe_SKIP_hardware_collection_explicit_collect_hardwa_6501af58); Exit; end;
  ConfigureDeviceSignalsRequest(True, CozyText_DeviceSignalsProbe_LOCAL_DEVICE_SIGNALS_PROBE_6e3d5a04,
    LowerCase(Copy(HandoffRandomNonce,1,48)), LowerCase(Copy(HandoffRandomNonce,1,48)));
  Budget := TMeasurementBudget.Start(4096, 5000); J := CollectDeviceSignalsJSON(Budget);
  try
    Status := J.GetValue<string>(CozyText_DeviceSignalsProbe_status_964a69ed);
    Require((Status = CozyText_DeviceSignalsProbe_MEASURED_3a0d6b62) or (Status = CozyText_DeviceSignalsProbe_PARTIAL_71a808a6) or (Status = CozyText_DeviceSignalsProbe_UNAVAILABLE_233f4c84));
    Require(Length(J.GetValue<string>(CozyText_DeviceSignalsProbe_scope_997860e5)) = 128);
    Require((J.GetValue<Integer>(CozyText_DeviceSignalsProbe_diskCount_521116f8) >= 0) and (J.GetValue<Integer>(CozyText_DeviceSignalsProbe_diskCount_521116f8) <= 8));
    Require((J.GetValue<Integer>(CozyText_DeviceSignalsProbe_nicCount_b388c49b) >= 0) and (J.GetValue<Integer>(CozyText_DeviceSignalsProbe_nicCount_b388c49b) <= 64));
    Writeln(CozyText_DeviceSignalsProbe_OBSERVED_scoped_device_diagnostics_a6b1c8c2, J.ToJSON);
    if Status <> CozyText_DeviceSignalsProbe_MEASURED_3a0d6b62 then Writeln(CozyText_DeviceSignalsProbe_SKIP_full_hardware_availability_5ca2633e, Status);
  finally J.Free; end;
  J := CollectDeviceSignalsJSON(Budget);
  try Require(J.GetValue<string>(CozyText_DeviceSignalsProbe_status_964a69ed) = CozyText_DeviceSignalsProbe_NOT_REQUESTED_001cb149); finally J.Free; end;
end;
{$ENDIF}
begin
  try
    Descriptor; Require(ParseStorageSerial(Buffer,128,Raw));
    Require((Length(Raw)=10) and (Raw[0]=Ord('S')) and (Raw[9]=Ord('C'))); ClearDeviceBytes(Raw);
    for I := 0 to 9 do
    begin
      Descriptor;
      case I of
        0: Put32(4,129); 1: Put32(4,35); 2: Put32(24,0); 3: Put32(24,35);
        4: Put32(24,128); 5: Put32(24,High(Cardinal)); 6: FillChar(Buffer[40],88,Ord('X'));
        7: Buffer[42] := 1; 8: FillChar(Buffer[40],14,32); 9: Put32(0,35);
      end;
      Require(not ParseStorageSerial(Buffer,128,Raw)); Require(Length(Raw)=0);
    end;
    Descriptor;
    for N := 0 to 127 do begin Okay := ParseStorageSerial(Buffer,N,Raw); Require(not Okay); ClearDeviceBytes(Raw); end;
    SetLength(Mac,6); Mac[0]:=2; Mac[1]:=$11; Mac[2]:=$22; Mac[3]:=$33; Mac[4]:=$44; Mac[5]:=$55;
    Require(ParsePermanentAddress(Mac,6,Raw)); ClearDeviceBytes(Raw);
    Require(not ParsePermanentAddress(Mac,7,Raw));
    Mac[0]:=3; Require(not ParsePermanentAddress(Mac,6,Raw)); Mac[0]:=2;
    SetLength(Buffer,6); FillChar(Buffer[0],6,0); Require(not ParsePermanentAddress(Buffer,6,Raw));
    FillChar(Buffer[0],6,$FF); Require(not ParsePermanentAddress(Buffer,6,Raw));
    SetLength(Key,32); FillChar(Key[0],32,7); Descriptor; Require(ParseStorageSerial(Buffer,128,Raw));
    A := Default(TDeviceSignalSet); B := Default(TDeviceSignalSet);
    AddDeviceSignal(A,1,Key,Raw); AddDeviceSignal(A,2,Key,Mac); AddDeviceSignal(A,1,Key,Raw);
    AddDeviceSignal(B,2,Key,Mac); AddDeviceSignal(B,1,Key,Raw);
    Require((A.Count=2) and (A.DiskCount=1) and (A.NicCount=1));
    Expected := FinishDeviceSignals(A,Key); Require(Expected=FinishDeviceSignals(B,Key));
    { Independent Node/noble-hashes keyed BLAKE3 reference over the v1 framing. }
    Require(Expected=CozyText_DeviceSignalsProbe_Digest_0ecc3861);
    FillChar(Key[0],32,8); B:=Default(TDeviceSignalSet);
    AddDeviceSignal(B,1,Key,Raw); AddDeviceSignal(B,2,Key,Mac);
    Changed:=FinishDeviceSignals(B,Key); Require(Changed<>Expected);
    ClearDeviceBytes(Raw); SetLength(Raw,1); A:=Default(TDeviceSignalSet);
    for I:=0 to 10 do begin Raw[0]:=Byte(I); AddDeviceSignal(A,1,Key,Raw); end;
    Require((A.Count=8) and (A.DiskCount=8));
    for I:=0 to 70 do begin Raw[0]:=Byte(I); AddDeviceSignal(A,2,Key,Raw); end;
    Require((A.Count=72) and (A.NicCount=64));
    ClearDeviceBytes(Buffer); ClearDeviceBytes(Raw); ClearDeviceBytes(Key); ClearDeviceBytes(Mac);
    FillChar(A,SizeOf(A),0); FillChar(B,SizeOf(B),0);
    Writeln(CozyText_DeviceSignalsProbe_PASS_device_signal_parsing_scoped_digest_contrac_5ca11967,Passed);
    {$IFNDEF FPC}NativeProbe;{$ELSE}Writeln(CozyText_DeviceSignalsProbe_SKIP_Windows_hardware_execution_828717d2);{$ENDIF}
  except on E: Exception do begin Writeln(E.ClassName,CozyText_DeviceSignalsProbe_Text_d6c85ec4,E.Message); Halt(1); end; end;
end.
