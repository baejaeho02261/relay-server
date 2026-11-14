program Cozy_ApiPointerCodecProbe;

{$APPTYPE CONSOLE}
{$R+}
{$Q+}

uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',

  Winapi.Windows, Winapi.WinSock2, System.SysUtils, System.Classes,
  Cozy.Api.Pointer;

{ Isolated fault-injection test. This program does NOT link Cozy.Platform.ExportResolver or
  the application. The fake reversible codec below is ONLY a test double.
  Production uses Windows EncodePointer/DecodePointer; the separate
  Cozy.ApiResolverProbe validates their real round trips with 126 exports. }

const
  CallerError: Cardinal = $20001111;
  EncoderError: Cardinal = $20002222;
  DecoderError: Cardinal = $20003333;
  TargetError: Cardinal = $20004444;

type
  TEightArguments = function(A, B, C, D, E, F, G, H: UInt64;
    var Total: UInt64): UInt64; stdcall;
  TBuffers = function(const Source; var Destination; Count: Cardinal;
    out Moved: Cardinal): BOOL; stdcall;
  TNoArguments = function: Cardinal; stdcall;
  TVoidCall = procedure(Value: Cardinal); stdcall;
  TSocketError = function: Integer; stdcall;
  TErrorWorker = class(TThread)
  private
    FNumber: Cardinal;
  public
    Failure: Boolean;
    constructor Create(Number: Cardinal);
    procedure Execute; override;
  end;

var
  TestMask: NativeUInt;
  Slot, SlotEight, SlotBuffers, SlotNoArgs, SlotVoid, SlotSocket: TEncodedApiPointer;
  VoidValue: Cardinal;
  Checked: Integer;

procedure Check(Condition: Boolean; const MessageText: string);
begin
  if not Condition then raise Exception.Create(MessageText);
  Inc(Checked);
end;

function ReadError: Cardinal; stdcall;
begin
  Result := Winapi.Windows.GetLastError;
end;

procedure WriteError(Value: Cardinal); stdcall;
begin
  Winapi.Windows.SetLastError(Value);
end;

function FakeEncode(Value: Pointer): Pointer; stdcall;
begin
  Result := Pointer(NativeUInt(Value) xor TestMask);
  Winapi.Windows.SetLastError(EncoderError);
end;

function FakeDecode(Value: Pointer): Pointer; stdcall;
begin
  Result := Pointer(NativeUInt(Value) xor TestMask);
  Winapi.Windows.SetLastError(DecoderError);
end;

function TargetEight(A, B, C, D, E, F, G, H: UInt64;
  var Total: UInt64): UInt64; stdcall;
begin
  Total := A + 2*B + 3*C + 4*D + 5*E + 6*F + 7*G + 8*H;
  Result := Total + UInt64($100000000);
  Winapi.Windows.SetLastError(TargetError);
end;

function TargetBuffers(const Source; var Destination; Count: Cardinal;
  out Moved: Cardinal): BOOL; stdcall;
begin
  Move(Source, Destination, Count);
  Moved := Count;
  Result := True;
  Winapi.Windows.SetLastError(TargetError);
end;

function TargetNoArgs: Cardinal; stdcall;
begin
  Result := Winapi.Windows.GetLastError;
end;

procedure TargetVoid(Value: Cardinal); stdcall;
begin
  VoidValue := Value;
  Winapi.Windows.SetLastError(TargetError);
end;

function TargetSocketError: Integer; stdcall;
begin
  Result := Winapi.WinSock2.WSAGetLastError;
end;

function WrappedEight(A, B, C, D, E, F, G, H: UInt64;
  var Total: UInt64): UInt64; stdcall;
var
  ApiTarget: TEightArguments;
begin
  ApiTarget := TEightArguments(DecodeApiPointer(SlotEight));
  Result := ApiTarget(A, B, C, D, E, F, G, H, Total);
end;

function WrappedBuffers(const Source; var Destination; Count: Cardinal;
  out Moved: Cardinal): BOOL; stdcall;
var
  ApiTarget: TBuffers;
begin
  ApiTarget := TBuffers(DecodeApiPointer(SlotBuffers));
  Result := ApiTarget(Source, Destination, Count, Moved);
end;

function WrappedNoArgs: Cardinal; stdcall;
var
  ApiTarget: TNoArguments;
begin
  ApiTarget := TNoArguments(DecodeApiPointer(SlotNoArgs));
  Result := ApiTarget();
end;

procedure WrappedVoid(Value: Cardinal); stdcall;
var
  ApiTarget: TVoidCall;
begin
  ApiTarget := TVoidCall(DecodeApiPointer(SlotVoid));
  ApiTarget(Value);
end;

function WrappedSocketError: Integer; stdcall;
var
  ApiTarget: TSocketError;
begin
  ApiTarget := TSocketError(DecodeApiPointer(SlotSocket));
  Result := ApiTarget();
end;

constructor TErrorWorker.Create(Number: Cardinal);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FNumber := Number;
end;

procedure TErrorWorker.Execute;
var
  I: Integer;
  Value: Cardinal;
begin
  try
    for I := 1 to 256 do
    begin
      Value := Cardinal($20010000) + FNumber * 1024 + Cardinal(I);
      Winapi.Windows.SetLastError(Value);
      if WrappedNoArgs() <> Value then
      begin
        Failure := True;
        Exit;
      end;
    end;
  except
    Failure := True;
  end;
end;

procedure TestGuardsAndCalls;
var
  Address: Pointer;
  Failed: Boolean;
  Sum, Actual, Src, Dst: UInt64;
  Count: Cardinal;
  ErrorValue: Cardinal;
  OK: BOOL;
  SocketResult: Integer;
  Data: TWSAData;
begin
  Slot := Default(TEncodedApiPointer);
  Failed := False;
  try
    Address := DecodeApiPointer(Slot);
  except
    on E: EInvalidOpException do Failed := True;
  end;
  Check(Failed, CozyText_ApiPointerCodecProbe_Uninitialized_codec_must_fail_fe900494);
  Failed := False;
  try
    InitializeApiPointerCodec(nil, nil, nil, nil);
  except
    on E: EArgumentException do Failed := True;
  end;
  Check(Failed, CozyText_ApiPointerCodecProbe_Missing_codec_addresses_must_fail_87e7c0f3);
  InitializeApiPointerCodec(@FakeEncode, @FakeDecode, @ReadError, @WriteError);
  ConfigureApiPointerStorage(@Winapi.Windows.VirtualAlloc, @Winapi.Windows.VirtualProtect,
    @Winapi.Windows.VirtualFree, @Winapi.Windows.VirtualQuery);
  Failed := False;
  try
    Address := DecodeApiPointer(Slot);
  except
    on E: EInvalidOpException do Failed := True;
  end;
  Check(Failed, CozyText_ApiPointerCodecProbe_Unbound_slot_must_fail_a11fb3ac);
  Failed := False;
  try
    BindApiPointer(Slot, nil);
  except
    on E: EArgumentException do Failed := True;
  end;
  Check(Failed and not Slot.IsBound, CozyText_ApiPointerCodecProbe_Binding_nil_must_fail_without_binding_slot_8ac1c2a9);
  Failed := False;
  try
    InitializeApiPointerCodec(@FakeEncode, @FakeDecode, @ReadError, @WriteError);
  except
    on E: EInvalidOpException do Failed := True;
  end;
  Check(Failed, CozyText_ApiPointerCodecProbe_Reinitialization_must_fail_8957e82d);

  Winapi.Windows.SetLastError(CallerError);
  BindApiPointer(Slot, Pointer(TestMask));
  ErrorValue := Winapi.Windows.GetLastError;
  Check(ErrorValue = CallerError, CozyText_ApiPointerCodecProbe_Encoder_must_preserve_incoming_error_25a1ce77);
  Check(Slot.IsBound and (Slot.EncodedValue = nil), CozyText_ApiPointerCodecProbe_Encoded_zero_is_a_bound_value_7a1f219b);
  Winapi.Windows.SetLastError(CallerError);
  Address := DecodeApiPointer(Slot);
  ErrorValue := Winapi.Windows.GetLastError;
  Check(Address = Pointer(TestMask), CozyText_ApiPointerCodecProbe_Encoded_zero_round_trip_0333b352);
  Check(ErrorValue = CallerError, CozyText_ApiPointerCodecProbe_Decoder_must_preserve_incoming_error_5f937ef4);
  { Real image target also exercises an encoded-zero value; registration forbids arbitrary sentinel addresses. }

  BindApiPointer(SlotEight, @TargetEight);
  BindApiPointer(SlotBuffers, @TargetBuffers);
  BindApiPointer(SlotNoArgs, @TargetNoArgs);
  BindApiPointer(SlotVoid, @TargetVoid);
  BindApiPointer(SlotSocket, @TargetSocketError);
  Sum := 0;
  Actual := WrappedEight(1, 2, 3, 4, 5, 6, 7, 8, Sum);
  ErrorValue := Winapi.Windows.GetLastError;
  Check((Sum = 204) and (Actual = UInt64($100000000) + 204),
    CozyText_ApiPointerCodecProbe_Register_stack_arguments_64_bit_return_and_var_o_8628c429);
  Check(ErrorValue = TargetError, CozyText_ApiPointerCodecProbe_Target_last_error_survives_wrapper_return_a4804c1c);
  Src := $0123456789ABCDEF;
  Dst := 0;
  Count := 0;
  OK := WrappedBuffers(Src, Dst, SizeOf(Src), Count);
  ErrorValue := Winapi.Windows.GetLastError;
  Check(OK and (Dst = Src) and (Count = SizeOf(Src)), CozyText_ApiPointerCodecProbe_Untyped_const_var_and_out_output_9fb51c1f);
  Check(ErrorValue = TargetError, CozyText_ApiPointerCodecProbe_Buffer_target_last_error_4499cc74);
  Winapi.Windows.SetLastError(CallerError);
  Actual := WrappedNoArgs();
  Check(Actual = CallerError, CozyText_ApiPointerCodecProbe_Zero_argument_error_reader_624924a9);
  WrappedVoid(77);
  ErrorValue := Winapi.Windows.GetLastError;
  Check((VoidValue = 77) and (ErrorValue = TargetError), CozyText_ApiPointerCodecProbe_Procedure_forwarding_514ea75d);

  Check(Winapi.WinSock2.WSAStartup($0202, Data) = 0, CozyText_ApiPointerCodecProbe_WSAStartup_c691a343);
  try
    Winapi.WinSock2.WSASetLastError(WSAEINVAL);
    SocketResult := WrappedSocketError();
    Check(SocketResult = WSAEINVAL, CozyText_ApiPointerCodecProbe_Winsock_error_survives_decode_a6bad84a);
  finally
    Winapi.WinSock2.WSACleanup;
  end;
end;

procedure TestSealedGuards;
var CopySlot, EmptySlot: TEncodedApiPointer; Failed: Boolean; Address: Pointer;
begin
  CopySlot := SlotEight;
  Failed := False;
  try
    Address := DecodeApiPointer(CopySlot);
  except
    on E: EInvalidOpException do Failed := True;
  end;
  Check(Failed, CozyText_ApiPointerCodecProbe_Copied_descriptor_cannot_redirect_another_slot_441d2601);
  EmptySlot := Default(TEncodedApiPointer);
  Failed := False;
  try
    BindApiPointer(EmptySlot, @TargetNoArgs);
  except
    on E: EInvalidOpException do Failed := True;
  end;
  Check(Failed, CozyText_ApiPointerCodecProbe_Late_binding_after_seal_fails_f0dad577);
  Failed := False;
  try
    BindApiPointer(SlotEight, @TargetNoArgs);
  except
    on E: EInvalidOpException do Failed := True;
  end;
  Check(Failed, CozyText_ApiPointerCodecProbe_Already_bound_slot_cannot_be_rebound_cce9e474);
  Winapi.Windows.SetLastError(CallerError);
  SealApiPointerStorage;
  Check(Winapi.Windows.GetLastError = CallerError, CozyText_ApiPointerCodecProbe_Repeated_seal_preserves_last_error_9abd5217);
  Check(ApiPointerStorageCount = 6, CozyText_ApiPointerCodecProbe_All_test_slots_are_still_present_31e143bb);
end;

procedure TestThreads;
var
  Workers: array[0..3] of TErrorWorker;
  I: Integer;
begin
  for I := Low(Workers) to High(Workers) do Workers[I] := nil;
  try
    for I := Low(Workers) to High(Workers) do
    begin
      Workers[I] := TErrorWorker.Create(Cardinal(I + 1));
      Workers[I].Start;
    end;
    for I := Low(Workers) to High(Workers) do
    begin
      Workers[I].WaitFor;
      Check(not Workers[I].Failure, CozyText_ApiPointerCodecProbe_Per_thread_error_preservation_59a9ede8);
    end;
  finally
    for I := Low(Workers) to High(Workers) do Workers[I].Free;
  end;
end;

begin
  try
    TestMask := NativeUInt(@TargetNoArgs);
    TestGuardsAndCalls;
    SealApiPointerStorage;
    Check(ApiPointerStorageIsSealed, CozyText_ApiPointerCodecProbe_Dedicated_API_arena_is_read_only_5a734148);
    Check(ApiPointerTargetsMatch([Pointer(TestMask), @TargetEight, @TargetBuffers,
      @TargetNoArgs, @TargetVoid, @TargetSocketError]), CozyText_ApiPointerCodecProbe_Exact_target_owner_manifest_accepted_d4e57a09);
    Check(not ApiPointerTargetsMatch([Pointer(TestMask), @TargetEight, @TargetBuffers,
      @TargetNoArgs, @TargetVoid, @TargetNoArgs]), CozyText_ApiPointerCodecProbe_Same_count_with_one_wrong_target_rejected_862ae765);
    Check(not ApiPointerTargetsMatch([@TargetEight]), CozyText_ApiPointerCodecProbe_Missing_mandatory_targets_rejected_aa001ad1);
    TestSealedGuards;
    TestThreads;
    Writeln(CozyText_ApiPointerCodecProbe_PASS_1f96373a, Checked, CozyText_ApiPointerCodecProbe_codec_ABI_error_checks_four_threads_x_256_calls_8be0d882);
  except
    on E: Exception do
    begin
      Writeln(CozyText_ApiPointerCodecProbe_FAIL_391aaf1a, E.ClassName, CozyText_ApiPointerCodecProbe_Text_004719b7, E.Message);
      ExitCode := 1;
    end;
  end;
end.
