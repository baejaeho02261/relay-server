program Cozy_HandoffCryptoProbe;

{$APPTYPE CONSOLE}
{$R+}
{$Q+}
{$B-}

uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
  Cozy.Strings.TestsHandoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsHandoff.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
 Cozy.Clock, System.SysUtils, System.Classes, System.SyncObjs, Winapi.Windows,
  Cozy.Api.Pointer, Cozy.Security, Cozy.Handoff.Crypto;

{ Windows-only AEAD integration. These tests exercise actual CNG, not a model.
  A successful local test does not substitute for A/B/O server/GUI testing. }

procedure Check(Value: Boolean; const MessageText: string);
begin
  if not Value then raise EInvalidOpException.Create(MessageText);
end;

procedure RunCase(Kind: Integer);
var Cipher, Other: THandoffCipher;
  Blob, Plain, AAD, Envelope, Output: TBytes;
  Rejected: Boolean; I: Integer;
begin
  Cipher := nil; Other := nil;
  try
    Cipher := THandoffCipher.Create;
    Blob := Cipher.PublicBlob;
    SetLength(Plain, 65536);
    for I := 0 to High(Plain) do Plain[I] := Byte(I and $FF);
    AAD := TEncoding.UTF8.GetBytes(CozyText_HandoffCryptoProbe_public_bootstrap_role_B_child_key_nonce_da98640d);
    if Kind = 8 then begin SetLength(AAD, 8192); FillChar(AAD[0], Length(AAD), 65); end;
    if Kind = 9 then SetLength(Plain, 1);
    Envelope := THandoffCipher.Encrypt(Blob, Plain, AAD);
    case Kind of
      1: AAD[0] := AAD[0] xor 1;
      2: Envelope[High(Envelope)] := Envelope[High(Envelope)] xor 1;
      3: Envelope[284] := Envelope[284] xor 1; // first GCM tag byte
      4: Envelope[28] := Envelope[28] xor 1; // first RSA wrapped-key byte
      5: begin Other := THandoffCipher.Create; FreeAndNil(Cipher); Cipher := Other; Other := nil; end;
      6: SetLength(Envelope, Length(Envelope) - 1);
      7: Envelope[8] := 2; // old envelope version
    end;
    Rejected := False;
    try Output := Cipher.Decrypt(Envelope, AAD);
    except on E: EDeviceSecurity do Rejected := True; end;
    if Kind in [0, 8, 9] then
    begin
      Check(not Rejected and (Length(Output) = Length(Plain)), CozyText_HandoffCryptoProbe_Valid_envelope_rejected_a33f5c65);
      Check(CompareMem(@Output[0], @Plain[0], Length(Plain)), CozyText_HandoffCryptoProbe_Plaintext_differs_0ca210ad);
    end
    else Check(Rejected and (Length(Output) = 0), CozyText_HandoffCryptoProbe_Unauthenticated_plaintext_escaped_ddbb1db9);
    WipeBytes(Output);
    Rejected := False;
    try Output := Cipher.Decrypt(Envelope, AAD);
    except on E: EDeviceSecurity do Rejected := True; end;
    Check(Rejected and (Length(Output) = 0), CozyText_HandoffCryptoProbe_Wrapping_key_decrypt_gate_reused_0e1d3055);
    Cipher.Close;
    Rejected := False;
    try Output := Cipher.PublicBlob;
    except on E: EInvalidOpException do Rejected := E.Message = CozyText_HandoffCryptoProbe_OBJECT_CLOSING_7e76a693; end;
    Check(Rejected and (Length(Output) = 0), CozyText_HandoffCryptoProbe_Closed_cipher_admitted_a_new_call_f05c6031);
  finally
    WipeBytes(Blob); WipeBytes(Plain); WipeBytes(AAD);
    WipeBytes(Envelope); WipeBytes(Output); Other.Free; Cipher.Free;
  end;
end;

function BytesHex(const Value: string): TBytes;
var I: Integer;
begin
  SetLength(Result, Length(Value) div 2);
  for I := 0 to High(Result) do Result[I] := StrToInt('$' + Copy(Value, I*2+1, 2));
end;

function IsCode(const E: Exception; const Code: string): Boolean;
begin Result := (E is EDeviceSecurity) and (E.Message = Code); end;

procedure MakeEnvelope(Cipher: THandoffCipher; out Plain, AAD, Envelope: TBytes);
var Blob: TBytes;
begin
  Plain := TEncoding.UTF8.GetBytes(CozyText_HandoffCryptoProbe_temporary_private_handoff_test_payload_1baf0ad1);
  AAD := TEncoding.UTF8.GetBytes(CozyText_HandoffCryptoProbe_public_test_role_B_key_nonce_6be2b493);
  Blob := Cipher.PublicBlob;
  try Envelope := THandoffCipher.Encrypt(Blob, Plain, AAD);
  finally WipeBytes(Blob); end;
end;

procedure RejectGoodAfterBad;
var Cipher: THandoffCipher; Plain, AAD, Good, Bad, Output: TBytes; Rejected: Boolean;
begin
  Cipher := THandoffCipher.Create;
  try
    MakeEnvelope(Cipher, Plain, AAD, Good);
    Bad := Copy(Good); Bad[0] := Bad[0] xor 1;
    Rejected := False;
    try Output := Cipher.Decrypt(Bad, AAD);
    except on E: Exception do Rejected := IsCode(E, CozyText_HandoffCryptoProbe_HANDOFF_CIPHER_HEADER_INVALID_6304805b); end;
    Check(Rejected and (Length(Output) = 0), CozyText_HandoffCryptoProbe_Malformed_first_attempt_was_not_rejected_13ad7eab);
    Rejected := False;
    { The second input is known-good, so rejection cannot be explained by the
      corrupted first envelope. It must be the same key's consumed gate. }
    try Output := Cipher.Decrypt(Good, AAD);
    except on E: Exception do Rejected := IsCode(E, CozyText_HandoffCryptoProbe_HANDOFF_CIPHER_ALREADY_CONSUMED_8d55e5b3); end;
    Check(Rejected and (Length(Output) = 0), CozyText_HandoffCryptoProbe_Good_envelope_revived_a_consumed_key_0fef053a);
  finally
    WipeBytes(Plain); WipeBytes(AAD); WipeBytes(Good); WipeBytes(Bad); WipeBytes(Output);
    Cipher.Free;
  end;
end;

procedure CancellationCase(CancelAt: Integer; Encrypting: Boolean);
var Cipher: THandoffCipher; Plain, Original, AAD, Envelope, Blob, Output: TBytes;
  Calls: Integer; Rejected: Boolean; Cancel: TFunc<Boolean>;
begin
  Cipher := THandoffCipher.Create; Calls := 0;
  try
    MakeEnvelope(Cipher, Plain, AAD, Envelope); Original := Copy(Plain);
    Cancel := function: Boolean
      begin Inc(Calls); Result := Calls >= CancelAt; end;
    Rejected := False;
    try
      if Encrypting then
      begin Blob := Cipher.PublicBlob; Output := THandoffCipher.Encrypt(Blob, Plain, AAD, Cancel); end
      else Output := Cipher.Decrypt(Envelope, AAD, Cancel);
    except on E: Exception do Rejected := IsCode(E, CozyText_HandoffCryptoProbe_HANDOFF_CIPHER_CANCELLED_c49cee74); end;
    Check(Rejected and (Length(Output) = 0), CozyText_HandoffCryptoProbe_Cancellation_published_output_3d76e8db);
    Check(CompareMem(@Plain[0], @Original[0], Length(Plain)), CozyText_HandoffCryptoProbe_Borrowed_input_was_modified_f2433e07);
    if not Encrypting then
    begin
      Rejected := False;
      try Output := Cipher.Decrypt(Envelope, AAD);
      except on E: Exception do Rejected := IsCode(E, CozyText_HandoffCryptoProbe_HANDOFF_CIPHER_ALREADY_CONSUMED_8d55e5b3); end;
      Check(Rejected and (Length(Output) = 0), CozyText_HandoffCryptoProbe_Cancellation_revived_consumed_decrypt_gate_5d631d18);
    end;
  finally
    Cancel := nil;
    WipeBytes(Plain); WipeBytes(Original); WipeBytes(AAD); WipeBytes(Envelope);
    WipeBytes(Blob); WipeBytes(Output); Cipher.Free;
  end;
end;

type
  TDecryptWorker = class(TThread)
  private
    FCipher: THandoffCipher;
    FEnvelope, FAAD: TBytes;
    FCheck: TFunc<Boolean>;
  protected
    procedure Execute; override;
  public
    Output: TBytes;
    Failure: string;
    Done: TEvent;
    constructor Create(Cipher: THandoffCipher; const Envelope, AAD: TBytes;
      const Cancel: TFunc<Boolean>);
    destructor Destroy; override;
  end;
  TCloseWorker = class(TThread)
  private FCipher: THandoffCipher;
  protected procedure Execute; override;
  public
    Done: TEvent;
    Failure: string;
    constructor Create(Cipher: THandoffCipher);
    destructor Destroy; override;
  end;
constructor TDecryptWorker.Create(Cipher: THandoffCipher; const Envelope, AAD: TBytes;
  const Cancel: TFunc<Boolean>);
begin
  inherited Create(True); FreeOnTerminate := False;
  FCipher := Cipher; FEnvelope := Envelope; FAAD := AAD; FCheck := Cancel;
  Done := TEvent.Create(nil, True, False, '');
end;
procedure TDecryptWorker.Execute;
begin
  try
    try Output := FCipher.Decrypt(FEnvelope, FAAD, FCheck);
    except on E: Exception do Failure := E.Message; end;
  finally Done.SetEvent; end;
end;
destructor TDecryptWorker.Destroy;
begin
  { Drain even a never-started/failed-start TThread before releasing fields
    Execute may still touch. The outer destructor retains the object storage. }
  inherited;
  WipeBytes(Output); FEnvelope := nil; FAAD := nil; FCheck := nil;
  Done.Free;
end;
constructor TCloseWorker.Create(Cipher: THandoffCipher);
begin
  inherited Create(True); FreeOnTerminate := False; FCipher := Cipher;
  Done := TEvent.Create(nil, True, False, '');
end;
procedure TCloseWorker.Execute;
begin
  try
    try FCipher.Close;
    except on E: Exception do Failure := E.Message; end;
  finally Done.SetEvent; end;
end;
destructor TCloseWorker.Destroy;
begin inherited; Done.Free; end;

procedure ConcurrentCase(Closing: Boolean);
var Cipher: THandoffCipher; First, Second: TDecryptWorker; Closer: TCloseWorker;
  Entered, ReleaseCall: TEvent; Plain, AAD, Envelope, PublicData: TBytes;
  Cancel: TFunc<Boolean>; FirstStarted, SecondStarted, CloserStarted: Boolean;
  Rejected: Boolean; Deadline: UInt64;
begin
  Cipher := nil; First := nil; Second := nil; Closer := nil;
  Entered := nil; ReleaseCall := nil;
  FirstStarted := False; SecondStarted := False; CloserStarted := False;
  try
    Cipher := THandoffCipher.Create;
    MakeEnvelope(Cipher, Plain, AAD, Envelope);
    Entered := TEvent.Create(nil, True, False, '');
    ReleaseCall := TEvent.Create(nil, True, False, '');
    Cancel := function: Boolean
      begin
        Entered.SetEvent;
        if ReleaseCall.WaitFor(5000) <> wrSignaled then
          raise EInvalidOpException.Create(CozyText_HandoffCryptoProbe_PROBE_BARRIER_TIMEOUT_588cdd11);
        Result := False;
      end;
    First := TDecryptWorker.Create(Cipher, Envelope, AAD, Cancel);
    First.Start; FirstStarted := True;
    Check(Entered.WaitFor(5000) = wrSignaled, CozyText_HandoffCryptoProbe_First_decrypt_never_entered_6b38c314);
    if Closing then
    begin
      Closer := TCloseWorker.Create(Cipher); Closer.Start; CloserStarted := True;
      Rejected := False; Deadline := CozyTick + 5000;
      repeat
        try PublicData := Cipher.PublicBlob;
        except on E: EInvalidOpException do Rejected := E.Message = CozyText_HandoffCryptoProbe_OBJECT_CLOSING_7e76a693; end;
        WipeBytes(PublicData);
        if not Rejected then Sleep(1);
      until Rejected or (CozyTick >= Deadline);
      Check(Rejected, CozyText_HandoffCryptoProbe_Close_did_not_seal_admission_255f0ad5);
      Check(Closer.Done.WaitFor(0) = wrTimeout, CozyText_HandoffCryptoProbe_Close_returned_before_active_decrypt_drained_8d2036d9);
    end
    else
    begin
      Second := TDecryptWorker.Create(Cipher, Envelope, AAD, nil);
      Second.Start; SecondStarted := True;
      Check(Second.Done.WaitFor(5000) = wrSignaled, CozyText_HandoffCryptoProbe_Competing_decrypt_did_not_finish_832c81a0);
      Second.WaitFor;
      Check((Second.Failure = CozyText_HandoffCryptoProbe_HANDOFF_CIPHER_ALREADY_CONSUMED_8d55e5b3) and
        (Length(Second.Output) = 0), CozyText_HandoffCryptoProbe_Two_calls_consumed_the_same_wrapping_key_23fd1d3d);
    end;
    ReleaseCall.SetEvent;
    Check(First.Done.WaitFor(5000) = wrSignaled, CozyText_HandoffCryptoProbe_Active_decrypt_did_not_drain_d9960ec0);
    First.WaitFor;
    if Closing then
    begin
      Check(Closer.Done.WaitFor(5000) = wrSignaled, CozyText_HandoffCryptoProbe_Close_did_not_observe_caller_exit_63ebaaf7);
      Closer.WaitFor;
      Check((Closer.Failure = '') and (First.Failure = CozyText_HandoffCryptoProbe_HANDOFF_CIPHER_CANCELLED_c49cee74) and
        (Length(First.Output) = 0), CozyText_HandoffCryptoProbe_Close_race_published_plaintext_or_failed_drain_c026abf4);
    end
    else
      Check((First.Failure = '') and (Length(First.Output) = Length(Plain)) and
        CompareMem(@First.Output[0], @Plain[0], Length(Plain)), CozyText_HandoffCryptoProbe_Winning_decrypt_failed_8d8e6d85);
  finally
    { A failed assertion must still unblock and join every started caller before
      keys/owners/events are freed; never terminate a running CNG thread. }
    if ReleaseCall <> nil then ReleaseCall.SetEvent;
    if FirstStarted then First.WaitFor;
    if SecondStarted then Second.WaitFor;
    if CloserStarted then Closer.WaitFor;
    First.Free; Second.Free; Closer.Free; Cancel := nil;
    Cipher.Free; Entered.Free; ReleaseCall.Free;
    WipeBytes(Plain); WipeBytes(AAD); WipeBytes(Envelope); WipeBytes(PublicData);
  end;
end;

procedure GenericGcmCases;
var Key, Nonce, AAD, Cipher, Tag, Expected, Output, Original: TBytes;
  Calls, CancelAt, Target: Integer; Cancel: TFunc<Boolean>; Rejected: Boolean;
begin
  { Public fixture generated independently with Node/OpenSSL AES-256-GCM. }
  Key := BytesHex(CozyText_HandoffCryptoProbe_Digest_8a5a4ea8);
  Nonce := BytesHex(CozyText_HandoffCryptoProbe_000102030405060708090a0b_84f2465d);
  AAD := TEncoding.UTF8.GetBytes(CozyText_HandoffCryptoProbe_handoff_probe_public_aad_384c8201);
  Expected := TEncoding.UTF8.GetBytes(CozyText_HandoffCryptoProbe_private_test_data_f69b7cd9);
  Cipher := BytesHex(CozyText_HandoffCryptoProbe_Digest_2e701768); Tag := BytesHex(CozyText_HandoffCryptoProbe_Digest_4705cac3);
  Original := Copy(Key);
  try
    Output := HandoffDecryptAes256Gcm(Key, Nonce, Tag, AAD, Cipher, 65536);
    Check((Length(Output) = Length(Expected)) and
      CompareMem(@Output[0], @Expected[0], Length(Expected)), CozyText_HandoffCryptoProbe_Generic_GCM_fixture_mismatch_7e555ac4);
    WipeBytes(Output);
    Tag[0] := Tag[0] xor 1; Rejected := False;
    try Output := HandoffDecryptAes256Gcm(Key, Nonce, Tag, AAD, Cipher, 65536);
    except on E: EDeviceSecurity do Rejected := True; end;
    Check(Rejected and (Length(Output) = 0), CozyText_HandoffCryptoProbe_Bad_generic_tag_published_plaintext_8b07761e);
    Tag[0] := Tag[0] xor 1;
    for CancelAt := 1 to 4 do
    begin
      Calls := 0; Target := CancelAt;
      Cancel := function: Boolean
        begin Inc(Calls); Result := Calls >= Target; end;
      Rejected := False;
      try Output := HandoffDecryptAes256Gcm(Key, Nonce, Tag, AAD, Cipher, 65536, Cancel);
      except on E: Exception do Rejected := IsCode(E, CozyText_HandoffCryptoProbe_HANDOFF_CIPHER_CANCELLED_c49cee74); end;
      Check(Rejected and (Length(Output) = 0), CozyText_HandoffCryptoProbe_Generic_cancellation_published_plaintext_b89356a1);
    end;
    Check(CompareMem(@Key[0], @Original[0], Length(Key)), CozyText_HandoffCryptoProbe_Borrowed_generic_key_was_modified_08681822);
  finally
    Cancel := nil;
    WipeBytes(Key); WipeBytes(Nonce); WipeBytes(AAD); WipeBytes(Cipher); WipeBytes(Tag);
    WipeBytes(Expected); WipeBytes(Output); WipeBytes(Original);
  end;
end;

var I: Integer;
begin
  try
    SealApiPointerStorage;
    for I := 0 to 9 do RunCase(I);
    RejectGoodAfterBad;
    for I := 1 to 4 do begin CancellationCase(I, False); CancellationCase(I, True); end;
    for I := 1 to 8 do ConcurrentCase(False);
    ConcurrentCase(True);
    GenericGcmCases;
    Writeln(CozyText_HandoffCryptoProbe_PASS_actual_CNG_integrity_owned_output_cancellat_7800f479);
  except on E: Exception do begin
    Writeln(CozyText_HandoffCryptoProbe_FAIL_deb3e2a0, E.ClassName, CozyText_HandoffCryptoProbe_Text_63978312, E.Message); ExitCode := 1;
  end; end;
end.
