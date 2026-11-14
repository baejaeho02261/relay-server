{ Compiled only with GAME_TLS_CONTRACT_TESTS. These fixtures call the exact
  private production validators above; no socket, server or session is used. Provider faults below are explicitly injected. }
type
  TTlsContractTransport = class
  public
    Calls: Integer;
    ReentrantStream: TGameTlsStream;
    ReentrantRejected: Boolean;
    Input: TBytes;
    InputOffset, FragmentSize: Integer;
    function ReadBytes(Buffer: Pointer; Count: Integer): Integer;
    function WriteBytes(Buffer: Pointer; Count: Integer): Boolean;
  end;

function TTlsContractTransport.ReadBytes(Buffer: Pointer; Count: Integer): Integer;
begin
  Inc(Calls);
  if ReentrantStream <> nil then
    ReentrantRejected := ReentrantStream.Read(Buffer, Count) = -1;
  Result := -1;
  if InputOffset<Length(Input) then
  begin
    Result:=Length(Input)-InputOffset;
    if Result>Count then Result:=Count;
    if (FragmentSize>0) and (Result>FragmentSize) then Result:=FragmentSize;
    Move(Input[InputOffset],Buffer^,Result); Inc(InputOffset,Result);
  end;
end;

function TTlsContractTransport.WriteBytes(Buffer: Pointer; Count: Integer): Boolean;
begin
  Inc(Calls);
  Result := False;
end;

{ Controlled provider descriptor/status faults below are NOT real Schannel
  records. They exercise the same production state machine with private test
  injection; the separate ReceiveProbe never enables this hook. }
var TlsFaultMode, TlsFaultCalls: Integer;
function ControlledDecrypt(var Context: TSecurityHandle;
  var MessageBuffers: TSecBufferDesc; Sequence: DWORD; Quality: Pointer): LongInt; stdcall;
type TBuffers = array[0..3] of TSecBuffer; PBuffers = ^TBuffers;
var Buffers:PBuffers; Base:PByte; Count:DWORD;
begin
  Inc(TlsFaultCalls); Buffers:=PBuffers(MessageBuffers.Buffers);
  Base:=Buffers^[0].Data; Count:=Buffers^[0].Size;
  if TlsFaultMode=7 then raise EInvalidOpException.Create(CozyText_TlsContracts_TLS_TEST_PROVIDER_EXCEPTION_486bee08);
  if TlsFaultMode in [1,2,3] then
  begin
    { A provider may have written in-place before reporting failure; none of
      those bytes may be published, and the owner must wipe them all. }
    if Count>0 then FillChar(Base^,Count,$4D);
    case TlsFaultMode of
      1:Exit(-2146893041); { SEC_E_MESSAGE_ALTERED }
      2:Exit(SecContextExpired);
      3:Exit($00090321); { SEC_I_RENEGOTIATE }
    end;
  end;
  if Count<6 then Exit(SecIncompleteMessage);
  FillChar(Buffers^,SizeOf(TBuffers),0);
  Buffers^[0].Kind:=BufferHeader; Buffers^[0].Size:=1; Buffers^[0].Data:=Base;
  Buffers^[1].Kind:=BufferData; Buffers^[1].Size:=3;
  Buffers^[1].Data:=Pointer(NativeUInt(Base)+1);
  Buffers^[2].Kind:=BufferTrailer; Buffers^[2].Size:=2;
  Buffers^[2].Data:=Pointer(NativeUInt(Base)+4);
  if Count>6 then begin Buffers^[3].Kind:=BufferExtra; Buffers^[3].Size:=Count-6; end;
  if TlsFaultMode=4 then Buffers^[1].Data:=Pointer(NativeUInt(Base)+Count);
  if TlsFaultMode=5 then begin Buffers^[3].Kind:=BufferExtra; Buffers^[3].Size:=Count; end;
  if TlsFaultMode=6 then begin Buffers^[1].Size:=0; Buffers^[1].Data:=nil; end;
  if TlsFaultMode=8 then MessageBuffers.Count:=5;
  Result:=SecOk;
end;
function OwnedBufferZero(Owner:TApiSensitiveBuffer):Boolean;
var Scope:TApiSensitiveScope; View:TApiBuffer; I:NativeUInt;
begin
  Result:=True; Scope:=Owner.OpenRead;
  try
    View:=Scope.Buffer;
    for I:=0 to View.Capacity-1 do if PByte(View.Read(I,1))^<>0 then Exit(False);
  finally Scope.Free; end;
end;
procedure RunTlsStateFaultTests;
var Transport:TTlsContractTransport; Stream:TGameTlsStream;
  Output:array[0..7] of Byte; Mode, Count, Checks, BeforeCalls:Integer;
  Counters:TTlsProbeCounters; Raised:Boolean; Scope:TApiSensitiveScope;
  procedure Check(Value:Boolean; const Message:string);
  begin if not Value then raise Exception.Create(CozyText_TlsContracts_TLS_state_fault_e1592d62+Message); Inc(Checks); end;
  procedure Fresh(Fragments:Integer; Truncated:Boolean);
  begin
    FreeAndNil(Stream); Transport.InputOffset:=0; Transport.FragmentSize:=Fragments;
    SetLength(Transport.Input,12);
    Transport.Input[0]:=0;Transport.Input[1]:=Ord('A');Transport.Input[2]:=Ord('B');Transport.Input[3]:=Ord('C');Transport.Input[4]:=0;Transport.Input[5]:=0;
    Transport.Input[6]:=0;Transport.Input[7]:=Ord('D');Transport.Input[8]:=Ord('E');Transport.Input[9]:=Ord('F');Transport.Input[10]:=0;Transport.Input[11]:=0;
    if Truncated then SetLength(Transport.Input,5);
    Stream:=TGameTlsStream.Create(Transport.ReadBytes,Transport.WriteBytes);
    Stream.FHandshakeStarted:=True; Stream.FAuthenticated:=True;
    { No fabricated security handle reaches Windows: only the explicit private
      hook is enabled. ProviderOverrideCalls proves that distinction. }
    ResetTlsProbeCounters; TlsFaultCalls:=0;
  end;
begin
  Checks:=0; Transport:=TTlsContractTransport.Create; Stream:=nil;
  TlsTestDecrypt:=ControlledDecrypt;
  try
    TlsFaultMode:=0; Fresh(0,False);
    Check(Stream.Read(@Output[0],1)=1,CozyText_TlsContracts_partial_plaintext_read_dea31f10);
    Check(Output[0]=Ord('A'),CozyText_TlsContracts_first_plaintext_byte_e1616b17);
    Check((Stream.FPlainCount=2) and (Stream.FPlainOffset=1),CozyText_TlsContracts_cursor_retains_pending_bytes_bf0666e0);
    Scope:=Stream.FPlain.OpenRead;
    try Check(PByte(Scope.Buffer.Read(0,1))^=0,CozyText_TlsContracts_consumed_byte_wiped_1fffe1c0); finally Scope.Free; end;
    Check(Stream.Read(@Output[0],2)=2,CozyText_TlsContracts_remaining_plaintext_read_e97b64f8);
    Check((Output[0]=Ord('B')) and (Output[1]=Ord('C')),CozyText_TlsContracts_tail_without_copied_array_06a81df0);
    Check(Stream.Read(@Output[0],3)=3,CozyText_TlsContracts_coalesced_second_record_69c0d7e5);
    Check((Output[0]=Ord('D')) and (Output[2]=Ord('F')),CozyText_TlsContracts_coalesced_bytes_preserved_882ce063);
    Counters:=ReadTlsProbeCounters;
    Check((Counters.ReadExtra=1) and (Counters.ProviderOverrideCalls=2) and
      (Counters.RealProviderCalls=0),CozyText_TlsContracts_controlled_provider_attribution_9a830629);
    Check(OwnedBufferZero(Stream.FPlain) and OwnedBufferZero(Stream.FCipher),CozyText_TlsContracts_consumed_owners_wiped_5af47979);
    Fresh(2,False); Check(Stream.Read(@Output[0],3)=3,CozyText_TlsContracts_fragmented_record_completed_fcf34d60);
    Counters:=ReadTlsProbeCounters; Check(Counters.ReadIncomplete=2,CozyText_TlsContracts_incomplete_status_exercised_28a83732);
    Fresh(0,True); FillChar(Output,SizeOf(Output),$A5);
    Check(Stream.Read(@Output[0],SizeOf(Output))=-1,CozyText_TlsContracts_truncated_record_rejected_6290af2e);
    Check(Output[0]=$A5,CozyText_TlsContracts_truncation_publishes_no_plaintext_833b479a);
    Check(not Stream.FAuthenticated and OwnedBufferZero(Stream.FCipher) and OwnedBufferZero(Stream.FPlain),CozyText_TlsContracts_truncation_clears_owners_359f18ca);
    for Mode:=1 to 8 do
    begin
      TlsFaultMode:=Mode; Fresh(0,False); FillChar(Output,SizeOf(Output),$A5); Raised:=False; Count:=-1;
      try Count:=Stream.Read(@Output[0],SizeOf(Output)); except on E:EInvalidOpException do Raised:=True; end;
      Check((Count=-1) or Raised,CozyText_TlsContracts_fault_cannot_return_plaintext_4e959d9d);
      Check(Output[0]=$A5,CozyText_TlsContracts_fault_output_sentinel_intact_f7a7cf69);
      Check(not Stream.FAuthenticated and not Stream.FHaveContext and not Stream.FHaveCredential,CozyText_TlsContracts_fault_terminal_state_76fa46bc);
      Check(OwnedBufferZero(Stream.FCipher) and OwnedBufferZero(Stream.FPlain),CozyText_TlsContracts_fault_owners_wiped_efcf6fde);
      if Mode=2 then begin Counters:=ReadTlsProbeCounters; Check(Counters.ContextExpired=1,CozyText_TlsContracts_close_notify_recognized_5beebaaa); end;
      BeforeCalls:=Transport.Calls;
      Check(Stream.Read(@Output[0],1)=-1,CozyText_TlsContracts_terminal_read_rejected_996f12ba);
      Check(not Stream.Write(@Output[0],1),CozyText_TlsContracts_terminal_write_rejected_e6999b96);
      Check(not Stream.Handshake(CozyText_TlsContracts_localhost_a900532b,StringOfChar('0',64)),CozyText_TlsContracts_terminal_handshake_rejected_69a2d100);
      Check(Transport.Calls=BeforeCalls,CozyText_TlsContracts_terminal_no_network_reuse_7efed750);
    end;
    TlsFaultMode:=0; Fresh(0,False); Stream.FAuthenticated:=False;
    BeforeCalls:=TlsFaultCalls; FillChar(Output,SizeOf(Output),$A5);
    Check(Stream.Read(@Output[0],1)=-1,CozyText_TlsContracts_unauthenticated_read_rejected_a01469b5);
    Check((Output[0]=$A5) and (TlsFaultCalls=BeforeCalls),CozyText_TlsContracts_no_provider_or_plaintext_before_authentication_4e6d1585);
  finally
    try Stream.Free; finally TlsTestDecrypt:=nil; Wipe(Transport.Input); Transport.Free; end;
  end;
  System.Writeln(CozyText_TlsContracts_PASS_bb33c9c1,Checks,CozyText_TlsContracts_controlled_TLS_state_fault_checks_provider_subst_cae37225);
end;

var TlsContextMode, TlsDeleteCalls, TlsFreeCredentialCalls:Integer;
function ControlledAcquire(Principal, PackageName:PWideChar;
  CredentialUse:DWORD; LogonId, AuthenticationData, GetKey, GetKeyArgument:Pointer;
  out Credential:TSecurityHandle; out Expiry:Int64):LongInt; stdcall;
begin Credential.Lower:=2; Credential.Upper:=3; Expiry:=0; Result:=SecOk; end;
function ControlledInitialize(Credential, Context:PSecurityHandle;
  TargetName:PWideChar; Requirements, Reserved1, DataRepresentation:DWORD;
  Input:PSecBufferDesc; Reserved2:DWORD; out NewContext:TSecurityHandle;
  Output:PSecBufferDesc; out Attributes:DWORD; out Expiry:Int64):LongInt; stdcall;
begin
  Attributes:=0; Expiry:=0;
  if TlsContextMode<>2 then begin NewContext.Lower:=4; NewContext.Upper:=5; end;
  if TlsContextMode=1 then raise EInvalidOpException.Create(CozyText_TlsContracts_TLS_TEST_PARTIAL_CONTEXT_EXCEPTION_9c0964c4);
  Result:=-2146893041;
end;
function ControlledDelete(var Context:TSecurityHandle):LongInt; stdcall;
begin
  if not SecurityHandleValid(Context) then raise Exception.Create(CozyText_TlsContracts_invalid_handle_sent_to_delete_c8f1d264);
  Inc(TlsDeleteCalls); InvalidateSecurityHandle(Context);
  if TlsContextMode=3 then raise EInvalidOpException.Create(CozyText_TlsContracts_TLS_TEST_DELETE_EXCEPTION_22fc42be);
  Result:=SecOk;
end;
function ControlledFreeCredential(var Credential:TSecurityHandle):LongInt; stdcall;
begin Inc(TlsFreeCredentialCalls); InvalidateSecurityHandle(Credential); Result:=SecOk; end;
procedure RunTlsContextCleanupTests;
var Transport:TTlsContractTransport; Stream:TGameTlsStream;
  Mode,Checks:Integer; Failed,Raised:Boolean; Scope:TApiSensitiveScope;
  Counters:TTlsProbeCounters;
  procedure Check(Value:Boolean; const Message:string);
  begin if not Value then raise Exception.Create(CozyText_TlsContracts_TLS_context_cleanup_67e041e4+Message); Inc(Checks); end;
begin
  Checks:=0; Transport:=TTlsContractTransport.Create; Stream:=nil;
  TlsTestAcquire:=ControlledAcquire; TlsTestInitialize:=ControlledInitialize;
  TlsTestDelete:=ControlledDelete; TlsTestFreeCredential:=ControlledFreeCredential;
  try
    for Mode:=0 to 3 do
    begin
      FreeAndNil(Stream); Stream:=TGameTlsStream.Create(Transport.ReadBytes,Transport.WriteBytes);
      TlsContextMode:=Mode; TlsDeleteCalls:=0; TlsFreeCredentialCalls:=0; ResetTlsProbeCounters;
      Scope:=Stream.FPlain.OpenWrite;
      try FillChar(Scope.Buffer.Write(0,8)^,8,$A5); finally Scope.Free; end;
      Scope:=Stream.FCipher.OpenWrite;
      try FillChar(Scope.Buffer.Write(0,8)^,8,$A5); finally Scope.Free; end;
      Failed:=False; Raised:=False;
      try Failed:=not Stream.Handshake(CozyText_TlsContracts_localhost_a900532b,StringOfChar('0',64));
      except on E:EInvalidOpException do Raised:=True; end;
      Check(Failed or Raised,CozyText_TlsContracts_failed_handshake_never_succeeds_03693a7d);
      if Mode=2 then Check(TlsDeleteCalls=0,CozyText_TlsContracts_untouched_invalid_handle_not_deleted_5278b008)
      else Check(TlsDeleteCalls=1,CozyText_TlsContracts_partial_failed_handle_deleted_exactly_once_207172ef);
      Check(TlsFreeCredentialCalls=1,CozyText_TlsContracts_credentials_freed_despite_context_failure_d1f2b8d1);
      Check(not Stream.FHaveContext and not Stream.FHaveCredential and not Stream.FAuthenticated,CozyText_TlsContracts_terminal_owner_flags_8f755f17);
      Check(not SecurityHandleValid(Stream.FContext),CozyText_TlsContracts_retired_context_invalidated_2a6c6d95);
      Check(OwnedBufferZero(Stream.FPlain) and OwnedBufferZero(Stream.FCipher),CozyText_TlsContracts_buffers_wiped_after_handshake_or_cleanup_excepti_928b5930);
      Counters:=ReadTlsProbeCounters;
      Check((Counters.RealProviderCalls=0) and (Counters.ProviderOverrideCalls>=3),CozyText_TlsContracts_context_faults_are_controlled_never_real_handles_09dc60f6);
    end;
    { An exceptional Clear must still attempt the second owner. This test
      deliberately violates the first owner's no-active-scope Clear rule. }
    FreeAndNil(Stream); Stream:=TGameTlsStream.Create(Transport.ReadBytes,Transport.WriteBytes);
    Scope:=Stream.FCipher.OpenWrite;
    try FillChar(Scope.Buffer.Write(0,8)^,8,$A5); finally Scope.Free; end;
    Stream.FCipherCount:=8; Stream.FPlainCount:=8; Stream.FPlainOffset:=1;
    Scope:=Stream.FPlain.OpenRead;
    try
      Raised:=False;
      try Stream.ClearBuffers; except on E:EInvalidOpException do Raised:=True; end;
      Check(Raised,CozyText_TlsContracts_active_first_owner_rejects_Clear_2314a426);
      Check(OwnedBufferZero(Stream.FCipher),CozyText_TlsContracts_second_owner_still_wiped_a134e57e);
      Check((Stream.FPlainCount=0) and (Stream.FPlainOffset=0) and (Stream.FCipherCount=0),CozyText_TlsContracts_counts_reset_before_fallible_Clear_062b6487);
    finally Scope.Free; end;
    Stream.ClearBuffers;
  finally
    try Stream.Free;
    finally
      TlsTestAcquire:=nil; TlsTestInitialize:=nil; TlsTestDelete:=nil; TlsTestFreeCredential:=nil;
      Transport.Free;
    end;
  end;
  System.Writeln(CozyText_TlsContracts_PASS_bb33c9c1,Checks,CozyText_TlsContracts_controlled_TLS_partial_context_and_exception_cle_5ed12419);
end;

procedure RunTlsContractTests;
var
  Bytes: TBytes;
  Buffers: array[0..3] of TSecBuffer;
  Extra: DWORD;
  Transport: TTlsContractTransport;
  Stream: TGameTlsStream;
  Rejected: Boolean;
  Checks: Integer;
  Scratch: Byte;
  PreviousCalls: Integer;
  procedure Check(Condition: Boolean; const Text: string);
  begin
    if not Condition then raise Exception.Create(CozyText_TlsContracts_TLS_contract_462a883b + Text);
    Inc(Checks);
  end;
  procedure SetBuffer(Index: Integer; Kind, Size: DWORD; Offset: Integer);
  begin
    Buffers[Index].Kind := Kind;
    Buffers[Index].Size := Size;
    Buffers[Index].Data := Pointer(NativeUInt(@Bytes[0]) + NativeUInt(Offset));
  end;
begin
  Checks := 0;
  Check(NativeTlsLayoutValid, CozyText_TlsContracts_Windows_x64_SSPI_sizes_and_member_offsets_c3096fc5);
  SetLength(Bytes, 64);
  try
    Check(Inside(Bytes, @Bytes[0], 64), CozyText_TlsContracts_entire_owned_buffer_accepted_77ff92a7);
    Check(Inside(Bytes, @Bytes[63], 1), CozyText_TlsContracts_last_byte_accepted_b53d435b);
    Check(not Inside(Bytes, @Bytes[63], 2), CozyText_TlsContracts_last_byte_overflow_rejected_96460492);
    Check(not Inside(Bytes, nil, 0), CozyText_TlsContracts_nil_span_rejected_f764742b);
    Check(not Inside(Bytes, Pointer(NativeUInt(@Bytes[0]) - 1), 1),
      CozyText_TlsContracts_address_below_allocation_rejected_06930c74);
    Check(Inside(Bytes, Pointer(NativeUInt(@Bytes[0]) + 64), 0),
      CozyText_TlsContracts_one_past_empty_span_accepted_9e02897d);
    Check(not Inside(Bytes, Pointer(NativeUInt(@Bytes[0]) + 64), 1),
      CozyText_TlsContracts_one_past_nonempty_span_rejected_d60c1486);
    Check(not Inside(Bytes, @Bytes[0], High(DWORD)), CozyText_TlsContracts_DWORD_length_overflow_rejected_c24f6bba);

    FillChar(Buffers, SizeOf(Buffers), 0);
    SetBuffer(0, BufferData, 20, 5);
    Buffers[3].Kind := BufferExtra;
    Buffers[3].Size := 16;
    Buffers[3].Data := nil; // Documented: EXTRA pointer is not a copy to consume.
    Check(PlainBuffersValid(Bytes, Buffers, Extra) and (Extra = 16),
      CozyText_TlsContracts_valid_plaintext_with_counted_unprocessed_tail_bc3d3929);
    FillChar(Buffers[0], SizeOf(Buffers[0]), 0);
    Check(PlainBuffersValid(Bytes, Buffers, Extra) and (Extra = 16),
      CozyText_TlsContracts_zero_plaintext_with_only_an_EXTRA_output_accepte_d6b77fa8);
    SetBuffer(0, BufferData, 20, 5);
    Buffers[3].Size := 65;
    Check(not PlainBuffersValid(Bytes, Buffers, Extra), CozyText_TlsContracts_oversized_extra_rejected_92295115);
    Buffers[3].Size := 16;
    Buffers[2].Kind := BufferExtra;
    Buffers[2].Size := 1;
    Check(not PlainBuffersValid(Bytes, Buffers, Extra), CozyText_TlsContracts_duplicate_extra_rejected_0c1c06f7);
    FillChar(Buffers[2], SizeOf(Buffers[2]), 0);
    SetBuffer(0, BufferData, 17, 40);
    Check(not PlainBuffersValid(Bytes, Buffers, Extra), CozyText_TlsContracts_plaintext_alias_into_encrypted_tail_rejected_cc94e02c);
    SetBuffer(0, BufferData, 20, 5);
    SetBuffer(1, BufferData, 6, 24);
    Check(not PlainBuffersValid(Bytes, Buffers, Extra), CozyText_TlsContracts_overlapping_plaintext_rejected_cd7a10d8);
    SetBuffer(1, BufferData, 6, 25);
    Check(PlainBuffersValid(Bytes, Buffers, Extra), CozyText_TlsContracts_adjacent_plaintext_spans_accepted_d26400d4);
    SetBuffer(1, BufferData, 2, 63);
    Check(not PlainBuffersValid(Bytes, Buffers, Extra), CozyText_TlsContracts_out_of_allocation_plaintext_rejected_dc1d673c);

    FillChar(Buffers, SizeOf(Buffers), 0);
    SetBuffer(0, BufferHeader, 5, 0);
    SetBuffer(1, BufferData, 20, 5);
    SetBuffer(2, BufferTrailer, 16, 25);
    Check(EncryptedBuffersValid(Bytes, Buffers), CozyText_TlsContracts_valid_bounded_encrypted_fragments_559dd232);
    SetBuffer(0, BufferHeader, 3, 0);
    SetBuffer(1, BufferData, 12, 3);
    SetBuffer(2, BufferTrailer, 8, 15);
    Check(EncryptedBuffersValid(Bytes, Buffers),
      CozyText_TlsContracts_smaller_returned_header_data_and_trailer_sizes_a_d58163af);
    SetBuffer(1, BufferData, 12, 5);
    SetBuffer(2, BufferTrailer, 8, 25);
    Check(EncryptedBuffersValid(Bytes, Buffers),
      CozyText_TlsContracts_nonoverlapping_fragment_gaps_accepted_after_outp_d0b11ddc);
    SetBuffer(0, BufferHeader, 5, 0);
    SetBuffer(1, BufferData, 20, 5);
    SetBuffer(2, BufferTrailer, 1, 24);
    Check(not EncryptedBuffersValid(Bytes, Buffers), CozyText_TlsContracts_overlapping_encrypted_trailer_rejected_6c478623);
    SetBuffer(2, BufferTrailer, 16, 63);
    Check(not EncryptedBuffersValid(Bytes, Buffers), CozyText_TlsContracts_invalid_final_fragment_rejected_before_send_0e5226f2);
    SetBuffer(2, BufferTrailer, 0, 25);
    Check(EncryptedBuffersValid(Bytes, Buffers), CozyText_TlsContracts_zero_length_trailer_accepted_f040f00c);
    SetBuffer(3, BufferData, 1, 40);
    Check(not EncryptedBuffersValid(Bytes, Buffers), CozyText_TlsContracts_unexpected_fourth_output_rejected_539eb876);
    FillChar(Buffers[3], SizeOf(Buffers[3]), 0);
    Buffers[1].Kind := BufferToken;
    Check(not EncryptedBuffersValid(Bytes, Buffers), CozyText_TlsContracts_wrong_encrypted_content_type_rejected_53904fef);

    SetLength(Bytes, MaxTlsRecordBytes + 1);
    FillChar(Buffers, SizeOf(Buffers), 0);
    SetBuffer(0, BufferData, MaxTlsRecordBytes, 0);
    Check(PlainBuffersValid(Bytes, Buffers, Extra), CozyText_TlsContracts_plaintext_aggregate_bound_accepted_5d82520a);
    Buffers[0].Size := MaxTlsRecordBytes + 1;
    Check(not PlainBuffersValid(Bytes, Buffers, Extra), CozyText_TlsContracts_plaintext_aggregate_overflow_rejected_8c6d26aa);
    Wipe(Bytes);
    Check(not Inside(Bytes, Pointer(1), 0), CozyText_TlsContracts_empty_owned_allocation_rejected_e501e6eb);
  finally
    Wipe(Bytes);
  end;

  Transport := TTlsContractTransport.Create;
  try
    Rejected := False;
    try
      Stream := TGameTlsStream.Create(nil, Transport.WriteBytes);
      Stream.Free;
    except
      on E: EArgumentException do Rejected := True;
    end;
    Check(Rejected, CozyText_TlsContracts_nil_read_callback_rejected_at_construction_4eb63b60);
    Rejected := False;
    try
      Stream := TGameTlsStream.Create(Transport.ReadBytes, nil);
      Stream.Free;
    except
      on E: EArgumentException do Rejected := True;
    end;
    Check(Rejected, CozyText_TlsContracts_nil_write_callback_rejected_at_construction_7c9756f2);
    Stream := TGameTlsStream.Create(Transport.ReadBytes, Transport.WriteBytes);
    try
      Check(not Stream.Handshake('', ''), CozyText_TlsContracts_invalid_handshake_rejected_without_I_O_d6511a97);
      Check(Stream.Read(nil, 1) = -1, CozyText_TlsContracts_unauthenticated_read_rejected_a01469b5);
      Check(not Stream.Write(nil, 1), CozyText_TlsContracts_unauthenticated_write_rejected_11ca9c5a);
      Check(Transport.Calls = 0, CozyText_TlsContracts_invalid_inputs_never_reach_transport_callbacks_57a7c25d);
      Stream.FCallLock := 1;
      Check(not Stream.Handshake(CozyText_TlsContracts_localhost_a900532b, StringOfChar('0', 64)),
        CozyText_TlsContracts_busy_handshake_rejected_without_touching_context_d1bc73da);
      Check(Stream.Read(@Scratch, 1) = -1, CozyText_TlsContracts_busy_read_rejected_014347ef);
      Check(not Stream.Write(@Scratch, 1), CozyText_TlsContracts_busy_write_rejected_f8c1c045);
      Check(Transport.Calls = 0, CozyText_TlsContracts_busy_operations_never_call_transport_faa31272);
      Stream.FCallLock := 0;
      { Fake only the precondition: empty cipher forces the callback path,
        before DecryptMessage. No fake handle is passed to Windows. }
      Stream.FAuthenticated := True;
      Stream.FHandshakeStarted := True;
      Transport.ReentrantStream := Stream;
      Check(Stream.Read(@Scratch, 1) = -1, CozyText_TlsContracts_transport_read_failure_propagated_0292e9c0);
      Check(Transport.ReentrantRejected, CozyText_TlsContracts_callback_recursion_rejected_without_deadlock_c3e51891);
      Check(not Stream.FAuthenticated and not Stream.FHaveContext and
        not Stream.FHaveCredential and (Stream.FPlainCount = 0) and
        (Stream.FCipherCount = 0), CozyText_TlsContracts_failed_stream_immediately_clears_native_state_8f2fed14);
      PreviousCalls := Transport.Calls;
      Check(not Stream.Handshake(CozyText_TlsContracts_localhost_a900532b, StringOfChar('0', 64)),
        CozyText_TlsContracts_failed_stream_cannot_restart_handshake_ed34d9ee);
      Check(Stream.Read(@Scratch, 1) = -1, CozyText_TlsContracts_failed_stream_cannot_read_again_390c0b20);
      Check(Transport.Calls = PreviousCalls, CozyText_TlsContracts_terminal_state_performs_no_network_IO_0759b78a);
      Check(Stream.FCallLock = 0, CozyText_TlsContracts_operation_guard_released_on_failure_217ac1ef);
      Transport.ReentrantStream := nil;
    finally
      Stream.Free;
    end;
  finally
    Transport.Free;
  end;
  System.Writeln(CozyText_TlsContracts_PASS_bb33c9c1, Checks, CozyText_TlsContracts_native_TLS_ABI_and_buffer_contract_checks_55ab5fa6);
  RunTlsStateFaultTests;
  RunTlsContextCleanupTests;
end;
