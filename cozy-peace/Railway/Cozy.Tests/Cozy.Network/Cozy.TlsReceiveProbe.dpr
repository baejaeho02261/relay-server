program Cozy_TlsReceiveProbe;
{$APPTYPE CONSOLE}
{$IFNDEF GAME_TLS_CONTRACT_TESTS}
  {$MESSAGE FATAL 'Compile the native receive probe with GAME_TLS_CONTRACT_TESTS for provider-path counters.'}
{$ENDIF}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{ No TLS provider substitution or trust exception. The same socket, Schannel,
  UTF-8, JSON and PE file readers used by the product consume fixture bytes. }
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Network in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Network.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsNetwork in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsNetwork.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}

  Winapi.Windows, System.SysUtils, System.JSON, System.NetEncoding,
  System.Diagnostics, Cozy.Api.Pointer, Cozy.Relay.Socket,
  Cozy.Tls in '..\..\Cozy.Source\Cozy.Network\Cozy.Tls.pas',
  Cozy.ProtocolJson, Cozy.CodeIntegrity;

var
  Client: TRelaySocketClient;
  Value, Report: TJSONObject;
  Plan: TCodeIntegrity;
  FileHandle: THandle;
  Bytes: TBytes;
  Line, RetryLine, Stage, CaseID, Nonce, Mode: string;
  Port, Limit: Integer;
  Written: DWORD;
  Connected, Received, Parsed, PeAccepted, Closed: Boolean;
  PreAuthenticationReadRejected, TerminalReadRejected: Boolean;
  PostFailureReadRejected, PostFailureWriteRejected: Boolean;
  Counters: TTlsProbeCounters;
  Clock: TStopwatch;

procedure ExecuteProbe;
begin
  Client := nil; Value := nil; Plan := nil; Report := nil;
  FileHandle := INVALID_HANDLE_VALUE;
  Connected := False; Received := False; Parsed := False; PeAccepted := False;
  PreAuthenticationReadRejected := False; TerminalReadRejected := False;
  PostFailureReadRejected := False; PostFailureWriteRejected := False;
  Stage := CozyText_TlsReceiveProbe_arguments_9ce4d398; Clock := TStopwatch.StartNew;
  try
    try
      if ParamCount <> 7 then raise EArgumentException.Create(CozyText_TlsReceiveProbe_RECEIVE_PROBE_ARGUMENTS_c197d016);
      CaseID := ParamStr(1); Port := StrToInt(ParamStr(2));
      Limit := StrToInt(ParamStr(4)); Mode := ParamStr(5); Nonce := ParamStr(6);
      if (Port < 1) or (Port > 65535) or (Limit < 1) or (Limit > 16384) or
        ((Mode <> CozyText_TlsReceiveProbe_json_5a8ad8da) and (Mode <> CozyText_TlsReceiveProbe_pe_30911e43) and (Mode <> CozyText_TlsReceiveProbe_json_close_bebd91ef)) or (Length(Nonce) <> 32) or
        (Length(CaseID) > 80) then raise EArgumentException.Create(CozyText_TlsReceiveProbe_RECEIVE_PROBE_ARGUMENTS_c197d016);
      SealApiPointerStorage;
      ResetTlsProbeCounters;
      Client := TRelaySocketClient.Create(3000, Limit);
      PreAuthenticationReadRejected := not Client.ReceiveLine(RetryLine);
      if (not PreAuthenticationReadRejected) or (RetryLine <> '') then
        raise Exception.Create(CozyText_TlsReceiveProbe_RECEIVE_PROBE_PREAUTH_DATA_9a2aaf59);
      Stage := CozyText_TlsReceiveProbe_tls_f915843c;
      Connected := Client.ConnectTLS(CozyText_TlsReceiveProbe_127_0_0_1_ab208a13, Port, CozyText_TlsReceiveProbe_localhost_07a66363, ParamStr(3));
      if Connected then
      begin
        Stage := CozyText_TlsReceiveProbe_send_c21d86de;
        if not Client.SendLine(CozyText_TlsReceiveProbe_JsonFixture_4bde6631 + Nonce + CozyText_TlsReceiveProbe_Text_a0549aed) then
          raise Exception.Create(CozyText_TlsReceiveProbe_RECEIVE_PROBE_SEND_4a2faef4);
        Stage := CozyText_TlsReceiveProbe_receive_c9dbd834;
        Received := Client.ReceiveLine(Line);
        if Received then
        begin
          Stage := CozyText_TlsReceiveProbe_json_5a8ad8da;
          Value := ParseProtocolObject(Line, Limit);
          Parsed := True;
          if Mode = CozyText_TlsReceiveProbe_pe_30911e43 then
          begin
            Stage := CozyText_TlsReceiveProbe_pe_30911e43;
            if not (Value.GetValue(CozyText_TlsReceiveProbe_pe_30911e43) is TJSONString) then
              raise EConvertError.Create(CozyText_TlsReceiveProbe_RECEIVE_PROBE_PE_FIELD_dff55551);
            Bytes := TNetEncoding.Base64.DecodeStringToBytes(Value.GetValue(CozyText_TlsReceiveProbe_pe_30911e43).Value);
            if (Length(Bytes) < 1) or (Length(Bytes) > 8192) then
              raise EConvertError.Create(CozyText_TlsReceiveProbe_RECEIVE_PROBE_PE_BOUND_5169c93a);
            { CREATE_NEW and delete-on-close: never load/execute received data,
              never overwrite an existing file or leave a downloaded image. }
            FileHandle := CreateFile(PChar(ParamStr(7)), GENERIC_READ or GENERIC_WRITE,
              0, nil, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY or FILE_FLAG_DELETE_ON_CLOSE, 0);
            if FileHandle = INVALID_HANDLE_VALUE then RaiseLastOSError;
            if not WriteFile(FileHandle, Bytes[0], Length(Bytes), Written, nil) or
              (Written <> Cardinal(Length(Bytes))) then RaiseLastOSError;
            Plan := TCodeIntegrity.Create(FileHandle, GetModuleHandle(nil));
            PeAccepted := True;
          end;
          if Mode = CozyText_TlsReceiveProbe_json_close_bebd91ef then
          begin
            Stage := CozyText_TlsReceiveProbe_close_ba840388;
            TerminalReadRejected := not Client.ReceiveLine(RetryLine);
            if TerminalReadRejected and (RetryLine <> '') then
              raise Exception.Create(CozyText_TlsReceiveProbe_RECEIVE_PROBE_CLOSED_DATA_9a8269f6);
          end;
        end;
      end;
    except
      on E: EArgumentException do begin
        WriteLn(CozyText_TlsReceiveProbe_JsonFixture_e1d5df92); ExitCode := 2; Exit;
      end;
      on E: Exception do begin
        { Only failures at an exercised boundary are observations. Setup/I/O
          failures must not look like a successful negative PE case. }
        if not (((Stage = CozyText_TlsReceiveProbe_receive_c9dbd834) and (E is EConvertError)) or
          ((Stage = CozyText_TlsReceiveProbe_json_5a8ad8da) and (E is EConvertError)) or
          ((Stage = CozyText_TlsReceiveProbe_pe_30911e43) and (E is ECodeIntegrity))) then
        begin WriteLn(CozyText_TlsReceiveProbe_JsonFixture_52b99ea6); ExitCode := 3; Exit; end;
      end;
    end;
    Closed := (Client = nil) or not Client.IsConnected;
    if Closed and (Client <> nil) then
    begin
      PostFailureReadRejected := not Client.ReceiveLine(RetryLine);
      PostFailureWriteRejected := not Client.SendLine(CozyText_TlsReceiveProbe_JsonFixture_6d37cfcb);
      if (RetryLine <> '') or Client.IsConnected then
        raise Exception.Create(CozyText_TlsReceiveProbe_RECEIVE_PROBE_FAILED_CONTEXT_REUSED_d6d55933);
    end;
    Counters := ReadTlsProbeCounters;
    Report := TJSONObject.Create;
    Report.AddPair(CozyText_TlsReceiveProbe_version_7bd3d051, TJSONNumber.Create(1));
    Report.AddPair(CozyText_TlsReceiveProbe_caseId_93d213c5, CaseID); Report.AddPair(CozyText_TlsReceiveProbe_nonce_495ad839, Nonce);
    Report.AddPair(CozyText_TlsReceiveProbe_nativeReceiveExecuted_0f183d1e, TJSONBool.Create(True));
    Report.AddPair(CozyText_TlsReceiveProbe_tlsConnected_04638418, TJSONBool.Create(Connected));
    Report.AddPair(CozyText_TlsReceiveProbe_lineReceived_2d6619dd, TJSONBool.Create(Received));
    Report.AddPair(CozyText_TlsReceiveProbe_jsonAccepted_b6e0bdba, TJSONBool.Create(Parsed));
    Report.AddPair(CozyText_TlsReceiveProbe_peAccepted_3d5b6406, TJSONBool.Create(PeAccepted));
    Report.AddPair(CozyText_TlsReceiveProbe_transportClosed_ee1df919, TJSONBool.Create(Closed));
    Report.AddPair(CozyText_TlsReceiveProbe_preAuthenticationReadRejected_f2827f31,TJSONBool.Create(PreAuthenticationReadRejected));
    Report.AddPair(CozyText_TlsReceiveProbe_terminalReadRejected_323f0948,TJSONBool.Create(TerminalReadRejected));
    Report.AddPair(CozyText_TlsReceiveProbe_postFailureReadRejected_d43a17a8,TJSONBool.Create(PostFailureReadRejected));
    Report.AddPair(CozyText_TlsReceiveProbe_postFailureWriteRejected_76bfe95a,TJSONBool.Create(PostFailureWriteRejected));
    Report.AddPair(CozyText_TlsReceiveProbe_handshakeIncomplete_148e5d82,TJSONNumber.Create(Counters.HandshakeIncomplete));
    Report.AddPair(CozyText_TlsReceiveProbe_readIncomplete_88aad012,TJSONNumber.Create(Counters.ReadIncomplete));
    Report.AddPair(CozyText_TlsReceiveProbe_readExtra_e4b3fc3c,TJSONNumber.Create(Counters.ReadExtra));
    Report.AddPair(CozyText_TlsReceiveProbe_contextExpired_833dc5b0,TJSONNumber.Create(Counters.ContextExpired));
    Report.AddPair(CozyText_TlsReceiveProbe_realProviderCalls_dfa41e4e,TJSONNumber.Create(Counters.RealProviderCalls));
    Report.AddPair(CozyText_TlsReceiveProbe_providerOverrideCalls_51c1aa8c,TJSONNumber.Create(Counters.ProviderOverrideCalls));
    Report.AddPair(CozyText_TlsReceiveProbe_stage_7a94aaff, Stage);
    Report.AddPair(CozyText_TlsReceiveProbe_elapsedMs_360d7c98, TJSONNumber.Create(Clock.ElapsedMilliseconds));
    WriteLn(Report.ToJSON);
  finally
    Report.Free; Plan.Free; Value.Free; Client.Free;
    if FileHandle <> INVALID_HANDLE_VALUE then CloseHandle(FileHandle);
    if Length(Bytes) <> 0 then FillChar(Bytes[0], Length(Bytes), 0);
  end;
end;

begin
  try
    ExecuteProbe;
  except
    on E: Exception do
    begin
      WriteLn(CozyText_TlsReceiveProbe_JsonFixture_52b99ea6);
      ExitCode := 3;
    end;
  end;
end.
