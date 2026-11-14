program Cozy_RelaySocketProbe;
{$APPTYPE CONSOLE}
{$IFNDEF GAME_RELAY_SOCKET_CONTRACT_TESTS}
  {$MESSAGE FATAL 'Dedicated probe requires GAME_RELAY_SOCKET_CONTRACT_TESTS.'}
{$ENDIF}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
uses
{ Cozy central text imports. }
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Network in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Network.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsNetwork in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsNetwork.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
 Cozy.Clock,
  Winapi.Windows, System.SysUtils, System.Classes, System.JSON,
  Cozy.Relay.Socket, Cozy.Api.Pointer;
var
  Client: TRelaySocketClient;
  Closer: TThread;
  Report: TJSONObject;
  CaseID, Host, Pin, Nonce, Line: string;
  Port, Budget, CancelAfter, CloseAfter: Integer;
  Started, Elapsed: UInt64;
  Connected, Sent, Received, Closed: Boolean;
begin
  Client := nil; Closer := nil; Report := nil;
  Connected := False; Sent := False; Received := False; Closed := False;
  Started := CozyTick;
  try
    try
      SealApiPointerStorage;
      if (ParamCount = 1) and (ParamStr(1) = CozyText_RelaySocketProbe_contracts_edbea367) then
      begin
        RunRelaySocketContractTests;
        WriteLn(CozyText_RelaySocketProbe_JsonFixture_1be8a01d);
        Exit;
      end;
      if ParamCount <> 8 then raise EArgumentException.Create(CozyText_RelaySocketProbe_SOCKET_PROBE_ARGUMENTS_d2732e08);
      CaseID := ParamStr(1); Host := ParamStr(2); Port := StrToInt(ParamStr(3));
      Pin := ParamStr(4); Budget := StrToInt(ParamStr(5));
      CancelAfter := StrToInt(ParamStr(6)); CloseAfter := StrToInt(ParamStr(7));
      Nonce := ParamStr(8);
      if (Length(CaseID) > 80) or (Length(Host) > 253) or
        (Port < 1) or (Port > 65535) or (Budget < 100) or (Budget > 5000) or
        (CancelAfter < -1) or (CancelAfter > Budget) or
        (CloseAfter < -1) or (CloseAfter > Budget) or (Length(Nonce) <> 32) then
        raise EArgumentException.Create(CozyText_RelaySocketProbe_SOCKET_PROBE_ARGUMENTS_d2732e08);
      Client := TRelaySocketClient.Create(Cardinal(Budget), 1024,
        function: Boolean
        begin Result := (CancelAfter >= 0) and
          (CozyTick - Started >= UInt64(CancelAfter)); end);
      Connected := Client.ConnectTLS(Host, Word(Port), CozyText_RelaySocketProbe_localhost_7916ab31, Pin);
      if Connected then
      begin
        Sent := Client.SendLine(CozyText_RelaySocketProbe_JsonFixture_65f4fc3e + Nonce + CozyText_RelaySocketProbe_Text_be09698f);
        if Sent then
        begin
          if CloseAfter >= 0 then
          begin
            Closer := TThread.CreateAnonymousThread(
              procedure
              begin
                Sleep(Cardinal(CloseAfter));
                Client.Close;
              end);
            Closer.FreeOnTerminate := False; Closer.Start;
          end;
          Received := Client.ReceiveLine(Line);
        end;
      end;
      Elapsed := CozyTick - Started;
      if Closer <> nil then begin Closer.WaitFor; FreeAndNil(Closer); end;
      Closed := not Client.IsConnected;
      Client.Free; Client := nil;
      Report := TJSONObject.Create;
      Report.AddPair(CozyText_RelaySocketProbe_version_7af40718, TJSONNumber.Create(1));
      Report.AddPair(CozyText_RelaySocketProbe_nativeSocketExecuted_18214f57, TJSONBool.Create(True));
      Report.AddPair(CozyText_RelaySocketProbe_caseId_fd18a030, CaseID); Report.AddPair(CozyText_RelaySocketProbe_nonce_596a8e93, Nonce);
      Report.AddPair(CozyText_RelaySocketProbe_connected_151d155e, TJSONBool.Create(Connected));
      Report.AddPair(CozyText_RelaySocketProbe_sent_e69c6829, TJSONBool.Create(Sent));
      Report.AddPair(CozyText_RelaySocketProbe_received_f079a037, TJSONBool.Create(Received));
      Report.AddPair(CozyText_RelaySocketProbe_closed_3a50791e, TJSONBool.Create(Closed));
      Report.AddPair(CozyText_RelaySocketProbe_line_4a91a826, Line);
      Report.AddPair(CozyText_RelaySocketProbe_elapsedMs_b3aa894a, TJSONNumber.Create(Int64(Elapsed)));
      WriteLn(Report.ToJSON);
    except
      on E: Exception do
      begin
        WriteLn(CozyText_RelaySocketProbe_JsonFixture_8702f2e4);
        ExitCode := 1;
      end;
    end;
  finally
    if Closer <> nil then begin Closer.WaitFor; Closer.Free; end;
    Report.Free; Client.Free;
  end;
end.
