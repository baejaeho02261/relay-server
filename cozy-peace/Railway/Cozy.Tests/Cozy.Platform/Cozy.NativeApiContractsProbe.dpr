program Cozy_NativeApiContractsProbe;
{$IFDEF FPC}{$MODE DELPHI}{$ELSE}{$APPTYPE CONSOLE}{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
 {$IFDEF FPC}SysUtils{$ELSE}System.SysUtils{$ENDIF}, Cozy.Api.Contracts;
var Data, Output: TBytes; ReadOnly, Writable, Other: TApiBuffer;
  Passed, I: Integer; Failed: Boolean; Command: array[0..3] of WideChar;
procedure Require(Value: Boolean);
begin if not Value then raise Exception.Create(CozyText_NativeApiContractsProbe_API_CONTRACT_FAILURE_b9a5ff80); Inc(Passed); end;
procedure RunSensitiveBufferContracts;
var Owner: TApiSensitiveBuffer; Scope, Extra: TApiSensitiveScope;
  View, Escaped, Fresh: TApiBuffer; Failed: Boolean; J: Integer;
  InFlight: PByte;
begin
  Owner := TApiSensitiveBuffer.Create(32);
  Scope := nil;
  try
    Require(Owner.Capacity = 32);
    Scope := Owner.OpenWrite;
    View := Scope.Buffer;
    for J := 0 to 31 do Require(PByte(View.Read(J, 1))^ = 0);
    FillChar(View.Write(0, 32)^, 32, $A5);
    Escaped := View;
    Failed := False; Extra := nil;
    try Extra := Owner.OpenRead;
    except on E: EInvalidOpException do Failed := True; end;
    Extra.Free; Require(Failed);
    Failed := False;
    try Owner.Clear;
    except on E: EInvalidOpException do Failed := True; end;
    Require(Failed);
    Scope.Close; Scope.Close;
    Scope.Free; Scope := nil;
    { Copying a view does not let it outlive the scope, including empty reads. }
    Failed := False;
    try Escaped.Read(0, 0);
    except on E: EInvalidOpException do Failed := True; end;
    Require(Failed);
    Failed := False;
    try Require(Escaped.Capacity = 32);
    except on E: EInvalidOpException do Failed := True; end;
    Require(Failed);
    Owner.Clear;
    Scope := Owner.OpenRead;
    Fresh := Scope.Buffer;
    for J := 0 to 31 do Require(PByte(Fresh.Read(J, 1))^ = 0);
    Failed := False;
    try Fresh.Write(0, 1);
    except on E: EArgumentException do Failed := True; end;
    Require(Failed);
    { A later scope never reactivates a prior token. }
    Failed := False;
    try Escaped.Disjoint(Fresh);
    except on E: EInvalidOpException do Failed := True; end;
    Require(Failed);
    Scope.Free; Scope := nil;
    { Exception/cancellation cleanup retires all copies. }
    try
      Scope := Owner.OpenWrite;
      try
        Escaped := Scope.Buffer;
        PByte(Escaped.Write(0, 1))^ := $7C;
        raise EAbort.Create(CozyText_NativeApiContractsProbe_TEST_CANCELLED_45b77352);
      finally Scope.Free; Scope := nil; end;
    except on E: EAbort do ; end;
    Failed := False;
    try Escaped.Completed(1, 1);
    except on E: EInvalidOpException do Failed := True; end;
    Require(Failed);
    Scope := Owner.OpenRead;
    View := Scope.Buffer;
    InFlight := PByte(View.Read(0, 1));
    Owner.Close;
    Owner.Close;
    { Close does not free storage used by an already pending synchronous call. }
    Require(InFlight^ = $7C);
    Failed := False;
    try View.Read(0, 1);
    except on E: EInvalidOpException do Failed := True; end;
    Require(Failed);
    Failed := False; Extra := nil;
    try Extra := Owner.OpenRead;
    except on E: EInvalidOpException do Failed := True; end;
    Extra.Free; Require(Failed);
    Owner.Free; Owner := nil;
    Failed := False;
    try View.Write(0, 0);
    except on E: EInvalidOpException do Failed := True; end;
    Require(Failed);
    Scope.Free; Scope := nil;
    { Never inspect InFlight after the scope releases its allocation. }
  finally Scope.Free; Owner.Free; end;
  Owner := TApiSensitiveBuffer.Create(0);
  Scope := nil;
  try
    Scope := Owner.OpenRead;
    View := Scope.Buffer;
    Require(View.Capacity = 0);
    Require(View.Read(0, 0) = nil);
  finally Scope.Free; Owner.Free; end;
  Failed := False; Owner := nil;
  try Owner := TApiSensitiveBuffer.Create(NativeUInt(MaxApiSensitiveBytes) + 1);
  except on E: EArgumentException do Failed := True; end;
  Owner.Free; Require(Failed);
  Owner := nil; Scope := nil;
  try
    try
      Owner := TApiSensitiveBuffer.Create(8);
      Scope := Owner.OpenWrite; Escaped := Scope.Buffer;
      FillChar(Escaped.Write(0, 8)^, 8, $B7);
      raise EAbort.Create(CozyText_NativeApiContractsProbe_TEST_OWNER_CANCELLED_a6590b57);
    finally
      Scope.Free; Scope := nil;
      Owner.Free; Owner := nil;
    end;
  except on E: EAbort do ; end;
  Failed := False;
  try Escaped.Read(0, 1);
  except on E: EInvalidOpException do Failed := True; end;
  Require(Failed);
  Owner := TApiSensitiveBuffer.CreateUtf8(CozyText_NativeApiContractsProbe_ABC_5081872d);
  Scope := nil;
  try
    Scope := Owner.OpenRead;
    View := Scope.Buffer;
    Require(View.Capacity = 3);
    Require(PByte(View.Read(0, 1))^ = Ord('A'));
    Require(PByte(View.Read(2, 1))^ = Ord('C'));
  finally Scope.Free; Owner.Free; end;
  Owner := TApiSensitiveBuffer.CreateUtf8('');
  try Require(Owner.Capacity = 0); finally Owner.Free; end;
  Owner := TApiSensitiveBuffer.CreateUtf8(UnicodeString(#$D55C#$AE00#$D83D#$DE00));
  Scope := nil;
  try
    Scope := Owner.OpenRead; View := Scope.Buffer;
    Require(View.Capacity = 10);
    Require(PByte(View.Read(0, 1))^ = $ED);
    Require(PByte(View.Read(6, 1))^ = $F0);
    Require(PByte(View.Read(9, 1))^ = $80);
  finally Scope.Free; Owner.Free; end;
  Owner := TApiSensitiveBuffer.Create(MaxApiSensitiveBytes);
  Scope := nil;
  try
    Scope := Owner.OpenRead; View := Scope.Buffer;
    Require(View.Capacity = MaxApiSensitiveBytes);
    Require(PByte(View.Read(MaxApiSensitiveBytes - 1, 1))^ = 0);
  finally Scope.Free; Owner.Free; end;
  Owner := TApiSensitiveBuffer.Create(1);
  Scope := nil;
  try
    Scope := Owner.OpenWrite; View := Scope.Buffer;
    InFlight := PByte(View.Write(0, 1)); InFlight^ := $63;
    { Destructor itself must revoke; no prior explicit Owner.Close. }
    Owner.Free; Owner := nil;
    Require(InFlight^ = $63);
    Failed := False;
    try View.Read(0, 1);
    except on E: EInvalidOpException do Failed := True; end;
    Require(Failed);
  finally Scope.Free; Owner.Free; end;

end;
procedure RunFramedUtf8Contracts;
const Values: array[0..5] of UnicodeString = ('', CozyText_NativeApiContractsProbe_ASCII_c254390c, #0,
  #$D55C#$AE00, #$D83D#$DE00, CozyText_NativeApiContractsProbe_line_0b8c0d96+#10+CozyText_NativeApiContractsProbe_slash_cd2e3618);
var Owner: TApiSensitiveBuffer; Scope: TApiSensitiveScope;
  Expected: TBytes; Borrowed: TApiBuffer; Text: UnicodeString;
  Index, K: Integer; Rejected: Boolean; InFlight: PByte;
begin
  for Index := Low(Values) to High(Values) do
  begin
    Owner := nil; Scope := nil; Text := Values[Index];
    Expected := TEncoding.UTF8.GetBytes('[' + Text + ']');
    try
      Owner := TApiSensitiveBuffer.CreateUtf8Framed('[', Text, ']', Length(Expected));
      Scope := Owner.OpenRead; Borrowed := Scope.Buffer;
      Require(Owner.Capacity = NativeUInt(Length(Expected)));
      for K := 0 to High(Expected) do
        Require(PByte(Borrowed.Read(K, 1))^ = Expected[K]);
      Require(Text = Values[Index]); { Source is borrowed, not modified. }
      FreeAndNil(Scope);
      Owner.Clear; Scope := Owner.OpenRead;
      for K := 0 to High(Expected) do Require(PByte(Scope.Buffer.Read(K, 1))^ = 0);
      FreeAndNil(Scope); FreeAndNil(Owner);
      Rejected := False;
      try Owner := TApiSensitiveBuffer.CreateUtf8Framed('[', Text, ']', Length(Expected)-1);
      except on E: EArgumentException do Rejected := True; end;
      Require(Rejected and (Owner = nil));
    finally
      Scope.Free; Owner.Free;
      if Length(Expected) <> 0 then FillChar(Expected[0], Length(Expected), 0);
      Expected := nil;
    end;
  end;
  Owner := TApiSensitiveBuffer.CreateUtf8Framed('', '', '', 0);
  try Require(Owner.Capacity = 0); finally Owner.Free; end;
  Owner := TApiSensitiveBuffer.CreateUtf8Framed('[', CozyText_NativeApiContractsProbe_secret_f345e4d4, ']', 8);
  Scope := nil;
  try
    Scope := Owner.OpenRead; Borrowed := Scope.Buffer;
    InFlight := PByte(Borrowed.Read(1, 1));
    Owner.Free; Owner := nil;
    Require(InFlight^ = Ord('s')); { Active synchronous call can still drain. }
    Rejected := False;
    try Borrowed.Read(0, 1);
    except on E: EInvalidOpException do Rejected := True; end;
    Require(Rejected);
  finally Scope.Free; Owner.Free; end;
  for Index := 0 to 2 do
  begin
    Owner := nil; Rejected := False;
    try
      case Index of
        0: Owner := TApiSensitiveBuffer.CreateUtf8Framed('', '', '', -1);
        1: Owner := TApiSensitiveBuffer.CreateUtf8Framed('', '', '', MaxApiSensitiveBytes+1);
        2: Owner := TApiSensitiveBuffer.CreateUtf8Framed(CozyText_NativeApiContractsProbe_ab_aab39a14, '', CozyText_NativeApiContractsProbe_cd_b675d528, 3);
      end;
    except on E: EArgumentException do Rejected := True; end;
    Owner.Free; Require(Rejected);
  end;
end;

begin
  try
    RunSensitiveBufferContracts;
    RunFramedUtf8Contracts;
    SetLength(Data, 16); SetLength(Output, 32);
    ReadOnly := TApiBuffer.ReadBytes(Data); Writable := TApiBuffer.WriteBytes(Output);
    Require(ReadOnly.Read(0, 0) = nil); Require(ReadOnly.Read(4, 8) = @Data[4]);
    for I := 0 to 8 do
    begin
      Failed := False;
      try
        case I of
          0: Other := TApiBuffer.Borrow(nil, 1, True);
          1: Other := TApiBuffer.Borrow(Pointer(High(NativeUInt)), 2, True);
          2: ReadOnly.Read(17, 0);
          3: ReadOnly.Read(8, 9);
          4: ReadOnly.Write(0, 1);
          5: Writable.Completed(16, 17);
          6: begin Other := TApiBuffer.Borrow(@Output[1], 8, True); Writable.Disjoint(Other); end;
          7: RequireApiTarget(nil);
          8: RequireApiStruct(7, 8);
        end;
      except on E: EArgumentException do Failed := True; end;
      Require(Failed);
    end;
    RequireCngBuffers(ReadOnly, Writable, 16, 32, False); Inc(Passed);
    Failed := False;
    try RequireCngBuffers(ReadOnly, Writable, 16, 33, False);
    except on E: EArgumentException do Failed := True; end; Require(Failed);
    { Matching base addresses are the only allowed in-place CNG case. }
    Other := TApiBuffer.Borrow(@Data[0], Length(Data), True);
    RequireCngBuffers(ReadOnly, Other, 16, 16, True); Inc(Passed);
    Failed := False;
    try RequireCngBuffers(ReadOnly, Other, 16, 16, False);
    except on E: EArgumentException do Failed := True; end; Require(Failed);
    Other := TApiBuffer.Borrow(@Data[1], Length(Data)-1, True); Failed := False;
    try RequireCngBuffers(ReadOnly, Other, 8, 8, True);
    except on E: EArgumentException do Failed := True; end; Require(Failed);
    { Win64 buffer capacities may exceed ULONG; no narrowing may reach CNG.
      These synthetic spans are never read, because length rejects first. }
    if SizeOf(NativeUInt) > SizeOf(Cardinal) then
    begin
      Other := TApiBuffer.Borrow(Pointer(NativeUInt(1)), NativeUInt(High(Cardinal))+1, True);
      Failed := False;
      try RequireCngBuffers(ReadOnly, Other, 16, NativeUInt(High(Cardinal))+1, False);
      except on E: EArgumentException do Failed := True; end; Require(Failed);
    end;
    Command[0] := 'x'; Command[1] := ' '; Command[2] := 'y'; Command[3] := #0;
    Other := TApiBuffer.Borrow(@Command[0], SizeOf(Command), True);
    RequireProcessCommand(Other, Length(Command)); Inc(Passed);
    Command[1] := #0; Failed := False;
    try RequireProcessCommand(Other, Length(Command));
    except on E: EArgumentException do Failed := True; end; Require(Failed);
    Command[1] := ' '; Command[3] := 'z'; Failed := False;
    try RequireProcessCommand(Other, Length(Command));
    except on E: EArgumentException do Failed := True; end; Require(Failed);
    Writeln(CozyText_NativeApiContractsProbe_PASS_native_API_ownership_buffer_contracts_12e9a1fd, Passed);
  except on E: Exception do begin Writeln(E.ClassName, CozyText_NativeApiContractsProbe_Text_50c293eb, E.Message); Halt(1); end; end;
end.
