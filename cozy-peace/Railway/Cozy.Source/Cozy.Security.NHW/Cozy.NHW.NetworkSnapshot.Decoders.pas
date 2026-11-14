unit Cozy.NHW.NetworkSnapshot.Decoders;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

// Internal read-only decoding layer; callers retain collection/handle ownership.
uses
  System.SysUtils, System.Classes;

type
  TIpForwardRow = record
    Dest, Mask, Policy, NextHop, IfIndex, RType, Proto, Age, NextHopAS,
    Metric1, Metric2, Metric3, Metric4, Metric5: Cardinal;
  end;
  PIpForwardRow = ^TIpForwardRow;

function ParseDefaultRoutes(const Data: TBytes; Used: Cardinal;
  Routes: TStringList): Boolean;
function DecodeRegString(const Data: TBytes; Used: Cardinal;
  out Value: string): Boolean;

implementation

function ParseDefaultRoutes(const Data: TBytes; Used: Cardinal;
  Routes: TStringList): Boolean;
var
  Count, I: Cardinal;
  R: PIpForwardRow;
begin
  Result := False;
  if Routes = nil then Exit;
  Routes.Clear;
  try
    if SizeOf(TIpForwardRow) <> 56 then Exit;
    if (Used < SizeOf(Cardinal)) or (NativeUInt(Used) > NativeUInt(Length(Data))) then Exit;
    Count := 0;
    Move(Data[0], Count, SizeOf(Count));
    if Count > (Used - Cardinal(SizeOf(Cardinal))) div Cardinal(SizeOf(TIpForwardRow)) then Exit;
    if Count <> 0 then
      for I := 0 to Count - 1 do
      begin
        R := Pointer(NativeUInt(@Data[0]) + NativeUInt(SizeOf(Cardinal)) +
          NativeUInt(I) * SizeOf(TIpForwardRow));
        if (R^.Dest = 0) and (R^.Mask = 0) then
          Routes.Add(IntToHex(R^.NextHop, 8) + ':' + IntToStr(R^.IfIndex) + ':' +
            IntToStr(R^.Metric1));
      end;
    Result := True;
  finally
    if not Result then Routes.Clear;
  end;
end;

function DecodeRegString(const Data: TBytes; Used: Cardinal;
  out Value: string): Boolean;
var
  Chars, I: Integer;
begin
  Result := False;
  Value := '';
  if NativeUInt(Used) > NativeUInt(Length(Data)) then Exit;
  if (Used and 1) <> 0 then Exit;
  if Used = 0 then Exit(True);
  Chars := Integer(Used div SizeOf(WideChar));
  if PWord(@Data[(Chars - 1) * 2])^ = 0 then Dec(Chars);
  // RegQueryValueEx does not guarantee a terminator; bounded nonterminated
  // text is valid. An embedded NUL, however, is not a complete scalar value.
  for I := 0 to Chars - 1 do
    if PWord(@Data[I * 2])^ = 0 then Exit;
  SetString(Value, PWideChar(@Data[0]), Chars);
  Result := True;
end;

end.
