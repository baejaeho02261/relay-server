unit Cozy.NHW.ETW.PropertyDecoders;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

// Internal read-only decoding layer; callers retain collection/handle ownership.
uses
  System.SysUtils;

function DecodeEtwUInt(const B: TBytes; out V: Cardinal): Boolean;
function DecodeEtwText(const B: TBytes; out S: string): Boolean;

implementation

function DecodeEtwUInt(const B: TBytes; out V: Cardinal): Boolean;
var
  Wide: UInt64;
begin
  V := 0;
  Result := False;
  if Length(B) = 4 then
  begin
    Move(B[0], V, 4);
    Exit(True);
  end;
  if Length(B) = 8 then
  begin
    Wide := 0;
    Move(B[0], Wide, 8);
    if Wide > UInt64(High(Cardinal)) then Exit;
    V := Cardinal(Wide);
    Exit(True);
  end;
end;

function DecodeEtwText(const B: TBytes; out S: string): Boolean;
var
  N, I, EndAt: Integer;
  C, Next: Word;
begin
  Result := False;
  S := '';
  if (Length(B) < 2) or Odd(Length(B)) or (Length(B) > 4096) then Exit;
  N := Length(B) div 2;
  EndAt := N;
  for I := 0 to N - 1 do
    if PWord(@B[I * 2])^ = 0 then
    begin
      EndAt := I;
      Break;
    end;
  if EndAt = 0 then Exit;
  for I := EndAt to N - 1 do
    if PWord(@B[I * 2])^ <> 0 then Exit;
  I := 0;
  while I < EndAt do
  begin
    C := PWord(@B[I * 2])^;
    if (C >= $D800) and (C <= $DBFF) then
    begin
      Inc(I);
      if I >= EndAt then Exit;
      Next := PWord(@B[I * 2])^;
      if (Next < $DC00) or (Next > $DFFF) then Exit;
    end
    else if (C >= $DC00) and (C <= $DFFF) then Exit;
    Inc(I);
  end;
  SetString(S, PWideChar(@B[0]), EndAt);
  Result := True;
end;

end.
