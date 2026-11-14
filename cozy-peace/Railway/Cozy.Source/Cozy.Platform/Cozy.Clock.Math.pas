unit Cozy.Clock.Math;
{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}{$Q+}{$R+}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Platform,
 {$IFDEF FPC}SysUtils{$ELSE}System.SysUtils{$ENDIF};
{ Pure arithmetic; no clock, process, server authority or Windows API access. }
function CozyCounterMilliseconds(Counter, Frequency: Int64): UInt64;
function CozyDeadlineAfter(At, Duration: UInt64): UInt64;
function CozyDeadlineRemaining(At, Deadline: UInt64; Maximum: Cardinal): Cardinal;
implementation
function CozyCounterMilliseconds(Counter, Frequency: Int64): UInt64;
var Whole, Rest, Divisor, Fraction, Accumulator: UInt64; Bit: Integer;
begin
  if (Counter < 0) or (Frequency <= 0) then
    raise EArgumentOutOfRangeException.Create(CozyText_Clock_Math_CLOCK_COUNTER_INVALID_dd6677db);
  Divisor := UInt64(Frequency);
  Whole := UInt64(Counter) div Divisor;
  Rest := UInt64(Counter) mod Divisor;
  if Whole > High(UInt64) div 1000 then
    raise EArgumentOutOfRangeException.Create(CozyText_Clock_Math_CLOCK_COUNTER_OVERFLOW_9aa13e7c);
  if Rest <= High(UInt64) div 1000 then
    Fraction := (Rest * 1000) div Divisor
  else
  begin
    { Exact floor(Rest*1000/Divisor), without a wide intermediate. Divisor
      is <= High(Int64), so each reduced doubling/addition fits UInt64. }
    Fraction := 0; Accumulator := 0;
    for Bit := 9 downto 0 do
    begin
      Fraction := Fraction shl 1;
      Accumulator := Accumulator shl 1;
      if Accumulator >= Divisor then
      begin Dec(Accumulator, Divisor); Inc(Fraction); end;
      if (1000 and (1 shl Bit)) <> 0 then
      begin
        Inc(Accumulator, Rest);
        if Accumulator >= Divisor then
        begin Dec(Accumulator, Divisor); Inc(Fraction); end;
      end;
    end;
  end;
  Result := Whole * 1000;
  if Fraction > High(UInt64) - Result then
    raise EArgumentOutOfRangeException.Create(CozyText_Clock_Math_CLOCK_COUNTER_OVERFLOW_9aa13e7c);
  Inc(Result, Fraction);
end;
function CozyDeadlineAfter(At, Duration: UInt64): UInt64;
begin
  if Duration > High(UInt64) - At then
    raise EArgumentOutOfRangeException.Create(CozyText_Clock_Math_CLOCK_DEADLINE_OVERFLOW_bb948c48);
  Result := At + Duration;
end;
function CozyDeadlineRemaining(At, Deadline: UInt64; Maximum: Cardinal): Cardinal;
var Left: UInt64;
begin
  if (At >= Deadline) or (Maximum = 0) then Exit(0);
  Left := Deadline - At;
  if Left > Maximum then Left := Maximum;
  Result := Cardinal(Left);
end;
end.
