unit Cozy.NHW.HighResolutionClock;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows;

// QPC describes observation/callback arrival, not kernel event generation.
function NHWTryQpcNow(out Value: Int64): Boolean;
function NHWQpcNow: Int64;
function NHWTryQpcConvertUS(StartQpc, EndQpc, Frequency: Int64;
  out ElapsedUS: UInt64): Boolean;
function NHWTryQpcElapsedUS(StartQpc, EndQpc: Int64;
  out ElapsedUS: UInt64): Boolean;
// Compatibility API: High(UInt64) is unavailable/overflow; zero is a valid
// duration. Production accounting uses the Try API, never the sentinel.
function NHWQpcElapsedUS(StartQpc, EndQpc: Int64): UInt64;

{$IFDEF NHW_NATIVE10P_TESTS}
function TestHighResolutionClock10P(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10P_TESTS}
uses System.SysUtils;
{$ENDIF}

var GQpcFrequency: Int64 = 0;

function NHWTryQpcNow(out Value: Int64): Boolean;
var V: Int64;
begin
  Value := 0;
  V := 0;
  Result := QueryPerformanceCounter(V) and (V >= 0);
  if Result then Value := V;
end;

function NHWQpcNow: Int64;
begin
  if not NHWTryQpcNow(Result) then Result := 0;
end;

function FractionMicroseconds(Numerator, Denominator: UInt64): UInt64;
var R: UInt64; BitIndex: Integer;
begin
  if Numerator <= High(UInt64) div 1000000 then
    Exit((Numerator * 1000000) div Denominator);
  // Long multiply/divide with a 20-bit multiplier. R always < Denominator;
  // subtraction-first reductions avoid overflowing R*2 or R+Numerator.
  Result := 0;
  R := 0;
  for BitIndex := 19 downto 0 do
  begin
    Result := Result * 2;
    if R >= Denominator - R then
    begin R := R - (Denominator - R); Inc(Result); end
    else R := R + R;
    if (UInt64(1000000) and (UInt64(1) shl BitIndex)) <> 0 then
    begin
      if R >= Denominator - Numerator then
      begin R := R - (Denominator - Numerator); Inc(Result); end
      else R := R + Numerator;
    end;
  end;
end;

function NHWTryQpcConvertUS(StartQpc, EndQpc, Frequency: Int64;
  out ElapsedUS: UInt64): Boolean;
var Delta, F, Whole, Fraction: UInt64;
begin
  Result := False;
  ElapsedUS := 0;
  if (Frequency <= 0) or (StartQpc < 0) or (EndQpc < StartQpc) then Exit;
  Delta := UInt64(EndQpc) - UInt64(StartQpc);
  F := UInt64(Frequency);
  Whole := Delta div F;
  if Whole > High(UInt64) div 1000000 then Exit;
  Whole := Whole * 1000000;
  Fraction := FractionMicroseconds(Delta mod F, F);
  if Fraction > High(UInt64) - Whole then Exit;
  ElapsedUS := Whole + Fraction;
  Result := True;
end;

function NHWTryQpcElapsedUS(StartQpc, EndQpc: Int64;
  out ElapsedUS: UInt64): Boolean;
begin
  Result := NHWTryQpcConvertUS(StartQpc, EndQpc, GQpcFrequency, ElapsedUS);
end;

function NHWQpcElapsedUS(StartQpc, EndQpc: Int64): UInt64;
begin
  if not NHWTryQpcElapsedUS(StartQpc, EndQpc, Result) then
    Result := High(UInt64);
end;

{$IFDEF NHW_NATIVE10P_TESTS}
{$I Cozy.NHW.Native10P.HighResolutionClock.inc}
{$ENDIF}

initialization
  if not QueryPerformanceFrequency(GQpcFrequency) then GQpcFrequency := 0;

end.
