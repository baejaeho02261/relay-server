program Cozy_ClockMathProbe;
{$IFDEF FPC}{$MODE DELPHI}{$ELSE}{$APPTYPE CONSOLE}{$ENDIF}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$Q+}{$R+}
uses
{ Cozy central text imports. }
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',

  {$IFDEF FPC}SysUtils, Classes,{$ELSE}System.SysUtils, System.Classes,{$ENDIF}
  Cozy.Clock.Math in '..\..\Cozy.Source\Cozy.Platform\Cozy.Clock.Math.pas';
{ Portable arithmetic protocol. Does not execute QPC, Windows waits, A/B/O,
  approval, signing or server authorization. Each line: counter/deadline/left. }
var Parts: TStringList; Line: string; Value: UInt64;
begin
  Parts := TStringList.Create;
  try
    Parts.Delimiter := ' '; Parts.StrictDelimiter := True;
    while not Eof(Input) do
    begin
      ReadLn(Line); if Line = '' then Continue;
      try
        Parts.DelimitedText := Line;
        if (Parts.Count = 3) and (Parts[0] = CozyText_ClockMathProbe_counter_b1e046fc) then
          Value := CozyCounterMilliseconds(StrToInt64(Parts[1]), StrToInt64(Parts[2]))
        else if (Parts.Count = 3) and (Parts[0] = CozyText_ClockMathProbe_deadline_54ab4f1e) then
          Value := CozyDeadlineAfter(StrToUInt64(Parts[1]), StrToUInt64(Parts[2]))
        else if (Parts.Count = 4) and (Parts[0] = CozyText_ClockMathProbe_left_d4161771) then
          Value := CozyDeadlineRemaining(StrToUInt64(Parts[1]), StrToUInt64(Parts[2]), StrToUInt(Parts[3]))
        else raise EArgumentException.Create(CozyText_ClockMathProbe_PROBE_INPUT_INVALID_c7b8daa6);
        WriteLn(CozyText_ClockMathProbe_OK_c8f9f9fa, Value);
      except on E: Exception do WriteLn(CozyText_ClockMathProbe_ERR_6dedc9ff); end;
    end;
  finally Parts.Free; end;
end.
