program CozyNHWExceptionRulesTests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'This test requires Win64.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.ExceptionRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ExceptionRules.pas',
  Cozy.NHW.SelfRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SelfRules.pas';

procedure Require(Value: Boolean; const Name: string);
begin
  if not Value then raise Exception.Create(Name);
end;

var
  Fn: TNHWRuntimeFunction;
  Bytes: Cardinal;
  State: TConfirmedCondition;
  Fingerprint: TStableFingerprint;
begin
  Fn.BeginAddress := $1000;
  Fn.EndAddress := $1100;
  Fn.UnwindData := $2100;
  Require(SizeOf(Fn) = 12, 'RUNTIME_FUNCTION x64 ABI size');
  Require(ExceptionRangeValid(Fn, $8000, 0, False), 'valid static range');
  Fn.EndAddress := $0FFF;
  Require(not ExceptionRangeValid(Fn, $8000, 0, False), 'reversed range');
  Fn.EndAddress := $1100;
  Require(not ExceptionRangeValid(Fn, $8000, $2000, True), 'unsorted range');
  Require(ExceptionUnwindHeaderValid(1, 3, $2100, $8000, Bytes), 'unwind header');
  Require(Bytes = 12, 'unwind slot alignment');
  Require(not ExceptionUnwindHeaderValid(0, 3, $2100, $8000, Bytes), 'invalid version');
  Require(not ExceptionUnwindHeaderValid(1, 1, $7FFF, $8000, Bytes), 'image overflow');
  State := Default(TConfirmedCondition);
  Require(not ConfirmExceptionCondition(State, True), 'first alert sample');
  Require(ConfirmExceptionCondition(State, True), 'confirmed alert');
  Require(not ConfirmExceptionCondition(State, True), 'dedupe alert');
  Require(not ConfirmExceptionCondition(State, False), 'recovery');
  Require(not ConfirmExceptionCondition(State, True), 'new episode first');
  Require(ConfirmExceptionCondition(State, True), 'new episode confirmed');
  Fingerprint := Default(TStableFingerprint);
  Require(not ObserveFingerprint(Fingerprint, 1, True), 'baseline');
  Require(not ObserveFingerprint(Fingerprint, 2, True), 'candidate');
  Require(ObserveFingerprint(Fingerprint, 2, True), 'candidate confirmed');
  Require(not ObserveFingerprint(Fingerprint, 2, True), 'candidate suppressed');
end.
