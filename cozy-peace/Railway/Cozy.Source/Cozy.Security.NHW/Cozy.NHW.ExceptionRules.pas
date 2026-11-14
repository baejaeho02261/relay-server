unit Cozy.NHW.ExceptionRules;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows;

// x64 RUNTIME_FUNCTION fields are RVAs, not absolute process pointers.
// Static .pdata is distinct from JIT/dynamically installed function tables.
type
  PNHWRuntimeFunction = ^TNHWRuntimeFunction;
  TNHWRuntimeFunction = packed record
    BeginAddress: Cardinal;
    EndAddress: Cardinal;
    UnwindData: Cardinal;
  end;

  TExceptionImageState = record
    ImageBase: NativeUInt;
    ImageSize: Cardinal;
    TableCount: Cardinal;
    TableDigest: UInt64;
    RangeDigest: UInt64;
    UnwindDigest: UInt64;
    RangeValid: Boolean;
    UnwindValid: Boolean;
    LookupConsistent: Boolean;
    HasUnwindSamples: Boolean;
    HasLookupSamples: Boolean;
  end;

  TConfirmedCondition = record
    Consecutive: Byte;
    Reported: Boolean;
  end;

function ExceptionRangeValid(const Entry: TNHWRuntimeFunction;
  ImageSize: Cardinal; PreviousBegin: Cardinal;
  HasPrevious: Boolean): Boolean;
function ExceptionUnwindHeaderValid(VersionFlags, CountCodes: Byte;
  UnwindRVA, ImageSize: Cardinal; out MinimumBytes: Cardinal): Boolean;
function ExceptionFingerprint(Hash, Value: UInt64): UInt64;
function ConfirmExceptionCondition(var State: TConfirmedCondition;
  Active: Boolean): Boolean;

{$IFDEF NHW_NATIVE10O_TESTS}
function TestExceptionRules10O(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10O_TESTS}
uses System.SysUtils;
{$ENDIF}

function ExceptionRangeValid(const Entry: TNHWRuntimeFunction;
  ImageSize: Cardinal; PreviousBegin: Cardinal;
  HasPrevious: Boolean): Boolean;
begin
  Result := (Entry.BeginAddress < Entry.EndAddress) and
    (Entry.EndAddress <= ImageSize) and
    (Entry.UnwindData < ImageSize) and
    ((not HasPrevious) or (Entry.BeginAddress >= PreviousBegin));
end;

function ExceptionUnwindHeaderValid(VersionFlags, CountCodes: Byte;
  UnwindRVA, ImageSize: Cardinal; out MinimumBytes: Cardinal): Boolean;
var
  Version, Flags: Byte;
  AlignedCodes, Required: Cardinal;
begin
  Result := False;
  MinimumBytes := 0;
  Version := VersionFlags and 7;
  Flags := VersionFlags shr 3;
  // Preserve the existing version 1..3 acceptance policy. This is a bounded
  // structural header check, not a complete opcode or handler-data verifier.
  if (Version = 0) or (Version > 3) then Exit;
  // CHAININFO (4) is mutually exclusive with EHANDLER/UHANDLER (1/2).
  if ((Flags and 4) <> 0) and ((Flags and 3) <> 0) then Exit;
  if (UnwindRVA and 3) <> 0 then Exit;
  AlignedCodes := (Cardinal(CountCodes) + 1) and (not Cardinal(1));
  Required := 4 + AlignedCodes * 2;
  if (Flags and 4) <> 0 then Inc(Required, 12)
  else if (Flags and 3) <> 0 then Inc(Required, 4);
  // Language-specific data may follow; only the mandatory trailer is sized.
  if UnwindRVA > ImageSize then Exit;
  if Required > ImageSize - UnwindRVA then Exit;
  MinimumBytes := Required;
  Result := True;
end;

function ExceptionFingerprint(Hash, Value: UInt64): UInt64;
begin
  Result := (Hash xor Value) * UInt64($00000100000001B3);
end;

function ConfirmExceptionCondition(var State: TConfirmedCondition;
  Active: Boolean): Boolean;
begin
  Result := False;
  if not Active then
  begin
    State := Default(TConfirmedCondition);
    Exit;
  end;
  if State.Consecutive < 3 then Inc(State.Consecutive);
  if (State.Consecutive >= 2) and not State.Reported then
  begin
    State.Reported := True;
    Result := True;
  end;
end;

{$IFDEF NHW_NATIVE10O_TESTS}
  {$I Cozy.NHW.Native10O.ExceptionRules.inc}
{$ENDIF}

end.
