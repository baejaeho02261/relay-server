unit Cozy.NHW.MeasuredBootEvidence;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  System.SysUtils,
  Cozy.NHW.Attestation.Hash;

type
  TMeasuredBootEvidence = record
    Available: Boolean;
    TpmVersion: Cardinal;
    LogSize: Cardinal;
    LogDigest: TSHA256Digest;
  end;

function CaptureMeasuredBootEvidence(out Evidence: TMeasuredBootEvidence;
  out RawLog: TBytes): Boolean;

implementation

uses
  Cozy.NHW.KernelTrust.TBS;

function CaptureMeasuredBootEvidence(out Evidence: TMeasuredBootEvidence;
  out RawLog: TBytes): Boolean;
var Info: TTpmDeviceInfo;
begin
  Evidence := Default(TMeasuredBootEvidence);
  RawLog := nil;
  if not CaptureMeasuredBootLog(Info, RawLog) then Exit(False);
  if not HashBytesSHA256(RawLog, Evidence.LogDigest) then
  begin
    if Length(RawLog) <> 0 then FillChar(RawLog[0], Length(RawLog), 0);
    RawLog := nil;
    Exit(False);
  end;
  Evidence.Available := True;
  Evidence.TpmVersion := Info.TpmVersion;
  Evidence.LogSize := Length(RawLog);
  Result := True;
end;

end.
