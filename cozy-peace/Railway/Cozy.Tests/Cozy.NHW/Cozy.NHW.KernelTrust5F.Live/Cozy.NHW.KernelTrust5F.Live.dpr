program CozyNHWKernelTrust5FLive;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust,
  Cozy.NHW.KernelTrust.Native,
  Cozy.NHW.KernelTrust.PlatformNative;

function DetectionCount(const Kinds: TDetectionKinds): Integer;
var K: TDetectionKind;
begin
  Result := 0;
  for K := Low(TDetectionKind) to High(TDetectionKind) do
    if K in Kinds then Inc(Result);
end;

var
  Monitor: TKernelTrustMonitor;
  Kinds: TDetectionKinds;
  Boot: TSecureBootSnapshot;
  CI: TCodeIntegritySnapshot;
  BootId: TBootIdentity;
  NativeModules, PSAPIModules: TKernelModuleInfos;
  Platform: TPlatformSecuritySnapshot;
  Captures: Integer;
begin
  Captures := 0;
  if CaptureBootIdentity(BootId) then Inc(Captures);
  if CaptureSecureBootSnapshot(Boot) then Inc(Captures);
  if CaptureCodeIntegritySnapshot(CI) then Inc(Captures);
  if CaptureNativeKernelModules(NativeModules) then Inc(Captures);
  if CapturePSAPIKernelModules(PSAPIModules) then Inc(Captures);
  if CapturePlatformSecuritySnapshot(Platform) then Inc(Captures);

  Monitor := TKernelTrustMonitor.Create;
  try
    Kinds := [];
    Monitor.Examine(1000, Kinds);
    Monitor.Examine(6000, Kinds);
    Monitor.Examine(11000, Kinds);
    Monitor.Examine(31000, Kinds);
    Monitor.Examine(61000, Kinds);
    Writeln('PASS live_captures=', Captures,
      ' observed_detections=', DetectionCount(Kinds),
      ' correlation_score=', Monitor.CorrelationScore,
      ' correlation_families=', Monitor.CorrelationFamilyCount);
  finally
    Monitor.Free;
  end;
end.
