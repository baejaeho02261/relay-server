unit Cozy.UserErrors;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

interface
{ Cozy central text imports. }
uses
  Cozy.Strings.Application;


type
  TCozyUserError = (cueNone, cueLicenseRejected, cueLicenseExpired,
    cueLicenseRevoked, cueConnectionUnavailable, cueOverlayUnavailable,
    cueSessionClosed, cueUnexpected);

{ Compatibility classification only. Production client diagnostics are silent.
  Never display server messages, exception details, paths or license values. }
function CozyUserErrorFromCode(const Code: string): TCozyUserError;
function CozyUserErrorText(Error: TCozyUserError): string;

implementation

function CozyUserErrorFromCode(const Code: string): TCozyUserError;
begin
  Result := cueUnexpected;
  if Length(Code) > 96 then Exit;
  if (Code = CozyText_UserErrors_LICENSE_KEY_INVALID_bb538cc9) or (Code = CozyText_UserErrors_DESKTOP_KEY_INVALID_2aabe82a) or
    (Code = CozyText_UserErrors_DESKTOP_KEY_USED_c042b4bb) then Result := cueLicenseRejected
  else if Code = CozyText_UserErrors_DESKTOP_EXPIRED_bbaaffca then Result := cueLicenseExpired
  else if (Code = CozyText_UserErrors_DESKTOP_REVOKED_d3cd0ced) or (Code = CozyText_UserErrors_DESKTOP_RELEASED_fe03b466) then
    Result := cueLicenseRevoked
  else if (Code = CozyText_UserErrors_CONNECT_TIMEOUT_d06bb0a7) or (Code = CozyText_UserErrors_BOOTSTRAP_DOWNLOAD_DEADLINE_044d218e) or
    (Code = CozyText_UserErrors_TRANSPORT_UNAVAILABLE_bf56e2c3) then Result := cueConnectionUnavailable
  else if (Code = CozyText_UserErrors_OVERLAY_START_FAILED_40d1c0bb) or
    (Code = CozyText_UserErrors_OVERLAY_KOREAN_FONT_UNAVAILABLE_87fdb2f0) or
    (Code = CozyText_UserErrors_OVERLAY_KOREAN_FONT_INVALID_684e2512) then Result := cueOverlayUnavailable;
end;

function CozyUserErrorText(Error: TCozyUserError): string;
begin
  { Retained for source compatibility. User-requested quiet operation applies
    to every error class, including unknown failures. Server error codes remain
    available to authenticated server-side operations. }
  Result := '';
end;

end.
