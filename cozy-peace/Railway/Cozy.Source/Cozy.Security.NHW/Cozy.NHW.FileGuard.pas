unit Cozy.NHW.FileGuard;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  Cozy.NHW.Logging,
  Cozy.NHW.FileNative;

type
  // Pure comparison state (also exercised by synthetic tests).
  TFileGuardState = record
  private
    FPriming: Integer;
    FReferenceId: string;
    FPathKnown: Boolean;
    FPathPresent: Boolean;
    FLastPathId: string;
    FMissingCount: Integer;
    FNameKnown: Boolean;
    FLastName: string;
    FReparseKnown: Boolean;
    FLastReparse: UInt64;
    FStreamsKnown: Boolean;
    FLastStreams: UInt64;
    FSecurityKnown: Boolean;
    FLastSecurity: UInt64;
    FLinksKnown: Boolean;
    FLastLinkMode: Byte;
    FLastLinks: UInt64;
    procedure BreakContinuity;
  public
    procedure Reset;
    procedure Observe(const E: TFileEvidence; var Detected: TDetectionKinds);
  end;

  TFileMonitor = class
  private
    FPath: string;
    FHandle: THandle;
    FNextCheck: UInt64;
    FState: TFileGuardState;
    procedure InitReference;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset(TargetHandle: THandle);
    procedure Examine(Tick: UInt64; var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE5K_TESTS}
function TestFileGuard5K(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.Native;

const
  FILE_CHECK_INTERVAL_MS = 2000;
  FILE_BASELINE_SAMPLES = 3;

procedure TFileGuardState.Reset;
begin
  FPriming := FILE_BASELINE_SAMPLES;
  FReferenceId := '';
  FPathKnown := False;
  FPathPresent := False;
  FLastPathId := '';
  FMissingCount := 0;
  FNameKnown := False;
  FLastName := '';
  FReparseKnown := False;
  FLastReparse := 0;
  FStreamsKnown := False;
  FLastStreams := 0;
  FSecurityKnown := False;
  FLastSecurity := 0;
  FLinksKnown := False;
  FLastLinkMode := 0;
  FLastLinks := 0;
end;

procedure TFileGuardState.BreakContinuity;
begin
  FMissingCount := 0; // keep approved identity and optional fingerprints
end;

procedure TFileGuardState.Observe(const E: TFileEvidence;
  var Detected: TDetectionKinds);
var
  Suppress, PathValid, BaselineSample: Boolean;

  procedure ObservePathIdentity;
  begin
    if PathValid then
    begin
      if E.PathPresent then
      begin
        if (not Suppress) and (FReferenceId <> '') and
           (E.PathId <> '') and (E.PathId[1] = FReferenceId[1]) and
           (E.PathId <> FReferenceId) and
           ((not FPathKnown) or (not FPathPresent) or
            (FLastPathId <> E.PathId)) then
          Include(Detected, dkFileSwap);
        FPathKnown := True;
        FPathPresent := True;
        FLastPathId := E.PathId;
        FMissingCount := 0;
      end
      else if FPathKnown and FPathPresent then
      begin
        // Two confirmed path-not-found observations suppress transient errors.
        if FMissingCount < 2 then Inc(FMissingCount);
        if FMissingCount >= 2 then
        begin
          if not Suppress then Include(Detected, dkFileRename);
          FPathPresent := False;
        end;
      end;
    end
    else
      BreakContinuity;
  end;

  procedure ObserveOptionalMetadata;
  begin
    if E.ReferenceNameKnown then
    begin
      if FNameKnown and (not Suppress) and (FLastName <> E.ReferenceName) then
        Include(Detected, dkFileRename);
      FNameKnown := True;
      FLastName := E.ReferenceName;
    end;
    if E.ReparseKnown then
    begin
      if FReparseKnown and (not Suppress) and
         (FLastReparse <> E.ReparseHash) then
        Include(Detected, dkReparse);
      FReparseKnown := True;
      FLastReparse := E.ReparseHash;
    end;
    if E.StreamsKnown then
    begin
      if FStreamsKnown and (not Suppress) and
         (FLastStreams <> E.StreamsHash) then
        Include(Detected, dkStream);
      FStreamsKnown := True;
      FLastStreams := E.StreamsHash;
    end;
    if E.SecurityKnown then
    begin
      if FSecurityKnown and (not Suppress) and
         (FLastSecurity <> E.SecurityHash) then
        Include(Detected, dkFileSecurity);
      FSecurityKnown := True;
      FLastSecurity := E.SecurityHash;
    end;
    if E.LinksKnown then
    begin
      // A switch between full link-name data and count-only fallback is not a
      // link change. Compare only observations with the same fidelity.
      if FLinksKnown and (not Suppress) and
         (FLastLinkMode = E.LinksMode) and (FLastLinks <> E.LinksHash) then
        Include(Detected, dkFileLink);
      FLinksKnown := True;
      FLastLinkMode := E.LinksMode;
      FLastLinks := E.LinksHash;
    end;
  end;

begin
  Suppress := FPriming > 0;
  PathValid := E.PathKnown and ((not E.PathPresent) or (E.PathId <> ''));
  BaselineSample := E.ReferenceIdKnown and (E.ReferenceId <> '') and PathValid;
  // Optional ADS/DACL/link support is not required, but an unknown reference
  // or path must never consume one of the three quiet baseline observations.
  if (FPriming > 0) and BaselineSample then Dec(FPriming);
  if E.ReferenceIdKnown and (E.ReferenceId <> '') and (FReferenceId = '') then
    FReferenceId := E.ReferenceId;

  // FileSwap: executable path now points to a different file ID, in the same
  // or another volume. Do not report access failures as a new file identity.
  ObservePathIdentity;
  // FileRename may also be produced when the original referenced FILE object
  // receives a different native name, without treating transient path errors
  // as evidence. A removed original path can mean delete/move/unlink as well.
  ObserveOptionalMetadata;
end;

constructor TFileMonitor.Create;
begin
  inherited Create;
  FHandle := INVALID_HANDLE_VALUE;
  FPath := '';
  FNextCheck := 0;
  FState.Reset;
end;

destructor TFileMonitor.Destroy;
begin
  CloseFileMetadata(FHandle);
  inherited Destroy;
end;

procedure TFileMonitor.Reset(TargetHandle: THandle);
var
  Chars: Cardinal;
  Buf: array[0..32767] of WideChar;
begin
  CloseFileMetadata(FHandle);
  FPath := '';
  FNextCheck := 0;
  FState.Reset;
  Chars := Length(Buf);
  if QueryProcessImageName(TargetHandle, @Buf[0], Chars) and
     (Chars > 0) and (Chars < Cardinal(Length(Buf))) then
    SetString(FPath, PWideChar(@Buf[0]), Integer(Chars));
end;

procedure TFileMonitor.InitReference;
var
  Id: string;
begin
  if (FPath = '') or not FileNativeAvailable then Exit;
  FHandle := OpenFileMetadata(FPath, False);
  if FHandle = INVALID_HANDLE_VALUE then Exit;
  if not ReadFileIdentity(FHandle, Id) then
  begin
    CloseFileMetadata(FHandle);
    Exit;
  end;
  FState.Reset; // First 3 valid checks establish quiet baseline.
end;

procedure TFileMonitor.Examine(Tick: UInt64; var Detected: TDetectionKinds);
var
  E: TFileEvidence;
begin
  if (FNextCheck <> 0) and (Tick >= FNextCheck) and
     (Tick - FNextCheck < FILE_CHECK_INTERVAL_MS) then Exit;
  FNextCheck := Tick;
  if FHandle = INVALID_HANDLE_VALUE then InitReference;
  if FHandle = INVALID_HANDLE_VALUE then Exit;

  try
    E := Default(TFileEvidence);
    E.ReferenceIdKnown := ReadFileIdentity(FHandle, E.ReferenceId);
    E.ReferenceNameKnown := ReadFileName(FHandle, E.ReferenceName);
    E.ReparseKnown := ReadReparseChain(FPath, E.ReparseHash);
    E.StreamsKnown := ReadStreamSet(FHandle, E.StreamsHash);
    E.SecurityKnown := ReadFileDacl(FHandle, E.SecurityHash);
    E.LinksKnown := ReadLinkSet(FHandle, E.LinksMode, E.LinksHash);
    ReadPathIdentity(FPath, E);
    FState.Observe(E, Detected);
  except
    FState.BreakContinuity;
    // Unexpected filesystem/NT query failures are UNKNOWN, not a detection.
    // Do not allow an optional file probe to stop the v14 handle monitor.
  end;
end;

{$IFDEF NHW_NATIVE5K_TESTS}
{$I Cozy.NHW.Native5K.FileGuard.inc}
{$ENDIF}

end.
