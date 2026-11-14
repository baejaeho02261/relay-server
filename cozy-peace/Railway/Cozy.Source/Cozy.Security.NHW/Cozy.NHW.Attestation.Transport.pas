unit Cozy.NHW.Attestation.Transport;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  System.SysUtils,
  Cozy.NHW.SessionEpochGuard,
  Cozy.NHW.Attestation.Hash,
  Cozy.NHW.SessionTrustLadder,
  Cozy.NHW.ServerNonceAttestation;

type
  TAttestationChallengeFrame = record
    Epoch: UInt64;
    ServerSequence: UInt64;
    Nonce: TAttestationNonce;
  end;

  TAttestationVerdictFrame = record
    Epoch: UInt64;
    ServerSequence: UInt64;
    Nonce: TAttestationNonce;
    BindingDigest: TSHA256Digest;
    Accepted: Boolean;
  end;

function BuildAttestationChallengeFrame(const Challenge: TAttestationChallengeFrame;
  out Frame: TBytes): Boolean;
function ParseAttestationChallengeFrame(const Frame: TBytes;
  out Challenge: TAttestationChallengeFrame): Boolean;
function BuildAttestationEvidenceFrame(const Evidence: TServerAttestationEvidence;
  const MeasuredBootLog: TBytes; out Frame: TBytes): Boolean;
function ParseAttestationEvidenceFrame(const Frame: TBytes;
  out Evidence: TServerAttestationEvidence; out MeasuredBootLog: TBytes): Boolean;
function BuildAttestationVerdictFrame(const Verdict: TAttestationVerdictFrame;
  out Frame: TBytes): Boolean;
function ParseAttestationVerdictFrame(const Frame: TBytes;
  out Verdict: TAttestationVerdictFrame): Boolean;

implementation

const
  ATTESTATION_FRAME_MAGIC = Cardinal($4157484E); // NHWA
  ATTESTATION_FRAME_VERSION = Word(1);
  AFK_CHALLENGE = Byte(1);
  AFK_EVIDENCE = Byte(2);
  AFK_VERDICT = Byte(3);
  ATTESTATION_MAX_FRAME = 16 * 1024 * 1024;

procedure AppendRaw(var B: TBytes; const Source; Count: Integer);
var
  OldLen: Integer;
begin
  if Count <= 0 then Exit;
  OldLen := Length(B);
  SetLength(B, OldLen + Count);
  Move(Source, B[OldLen], Count);
end;

procedure AppendU8(var B: TBytes; V: Byte);
begin
  AppendRaw(B, V, SizeOf(V));
end;

procedure AppendU16(var B: TBytes; V: Word);
begin
  AppendRaw(B, V, SizeOf(V));
end;

procedure AppendU32(var B: TBytes; V: Cardinal);
begin
  AppendRaw(B, V, SizeOf(V));
end;

procedure AppendU64(var B: TBytes; V: UInt64);
begin
  AppendRaw(B, V, SizeOf(V));
end;

function ReadRaw(const B: TBytes; var Offset: Integer; var Dest;
  Count: Integer): Boolean;
begin
  Result := False;
  if (Count < 0) or (Offset < 0) or (Offset > Length(B)) or
     (Count > Length(B) - Offset) then Exit;
  if Count > 0 then Move(B[Offset], Dest, Count);
  Inc(Offset, Count);
  Result := True;
end;

function BeginFrame(Kind: Byte; PayloadSize: Cardinal;
  out Frame: TBytes): Boolean;
var
  Reserved: Byte;
begin
  Frame := nil;
  Result := False;
  if PayloadSize > ATTESTATION_MAX_FRAME then Exit;
  Reserved := 0;
  AppendU32(Frame, ATTESTATION_FRAME_MAGIC);
  AppendU16(Frame, ATTESTATION_FRAME_VERSION);
  AppendU8(Frame, Kind);
  AppendU8(Frame, Reserved);
  AppendU32(Frame, PayloadSize);
  Result := True;
end;

function ReadHeader(const Frame: TBytes; ExpectedKind: Byte;
  out Offset: Integer; out PayloadSize: Cardinal): Boolean;
var
  Magic: Cardinal;
  Version: Word;
  Kind, Reserved: Byte;
begin
  Result := False;
  Offset := 0;
  PayloadSize := 0;
  if not ReadRaw(Frame, Offset, Magic, SizeOf(Magic)) then Exit;
  if not ReadRaw(Frame, Offset, Version, SizeOf(Version)) then Exit;
  if not ReadRaw(Frame, Offset, Kind, SizeOf(Kind)) then Exit;
  if not ReadRaw(Frame, Offset, Reserved, SizeOf(Reserved)) then Exit;
  if not ReadRaw(Frame, Offset, PayloadSize, SizeOf(PayloadSize)) then Exit;
  if (Magic <> ATTESTATION_FRAME_MAGIC) or
     (Version <> ATTESTATION_FRAME_VERSION) or
     (Kind <> ExpectedKind) or (Reserved <> 0) or
     (PayloadSize > ATTESTATION_MAX_FRAME) then Exit;
  if PayloadSize <> Cardinal(Length(Frame) - Offset) then Exit;
  Result := True;
end;

function BuildAttestationChallengeFrame(
  const Challenge: TAttestationChallengeFrame; out Frame: TBytes): Boolean;
const
  PAYLOAD_SIZE = 48;
begin
  Result := False;
  if (Challenge.Epoch = 0) or (Challenge.ServerSequence = 0) or
     AttestationNonceIsZero(Challenge.Nonce) then Exit;
  if not BeginFrame(AFK_CHALLENGE, PAYLOAD_SIZE, Frame) then Exit;
  AppendU64(Frame, Challenge.Epoch);
  AppendU64(Frame, Challenge.ServerSequence);
  AppendRaw(Frame, Challenge.Nonce[0], SizeOf(Challenge.Nonce));
  Result := True;
end;

function ParseAttestationChallengeFrame(const Frame: TBytes;
  out Challenge: TAttestationChallengeFrame): Boolean;
var
  Offset: Integer;
  PayloadSize: Cardinal;
begin
  Challenge := Default(TAttestationChallengeFrame);
  Result := False;
  if not ReadHeader(Frame, AFK_CHALLENGE, Offset, PayloadSize) then Exit;
  if not ReadRaw(Frame, Offset, Challenge.Epoch, SizeOf(Challenge.Epoch)) then Exit;
  if not ReadRaw(Frame, Offset, Challenge.ServerSequence,
       SizeOf(Challenge.ServerSequence)) then Exit;
  if not ReadRaw(Frame, Offset, Challenge.Nonce[0], SizeOf(Challenge.Nonce)) then Exit;
  if Offset <> Length(Frame) then Exit;
  if (Challenge.Epoch = 0) or (Challenge.ServerSequence = 0) or
     AttestationNonceIsZero(Challenge.Nonce) then Exit;
  Result := True;
end;

function BuildAttestationEvidenceFrame(const Evidence: TServerAttestationEvidence;
  const MeasuredBootLog: TBytes; out Frame: TBytes): Boolean;
var
  PayloadSize: UInt64;
  AvailableByte: Byte;
begin
  Result := False;
  Frame := nil;
  if (Evidence.Epoch = 0) or (Evidence.ServerSequence = 0) or
     AttestationNonceIsZero(Evidence.Nonce) then Exit;
  if Length(MeasuredBootLog) > ATTESTATION_MAX_FRAME then Exit;

  PayloadSize := SizeOf(UInt64) * 5 + SizeOf(TAttestationNonce) +
    SizeOf(Evidence.BootIdentity.LowPart) + SizeOf(Evidence.BootIdentity.HighPart) +
    3 + SizeOf(Cardinal) * 3 + SizeOf(TSHA256Digest) * 2 +
    UInt64(Length(MeasuredBootLog));
  if PayloadSize > ATTESTATION_MAX_FRAME then Exit;
  if not BeginFrame(AFK_EVIDENCE, Cardinal(PayloadSize), Frame) then Exit;

  AppendU64(Frame, Evidence.Epoch);
  AppendU64(Frame, Evidence.ServerSequence);
  AppendRaw(Frame, Evidence.Nonce[0], SizeOf(Evidence.Nonce));
  AppendU64(Frame, Evidence.BootIdentity.LowPart);
  AppendU64(Frame, Evidence.BootIdentity.HighPart);
  AppendU8(Frame, Byte(Ord(Evidence.SessionTrust)));
  AppendU8(Frame, Evidence.ResponseVoteMask);
  if Evidence.MeasuredBoot.Available then AvailableByte := 1 else AvailableByte := 0;
  AppendU8(Frame, AvailableByte);
  AppendU64(Frame, Evidence.TrustDigest);
  AppendU64(Frame, Evidence.DriverDigest);
  AppendU64(Frame, Evidence.IntegrityDigest);
  AppendU32(Frame, Evidence.MeasuredBoot.TpmVersion);
  AppendU32(Frame, Evidence.MeasuredBoot.LogSize);
  AppendRaw(Frame, Evidence.MeasuredBoot.LogDigest[0], SizeOf(Evidence.MeasuredBoot.LogDigest));
  AppendRaw(Frame, Evidence.BindingDigest[0], SizeOf(Evidence.BindingDigest));
  AppendU32(Frame, Cardinal(Length(MeasuredBootLog)));
  if Length(MeasuredBootLog) > 0 then
    AppendRaw(Frame, MeasuredBootLog[0], Length(MeasuredBootLog));
  Result := True;
end;

function ParseAttestationEvidenceFrame(const Frame: TBytes;
  out Evidence: TServerAttestationEvidence; out MeasuredBootLog: TBytes): Boolean;
var
  Offset: Integer;
  PayloadSize: Cardinal;
  TrustByte, AvailableByte: Byte;
  LogLength: Cardinal;
begin
  Evidence := Default(TServerAttestationEvidence);
  MeasuredBootLog := nil;
  Result := False;
  if not ReadHeader(Frame, AFK_EVIDENCE, Offset, PayloadSize) then Exit;
  if not ReadRaw(Frame, Offset, Evidence.Epoch, SizeOf(Evidence.Epoch)) then Exit;
  if not ReadRaw(Frame, Offset, Evidence.ServerSequence,
       SizeOf(Evidence.ServerSequence)) then Exit;
  if not ReadRaw(Frame, Offset, Evidence.Nonce[0], SizeOf(Evidence.Nonce)) then Exit;
  if not ReadRaw(Frame, Offset, Evidence.BootIdentity.LowPart,
       SizeOf(Evidence.BootIdentity.LowPart)) then Exit;
  if not ReadRaw(Frame, Offset, Evidence.BootIdentity.HighPart,
       SizeOf(Evidence.BootIdentity.HighPart)) then Exit;
  if not ReadRaw(Frame, Offset, TrustByte, SizeOf(TrustByte)) then Exit;
  if TrustByte > Byte(Ord(High(TKernelSessionTrust))) then Exit;
  Evidence.SessionTrust := TKernelSessionTrust(TrustByte);
  if not ReadRaw(Frame, Offset, Evidence.ResponseVoteMask,
       SizeOf(Evidence.ResponseVoteMask)) then Exit;
  if not ReadRaw(Frame, Offset, AvailableByte, SizeOf(AvailableByte)) then Exit;
  if AvailableByte > 1 then Exit;
  Evidence.MeasuredBoot.Available := AvailableByte = 1;
  if not ReadRaw(Frame, Offset, Evidence.TrustDigest, SizeOf(Evidence.TrustDigest)) then Exit;
  if not ReadRaw(Frame, Offset, Evidence.DriverDigest, SizeOf(Evidence.DriverDigest)) then Exit;
  if not ReadRaw(Frame, Offset, Evidence.IntegrityDigest, SizeOf(Evidence.IntegrityDigest)) then Exit;
  if not ReadRaw(Frame, Offset, Evidence.MeasuredBoot.TpmVersion,
       SizeOf(Evidence.MeasuredBoot.TpmVersion)) then Exit;
  if not ReadRaw(Frame, Offset, Evidence.MeasuredBoot.LogSize,
       SizeOf(Evidence.MeasuredBoot.LogSize)) then Exit;
  if not ReadRaw(Frame, Offset, Evidence.MeasuredBoot.LogDigest[0],
       SizeOf(Evidence.MeasuredBoot.LogDigest)) then Exit;
  if not ReadRaw(Frame, Offset, Evidence.BindingDigest[0],
       SizeOf(Evidence.BindingDigest)) then Exit;
  if not ReadRaw(Frame, Offset, LogLength, SizeOf(LogLength)) then Exit;
  if LogLength > Cardinal(Length(Frame) - Offset) then Exit;
  SetLength(MeasuredBootLog, LogLength);
  if (LogLength > 0) and
     not ReadRaw(Frame, Offset, MeasuredBootLog[0], Integer(LogLength)) then Exit;
  if Offset <> Length(Frame) then Exit;
  if Evidence.MeasuredBoot.Available and
     (Evidence.MeasuredBoot.LogSize <> LogLength) then Exit;
  if (Evidence.Epoch = 0) or (Evidence.ServerSequence = 0) or
     AttestationNonceIsZero(Evidence.Nonce) then Exit;
  Result := True;
end;

function BuildAttestationVerdictFrame(const Verdict: TAttestationVerdictFrame;
  out Frame: TBytes): Boolean;
const
  PAYLOAD_SIZE = 81;
var
  AcceptedByte: Byte;
begin
  Result := False;
  if (Verdict.Epoch = 0) or (Verdict.ServerSequence = 0) or
     AttestationNonceIsZero(Verdict.Nonce) then Exit;
  if not BeginFrame(AFK_VERDICT, PAYLOAD_SIZE, Frame) then Exit;
  AppendU64(Frame, Verdict.Epoch);
  AppendU64(Frame, Verdict.ServerSequence);
  AppendRaw(Frame, Verdict.Nonce[0], SizeOf(Verdict.Nonce));
  AppendRaw(Frame, Verdict.BindingDigest[0], SizeOf(Verdict.BindingDigest));
  if Verdict.Accepted then AcceptedByte := 1 else AcceptedByte := 0;
  AppendU8(Frame, AcceptedByte);
  Result := True;
end;

function ParseAttestationVerdictFrame(const Frame: TBytes;
  out Verdict: TAttestationVerdictFrame): Boolean;
var
  Offset: Integer;
  PayloadSize: Cardinal;
  AcceptedByte: Byte;
begin
  Verdict := Default(TAttestationVerdictFrame);
  Result := False;
  if not ReadHeader(Frame, AFK_VERDICT, Offset, PayloadSize) then Exit;
  if not ReadRaw(Frame, Offset, Verdict.Epoch, SizeOf(Verdict.Epoch)) then Exit;
  if not ReadRaw(Frame, Offset, Verdict.ServerSequence,
       SizeOf(Verdict.ServerSequence)) then Exit;
  if not ReadRaw(Frame, Offset, Verdict.Nonce[0], SizeOf(Verdict.Nonce)) then Exit;
  if not ReadRaw(Frame, Offset, Verdict.BindingDigest[0],
       SizeOf(Verdict.BindingDigest)) then Exit;
  if not ReadRaw(Frame, Offset, AcceptedByte, SizeOf(AcceptedByte)) then Exit;
  if Offset <> Length(Frame) then Exit;
  if AcceptedByte > 1 then Exit;
  if (Verdict.Epoch = 0) or (Verdict.ServerSequence = 0) or
     AttestationNonceIsZero(Verdict.Nonce) then Exit;
  Verdict.Accepted := AcceptedByte = 1;
  Result := True;
end;

end.
