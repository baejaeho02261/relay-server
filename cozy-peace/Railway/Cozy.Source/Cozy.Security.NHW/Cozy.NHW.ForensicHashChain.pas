unit Cozy.NHW.ForensicHashChain;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  THash256 = array[0..31] of Byte;
  TChainPayload = packed record
    Sequence: UInt64;
    Tick: UInt64;
    TargetPID: Cardinal;
    Score: Byte;
    VisibilityGap: Byte;
    EventBits: array[0..31] of Byte;
    PreviousHash: THash256;
  end;
  TForensicHashFrame = packed record
    Payload: TChainPayload;
    Digest: THash256;
  end;

  // v68: SHA-256 linked RAM evidence ring. No file, registry, network,
  // telemetry export, or hidden persistence. Unkeyed SHA-256 alone CANNOT
  // authenticate against an attacker who can rewrite the entire process RAM.
  TForensicHashChain = class
  private
    FItems: array[0..255] of TForensicHashFrame;
    FNext, FCount: Integer;
    FSequence: UInt64;
    FLastHash: THash256;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Prune(Tick: UInt64);
    function Append(Tick: UInt64; TargetPID: Cardinal;
      const Detected: TDetectionKinds; Score: Byte;
      VisibilityGap: Boolean): Boolean;
    function Verify: Boolean;
    function Latest(out Frame: TForensicHashFrame): Boolean;
    property Count: Integer read FCount;
  end;

function HashingAvailable: Boolean;

implementation

uses System.SysUtils, Cozy.NHW.WinPointers, Cozy.NHW.NativeSafety;

type
  TBCryptOpen = function(out Alg: THandle; Algorithm, ImplName: PWideChar;
    Flags: Cardinal): LongInt; stdcall;
  TBCryptHash = function(Alg: THandle; Secret: Pointer;
    SecretBytes: Cardinal; Input: Pointer; InputBytes: Cardinal;
    Output: Pointer; OutputBytes: Cardinal): LongInt; stdcall;
  TBCryptClose = function(Alg: THandle; Flags: Cardinal): LongInt; stdcall;

var
  FnOpen: TBCryptOpen = nil;
  FnHash: TBCryptHash = nil;
  FnClose: TBCryptClose = nil;
  Resolved: Boolean = False;
  HashAlg: THandle = 0;

procedure ResolveHash;
var M: HMODULE;
begin
  if Resolved then Exit;
  Resolved := True;
  M := WinLoadLibrary('bcrypt.dll');
  FnOpen := TBCryptOpen(WinExport(M, 'BCryptOpenAlgorithmProvider'));
  FnHash := TBCryptHash(WinExport(M, 'BCryptHash'));
  FnClose := TBCryptClose(WinExport(M, 'BCryptCloseAlgorithmProvider'));
  if Assigned(FnOpen) and Assigned(FnHash) and Assigned(FnClose) then
    if FnOpen(HashAlg, PWideChar('SHA256'), nil, 0) <> 0 then
      HashAlg := 0;
end;

function HashingAvailable: Boolean;
begin
  ResolveHash;
  Result := (HashAlg <> 0) and Assigned(FnHash);
end;

function HashPayload(const P: TChainPayload; out D: THash256): Boolean;
begin
  FillChar(D, SizeOf(D), 0);
  Result := False;
  if not HashingAvailable then Exit;
  Result := FnHash(HashAlg, nil, 0, @P, SizeOf(P),
    @D[0], SizeOf(D)) = 0;
end;

constructor TForensicHashChain.Create;
begin inherited Create; Reset; end;

destructor TForensicHashChain.Destroy;
begin Reset; inherited Destroy; end;

procedure TForensicHashChain.Reset;
begin
  FillChar(FItems, SizeOf(FItems), 0);
  FillChar(FLastHash, SizeOf(FLastHash), 0);
  FNext := 0;
  FCount := 0;
  FSequence := 0;
end;

procedure TForensicHashChain.Prune(Tick: UInt64);
var Oldest: Integer;
begin
  if FCount = 0 then Exit;
  Oldest := (FNext - FCount + Length(FItems)) mod Length(FItems);
  if not NHWExpired(FItems[Oldest].Payload.Tick, Tick, 60000) then Exit;
  // Never silently erase evidence of a damaged chain or unavailable crypto.
  // The periodic engine verifier continues to report a failed verification.
  if not Verify then Exit;
  while FCount > 0 do
  begin
    Oldest := (FNext - FCount + Length(FItems)) mod Length(FItems);
    if not NHWExpired(FItems[Oldest].Payload.Tick, Tick, 60000) then Break;
    FItems[Oldest] := Default(TForensicHashFrame);
    Dec(FCount);
  end;
  if FCount = 0 then FillChar(FLastHash, SizeOf(FLastHash), 0);
end;

function TForensicHashChain.Append(Tick: UInt64; TargetPID: Cardinal;
  const Detected: TDetectionKinds; Score: Byte;
  VisibilityGap: Boolean): Boolean;
var R: TForensicHashFrame;
  N: Integer;

  procedure PrepareEvidencePayload;
  var
    K: TDetectionKind;
  begin
    R := Default(TForensicHashFrame);
    R.Payload.Sequence := FSequence + 1;
    R.Payload.Tick := Tick;
    R.Payload.TargetPID := TargetPID;
    R.Payload.Score := Score;
    if VisibilityGap then R.Payload.VisibilityGap := 1;
    for K := Low(TDetectionKind) to High(TDetectionKind) do
      if K in Detected then
      begin
        N := Ord(K);
        R.Payload.EventBits[N shr 3] :=
          R.Payload.EventBits[N shr 3] or Byte(1 shl (N and 7));
      end;
    Move(FLastHash, R.Payload.PreviousHash, SizeOf(FLastHash));
  end;

  procedure CommitHashedFrame;
  begin
    FItems[FNext] := R;
    Move(R.Digest, FLastHash, SizeOf(FLastHash));
    Inc(FSequence);
    FNext := (FNext + 1) mod Length(FItems);
    if FCount < Length(FItems) then Inc(FCount);
  end;

begin
  Result := False;
  if (Detected = []) and not VisibilityGap then Exit;
  if not HashingAvailable then Exit;
  PrepareEvidencePayload;
  if not HashPayload(R.Payload, R.Digest) then Exit;
  CommitHashedFrame;
  Result := True;
end;

function TForensicHashChain.Verify: Boolean;
var I, Pos: Integer;
  D, Previous: THash256;
  HasPrevious: Boolean;
begin
  Result := HashingAvailable;
  if not Result then Exit;
  FillChar(Previous, SizeOf(Previous), 0);
  HasPrevious := False;
  for I := 0 to FCount - 1 do
  begin
    Pos := (FNext - FCount + I + Length(FItems)) mod Length(FItems);
    if not HashPayload(FItems[Pos].Payload, D) or
      not CompareMem(@D[0], @FItems[Pos].Digest[0], SizeOf(D)) then
      Exit(False);
    if HasPrevious and
      not CompareMem(@Previous[0],
        @FItems[Pos].Payload.PreviousHash[0], SizeOf(D)) then
      Exit(False);
    Move(D, Previous, SizeOf(D));
    HasPrevious := True;
  end;
  if FCount > 0 then
    Result := CompareMem(@Previous[0], @FLastHash[0], SizeOf(D));
end;

function TForensicHashChain.Latest(out Frame: TForensicHashFrame): Boolean;
var Pos: Integer;
begin
  Frame := Default(TForensicHashFrame);
  Result := FCount > 0;
  if not Result then Exit;
  Pos := (FNext - 1 + Length(FItems)) mod Length(FItems);
  Frame := FItems[Pos];
end;

initialization
  // Keep SHA-256 provider lazy; no API calls before an evidence event.
  Resolved := False;

finalization
  if (HashAlg <> 0) and Assigned(FnClose) then
  begin
    FnClose(HashAlg, 0);
    HashAlg := 0;
  end;

end.
