unit Cozy.NHW.SessionEpochGuard;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

type
  TAttestationNonce = array[0..31] of Byte;

  TSessionEpochGuard = class
  private
    FCurrentEpoch: UInt64;
    FSeen: array[0..7] of TAttestationNonce;
    FSeenCount: Integer;
    FNext: Integer;
    function NonceSeen(const Nonce: TAttestationNonce): Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    function AcceptChallenge(Epoch: UInt64;
      const Nonce: TAttestationNonce): Boolean;
    property CurrentEpoch: UInt64 read FCurrentEpoch;
  end;

function AttestationNonceIsZero(const Nonce: TAttestationNonce): Boolean;
function AttestationNonceEqual(const A, B: TAttestationNonce): Boolean;

implementation

function AttestationNonceIsZero(const Nonce: TAttestationNonce): Boolean;
var I: Integer; Acc: Byte;
begin
  Acc := 0;
  for I := 0 to High(Nonce) do Acc := Acc or Nonce[I];
  Result := Acc = 0;
end;

function AttestationNonceEqual(const A, B: TAttestationNonce): Boolean;
var I: Integer; Diff: Byte;
begin
  Diff := 0;
  for I := 0 to High(A) do Diff := Diff or (A[I] xor B[I]);
  Result := Diff = 0;
end;

constructor TSessionEpochGuard.Create;
begin
  inherited Create;
  Reset;
end;

destructor TSessionEpochGuard.Destroy;
begin
  Reset;
  inherited Destroy;
end;

procedure TSessionEpochGuard.Reset;
begin
  FCurrentEpoch := 0;
  FillChar(FSeen, SizeOf(FSeen), 0);
  FSeenCount := 0;
  FNext := 0;
end;

function TSessionEpochGuard.NonceSeen(const Nonce: TAttestationNonce): Boolean;
var I: Integer;
begin
  for I := 0 to FSeenCount - 1 do
    if AttestationNonceEqual(FSeen[I], Nonce) then Exit(True);
  Result := False;
end;

function TSessionEpochGuard.AcceptChallenge(Epoch: UInt64;
  const Nonce: TAttestationNonce): Boolean;
begin
  Result := False;
  if (Epoch = 0) or AttestationNonceIsZero(Nonce) then Exit;
  if (FCurrentEpoch <> 0) and (Epoch < FCurrentEpoch) then Exit;
  if NonceSeen(Nonce) then Exit;
  if Epoch > FCurrentEpoch then FCurrentEpoch := Epoch;
  FSeen[FNext] := Nonce;
  FNext := (FNext + 1) mod Length(FSeen);
  if FSeenCount < Length(FSeen) then Inc(FSeenCount);
  Result := True;
end;

end.
