unit Cozy.Handoff.Kdf;

{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Handoff,
 {$IFDEF FPC}SysUtils{$ELSE}System.SysUtils{$ENDIF}, Cozy.Api.Contracts;

{ Seed MUST be 32 fresh CNG random bytes for this one envelope. The fixed-size
  seed prefix and exact bounded AAD are fed without concatenated secret copies.
  The final 32-byte key, not the seed, is RSA wrapped, so V3 decrypt stays exact. }
function DeriveHandoffContentKey(const Seed, AuthenticatedTranscript: TBytes): TBytes;
{ Production encryption keeps the random seed and content key in dedicated
  allocations. Only the hasher output boundary uses a temporary array, wiped
  before returning the owned key; no key is returned through a shared TBytes. }
function DeriveHandoffContentKeyOwned(const Seed: TApiBuffer;
  const AuthenticatedTranscript: TBytes): TApiSensitiveBuffer;

implementation

uses Cozy.Hashes;

function DeriveHandoffContentKeyOwned(const Seed: TApiBuffer;
  const AuthenticatedTranscript: TBytes): TApiSensitiveBuffer;
const Domain: AnsiString = CozyText_Handoff_Kdf_cozy_Client_Handoff_V3_AES256GCM_ContentKey_v1_65f49ab9;
var Context, Digest: TBytes; Hasher: TBlake3Hasher;
  Scope: TApiSensitiveScope; I: Integer;
begin
  Result := nil; Hasher := nil; Digest := nil;
  if (Seed.Capacity <> 32) or (Length(AuthenticatedTranscript) < 1) or
    (Length(AuthenticatedTranscript) > 8192) then
    raise EArgumentException.Create(CozyText_Handoff_Kdf_Invalid_handoff_key_derivation_input_997b0e1e);
  SetLength(Context, Length(Domain));
  for I := 1 to Length(Domain) do Context[I - 1] := Byte(Domain[I]);
  try
    try
      Hasher := TBlake3Hasher.CreateDeriveKey(Context);
      Hasher.Update(Seed.Read(0, 32)^, 32);
      Hasher.Update(AuthenticatedTranscript[0], Length(AuthenticatedTranscript));
      Digest := Hasher.FinishBytes(32);
      Result := TApiSensitiveBuffer.Create(32);
      Scope := Result.OpenWrite;
      try Move(Digest[0], Scope.Buffer.Write(0, 32)^, 32);
      finally Scope.Free; end;
    except
      Result.Free; raise;
    end;
  finally
    if Length(Digest) <> 0 then FillChar(Digest[0], Length(Digest), 0);
    Digest := nil;
    Hasher.Free;
    if Length(Context) <> 0 then FillChar(Context[0], Length(Context), 0);
  end;
end;

function DeriveHandoffContentKey(const Seed, AuthenticatedTranscript: TBytes): TBytes;
var Owner: TApiSensitiveBuffer; Scope: TApiSensitiveScope;
begin
  Result := nil;
  Owner := DeriveHandoffContentKeyOwned(TApiBuffer.ReadBytes(Seed), AuthenticatedTranscript);
  try
    Scope := Owner.OpenRead;
    try
      try
        SetLength(Result, 32);
        Move(Scope.Buffer.Read(0, 32)^, Result[0], 32);
      except
        if Length(Result) <> 0 then FillChar(Result[0], Length(Result), 0);
        Result := nil; raise;
      end;
    finally Scope.Free; end;
  finally Owner.Free; end;
end;

end.
