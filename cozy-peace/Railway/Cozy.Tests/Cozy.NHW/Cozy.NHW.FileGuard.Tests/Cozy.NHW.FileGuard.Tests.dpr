program CozyNHW_FileGuard_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build as Windows 64-bit.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.FileNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.FileNative.pas',
  Cozy.NHW.FileGuard in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.FileGuard.pas';

procedure Expect(const Condition: Boolean);
begin
  if not Condition then raise Exception.Create('Synthetic file-change test failed.');
end;

function Initial: TFileEvidence;
begin
  Result := Default(TFileEvidence);
  Result.ReferenceIdKnown := True;
  Result.ReferenceId := 'I:ORIGINAL';
  Result.PathKnown := True;
  Result.PathPresent := True;
  Result.PathId := 'I:ORIGINAL';
  Result.ReferenceNameKnown := True;
  Result.ReferenceName := '\\original.exe';
  Result.ReparseKnown := True;
  Result.ReparseHash := 1;
  Result.StreamsKnown := True;
  Result.StreamsHash := 2;
  Result.SecurityKnown := True;
  Result.SecurityHash := 3;
  Result.LinksKnown := True;
  Result.LinksMode := 1;
  Result.LinksHash := 4;
end;

procedure Prime(var S: TFileGuardState; const E: TFileEvidence);
var
  K: TDetectionKinds;
  I: Integer;
begin
  S.Reset;
  for I := 1 to 3 do
  begin
    K := [];
    S.Observe(E, K);
    Expect(K = []);
  end;
end;

procedure TestEachChange;
var
  S: TFileGuardState;
  E, Base: TFileEvidence;
  K: TDetectionKinds;
begin
  Base := Initial;
  Prime(S, Base);

  E := Base;
  E.PathId := 'I:REPLACED';
  K := [];
  S.Observe(E, K);
  Expect(K = [dkFileSwap]);
  K := [];
  S.Observe(E, K);
  Expect(K = []);

  E := Base;
  E.ReferenceName := '\\renamed.exe';
  K := [];
  S.Observe(E, K);
  Expect(K = [dkFileRename]);

  E.ReparseHash := 12;
  K := [];
  S.Observe(E, K);
  Expect(K = [dkReparse]);

  E.StreamsHash := 22;
  K := [];
  S.Observe(E, K);
  Expect(K = [dkStream]);

  E.SecurityHash := 33;
  K := [];
  S.Observe(E, K);
  Expect(K = [dkFileSecurity]);

  E.LinksHash := 44;
  K := [];
  S.Observe(E, K);
  Expect(K = [dkFileLink]);

  E.SecurityKnown := False;
  E.SecurityHash := 55;
  K := [];
  S.Observe(E, K);
  Expect(K = []); // Read failure must not invent a change.

  E.LinksMode := 2;
  E.LinksHash := 2;
  K := [];
  S.Observe(E, K);
  Expect(K = []); // Full enumeration -> count-only is not an actual change.
  E.LinksHash := 3;
  K := [];
  S.Observe(E, K);
  Expect(K = [dkFileLink]);
end;

procedure TestMissingPath;
var
  S: TFileGuardState;
  Base, E: TFileEvidence;
  K: TDetectionKinds;
begin
  Base := Initial;
  Prime(S, Base);
  E := Base;
  E.PathPresent := False;
  K := [];
  S.Observe(E, K);
  Expect(K = []);
  K := [];
  S.Observe(E, K);
  Expect(K = [dkFileRename]);
  K := [];
  S.Observe(E, K);
  Expect(K = []);
end;

begin
  try
    TestEachChange;
    TestMissingPath;
    ExitCode := 0;
  except
    on E: Exception do ExitCode := 1;
  end;
end.
