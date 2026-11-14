program CozyNHW_KernelTrust5E_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.SessionTrustLadder in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SessionTrustLadder.pas',
  Cozy.NHW.SessionEpochGuard in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SessionEpochGuard.pas',
  Cozy.NHW.SessionInvalidation in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SessionInvalidation.pas',
  Cozy.NHW.ResponsePath.Dispatch in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ResponsePath.Dispatch.pas',
  Cozy.NHW.ResponsePath.Trust in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ResponsePath.Trust.pas',
  Cozy.NHW.ResponsePath.Driver in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ResponsePath.Driver.pas',
  Cozy.NHW.ResponsePath.Integrity in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ResponsePath.Integrity.pas',
  Cozy.NHW.ResponsePathMesh in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ResponsePathMesh.pas';

procedure Check(Value: Boolean);
begin
  if not Value then raise Exception.Create('KernelTrust5E validation failed');
end;

type
  TRecorder = class
  public
    TrustCount: Integer;
    DriverCount: Integer;
    IntegrityCount: Integer;
    procedure OnTrust(const Event: TResponsePathEvent);
    procedure OnDriver(const Event: TResponsePathEvent);
    procedure OnIntegrity(const Event: TResponsePathEvent);
  end;

procedure TRecorder.OnTrust(const Event: TResponsePathEvent);
begin
  if Event.Channel = rpcTrust then Inc(TrustCount);
end;

procedure TRecorder.OnDriver(const Event: TResponsePathEvent);
begin
  if Event.Channel = rpcDriver then Inc(DriverCount);
end;

procedure TRecorder.OnIntegrity(const Event: TResponsePathEvent);
begin
  if Event.Channel = rpcIntegrity then Inc(IntegrityCount);
end;

var
  Guard: TSessionEpochGuard;
  Latch: TSessionInvalidationLatch;
  Mesh: TResponsePathMesh;
  R: TRecorder;
  N1, N2: TAttestationNonce;
  Kinds: TDetectionKinds;
begin
  FillChar(N1, SizeOf(N1), 0);
  FillChar(N2, SizeOf(N2), 0);
  N1[0] := 1;
  N2[0] := 2;

  Guard := TSessionEpochGuard.Create;
  try
    Check(Guard.AcceptChallenge(1, N1));
    Check(not Guard.AcceptChallenge(1, N1));
    Check(Guard.AcceptChallenge(1, N2));
    Check(not Guard.AcceptChallenge(0, N1));
    Check(Guard.CurrentEpoch = 1);
  finally
    Guard.Free;
  end;

  Latch := TSessionInvalidationLatch.Create;
  try
    Latch.BeginEpoch(7);
    Latch.ObserveLocal(kstUntrusted, True, 1000);
    Check(not Latch.Invalidated);
    Latch.ObserveLocal(kstUntrusted, True, 2000);
    Check(Latch.Invalidated);
  finally
    Latch.Free;
  end;

  Mesh := TResponsePathMesh.Create;
  R := TRecorder.Create;
  try
    Mesh.SetSinks(R.OnTrust, R.OnDriver, R.OnIntegrity);
    Kinds := [dkBootTrust, dkVulnerableDriver, dkCodeIntegrityPolicy];
    Mesh.Observe(Kinds, 1000);
    Check((R.TrustCount = 1) and (R.DriverCount = 1) and
      (R.IntegrityCount = 1));
    Check(Mesh.Quorum(1000));
    Mesh.Reset;
    Kinds := [dkBootTrust];
    Mesh.Observe(Kinds, 2000);
    Check(R.TrustCount = 2); // sink survives local evidence reset
  finally
    R.Free;
    Mesh.Free;
  end;
end.
