unit Cozy.NHW.TpmQuote;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

interface

uses
  System.SysUtils, System.JSON;

type
  { The identity enrollment owner transfers the activated AIK to this bounded
    session object. No caller may replace its key with an uploaded public key.
    Failure/unavailability is not an attack or proof of boot integrity. }
  ICozyTpmQuoter = interface
    ['{DB920EA8-3514-46F5-9AE5-0775E773408C}']
    function TryQuote(const QualifyingDigest: TBytes;
      out Quote: TJSONObject): Boolean;
  end;

implementation

end.
