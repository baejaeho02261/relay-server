library Cozy.ModuleGenerationFixture;
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{ A test-only, inert loader notification fixture. It has no loader actions,
  shared runtime packages, network access, or application security state. }
function GameModuleGenerationFixture: Cardinal; stdcall;
begin Result := $4D474631; end;
exports GameModuleGenerationFixture name 'GameModuleGenerationFixture';
begin
end.
