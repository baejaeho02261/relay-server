param(
  [Parameter(Mandatory=$true)][string]$DelphiProbe,
  [Parameter(Mandatory=$true)][string]$SdkProbe
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# One shared, regression-tested parser enforces every required ABI field. This
# wrapper runs compiled probes; it never treats a source/layout fixture as ABI.
$node = (Get-Command node.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$compare = Join-Path $PSScriptRoot 'Cozy.compare-native-abi.js'
$delphi = (Resolve-Path -LiteralPath $DelphiProbe).ProviderPath
$sdk = (Resolve-Path -LiteralPath $SdkProbe).ProviderPath
& $node $compare $delphi $sdk
if ($LASTEXITCODE -ne 0) { throw 'ABI_COMPARISON_FAILED' }
