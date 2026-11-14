# Isolated test-object auditor; production Cozy.Audit-Object.ps1 continues to reject these exports.
param([Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference = 'Stop'
try {
  [byte[]]$bytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path))
  function Need([UInt64]$offset,[UInt64]$count) {
    if ($offset -gt $bytes.LongLength -or $count -gt ($bytes.LongLength-$offset)) { throw 'Truncated ELF object.' }
  }
  function U16([UInt64]$offset) { Need $offset 2; return [BitConverter]::ToUInt16($bytes,[int]$offset) }
  function U32([UInt64]$offset) { Need $offset 4; return [BitConverter]::ToUInt32($bytes,[int]$offset) }
  function U64([UInt64]$offset) { Need $offset 8; return [BitConverter]::ToUInt64($bytes,[int]$offset) }
  function Str([UInt64]$offset,[UInt64]$limit) {
    Need $offset $limit; [UInt64]$n=0
    while ($n -lt $limit -and $bytes[[int]($offset+$n)] -ne 0) { $n++ }
    if ($n -eq $limit) { throw 'Unterminated ELF string.' }
    return [Text.Encoding]::ASCII.GetString($bytes,[int]$offset,[int]$n)
  }
  Need 0 64
  if ($bytes[0] -ne 127 -or $bytes[1] -ne 69 -or $bytes[2] -ne 76 -or $bytes[3] -ne 70 -or $bytes[4] -ne 2 -or $bytes[5] -ne 1 -or (U16 16) -ne 1 -or (U16 18) -ne 62) {
    throw 'Expected classic bcc64 little-endian ELF64 x86-64 relocatable object. COFF/bcc64x is not accepted.'
  }
  $sectionOffset=U64 40; $sectionSize=U16 58; $sectionCount=U16 60; $nameIndex=U16 62
  if ($sectionSize -ne 64 -or $sectionCount -lt 2 -or $nameIndex -ge $sectionCount) { throw 'Unsupported ELF section table.' }
  Need $sectionOffset ([UInt64]$sectionSize*$sectionCount)
  $sections=@()
  for($i=0;$i -lt $sectionCount;$i++) {
    $p=$sectionOffset+[UInt64]$i*$sectionSize
    $sections += [pscustomobject]@{Name=(U32 $p);Type=(U32 ($p+4));Offset=(U64 ($p+24));Size=(U64 ($p+32));Link=(U32 ($p+40));Entry=(U64 ($p+56))}
  }
  $names=$sections[$nameIndex]; Need $names.Offset $names.Size
  $undefined=New-Object 'System.Collections.Generic.List[string]'
  $exports=New-Object 'System.Collections.Generic.HashSet[string]'
  $foundSymbols=$false
  foreach($s in $sections) {
    if($s.Name -ge $names.Size){throw 'Invalid ELF section name.'}
    $name=Str ($names.Offset+$s.Name) ($names.Size-$s.Name)
    if($s.Size -gt 0 -and $name -match '(^|\.)(init_array|fini_array|ctors|dtors)(\.|$)'){throw "Unexpected static initialization section: $name"}
    if($s.Type -ne 2){continue}
    $foundSymbols=$true
    if($s.Entry -ne 24 -or $s.Size%24 -ne 0 -or $s.Link -ge $sectionCount){throw 'Invalid ELF symbol table.'}
    Need $s.Offset $s.Size; $strings=$sections[$s.Link]; Need $strings.Offset $strings.Size
    for([UInt64]$p=$s.Offset;$p -lt $s.Offset+$s.Size;$p+=24){
      $nameOffset=U32 $p; $target=U16 ($p+6)
      if($nameOffset -eq 0){continue}
      if($nameOffset -ge $strings.Size){throw 'Invalid symbol string offset.'}
      $symbol=Str ($strings.Offset+$nameOffset) ($strings.Size-$nameOffset)
      if($target -eq 0){$undefined.Add($symbol)}
      elseif($symbol.StartsWith('game_imgui_')){[void]$exports.Add($symbol)}
    }
  }
  if(!$foundSymbols){throw 'Missing ELF symbol table.'}
  if($undefined.Count -ne 0){throw ('Unresolved native dependencies: '+(($undefined | Sort-Object -Unique) -join ', '))}
  $required=@('abi_version','create','destroy','resize','set_dpi','gpu_identity','new_frame','mouse_pos','mouse_button','mouse_wheel','key','focus','clear_input','begin_canvas','set_cursor_pos','button','text','end_canvas','render_present','last_error')
  foreach($suffix in $required){if(!$exports.Contains('game_imgui_'+$suffix)){throw ('Missing C ABI entry: game_imgui_'+$suffix)}}
  foreach($name in @('game_imgui_test_fault','game_imgui_test_live_arena_bytes','game_imgui_test_retain_device')){if(!$exports.Contains($name)){throw ('Missing isolated test entry: '+$name)}}
  Write-Output 'PASS: TEST-ONLY ELF64, production ABI plus fault entries, no undefined imports or static constructors. Never link this object into A/B/O.'
  exit 0
} catch { Write-Error $_ -ErrorAction Continue; exit 1 }
