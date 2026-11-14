param(
 [Parameter(Mandatory=$true)][ValidateSet('check','apply')][string]$Mode,
 [Parameter(Mandatory=$true)][string]$DataDirectory,
 [Parameter(Mandatory=$true)][string]$ServiceSid,
 [string]$WitnessDirectory = ''
)
$ErrorActionPreference = 'Stop'
try {
 $service = New-Object System.Security.Principal.SecurityIdentifier($ServiceSid)
 $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
 $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
 if ($ServiceSid -in @('S-1-1-0','S-1-5-11','S-1-5-32-545')) { throw 'ACL_SERVICE_IDENTITY_INVALID' }
 $allowed = @($service.Value, $system.Value, $admins.Value)
 $roots = @($DataDirectory)
 if ($WitnessDirectory) { $roots += $WitnessDirectory }
 $checked = 0
 foreach ($directory in $roots) {
  $full = [System.IO.Path]::GetFullPath($directory)
  if (-not [System.IO.Directory]::Exists($full)) { throw 'ACL_DIRECTORY_MISSING' }
  # Reject a reparse point at every ancestor, not just the final directory.
  $ancestor = New-Object System.IO.DirectoryInfo($full)
  while ($null -ne $ancestor) {
   if (($ancestor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'ACL_REPARSE_PATH' }
   $ancestor = $ancestor.Parent
  }
  $entries = New-Object 'System.Collections.Generic.List[System.IO.FileSystemInfo]'
  $entries.Add((Get-Item -LiteralPath $full -Force))
  for ($index=0; $index -lt $entries.Count; $index++) {
   $entry = $entries[$index]
   if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'ACL_REPARSE_PATH' }
   if ($entry -is [System.IO.DirectoryInfo]) {
    foreach ($child in Get-ChildItem -LiteralPath $entry.FullName -Force) {
     if ($entries.Count -ge 100000) { throw 'ACL_ENTRY_LIMIT' }
     $entries.Add($child)
    }
   }
  }
  if ($Mode -eq 'apply') {
   $acl = New-Object System.Security.AccessControl.DirectorySecurity
   $acl.SetAccessRuleProtection($true, $false)
   $acl.SetOwner($admins)
   $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
   foreach ($sid in @($system, $admins)) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inherit, 'None', 'Allow')
    $acl.AddAccessRule($rule)
   }
   if ($ServiceSid -notin @($system.Value, $admins.Value)) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($service, 'Modify,Synchronize', $inherit, 'None', 'Allow')
    $acl.AddAccessRule($rule)
   }
   Set-Acl -LiteralPath $full -AclObject $acl
   foreach ($entry in $entries | Select-Object -Skip 1) {
    $child = Get-Acl -LiteralPath $entry.FullName
    $child.SetAccessRuleProtection($false, $false)
    foreach ($rule in @($child.GetAccessRules($true,$false,[System.Security.Principal.SecurityIdentifier]))) { $child.RemoveAccessRuleSpecific($rule) }
    $child.SetOwner($admins)
    Set-Acl -LiteralPath $entry.FullName -AclObject $child
   }
  }
  foreach ($entry in $entries) {
   $acl = Get-Acl -LiteralPath $entry.FullName
   if ($entry.FullName -eq $full -and -not $acl.AreAccessRulesProtected) { throw 'ACL_ROOT_INHERITANCE_ENABLED' }
   if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -notin $allowed) { throw 'ACL_OWNER_UNTRUSTED' }
   $rights = @{}
   foreach ($rule in $acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -notin $allowed) { throw 'ACL_UNEXPECTED_PRINCIPAL' }
    $sid = $rule.IdentityReference.Value
    if (-not $rights.ContainsKey($sid)) { $rights[$sid] = [int64]0 }
    $rights[$sid] = $rights[$sid] -bor [int64]$rule.FileSystemRights
   }
   $needed = [int64][System.Security.AccessControl.FileSystemRights]::Modify
   if (-not $rights.ContainsKey($service.Value) -or ($rights[$service.Value] -band $needed) -ne $needed) { throw 'ACL_SERVICE_ACCESS_MISSING' }
   $checked++
  }
 }
 @{version=1;ok=$true;mode=$Mode;entries=$checked;checkedAt=[DateTime]::UtcNow.ToString('o');physicalStorageIndependenceVerified=$false} | ConvertTo-Json -Compress
 exit 0
} catch {
 $code = $_.Exception.Message
 if ($code -notmatch '^ACL_[A-Z_]+$') { $code = 'ACL_OPERATION_FAILED' }
 @{version=1;ok=$false;mode=$Mode;error=$code;checkedAt=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Compress
 exit 1
}
