##########
####  
####  Initial Server Setup 
####  For Windows Server in GNS3
####  So it doesn't eat all my bandwidth
####  MICROSOFFFFT
####
##########

# Simple hashing function for strings

function Get-StringHash {
  Param(
    [Parameter(Mandatory = $true)]
    [String]$InputString
  )

  $stringAsStream = [System.IO.MemoryStream]::new()
  $writer = [System.IO.StreamWriter]::new($stringAsStream)
  $writer.Write($InputString)
  $writer.Flush()
  $stringAsStream.Position = 0

  $HashResult = Get-FileHash -Algorithm SHA256 -InputStream $stringAsStream | Select-Object Hash
  $HashResult.Hash
}


# Disables IPv6 features:
#   - IPv6 on interface
#   - IPv6 options in NIC driver
#   - IPv6 adapters (Teredo, etc.)

function Disable-IPv6 {
  Param (
    [Parameter(Mandatory = $true)]
    [Microsoft.Management.Infrastructure.CimInstance] $NetAdapter
  )

  # Disable IPv6 on interface
  try {
    Write-Host "Disabling IPv6 on network adapter..."
    Disable-NetAdapterBinding -Name $NetAdapter.Name `
      -ComponentID ms_tcpip6 `
      -ErrorAction Stop
    Write-Host -ForegroundColor Green "`tDone disabling IPv6."
  }
  catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
    Write-Host "Error accessing interface or IPv6 component."
  }

  # Disable IPv6 driver options on interface
  try {
  
    $IfaceAdvancedProps = Get-NetAdapterAdvancedProperty -Name $NetAdapter.Name `
      -ErrorAction Stop
    $AdvancePropsChanged = $false
    Write-Host "Checking IPv6 driver options..."
    foreach ($AdvancedProp in $IfaceAdvancedProps) {
      $IsIPv6 = ($AdvancedProp.DisplayName | Tee-Object -Variable DisplayName | Out-String) -match '(IPv6)'
      $IsEnabled = ($AdvancedProp.DisplayValue | Tee-Object -Variable DisplayValue | Out-String) -match 'Enabled'
      if ($IsIPv6 -and $IsEnabled) {
        $AdvancePropsChanged = $true
        Write-Host -NoNewline "`tDisabling $DisplayName..."
        Set-NetAdapterAdvancedProperty -Name $EthernetInterface.Name `
          -DisplayName "$DisplayName" `
          -DisplayValue 'Disabled' `
          -ErrorAction Stop             
        Write-Host -ForegroundColor Green "`tDone."
      }
    }

    if (-not $AdvancePropsChanged) {
      Write-Host -ForegroundColor Green "`tIPv6 options already disabled."
    }
  }
  catch {
    Write-Host Encountered an unknown error while modifying $DisplayName      
  }

  # Disable 6to4 adapter
  try {
    Write-Host "Checking 6to4 tunneling..."
    $Net6to4Settings = Get-Net6to4Configuration | Select-Object -Property State, AutoSharing, RelayState
    $Net6to4NeedsChange = $false

    foreach ($Net6to4Setting in $Net6to4Settings.PsObject.Properties) {
      if ($Net6to4Setting.Value -match 'Enabled') {
        Write-Host -NoNewline ("`tFound 6to4 {0} is " -f $Net6to4Setting.Name )
        Write-Host -ForegroundColor Yellow "enabled."
        $Net6to4NeedsChange = $true
      }
    }

    if ($Net6to4NeedsChange) {
      Write-Host -NoNewline "`tDisabling all 6to4 options..."
      Set-Net6to4Configuration -State Disabled -AutoSharing Disabled -RelayState Disabled -ErrorAction Stop
      Write-Host -ForegroundColor Green "`tDone."
    }
    else {
      Write-Host -ForegroundColor Green "`t 6to4 already disabled."
    }
 
  }
  catch {
    Write-Host "Encountered an error modifying configuration."
  }

  # Disable Teredo adapter
  try {
    Write-Host "Checking Teredo... "
    $TeredoState = (Get-NetTeredoConfiguration).Type
 
    if ($TeredoState -notmatch 'Disabled') {
      Write-Host -NoNewline "`tTeredo is currently "
      Write-Host -ForegroundColor Yellow "enabled."
      Write-Host "`tDisabling Teredo... "
      Set-NetTeredoConfiguration -Type Disabled -ErrorAction Stop
      Write-Host -NoNewLine "`tTeredo is now "
      Write-Host -ForegroundColor Green "disabled."
    }
    else {
      Write-Host -ForegroundColor Green "`tTeredo already disabled."
    }
  }
  catch {
    Write-Host "Error disabling Teredo."
  }

  # Disable ISATAP adapter
  try { 
    Write-Host Checking ISATAP...
    $IsatapConfiguration = $(Get-NetIsatapConfiguration).State

    if ($IsatapConfiguration -notmatch 'Disabled') {
      Write-Host -NoNewline "`tISATAP is currently "
      Write-Host -ForegroundColor Yellow "enabled."
      Write-Host -NoNewline "`tDisabling ISATAP... "
      Set-NetIsatapConfiguration -State Disabled -ResolutionState Disabled -ErrorAction Stop
      Write-Host -ForegroundColor Green "done."
    }
    else {
      Write-Host -ForegroundColor Green "`tISATAP already disabled."
    }
  }
  catch { 
    Write-Host "Error disabling ISATAP"
  }
}



# Removes existing addresses
# Statically addresses NIC

function Set-StaticIPv4Address {
  Param (
    [Parameter(Mandatory = $true)][Microsoft.Management.Infrastructure.CimInstance] $NetAdapter,
    [Parameter(Mandatory = $true)][ValidateLength(7, 15)][String]$IPv4Address,
    [Parameter(Mandatory = $true)][ValidateScript({ ($_ -ge 0) -and ($_ -le 32) })][Int]$NetMask,
    [Parameter(Mandatory = $true)][ValidateLength(7, 15)][String]$DefaultGateway,
    [Parameter(Mandatory = $true)][ValidateScript({ foreach ($_server in $_) {
          if ($_server.Length -le 6) { return $false }
          if ($_server.Length -ge 16) { return  $false }
          return $true
        } })][Array]$NameServers)
                                                      
  if ($NetAdapter.Status -match "Up") {
    Write-Host "Interface appears to be up. Continuing..."
  }
  if ($NetAdapter.Status -match "Disconnected") {
    Write-Host "Interface doesn't appear to be up. Continuing..."
  }
  
  try {
    Write-Host "Removing IP address, if present."
    $NetAdapter | Remove-NetIPAddress -AddressFamily IPv4 -Confirm:$false -ErrorAction Stop
    Write-Host -ForegroundColor Green "`tRemoved IP address."
  }
  catch { 
    Write-Host -ForegroundColor Yellow "Unable to remove IP address."
  }                 

  try {
    Write-Host "Removing routes, if present."
    $NetAdapter | Remove-NetRoute -AddressFamily IPv4 -Confirm:$false -ErrorAction Stop
    Write-Host -ForegroundColor Green "`tRemoved routes."
  }
  catch { 
    Write-Host -ForegroundColor Yellow "Unable to remove routes."
  } 

  try {
    Write-Host "Configuring IP address."
    $NetAdapter | New-NetIPAddress -IPAddress $IPv4Address -AddressFamily IPv4 `
      -PrefixLength $NetMask -DefaultGateway $DefaultGateway `
      -Confirm:$false -ErrorAction Stop | Out-Null
    Write-Host -ForegroundColor Green "`tAssigned IP address."
  }
  catch { 
    Write-Host -ForegroundColor Yellow "`tUnable to assign IP address."
  } 

  try {
    Write-Host "Configuring DNS servers."
    $NetAdapter | Set-DnsClientServerAddress -ServerAddresses $NameServers
    Write-Host -ForegroundColor Green "`tConfigured DNS servers."
  }
  catch { 
    Write-Host -ForegroundColor Yellow "`tUnable to configured DNS servers."
  } 

}



# Stops services
# Disables services
# Prevent services from communicating inbound
# Prevents services from communicating inbound

function Disable-Services {

  Write-Host "Blocking Windows Update and other unwanted services."
  $Services = @(
    "wuauserv",
    "UsoSvc",
    "WaaSMedicSVC",
    "InstallService",
    "DiagTrack",
    "WSearch",
    "AxInstSV",
    "BITS",
    "bthserv",
    "DiagTrack",
    "DoSvc",
    "iphlpsvc",
    "lmhosts",
    "Wcmsvc",
    "WerSvc",
    "WinHttpAutoProxySvc"
  )

  foreach ($Service in $Services) {
    $RuleName = "Block $Service"
    $RuleDisplayGroup = "Scripted Rules"
    $RuleProfile = "Any"

    $InboundHash = "{0}{1}{2}Inbound" -f $RuleName, $RuleDisplayGroup, $RuleProfile
    $OutboundHash = "{0}{1}{2}Outbound" -f $RuleName, $RuleDisplayGroup, $RuleProfile
    
    $RuleIdentifiers = @{
      "InboundHash"  = Get-StringHash("{0}{1}{2}Inbound" -f $RuleName, $RuleDisplayGroup, $RuleProfile)
      "OutboundHash" = Get-StringHash("{0}{1}{2}Outbound" -f $RuleName, $RuleDisplayGroup, $RuleProfile)
    }

    try {
      Get-Service -Name $Service | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue | Stop-Service -Force -NoWait -ErrorAction Stop 
      Write-Host -ForegroundColor Green "`tStopped $Service"
      Write-Host "`tChecking if $Service is blocked inbound"
      $InboundRuleExists = Get-NetFirewallRule -Name $RuleIdentifiers["InboundHash"] -ErrorAction SilentlyContinue
      if ($InboundRuleExists) {
        Write-Host -ForegroundColor Green "`t$Service already blocked inbound."
      }
      else {
        New-NetFirewallRule -DisplayName "Block $Service" -Name $RuleIdentifiers["InboundHash"] -Direction Inbound `
          -Profile "$RuleProfile" -Service $Service -Action Block `
          -Enabled True -Group "$RuleDisplayGroup" -ErrorAction Stop | Out-Null
        Write-Host -ForegroundColor Green "`tBlocked $Service inbound"
      }
      
      Write-Host "`tChecking if $Service is blocked outbound."
      $OutboundRuleExists = Get-NetFirewallRule -Name $RuleIdentifiers["OutboundHash"] -ErrorAction SilentlyContinue
      if ($OutboundRuleExists) {
        Write-Host -ForegroundColor Green "`t$Service already blocked outbound."
      }
      else {
        New-NetFirewallRule -DisplayName "Block $Service" -Name $RuleIdentifiers["OutboundHash"] -Direction Outbound `
          -Profile $RuleProfile -Service $Service -Action Block `
          -Enabled True -Group "$RuleDisplayGroup" -ErrorAction Stop | Out-Null
        Write-Host -ForegroundColor Green "`tBlocked $Service outbound"
      }

    }
    catch {
      Write-Host -ForegroundColor Yellow "`tFailed to stop $Service or block it with Windows Firewall"
    }
 
  }


}


# Appends entries to HOSTS file
# Directs MS Update domains into the void
# at 0.0.0.0

function Block-MSUpdateDomains {

  $Hosts_File_Location = "$env:SystemDrive" + "\Windows\System32\drivers\etc\hosts"
  $AlreadyFinished = Select-String -Path $Hosts_File_Location -Pattern "###HostsPresent"
  
  Write-Host "Checking if hosts file already updated."
  if ($AlreadyFinished -ne $null) {
    Write-Host -ForegroundColor Green "`tHosts already appended"
    return
  }
  else {
    Add-Content -Path $Hosts_File_Location -Value "###HostsPresent"
    Write-Host -ForegroundColor Green "`tAppended hosts."
  }

  $BlockedDomains = @(
    "0.0.0.0    microsoft.com"
    "0.0.0.0    windowsupdate.microsoft.com",
    "0.0.0.0    update.microsoft.com",
    "0.0.0.0    windowsupdate.com",
    "0.0.0.0    download.windowsupdate.com",
    "0.0.0.0    download.microsoft.com",
    "0.0.0.0    wustat.windows.com",
    "0.0.0.0    netservicepack.microsoft.com",
    "0.0.0.0    stats.microsoft.com",
    "0.0.0.0    bing.com"
  )

  foreach ($BlockedDomain in $BlockedDomains) {
    Write-Host -ForegroundColor Green "`t$BlockedDomain"
    Add-Content -Path $Hosts_File_Location -Value $BlockedDomain
  }
}


# Modify default MS firewall rules
# allowing unnecessary traffic
# Set them to block

function Disable-MSFirewallRules {

  $RuleGroups = @(
    "Delivery Optimization",
    "Start",
    "Windows Media Player Network Sharing Service",
    "Windows Search",
    "DiagTrack",
    "Email and accounts",
    "Narrator"
  )


  foreach ($RuleGroup in $RuleGroups) {
    Write-Host "Switching rules in $RuleGroup to 'block.'"
    $GroupRules = Get-NetFirewallRule -DisplayGroup $RuleGroup
    foreach ($Rule in $GroupRules) {
      $Rule | Set-NetFirewallRule -Action Block -Enabled True
      Write-Host -ForegroundColor Green ("`tBlocked {0}." -f $Rule.DisplayName)
    }
  }

}
  

# Disabled any scheduled tasks we can

function Disable-MSScheduledTasks {
  $ScheduledTaskPaths = @(
    "\Microsoft\Windows\CloudExperienceHost\",
    "\Microsoft\Windows\Speech\",
    "\Microsoft\Windows\UpdateOrchestrator\",
    "\Microsoft\Windows\Windows Error Reporting\",
    "\Microsoft\Windows\WindowsUpdate\"
  )

  foreach ($ScheduledTaskPath in $ScheduledTaskPaths) {
    Write-Host "Checking for scheduled tasks in $ScheduledTaskPath"
    $ScheduledTasks = Get-ScheduledTask -TaskPath $ScheduledTaskPath
    foreach ($ScheduledTask in $ScheduledTasks) {
      Write-Host ("`tFound {0}" -f $ScheduledTask.TaskName)
      try {
        $ScheduledTask | Disable-ScheduledTask -ErrorAction Stop | Out-Null
        Write-Host -ForegroundColor Green ("`tDisabled {0}." -f $ScheduledTask.TaskName)
      }
      catch [Microsoft.Management.Infrastructure.CimException] {
        Write-Host -ForegroundColor Yellow ("`tCouldn't disable {0}." -f $ScheduledTask.TaskName)
      }
    }
  }

}

# DEFINE VARIABLES HERE

$EthernetInterface = Get-NetAdapter -Physical 
$IPv4Address = "192.168.122.102"
$NetMask = 24
$DefaultGateway = "192.168.122.1"
$NameServers = @("1.1.1.1", " 8.8.8.8")


Disable-IPv6 -NetAdapter $EthernetInterface
Set-StaticIPv4Address -NetAdapter $EthernetInterface -IPv4Address $IPv4Address -NetMask $NetMask -DefaultGateway $DefaultGateway -NameServers $NameServers
Disable-Services
Block-MSUpdateDomains
Disable-MSFirewallRules
Disable-MSScheduledTasks
