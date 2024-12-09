### Directory

- [WinServer_InitialConfig.ps1](https://github.com/tachyon-technical/PowerShell-Scripts/blob/main/WinServer_InitialConfig.ps1) is for short-lived Windows Server VMs in a lab environment
  - Disables IPv6 on interface
  - Disables IPv6 driver options
  - Disables 6to4, Teredo, and ISATAP
  - Statically configures NIC
  - Disables Windows Update and various services not needed in labs
  - Blocks traffic from those services inbound and outbound
  - Adds MS update domains to hosts file (pointing to 0.0.0.0)
  - Switches unecessary firewall _Allow_ rules to _Block_
  - Disables various scheduled tasks
  - Sets timezone
  - Sets hostname
