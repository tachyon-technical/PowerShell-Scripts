### Directory

- **WinServer_InitialConfig.ps1** is for short-lived Windows Server VMs in a lab environment
  - Disables IPv6 on interface
  - Disables IPv6 driver options
  - Disables 6to4, Teredo, and ISATAP
  - Statically configures interfaces
  - Disables Windows Update and various services not needed in labs
  - Blocks traffic from those services inbound and outbound
  - Adds MS update domains to hosts file (pointing to 0.0.0.0)
  - Switches unecessary firewall Allow rules to Block
  - Disables various scheduled tasks
  - Sets timezone
  - Sets hostname
