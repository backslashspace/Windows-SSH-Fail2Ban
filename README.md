___
# Windows Fail2Ban: SSH Brute-Force protection 

Just like the original [Fail2Ban](https://github.com/fail2ban/fail2ban), this configurable and easy to use solution works by scanning
logs, in this case the Windows event log from the [Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH) service and bans IPs with
too many failed authentication attempts, whether with passwords or public/private key authentication. It does this by updating firewall rules
to reject new connections from those IPs for a configurable amount of time.<br /><br />
[IPv4 & IPv6 are supported]

This program is able to reduce the rate of incorrect authentication
attempts, but cannot eliminate the risk presented by weak authentication.
Make sure to configure your sshd service securely, this might help:

For a SSH audit: [sshaudit.com](https://www.sshaudit.com/)                      
sshd config reverence: [linux.die.net](https://linux.die.net/man/5/ssh_config)

___

## Installation

The installation is straight forward and only takes a couple clicks:

- Download the latest installer from the [releases](https://github.com/backslashspace/Windows-SSH-Fail2Ban/releases) and execute it
- Follow the installation instructions
- Done

#### What the installer does
1. The installer will extract the following files to `C:\Program Files\OpenSSH-Fail2Ban\`:

  - `F2B-SRV.exe`: the service application
  - `F2B-CLI.exe`: the commandline interface
  - `config.txt`: _the config file_

2. `C:\Program Files\OpenSSH-Fail2Ban\` will be added to the System Path variable, making `F2B-CLI.exe` globally accessible in the command line.

3. `F2B-SRV.exe` will be registered as a Windows Service with the name `OpenSSH Fail2Ban`, and is configured by default to start at boot.
___

## Feature & capabilities
The solution consists of two components: the service and the command line application.
The command line application has the same functionality plus management 
features for banned IPs, 'trusted' IPs and IPs ban history.

#### F2B-SRV & config: How it works and what it does

By default the program will check every 5 seconds (`LogScanIntervall=5/s`) the last hour (`LogScanTime=1/h`) of the sshd log, and will ban every IP that exceeds 10 failed attempts (`FailTrigger=10`). 
By default, if the server and client are unable to exchange their banners or fail to negotiate a key exchange algorithm, this will be counted as a failed attempt, which can be deactivated (`CountBannerError=true`, 
`CatchNegotiationErrors=true`).
Furthermore, automatic permanent bans are deactivated (`PermBan=false`) by default.

The ban duration can be configured like the following:<br />
`BanTime=1/h,3/h,1/d,7/d,14/d,1/M,3/M`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(More or less values are possible)<br />
Forexample, this will result in the first ban being 1 hour long, the third 1 day and the 7th 3 months long, after 7 times the last configured time will be used (3 months in this example), if `PermBan` is set to true, the IP will be permanently banned.
Alternatively if `BanTime=off` & `PermBan=true`the IP will be permanently banned on the first offense.

When a ban is triggered, the program will block the IP based on its 
history for the configured amount of time and adds it to its database, 
automatic unbans are handled by the Windows Task Scheduler, which 
updates the firewall, & database.

Furthermore, every ban is logged in the Windows event log under `OpenSSH-Fail2Ban` with the following information: 
- banned IP
- failed authentication method / used username*s
- assigned ban ID
- ban duration
- ban time
- unban time

#### `F2B-CLI` The command line

You can display all possible commands via `F2B-CLI /help`

- `/Help` Shows all possible commands and format
- `/About` Shows the Application version and link to this page
- `/Start` Starts the service with formatted output in the current terminal session

- `/Show` with following parameters:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; `Banned` Shows a formatted list which contains the ban ID, IP, ban date & unban date

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; `Trusted` Shows a formatted list with all configured 'Trusted' IPs

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; `History` Shows a formatted list which contains all IPs that have been banned and how often

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; `History x.x.x.x` Shows the ban history of given IP x.x.x.x

- `/Add` with following parameters:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; `Banned x.x.x.x` Bans IP x.x.x.x permanently and adds it to the database

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; `Trusted x.x.x.x` Adds IP x.x.x.x to the list of trusted IPs (IP will be ignored by the service)

- `/Remove` with following parameters:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; `Trusted x.x.x.x` Removes IP x.x.x.x from the list of trusted IPs (when 'all' instead of an IP is used, all IPs are targeted)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; `History x.x.x.x` Removes history of IP x.x.x.x (can be used with 'all')

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; `Banned x.x.x.x` Unbans IP x.x.x.x & removes it from the database (can be used with 'all')

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; `Banned x.x.x.x /S` Unbans IP x.x.x.x & prevents a reban if the IP happens to be in the log scan time (can be used with 'all')


This information is stored in the Registry under `HKEY_LOCAL_MACHINE\SOFTWARE\OpenSSH-Fail2Ban`

___
Written in C# 9.0 and running on .Net Framework 4.8.<br />
Tested with OpenSSH V8.9.1.0p1
