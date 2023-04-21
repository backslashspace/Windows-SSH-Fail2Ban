___
# Windows SSH Fail2Ban: SSH Brute-Force protection 

Just like the original [Fail2Ban](https://github.com/fail2ban/fail2ban), this configurable and easy to use solution works by scanning
logs, in this case the Windows event log from the [Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH) service and bans IPs with
too many failed authentication attempts, whether with passwords or public/private key authentication. It does this by updating firewall rules
to reject new connections from those IPs for a configurable amount of time.

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

You can display all possible commands via `F2B-CLI /help`

#### `F2B-CLI` The command line

- `/Help` Shows all possible commands and format
- `/About` Shows the Application version and link to this page
- `/Start` Starts the service with formatted output in the current terminal session

- `/Show` [ Banned | Trusted | [  History | History  "IP" ] ]
