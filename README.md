# OpenVPN Installer for Rocky Linux 9.4

This script automates the installation and configuration of OpenVPN on Rocky Linux 9.4, with a focus on enhanced security features and support for OpenVPN versions 2.4.12 through 2.6.11. It is based on the work of [angristan's OpenVPN installer](https://github.com/angristan/openvpn-install), with significant modifications to target Rocky Linux 9.4 and provide version-specific configurations.

## Features

- Automated installation of OpenVPN (versions 2.4.12 through 2.6.11) on Rocky Linux 9.4
- Version-specific configurations to ensure compatibility and optimal security
- Enhanced security features tailored to each supported OpenVPN version
- Support for both repository and source installations
- Simplified user management
- Firewall rules and IP forwarding managed seamlessly
- Unprivileged mode: run as `nobody`/`nogroup`
- Various DNS resolver options for clients
- NATed IPv6 support (for OpenVPN 2.6.0+)
- DNS leak protection for Windows 10 clients
- Randomized server certificate name
- Option to protect clients with a password (private key encryption)
- Support for configuration files and command-line arguments
- Automated installation mode

## Changes from angristan's version

- Targeted specifically for Rocky Linux 9.4
- Extended support for OpenVPN versions 2.4.12 through 2.6.11
- Removed support for other distributions to focus on Rocky Linux
- Enhanced security configurations adapted to each supported OpenVPN version
- Simplified installation process with version-aware configurations
- Improved error handling and logging
- Added support for headless/automated installations
- Implemented configuration file support for easier deployment

## Prerequisites

- Rocky Linux 9.4 or later
- Root access
- Active internet connection
- Bash version 4 or higher

## Installation

You have several options for downloading and using this installer:

### Option 1: Download the installer script only

1. Download the script:

```bash
curl -O https://gitlab.com/albedo_black/openvpn-installer/-/raw/main/openvpn-installer.sh
```

2. Make the script executable:

```bash
chmod +x openvpn-installer.sh
```

### Option 2: Download the installer script and configuration files

1. Create a directory for the project and navigate to it:

```bash
mkdir openvpn-installer && cd openvpn-installer
```

2. Download the script:

```bash
curl -O https://gitlab.com/albedo_black/openvpn-installer/-/raw/main/openvpn-installer.sh
```

3. Download the configuration files:

```bash
mkdir conf.d
curl -o conf.d/openvpn-config.conf https://gitlab.com/albedo_black/openvpn-installer/-/raw/expanded-ovpn-ver-supt/conf.d/openvpn-config.conf
curl -o conf.d/vpn-users.conf https://gitlab.com/albedo_black/openvpn-installer/-/raw/expanded-ovpn-ver-supt/conf.d/vpn-users.conf
```

4. Make the script executable:

```bash
chmod +x openvpn-installer.sh
```

### Option 3: Clone the entire repository

1. Clone the repository:

```bash
git clone https://gitlab.com/albedo_black/openvpn-installer.git
```

2. Navigate to the project directory:

```bash
cd openvpn-installer
```

3. Make the script executable:

```bash
chmod +x openvpn-installer.sh
```

## Usage

### Basic Installation

Run the script as root:

```bash
sudo ./openvpn-installer.sh
```

Follow the on-screen prompts to complete the installation. The interactive menu will guide you through the following options:

1. Install OpenVPN
2. Add a new user
3. Revoke an existing user
4. Remove OpenVPN
5. Exit

When installing or adding a new user, you'll be prompted to choose:
- The OpenVPN protocol (UDP or TCP)
- The port for OpenVPN to listen on
- DNS resolver for the clients
- Whether to use compression
- Whether to customize encryption settings
- Whether to generate a client configuration with or without a password

### Advanced Installation Options

#### Using Configuration Files

To use the configuration files, pass them as arguments to the script:

```bash
sudo ./openvpn-installer.sh --openvpn-config conf.d/openvpn-config.conf --users-config conf.d/vpn-users.conf
```

#### Automated Installation

For headless or automated installations, use the `--auto-install` option:

```bash
sudo ./openvpn-installer.sh --auto-install
```

You can combine this with configuration files:

```bash
sudo ./openvpn-installer.sh --auto-install --openvpn-config conf.d/openvpn-config.conf --users-config conf.d/vpn-users.conf
```

If you don't specify the config files in auto-install mode, the script will look for `openvpn-config.conf` and `vpn-users.conf` in the `conf.d` directory.

## Configuration Files

The installer script supports two configuration files for automated and customized installations:

### 1. OpenVPN Server Configuration (`conf.d/openvpn-config.conf`)

This configuration file allows for fine-tuned control over the installation process and OpenVPN settings. Notable options include:

- `INSTALL_METHOD`: Choose between repository (1) or source (2) installation.
- `USE_LATEST_VERSIONS`: Automatically use the latest versions of OpenVPN and EasyRSA.
- `SKIP_CHECKSUM`: Option to skip checksum verification (use with caution).
- `OPENVPN_DOWNLOAD_URL` and `EASYRSA_DOWNLOAD_URL`: Specify custom download URLs for source installation.
- `FIREWALL_MANAGER`: Choose between `firewalld` and `iptables` for firewall management.
- `IP_FORWARD`: Control IP forwarding at the system level.

When using the configuration file, these settings will override the default values in the script, allowing for a customized and repeatable installation process. The full scheme and details are below:

```ini
# Network Configuration
PORT=1194                  # The port OpenVPN will listen on
PROTOCOL=udp               # Protocol to use (udp or tcp)
DEVICE=tun                 # The tun or tap device to use

# DNS Configuration
DNS1=8.8.8.8               # Primary DNS server
DNS2=8.8.4.4               # Secondary DNS server

# Encryption and Security
CIPHER=AES-256-GCM         # Encryption cipher to use
HMAC_ALG=SHA256            # HMAC algorithm for packet authentication
DH_CURVE=prime256v1        # Diffie-Hellman parameters for key exchange
TLS_SIG=1                  # Enable TLS control channel security (0 for tls-auth, 1 for tls-crypt)

# OpenVPN Version
OPENVPN_VERSION=           # Leave empty for latest, or specify (e.g., 2.5.9)

# Advanced Options
COMPRESSION_ENABLED=0      # Enable compression (0 for disabled, 1 for enabled)
CUSTOMIZE_ENC=0            # Allow customizing encryption settings (0 for no, 1 for yes)
USE_PREDEFINED_DH_PARAM=1  # Use predefined DH parameters (0 for no, 1 for yes)
EASYRSA_CERT_EXPIRE=3650   # Certificate validity in days
EASYRSA_CRL_DAYS=3650      # CRL validity in days

# IPv6 Support (for OpenVPN 2.6.0+)
IPV6_SUPPORT=0             # Enable IPv6 support (0 for disabled, 1 for enabled)

# Logging and Verbosity
VERB=3                     # Log verbosity level (0-11, default 3)

# Client-specific Settings
ALLOW_MULTIPLE_CLIENTS=0   # Allow clients to use the same certificate (0 for no, 1 for yes)
```

### 2. VPN Users Configuration (`conf.d/vpn-users.conf`)

This file is used to automatically generate user credentials and keys for the VPN:

```ini
# User Configuration
# Format: USERNAME=PASSWORD
# Set PASSWORD to 'nopass' for a client without a password
user1=password123
user2=nopass
user3=strongPassword!

# Global Password Setting
# USE_SAME_PASSWORD=1
# GLOBAL_PASSWORD=global_password_here

# Password Generation
# GENERATE_RANDOM_PASSWORDS=1
# MIN_PASSWORD_LENGTH=12
# INCLUDE_SPECIAL_CHARS=1
```

## Version-Specific Features

The script adapts its configurations based on the installed or selected OpenVPN version:

- For versions 2.5.0 and above:
  - Uses `data-ciphers` instead of `cipher`
  - Uses `tls-ciphersuites` instead of `tls-cipher`
  - Enables OpenSSL legacy provider
- For versions 2.5.7 and above:
  - Adds `providers legacy default` option
- For versions 2.5.8 and above:
  - Adds `auth-gen-token` for server and `auth-token-user` for clients
- For versions 2.6.0 and above:
  - Adds IPv6 support with appropriate routing options

## Security and Encryption

This script implements several security enhancements:

- Enforces TLS 1.2 as the minimum version
- Uses ECDSA certificates with the `prime256v1` curve
- Implements version-specific cipher suites and options
- Enables `tls-crypt` for an extra layer of security
- Runs the server in unprivileged mode as the `nobody` user
- Enables DNS leak protection for Windows 10 clients

## Compatibility

This script is designed specifically for Rocky Linux 9.4 and later. It requires `systemd` and `firewalld`.

## Troubleshooting

If you encounter issues during installation or use, please check the following:

1. Ensure you're running the script as root.
2. Verify that your system meets the prerequisites.
3. Check the OpenVPN logs at `/var/log/openvpn/`.
4. If using configuration files, ensure they are formatted correctly.
5. For version-specific issues, confirm that the detected OpenVPN version is correct.

For further assistance, please open an issue on the project's GitLab page.

## Contributing

Contributions to this project are welcome. Please fork the repository, make your changes, and submit a merge request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

This script is based on the work of:
- [Nyr](https://github.com/Nyr/openvpn-install)
- [angristan](https://github.com/angristan/openvpn-install)

Modified by [Tyler Zervas (albedo_black)](https://gitlab.com/albedo_black) for Rocky Linux 9.4 with support for OpenVPN versions 2.4.12 through 2.6.11 and enhanced security features.

## Disclaimer

This script is provided as-is, without any warranties or guarantees. Always review the script and understand its operations before running it on your system, especially in production environments. Ensure that the use of OpenVPN complies with your organization's security policies and any applicable regulations.
