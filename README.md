# OpenVPN Installer for Rocky Linux 9.4

This script automates the installation of OpenVPN on Rocky Linux 9.4, with a focus on FIPS compliance and enhanced security features. It is based on the work of [angristan's OpenVPN installer](https://github.com/angristan/openvpn-install), with modifications to target Rocky Linux 9.4 and OpenVPN 2.5.9 specifically.

## Features

- Automated installation of OpenVPN 2.5.9 on Rocky Linux 9.4
- FIPS compliance-oriented configurations
- Enhanced security features
- Support for both repository and source installations
- Simplified user management
- Iptables rules and forwarding managed seamlessly
- Unprivileged mode: run as `nobody`/`nogroup`
- Variety of DNS resolvers to be pushed to the clients
- NATed IPv6 support
- Block DNS leaks on Windows 10
- Randomised server certificate name
- Choice to protect clients with a password (private key encryption)

## Changes from angristan's version

- Targeted specifically for Rocky Linux 9.4
- Updated to use OpenVPN 2.5.9
- Removed support for other distributions to focus on Rocky Linux
- Added FIPS compliance considerations
- Enhanced security configurations
- Simplified installation process
- Improved error handling and logging
- Added support for headless/automated installations

## Usage

### Installation

1. Download the script using curl or wget:

```bash
# Using curl:
curl -O https://gitlab.com/albdeo_black/openvpn-installer/-/raw/main/openvpn-installer.sh

# Using wget:
wget https://gitlab.com/albdeo_black/openvpn-installer/-/raw/main/openvpn-installer.sh
```

2. Make the script executable:

```bash
chmod +x openvpn-installer.sh
```

3. Run the script as root:

```bash
sudo ./openvpn-installer.sh
```

4. Follow the on-screen prompts to complete the installation.

### Headless Installation

Set the `AUTO_INSTALL` variable, then run the script:

```bash
AUTO_INSTALL=y ./openvpn-installer.sh openvpn-config.conf openvpn-users.conf

# or

export AUTO_INSTALL=y
./openvpn-installer.sh openvpn-config.conf openvpn-users.conf
```

### User Management

To add or revoke users, simply run the script again and choose the appropriate options.

### Headless User Addition

It's also possible to automate the addition of a new user. Here, the key is to provide the (string) value of the `MENU_OPTION` variable along with the remaining mandatory variables before invoking the script.

The following Bash script adds a new user `foo` to an existing OpenVPN configuration:

```bash
#!/bin/bash
export MENU_OPTION="1"
export CLIENT="foo"
export PASS="1"
./openvpn-install.sh
```

## Security and Encryption

OpenVPN's default settings are pretty weak regarding encryption. This script aims to improve that.

### TLS Version

With `tls-version-min 1.2` we enforce TLS 1.2, the best protocol currently available for OpenVPN. TLS 1.2 is supported since OpenVPN 2.3.3.

### Certificate

This script provides ECDSA certificates, which are faster, lighter, and more secure. It defaults to ECDSA with `prime256v1`.

### Data Channel

By default, OpenVPN uses `AES-256-GCM` for data channel encryption, which provides confidentiality, integrity, and authenticity assurances on the data.

### Control Channel

The script proposes the following options, depending on the certificate:

- ECDSA:
  - `TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256`
  - `TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384`
- RSA:
  - `TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256`
  - `TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384`

It defaults to `TLS-ECDHE-*-WITH-AES-128-GCM-SHA256`.

### Diffie-Hellman Key Exchange

The script provides the following options:

- ECDH: `prime256v1`/`secp384r1`/`secp521r1` curves
- DH: `2048`/`3072`/`4096` bits keys

It defaults to `prime256v1`.

### `tls-auth` and `tls-crypt`

`tls-crypt` is an OpenVPN 2.4 feature that provides encryption in addition to authentication, and it is more privacy-friendly.

## Compatibility

The script supports Rocky Linux 9.4 and later. It requires `systemd`.

## License

This project is licensed under the MIT License. See the [LICENSE](https://gitlab.com/albdeo_black/openvpn-installer/-/raw/main/LICENSE) file for details.

## Acknowledgements

This script is based on the work of:
- [Nyr](https://github.com/Nyr/openvpn-install)
- [angristan](https://github.com/angristan/openvpn-install)

Modified by [Tyler Zervas (albedo_black)](https://gitlab.com/albedo_black) for Rocky Linux 9.4 with FIPS compliance and enhanced security features.

## Disclaimer

This script is provided as-is, without any warranties or guarantees. Always review the script and understand its operations before running it on your system, especially in production environments.
