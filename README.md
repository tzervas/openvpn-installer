# OpenVPN Installer for Rocky Linux 9.4

This script automates the installation and configuration of OpenVPN on Rocky Linux 9.4, with a focus on FIPS compliance and enhanced security features. It is based on the work of [angristan's OpenVPN installer](https://github.com/angristan/openvpn-install), with modifications to target Rocky Linux 9.4 and OpenVPN 2.5.9 specifically.

## Features

- Automated installation of OpenVPN 2.5.9 (or latest version) on Rocky Linux 9.4
- FIPS compliance-oriented configurations
- Enhanced security features
- Support for both repository and source installations
- Simplified user management
- Firewall rules and IP forwarding managed seamlessly
- Unprivileged mode: run as `nobody`/`nogroup`
- Various DNS resolver options for clients
- NATed IPv6 support
- DNS leak protection for Windows 10 clients
- Randomized server certificate name
- Option to protect clients with a password (private key encryption)
- Support for configuration files and command-line arguments
- Automated installation mode

## Changes from angristan's version

- Targeted specifically for Rocky Linux 9.4
- Updated to use OpenVPN 2.5.9 by default, with option to use latest versions
- Removed support for other distributions to focus on Rocky Linux
- Added FIPS compliance considerations
- Enhanced security configurations
- Simplified installation process
- Improved error handling and logging
- Added support for headless/automated installations
- Implemented configuration file support

## Prerequisites

- Rocky Linux 9.4 or later
- Root access
- Active internet connection

## Usage

### Basic Installation

1. Download the script:

```bash
curl -O https://gitlab.com/albedo_black/openvpn-installer/-/raw/main/openvpn-installer.sh
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

### Advanced Installation Options

#### Using Configuration Files

You can use configuration files to set up OpenVPN and manage users. There are two types of configuration files:

1. OpenVPN Configuration (`openvpn-config.conf`)
2. Users Configuration (`openvpn-users.conf`)

To use these configuration files, pass them as arguments to the script:

```bash
sudo ./openvpn-installer.sh --openvpn-config /path/to/openvpn-config.conf --users-config /path/to/openvpn-users.conf
```

#### Automated Installation

For headless or automated installations, use the `--auto-install` option:

```bash
sudo ./openvpn-installer.sh --auto-install
```

You can combine this with configuration files:

```bash
sudo ./openvpn-installer.sh --auto-install --openvpn-config /path/to/openvpn-config.conf --users-config /path/to/openvpn-users.conf
```

If you don't specify the config files in auto-install mode, the script will look for `openvpn-config.conf` and `openvpn-users.conf` in the current directory.

### Configuration File Format

Both configuration files use a simple `key=value` format. Here's an example of `openvpn-config.conf`:

```
PORT=1194
PROTOCOL=udp
DNS1=8.8.8.8
DNS2=8.8.4.4
COMPRESSION_ENABLED=n
CUSTOMIZE_ENC=n
```

And an example of `openvpn-users.conf`:

```
CLIENT=client1
PASS=1
```

### User Management

To add or revoke users, you can either:

1. Run the script again and choose the appropriate options from the menu.
2. Update the `openvpn-users.conf` file and run the script with the `--users-config` option.

## Security and Encryption

This script implements several security enhancements over the default OpenVPN settings:

### TLS Version

The script enforces TLS 1.2 as the minimum version, which is the most secure protocol currently available for OpenVPN.

### Certificates

The script uses ECDSA certificates with the `prime256v1` curve by default, which are faster, lighter, and more secure than RSA certificates.

### Data Channel Encryption

By default, the script uses `AES-256-GCM` for data channel encryption, providing confidentiality, integrity, and authenticity assurances on the data.

### Control Channel Encryption

The script uses `TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384` for the control channel, providing strong security for key exchange and authentication.

### Diffie-Hellman Key Exchange

The script uses ECDH with the `prime256v1` curve for Diffie-Hellman key exchange.

### Additional Security Measures

- `tls-crypt` is used to add an extra layer of security to the TLS channel.
- The server runs in unprivileged mode as the `nobody` user.
- DNS leak protection is enabled for Windows 10 clients.

## Compatibility

This script is designed specifically for Rocky Linux 9.4 and later. It requires `systemd` and `firewalld`.

## Troubleshooting

If you encounter any issues during installation or use, please check the following:

1. Ensure you're running the script as root.
2. Verify that your system meets the prerequisites.
3. Check the OpenVPN logs at `/var/log/openvpn/`.
4. If using configuration files, ensure they are formatted correctly.

For further assistance, please open an issue on the project's GitLab page.

## Contributing

Contributions to this project are welcome. Please fork the repository, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

This script is based on the work of:
- [Nyr](https://github.com/Nyr/openvpn-install)
- [angristan](https://github.com/angristan/openvpn-install)

Modified by [Tyler Zervas (albedo_black)](https://gitlab.com/albedo_black) for Rocky Linux 9.4 with FIPS compliance and enhanced security features.

## Disclaimer

This script is provided as-is, without any warranties or guarantees. Always review the script and understand its operations before running it on your system, especially in production environments. Ensure that the use of OpenVPN complies with your organization's security policies and any applicable regulations.