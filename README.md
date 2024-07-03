# OpenVPN Installer for Rocky Linux 9.4

This script automates the installation of OpenVPN on Rocky Linux 9.4, with a focus on FIPS compliance and enhanced security features. It is based on the work of [angristan's OpenVPN installer](https://github.com/angristan/openvpn-install), with modifications to target Rocky Linux 9.4 and OpenVPN 2.5.9 specifically.

## Features

- Automated installation of OpenVPN 2.5.9 on Rocky Linux 9.4
- FIPS compliance-oriented configurations
- Enhanced security features
- Support for both repository and source installations
- Simplified user management

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

1. Download the script using curl or wget:

   Using curl:
curl -O https://gitlab.com/albdeo_black/openvpn-installer/-/raw/main/openvpn-installer.sh
Copy
Using wget:
wget https://gitlab.com/albdeo_black/openvpn-installer/-/raw/main/openvpn-installer.sh
Copy
2. Make the script executable:
chmod +x openvpn-installer.sh
Copy
3. Run the script as root:
sudo ./openvpn-installer.sh
Copy
4. Follow the on-screen prompts to complete the installation.

## Headless Installation

For automated installations, you can use the `openvpn-config.conf` file to set your preferences. First, download the configuration file:
curl -O https://gitlab.com/albdeo_black/openvpn-installer/-/raw/main/openvpn-config.conf
Copy
or
wget https://gitlab.com/albdeo_black/openvpn-installer/-/raw/main/openvpn-config.conf
Copy
Then, run the script with:
sudo ./openvpn-installer.sh openvpn-config.conf
Copy
## User Management

To add or revoke users, simply run the script again and choose the appropriate option.

## License

This project is licensed under the MIT License. See the [LICENSE](https://gitlab.com/albdeo_black/openvpn-installer/-/raw/main/LICENSE) file for details.

## Acknowledgements

This script is based on the work of:
- [Nyr](https://github.com/Nyr/openvpn-install)
- [angristan](https://github.com/angristan/openvpn-install)

Modified by [Tyler Zervas (tzervas)](https://github.com/tzervas) for Rocky Linux 9.4 with FIPS compliance and enhanced security features.

## Disclaimer

This script is provided as-is, without any warranties or guarantees. Always review the script and understand its operations before running it on your system, especially in production environments.
