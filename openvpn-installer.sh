#!/bin/bash

# OpenVPN installer for Rocky Linux 9.4
# Based on the work of angristan (https://github.com/angristan/openvpn-install)
# Modified for Rocky Linux 9.4 and OpenVPN 2.5.9 with enhanced security features
#
# Original work licensed under MIT License
# Copyright (c) 2013 Nyr
# Copyright (c) 2016 Stanislas Lange (angristan)
#
# This modified version is also licensed under MIT License
# Copyright (c) 2024 Tyler Zervas (albedo_black)
#
# Full license text can be found in the LICENSE file in the root directory of this source tree
# or at https://opensource.org/licenses/MIT

set -euo pipefail

# Global variables
OPENVPN_VERSION="2.5.9"
EASYRSA_VERSION="3.1.6"
OPENVPN_DOWNLOAD_URL="https://swupdate.openvpn.org/community/releases/openvpn-$OPENVPN_VERSION.tar.gz"
OPENVPN_SHA256="9d3379d00a62575aad981ce4d90240efc63a8ba0d9a9e87bb12e0d465d4d3f97"
EASYRSA_DOWNLOAD_URL="https://github.com/OpenVPN/easy-rsa/releases/download/v$EASYRSA_VERSION/EasyRSA-$EASYRSA_VERSION.tgz"
EASYRSA_SHA256="41d026bad2eef1520ae6613598f9e1e1be0e6c0c8f0fdc9ed7c58873a8e57cc2"

# Function to log messages
function log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if script is run as root
function check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_message "This script must be run as root" >&2
        exit 1
    fi
}

# Function to check if TUN device is available
function check_tun() {
    if [[ ! -e /dev/net/tun ]]; then
        log_message "TUN is not available" >&2
        exit 1
    fi
}

# Function to check OS
function check_os() {
    if [[ ! -e /etc/rocky-release ]]; then
        log_message "This script is only for Rocky Linux 9.4 or later." >&2
        exit 1
    fi
    source /etc/os-release
    if [[ $ID != "rocky" || ${VERSION_ID%.*} -lt 9 ]]; then
        log_message "This script requires Rocky Linux 9.4 or later." >&2
        exit 1
    fi
}

# Function to get public IP
function get_public_ip() {
    IP=$(curl -s https://api.ipify.org)
}

# Function to ensure base packages are installed
function ensure_base_packages() {
    log_message "Checking and installing necessary base packages..."
    local packages=(
        "curl"
        "wget"
        "ca-certificates"
        "openssl"
        "dnf-plugins-core"
        "tar"
        "which"
    )

    dnf install -y "${packages[@]}"
}

# Function to check and install EPEL
function install_epel() {
    if ! rpm -qa | grep -q epel-release; then
        log_message "Installing EPEL repository..."
        dnf install -y epel-release
    else
        log_message "EPEL repository is already installed."
    fi
}

# Function to securely download and verify files
function secure_download() {
    local url=$1
    local output=$2
    local expected_hash=$3

    log_message "Downloading $output..."
    if ! wget --https-only -q -O "$output" "$url"; then
        log_message "Failed to download $output" >&2
        return 1
    fi

    log_message "Verifying $output..."
    local computed_hash=$(sha256sum "$output" | cut -d' ' -f1)

    if [[ "$computed_hash" != "$expected_hash" ]]; then
        log_message "Hash verification failed for $output" >&2
        rm -f "$output"
        return 1
    fi

    log_message "$output downloaded and verified successfully"
}

# Function to install OpenVPN and Easy-RSA from repositories
function install_from_repo() {
    log_message "Installing OpenVPN and Easy-RSA from repositories..."
    dnf install -y openvpn-$OPENVPN_VERSION easy-rsa-$EASYRSA_VERSION
}

# Function to install build tools
function install_build_tools() {
    log_message "Installing build tools..."
    dnf groupinstall -y "Development Tools"
    dnf install -y openssl-devel lzo-devel pam-devel
}

# Function to compile and install OpenVPN from source
function install_from_source() {
    log_message "Compiling and installing OpenVPN from source..."

    if ! secure_download "$OPENVPN_DOWNLOAD_URL" "openvpn-$OPENVPN_VERSION.tar.gz" "$OPENVPN_SHA256"; then
        log_message "Failed to download or verify OpenVPN source" >&2
        exit 1
    fi

    tar xzf openvpn-$OPENVPN_VERSION.tar.gz
    cd openvpn-$OPENVPN_VERSION
    ../conf.d/configure --enable-lzo --enable-iproute2
    make
    make install
    cd ..
    rm -rf openvpn-$OPENVPN_VERSION openvpn-$OPENVPN_VERSION.tar.gz

    log_message "Installing Easy-RSA..."
    if ! secure_download "$EASYRSA_DOWNLOAD_URL" "EasyRSA-$EASYRSA_VERSION.tgz" "$EASYRSA_SHA256"; then
        log_message "Failed to download or verify Easy-RSA source" >&2
        exit 1
    fi

    tar xzf EasyRSA-$EASYRSA_VERSION.tgz
    mv EasyRSA-$EASYRSA_VERSION /usr/local/share/easy-rsa
    ln -s /usr/local/share/easy-rsa/easyrsa /usr/local/bin
    rm EasyRSA-$EASYRSA_VERSION.tgz
}

# Function to choose installation method
function choose_install_method() {
    echo "Install OpenVPN from: "
    echo "1) Repositories (default)"
    echo "2) Source"
    read -p "Enter choice [1-2]: " install_choice
    case ${install_choice:-1} in
        2) return 2 ;;
        *) return 1 ;;
    esac
}

# Function to install OpenVPN
function install_openvpn() {
    install_epel

    if [[ -z ${INSTALL_METHOD:-} ]]; then
        choose_install_method
        install_choice=$?
    else
        install_choice=$INSTALL_METHOD
    fi

    if [ $install_choice -eq 2 ]; then
        install_build_tools
        install_from_source
    else
        install_from_repo
    fi

    # Enable IP Forwarding
    echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-openvpn.conf
    sysctl --system
}

# Function to generate OpenVPN server config
function generate_server_config() {
    log_message "Generating server config..."
    cat > /etc/openvpn/server.conf <<EOF
port ${SERVER_PORT:-1194}
proto ${PROTOCOL:-udp}
dev tun
user nobody
group nobody
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS ${DNS1:-8.8.8.8}"
push "dhcp-option DNS ${DNS2:-8.8.4.4}"
dh none
ecdh-curve prime256v1
tls-crypt tls-crypt.key
crl-verify crl.pem
ca ca.crt
cert server.crt
key server.key
auth SHA256
cipher ${CIPHER:-AES-256-GCM}
ncp-ciphers ${CIPHER:-AES-256-GCM}
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3
EOF
}

# Function to generate certificates
function generate_certificates() {
    log_message "Generating certificates..."
    mkdir -p /etc/openvpn/easy-rsa
    cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/

    cd /etc/openvpn/easy-rsa/
    ./easyrsa init-pki
    ./easyrsa --batch build-ca nopass
    EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
    EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full client nopass
    EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

    # Generate tls-crypt key
    openvpn --genkey secret /etc/openvpn/tls-crypt.key

    cp pki/{ca.crt,private/ca.key,issued/server.crt,private/server.key,crl.pem} /etc/openvpn
}

# Function to configure firewall
function configure_firewall() {
    log_message "Configuring firewall..."
    firewall-cmd --permanent --add-port=${SERVER_PORT:-1194}/${PROTOCOL:-udp}
    firewall-cmd --permanent --add-masquerade
    firewall-cmd --reload
}

# Function to start OpenVPN
function start_openvpn() {
    log_message "Starting OpenVPN..."
    systemctl enable openvpn@server
    systemctl start openvpn@server
}

# Function to create client config
function create_client_config() {
    log_message "Creating client config..."
    mkdir -p /etc/openvpn/clients
    cat > /etc/openvpn/clients/client.ovpn <<EOF
client
dev tun
proto ${PROTOCOL:-udp}
remote $IP ${SERVER_PORT:-1194}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher ${CIPHER:-AES-256-GCM}
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3
EOF

    echo "<ca>" >> /etc/openvpn/clients/client.ovpn
    cat /etc/openvpn/ca.crt >> /etc/openvpn/clients/client.ovpn
    echo "</ca>" >> /etc/openvpn/clients/client.ovpn

    echo "<cert>" >> /etc/openvpn/clients/client.ovpn
    sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/easy-rsa/pki/issued/client.crt >> /etc/openvpn/clients/client.ovpn
    echo "</cert>" >> /etc/openvpn/clients/client.ovpn

    echo "<key>" >> /etc/openvpn/clients/client.ovpn
    cat /etc/openvpn/easy-rsa/pki/private/client.key >> /etc/openvpn/clients/client.ovpn
    echo "</key>" >> /etc/openvpn/clients/client.ovpn

    echo "<tls-crypt>" >> /etc/openvpn/clients/client.ovpn
    cat /etc/openvpn/tls-crypt.key >> /etc/openvpn/clients/client.ovpn
    echo "</tls-crypt>" >> /etc/openvpn/clients/client.ovpn
}

# Function to create a new client
function newClient() {
    echo ""
    echo "Tell me a name for the client."
    echo "The name must consist of alphanumeric characters, or it may also include an underscore or a dash."

    until [[ $CLIENT =~ ^[a-zA-Z0-9_-]+$ ]]; do
        read -rp "Client name: " -e CLIENT
    done

    echo ""
    echo "Do you want to protect the configuration file with a password?"
    echo "(e.g. encrypt the private key with a password)"
    echo "   1) Add a passwordless client"
    echo "   2) Use a password for the client"

    until [[ $PASS =~ ^[1-2]$ ]]; do
        read -rp "Select an option [1-2]: " -e -i 1 PASS
    done

    cd /etc/openvpn/easy-rsa/ || return
    case $PASS in
    1)
        ./easyrsa --batch build-client-full "$CLIENT" nopass
        ;;
    2)
        echo "⚠️ You will be asked for the client password below ⚠️"
        ./easyrsa --batch build-client-full "$CLIENT"
        ;;
    esac

    # Generate the custom client.ovpn
    homeDir="/root"
    cp /etc/openvpn/clients/client.ovpn "$homeDir/$CLIENT.ovpn"
    {
        echo "<ca>"
        cat "/etc/openvpn/ca.crt"
        echo "</ca>"
        echo "<cert>"
        sed -ne '/BEGIN CERTIFICATE/,$ p' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
        echo "</cert>"
        echo "<key>"
        cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
        echo "</key>"
        echo "<tls-crypt>"
        cat /etc/openvpn/tls-crypt.key
        echo "</tls-crypt>"
    } >> "$homeDir/$CLIENT.ovpn"

    echo ""
    echo "The configuration file has been written to $homeDir/$CLIENT.ovpn."
    echo "Download the .ovpn file and import it in your OpenVPN client."
}

# Function to revoke a client
function revokeClient() {
    NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
    if [[ $NUMBEROFCLIENTS == '0' ]]; then
        echo ""
        echo "You have no existing clients!"
        exit 1
    fi

    echo ""
    echo "Select the existing client certificate you want to revoke"
    tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
    until [[ $CLIENTNUMBER -ge 1 && $CLIENTNUMBER -le $NUMBEROFCLIENTS ]]; do
        read -rp "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
    done
    CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
    cd /etc/openvpn/easy-rsa/ || return
    ./easyrsa --batch revoke "$CLIENT"
    EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
    rm -f /etc/openvpn/crl.pem
    cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
    chmod 644 /etc/openvpn/crl.pem
    rm -f "/root/$CLIENT.ovpn"
    sed -i "/^$CLIENT,.*/d" /etc/openvpn/ipp.txt
    echo ""
    echo "Certificate for client $CLIENT revoked."
}

# Function to remove OpenVPN
function removeOpenVPN() {
    echo ""
    read -rp "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
    if [[ $REMOVE == 'y' ]]; then
        # Stop OpenVPN
        systemctl stop openvpn-server@server
        systemctl disable openvpn-server@server

        # Remove OpenVPN
        yum remove -y openvpn easy-rsa

        # Remove configuration files
        rm -rf /etc/openvpn
        rm -f /etc/sysctl.d/99-openvpn.conf

        # Remove firewall rules
        firewall-cmd --permanent --remove-port=${SERVER_PORT:-1194}/${PROTOCOL:-udp}
        firewall-cmd --permanent --remove-masquerade
        firewall-cmd --reload

        # Remove client configurations
        rm -rf /root/*.ovpn

        echo ""
        echo "OpenVPN removed!"
    else
        echo ""
        echo "Removal aborted!"
    fi
}

# Function to manage OpenVPN
function manageMenu() {
    echo "Welcome to OpenVPN Installer for Rocky Linux 9.4!"
    echo ""
    echo "What do you want to do?"
    echo "   1) Add a new user"
    echo "   2) Revoke existing user"
    echo "   3) Remove OpenVPN"
    echo "   4) Exit"
    until [[ $MENU_OPTION =~ ^[1-4]$ ]]; do
        read -rp "Select an option [1-4]: " MENU_OPTION
    done

    case $MENU_OPTION in
    1)
        newClient
        ;;
    2)
        revokeClient
        ;;
    3)
        removeOpenVPN
        ;;
    4)
        exit 0
        ;;
    esac
}

# Main function
function main() {
    check_root
    check_tun
    check_os
    ensure_base_packages
    get_public_ip

    if [[ -e /etc/openvpn/server.conf ]]; then
        manageMenu
    else
        installOpenVPN
        generate_server_config
        generate_certificates
        configure_firewall
        start_openvpn
        create_client_config
        newClient

        echo ""
        log_message "OpenVPN has been installed and configured."
        log_message "You can now use the management menu to add or revoke clients."
    fi
}

# Check if a config file is provided
if [[ -f "$1" ]]; then
    source "$1"
fi

# Run main function
main
