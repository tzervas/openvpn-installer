#!/bin/bash

# OpenVPN installer for Rocky Linux 9.4
# Supports OpenVPN versions 2.4.12 through 2.6.11
# Based on the work of angristan (https://github.com/angristan/openvpn-install)
# Modified for Rocky Linux 9.4 and OpenVPN 2.4.12 through 2.6.11 with enhanced security features
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

# Global constants
readonly SUPPORTED_VERSIONS=("2.4.12" "2.4.13" "2.5.0" "2.5.1" "2.5.2" "2.5.3" "2.5.4" "2.5.5" "2.5.6" "2.5.7" "2.5.8" "2.5.9" "2.6.0" "2.6.1" "2.6.2" "2.6.3" "2.6.4" "2.6.5" "2.6.6" "2.6.7" "2.6.8" "2.6.9" "2.6.10" "2.6.11")
readonly DEFAULT_OPENVPN_VERSION="2.5.9"
readonly DEFAULT_EASYRSA_VERSION="3.1.6"

# Global variables
USE_LATEST_VERSIONS=false
SKIP_CHECKSUM=false
OPENVPN_DOWNLOAD_URL=""
EASYRSA_DOWNLOAD_URL=""
OPENVPN_SHA256=""
EASYRSA_SHA256=""
OPENVPN_CONFIG=""
USERS_CONFIG=""
AUTO_INSTALL=""
OPENVPN_VERSION=""

# Configuration variables (can be set via config file or CLI)
IP=""
PUBLIC_IP=""
PROTOCOL=""
PORT=""
DNS=""
COMPRESSION_ENABLED=""
CUSTOMIZE_ENC=""
CLIENT=""
PASS=""

# Utility functions
function log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

function check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_message "This script must be run as root" >&2
        exit 1
    fi
}

function check_tun() {
    if [[ ! -e /dev/net/tun ]]; then
        log_message "TUN is not available" >&2
        exit 1
    fi
}

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

function get_public_ip() {
    PUBLIC_IP=$(curl -s https://api.ipify.org)
}

function version_greater_equal() {
    printf '%s\n%s' "$2" "$1" | sort -C -V
}

function detect_openvpn_version() {
    if command -v openvpn >/dev/null 2>&1; then
        OPENVPN_VERSION=$(openvpn --version | head -n1 | awk '{print $2}')
    else
        OPENVPN_VERSION=$DEFAULT_OPENVPN_VERSION
    fi
    log_message "Detected OpenVPN version: $OPENVPN_VERSION"

    if ! [[ " ${SUPPORTED_VERSIONS[@]} " =~ " ${OPENVPN_VERSION} " ]]; then
        log_message "Warning: Detected version $OPENVPN_VERSION is not in the officially supported list."
        log_message "The script will attempt to use the closest supported configuration."
    fi
}

function get_latest_version_info() {
    local repo=$1
    local redirect_url=$(curl -s -o /dev/null -w "%{redirect_url}" "https://github.com/OpenVPN/${repo}/releases/latest")
    local version=$(echo $redirect_url | grep -oP 'v\K[\d\.]+')

    if [[ $repo == "openvpn" ]]; then
        local release_url="https://github.com/OpenVPN/${repo}/releases/download/v${version}/${repo}-${version}.tar.gz"
        local checksum_url="${release_url}.asc"
        local source_url="https://github.com/OpenVPN/${repo}/archive/refs/tags/v${version}.tar.gz"
    elif [[ $repo == "easy-rsa" ]]; then
        local release_url="https://github.com/OpenVPN/${repo}/releases/download/v${version}/EasyRSA-${version}.tgz"
        local checksum_url="${release_url}.sig"
        local source_url="https://github.com/OpenVPN/${repo}/archive/refs/tags/v${version}.tar.gz"
    else
        log_message "Unknown repository: $repo" >&2
        return 1
    fi

    echo "VERSION=$version"
    echo "RELEASE_URL=$release_url"
    echo "CHECKSUM_URL=$checksum_url"
    echo "SOURCE_URL=$source_url"
}

function prompt_use_latest_versions() {
    if [[ $AUTO_INSTALL != "y" ]]; then
        read -p "Do you want to use the latest versions of OpenVPN and EasyRSA? (y/n): " response
        case $response in
            [Yy]* ) USE_LATEST_VERSIONS=true;;
            * ) USE_LATEST_VERSIONS=false;;
        esac
    fi
}

function setup_download_info() {
    if $USE_LATEST_VERSIONS; then
        log_message "Fetching latest version information..."

        eval $(get_latest_version_info "openvpn")
        OPENVPN_VERSION=$VERSION
        OPENVPN_DOWNLOAD_URL=$RELEASE_URL
        OPENVPN_CHECKSUM_URL=$CHECKSUM_URL

        eval $(get_latest_version_info "easy-rsa")
        EASYRSA_VERSION=$VERSION
        EASYRSA_DOWNLOAD_URL=$RELEASE_URL
        EASYRSA_CHECKSUM_URL=$CHECKSUM_URL

        log_message "Using latest versions:"
    else
        log_message "Using default versions:"
        OPENVPN_VERSION=$DEFAULT_OPENVPN_VERSION
        EASYRSA_VERSION=$DEFAULT_EASYRSA_VERSION
        OPENVPN_DOWNLOAD_URL="https://swupdate.openvpn.org/community/releases/openvpn-${OPENVPN_VERSION}.tar.gz"
        EASYRSA_DOWNLOAD_URL="https://github.com/OpenVPN/easy-rsa/releases/download/v${EASYRSA_VERSION}/EasyRSA-${EASYRSA_VERSION}.tgz"
        OPENVPN_CHECKSUM_URL="${OPENVPN_DOWNLOAD_URL}.asc"
        EASYRSA_CHECKSUM_URL="${EASYRSA_DOWNLOAD_URL}.sig"
    fi

    log_message "OpenVPN version: $OPENVPN_VERSION"
    log_message "EasyRSA version: $EASYRSA_VERSION"

    if ! $SKIP_CHECKSUM; then
        OPENVPN_SHA256=$(get_sha256_checksum "$OPENVPN_CHECKSUM_URL")
        EASYRSA_SHA256=$(get_sha256_checksum "$EASYRSA_CHECKSUM_URL")

        if [[ -z "$OPENVPN_SHA256" || -z "$EASYRSA_SHA256" ]]; then
            if [[ $AUTO_INSTALL == "y" ]]; then
                log_message "Failed to retrieve checksums. Exiting." >&2
                exit 1
            else
                read -p "Failed to retrieve checksums. Continue without checksum verification? (y/n): " response
                case $response in
                    [Yy]* ) SKIP_CHECKSUM=true;;
                    * ) exit 1;;
                esac
            fi
        fi
    fi
}

function get_sha256_checksum() {
    local url=$1
    local checksum=$(curl -sL "$url" | gpg --verify - 2>&1 | grep -oP 'SHA256 checksum: \K[a-f0-9]{64}')
    if [[ -z "$checksum" ]]; then
        log_message "Failed to retrieve or verify SHA256 checksum from $url" >&2
        return 1
    fi
    echo "$checksum"
}

function ensure_base_packages() {
    log_message "Checking and installing necessary base packages..."
    readarray -t packages <<EOF
curl
wget
ca-certificates
openssl
dnf-plugins-core
tar
which
gnupg
EOF

    dnf install -y "${packages[@]}"
}

function install_epel() {
    if ! rpm -qa | grep -q epel-release; then
        log_message "Installing EPEL repository..."
        dnf install -y epel-release
    else
        log_message "EPEL repository is already installed."
    fi
}

function secure_download() {
    local url=$1
    local output=$2
    local expected_hash=$3

    log_message "Downloading $output..."
    if ! wget --https-only -q -O "$output" "$url"; then
        log_message "Failed to download $output" >&2
        return 1
    fi

    if ! $SKIP_CHECKSUM; then
        log_message "Verifying $output..."
        local computed_hash=$(sha256sum "$output" | cut -d' ' -f1)

        if [[ "$computed_hash" != "$expected_hash" ]]; then
            log_message "Hash verification failed for $output" >&2
            rm -f "$output"
            return 1
        fi
    fi

    log_message "$output downloaded successfully"
}

function install_from_source() {
    log_message "Compiling and installing OpenVPN from source..."

    if ! secure_download "$OPENVPN_DOWNLOAD_URL" "openvpn-$OPENVPN_VERSION.tar.gz" "$OPENVPN_SHA256"; then
        log_message "Failed to download or verify OpenVPN source" >&2
        exit 1
    fi

    tar xzf openvpn-$OPENVPN_VERSION.tar.gz
    cd openvpn-$OPENVPN_VERSION
    ./configure --enable-lzo --enable-iproute2
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

function install_from_repo() {
    log_message "Installing OpenVPN and Easy-RSA from repositories..."
    dnf install -y openvpn easy-rsa
}

function install_build_tools() {
    log_message "Installing build tools..."
    dnf groupinstall -y "Development Tools"
    dnf install -y openssl-devel lzo-devel pam-devel
}

function choose_install_method() {
    if [[ $AUTO_INSTALL != "y" ]]; then
        echo "Install OpenVPN from: "
        echo "1) Repositories (default)"
        echo "2) Source"
        read -p "Enter choice [1-2]: " install_choice
        case ${install_choice:-1} in
            2) return 2 ;;
            *) return 1 ;;
        esac
    else
        return 1  # Default to repository install for auto-install
    fi
}

function install_openvpn() {
    install_epel

    if [[ -z ${INSTALL_METHOD:-} ]]; then
        choose_install_method
        INSTALL_METHOD=$?
    fi

    if [[ $INSTALL_METHOD -eq 2 ]]; then
        install_build_tools
        install_from_source
    else
        install_from_repo
    fi

    # Enable IP Forwarding
    echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-openvpn.conf
    sysctl --system

    if version_greater_equal "$OPENVPN_VERSION" "2.5.0"; then
        log_message "Enabling OpenSSL legacy provider..."
        if [ -f /etc/ssl/openssl.cnf ]; then
            sed -i '/^\[provider_sect\]/a legacy = legacy_sect' /etc/ssl/openssl.cnf
            echo -e "\n[legacy_sect]\nactivate = 1" >> /etc/ssl/openssl.cnf
        fi
    fi
}

function generate_server_config() {
    log_message "Generating server config..."
    local cipher_option=""
    local tls_cipher_option=""
    local providers_option=""
    local auth_token_option=""

    if version_greater_equal "$OPENVPN_VERSION" "2.5.0"; then
        cipher_option="data-ciphers ${CIPHER:-AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305}"
        tls_cipher_option="tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
        if version_greater_equal "$OPENVPN_VERSION" "2.5.7"; then
            providers_option="providers legacy default"
        fi
        if version_greater_equal "$OPENVPN_VERSION" "2.5.8"; then
            auth_token_option="auth-gen-token"
        fi
    else
        cipher_option="cipher ${CIPHER:-AES-256-CBC}"
        tls_cipher_option="tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
    fi

    cat > /etc/openvpn/server.conf <<EOF
port ${PORT:-1194}
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
$cipher_option
$tls_cipher_option
tls-server
tls-version-min 1.2
$providers_option
$auth_token_option
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3
EOF

    if version_greater_equal "$OPENVPN_VERSION" "2.5.0"; then
        echo "push \"block-outside-dns\"" >> /etc/openvpn/server.conf
    fi

    if version_greater_equal "$OPENVPN_VERSION" "2.6.0"; then
        echo "push \"route-ipv6 2000::/3\"" >> /etc/openvpn/server.conf
        echo "server-ipv6 2001:db8:1::/64" >> /etc/openvpn/server.conf
    fi
}

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

function configure_firewall() {
    log_message "Configuring firewall..."
    firewall-cmd --permanent --add-port=${PORT:-1194}/${PROTOCOL:-udp}
    firewall-cmd --permanent --add-masquerade
    
    if version_greater_equal "$OPENVPN_VERSION" "2.6.0"; then
        firewall-cmd --permanent --add-masquerade --ipv6
    fi
    
    firewall-cmd --reload
}

function start_openvpn() {
    log_message "Starting OpenVPN..."
    systemctl enable openvpn@server
    systemctl start openvpn@server
}

function create_client_config() {
    log_message "Creating client config..."
    local cipher_option=""
    local tls_cipher_option=""
    local auth_token_option=""

    if version_greater_equal "$OPENVPN_VERSION" "2.5.0"; then
        cipher_option="data-ciphers ${CIPHER:-AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305}"
        tls_cipher_option="tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
        if version_greater_equal "$OPENVPN_VERSION" "2.5.8"; then
            auth_token_option="auth-token-user"
        fi
    else
        cipher_option="cipher ${CIPHER:-AES-256-CBC}"
        tls_cipher_option="tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
    fi

    mkdir -p /etc/openvpn/clients
    cat > /etc/openvpn/clients/client.ovpn <<EOF
client
dev tun
proto ${PROTOCOL:-udp}
remote ${PUBLIC_IP} ${PORT:-1194}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
$cipher_option
$tls_cipher_option
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3
$auth_token_option
EOF

    if version_greater_equal "$OPENVPN_VERSION" "2.6.0"; then
        echo "pull-filter ignore \"route-ipv6\"" >> /etc/openvpn/clients/client.ovpn
        echo "pull-filter ignore \"ifconfig-ipv6\"" >> /etc/openvpn/clients/client.ovpn
    fi

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

function cleanup() {
    log_message "Cleaning up temporary files..."
    rm -f openvpn-*.tar.gz EasyRSA-*.tgz
}

function check_version() {
    if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
        log_message "This script requires Bash version 4 or higher" >&2
        exit 1
    fi
}

function parse_config_file() {
    local config_file=$1
    if [[ -f "$config_file" ]]; then
        log_message "Loading configuration from $config_file"
        while IFS='=' read -r key value; do
            if [[ ! $key =~ ^[[:space:]]*# && -n $value ]]; then
                value=$(echo "$value" | tr -d '"' | tr -d "'")
                export "$key=$value"
                log_message "Loaded: $key=$value"
            fi
        done < "$config_file"
    else
        log_message "Config file $config_file not found. Using defaults or CLI options."
    fi
}

function parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --openvpn-config)
                OPENVPN_CONFIG="$2"
                shift 2
                ;;
            --users-config)
                USERS_CONFIG="$2"
                shift 2
                ;;
            --auto-install)
                AUTO_INSTALL="y"
                shift
                ;;
            --no-checksum)
                SKIP_CHECKSUM=true
                shift
                ;;
            *)
                log_message "Unknown option: $1" >&2
                exit 1
                ;;
        esac
    done
}

function main() {
    parse_arguments "$@"

    if [[ -n $OPENVPN_CONFIG ]]; then
        parse_config_file "$OPENVPN_CONFIG"
    fi

    if [[ -n $USERS_CONFIG ]]; then
        parse_config_file "$USERS_CONFIG"
    fi

    if [[ $AUTO_INSTALL == "y" ]]; then
        # Set default config files if not specified
        OPENVPN_CONFIG=${OPENVPN_CONFIG:-"openvpn-config.conf"}
        USERS_CONFIG=${USERS_CONFIG:-"openvpn-users.conf"}

        # Try to load default config files
        [[ -f $OPENVPN_CONFIG ]] && parse_config_file "$OPENVPN_CONFIG"
        [[ -f $USERS_CONFIG ]] && parse_config_file "$USERS_CONFIG"
    fi

    check_version
    check_root
    check_tun
    check_os
    ensure_base_packages
    get_public_ip
    detect_openvpn_version
    prompt_use_latest_versions
    setup_download_info
    install_openvpn
    generate_server_config
    generate_certificates
    configure_firewall
    start_openvpn
    create_client_config

    log_message "OpenVPN $OPENVPN_VERSION has been installed and configured."
    log_message "Client configuration is available at /etc/openvpn/clients/client.ovpn"
}

# Set trap for cleanup
trap cleanup EXIT

# Run the main function with all script arguments
main "$@"
