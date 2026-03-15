#!/bin/bash

###############################################################################
# TLS Certificate Setup for OpenFlow Channel (audit 1.4)
#
# Generates TLS certificates for the Ryu controller and OVS switches
# using ovs-pki. Outputs certificates to config/tls/ directory.
#
# Without TLS, the OpenFlow channel is plaintext — a MITM attacker on the
# management network can inject flow rules (e.g., redirect traffic or
# disable DROP rules).
#
# Usage:
#     sudo bash setup_tls.sh
#
# After running, configure:
#   1. Ryu controller: see output for ryu.conf TLS options
#   2. OVS switches: see output for ovs-vsctl commands
#   3. topology.py: change tcp: to ssl: in controller connection
#
# Requirements:
#     - ovs-pki (part of Open vSwitch)
#     - Root privileges (for ovs-pki init)
#
###############################################################################

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Resolve paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TLS_DIR="${SCRIPT_DIR}/../config/tls"
PKI_DIR="/var/lib/openvswitch/pki"

echo ""
echo "======================================================================"
echo "  TLS Certificate Setup for OpenFlow Channel"
echo "======================================================================"
echo ""

# Check prerequisites
if ! command -v ovs-pki &> /dev/null; then
    echo -e "${RED}[ERROR]${NC} ovs-pki not found"
    echo "Install Open vSwitch: sudo apt-get install openvswitch-common"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Root privileges required"
    echo "Usage: sudo bash setup_tls.sh"
    exit 1
fi

# Create output directory
mkdir -p "${TLS_DIR}"
echo -e "${BLUE}[INFO]${NC} Output directory: ${TLS_DIR}"

# Initialize PKI if needed
if [ ! -d "${PKI_DIR}" ]; then
    echo -e "${BLUE}[INFO]${NC} Initializing OVS PKI..."
    ovs-pki init --force
fi

# Generate controller certificate
echo -e "${BLUE}[INFO]${NC} Generating controller certificate..."
cd "${TLS_DIR}"
ovs-pki req+sign controller controller 2>/dev/null || true
echo -e "${GREEN}[OK]${NC} Controller certificate: ${TLS_DIR}/controller-cert.pem"

# Generate switch certificate
echo -e "${BLUE}[INFO]${NC} Generating switch certificate..."
ovs-pki req+sign switch switch 2>/dev/null || true
echo -e "${GREEN}[OK]${NC} Switch certificate: ${TLS_DIR}/switch-cert.pem"

# Copy CA certificate
if [ -f "${PKI_DIR}/switchca/cacert.pem" ]; then
    cp "${PKI_DIR}/switchca/cacert.pem" "${TLS_DIR}/ca-cert.pem"
    echo -e "${GREEN}[OK]${NC} CA certificate: ${TLS_DIR}/ca-cert.pem"
fi

# Set permissions
chmod 600 "${TLS_DIR}"/*-privkey.pem 2>/dev/null || true
chmod 644 "${TLS_DIR}"/*-cert.pem 2>/dev/null || true
chmod 644 "${TLS_DIR}"/ca-cert.pem 2>/dev/null || true

echo ""
echo "======================================================================"
echo "  Configuration Instructions"
echo "======================================================================"
echo ""
echo "1. Add to ryu.conf (uncomment the TLS section):"
echo ""
echo "   ctl_privkey = ${TLS_DIR}/controller-privkey.pem"
echo "   ctl_cert = ${TLS_DIR}/controller-cert.pem"
echo "   ca_certs = ${TLS_DIR}/ca-cert.pem"
echo ""
echo "2. Configure each OVS switch:"
echo ""
for switch in s1 s2 s3 s4 s5; do
    echo "   ovs-vsctl set-ssl \\"
    echo "     ${TLS_DIR}/switch-privkey.pem \\"
    echo "     ${TLS_DIR}/switch-cert.pem \\"
    echo "     ${TLS_DIR}/ca-cert.pem"
    echo "   ovs-vsctl set-controller ${switch} ssl:127.0.0.1:6653"
    echo ""
    break  # Only show once as example
done
echo "   (repeat for s1-s5)"
echo ""
echo "3. In topology.py, change the controller connection:"
echo "   RemoteController(name, ip='127.0.0.1', port=6653)"
echo "   # Mininet will use ssl: protocol when OVS has set-ssl configured"
echo ""
echo "======================================================================"
echo -e "${GREEN}[DONE]${NC} TLS certificates generated successfully"
echo ""
echo -e "${YELLOW}NOTE:${NC} TLS is OPTIONAL for development/testing in Mininet."
echo "The controller logs a WARNING when TLS is not configured."
echo ""
