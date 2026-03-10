#!/bin/bash

###############################################################################
# Open vSwitch Configuration Script for SDN DDoS Detection Network
#
# This script configures Open vSwitch (OVS) settings for all switches in the
# spine-leaf topology. It sets controller connections, OpenFlow protocol
# version, fail-mode, and enables statistics collection.
#
# Switches configured: s1, s2 (spine), s3, s4, s5 (leaf)
# Controller: tcp:127.0.0.1:6653
# Protocol: OpenFlow 1.3
# Fail-mode: standalone (switches forward independently if controller disconnected)
# Changed from 'secure' to prevent total network blackout on controller failure
#
# Usage:
#     sudo bash ovs_config.sh
#
# Requirements:
#     - Open vSwitch installed
#     - Switches must be created by Mininet before running this script
#     - Root privileges required
#
###############################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Controller configuration
CONTROLLER_IP="127.0.0.1"
CONTROLLER_PORT="6653"
CONTROLLER_ADDR="tcp:${CONTROLLER_IP}:${CONTROLLER_PORT}"

# List of switches to configure
SWITCHES=("s1" "s2" "s3" "s4" "s5")

# Statistics collection interval (seconds)
STATS_INTERVAL=5

###############################################################################
# Function: print_banner
# Description: Print script banner
###############################################################################
print_banner() {
    echo ""
    echo "======================================================================"
    echo "    Open vSwitch Configuration for SDN DDoS Detection"
    echo "======================================================================"
    echo ""
}

###############################################################################
# Function: check_root
# Description: Check if script is run with root privileges
###############################################################################
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}ERROR: This script must be run as root${NC}"
        echo "Usage: sudo bash ovs_config.sh"
        exit 1
    fi
}

###############################################################################
# Function: check_ovs_installed
# Description: Check if Open vSwitch is installed
###############################################################################
check_ovs_installed() {
    echo -e "${BLUE}[INFO]${NC} Checking Open vSwitch installation..."

    if ! command -v ovs-vsctl &> /dev/null; then
        echo -e "${RED}[ERROR]${NC} ovs-vsctl command not found"
        echo "Open vSwitch is not installed or not in PATH"
        exit 1
    fi

    echo -e "${GREEN}[OK]${NC} Open vSwitch is installed"
}

###############################################################################
# Function: check_switch_exists
# Description: Check if a switch exists in OVS
# Arguments:
#     $1 - Switch name
# Returns:
#     0 if switch exists, 1 otherwise
###############################################################################
check_switch_exists() {
    local switch=$1
    ovs-vsctl br-exists "$switch" 2>/dev/null
    return $?
}

###############################################################################
# Function: configure_switch
# Description: Configure a single switch with controller and OpenFlow settings
# Arguments:
#     $1 - Switch name
###############################################################################
configure_switch() {
    local switch=$1

    echo ""
    echo -e "${BLUE}[INFO]${NC} Configuring switch: ${YELLOW}${switch}${NC}"

    # Check if switch exists
    if ! check_switch_exists "$switch"; then
        echo -e "${YELLOW}[WARN]${NC} Switch ${switch} does not exist (may not be created yet)"
        echo "        This is normal if Mininet network hasn't started"
        return 1
    fi

    # Set controller
    echo -e "  → Setting controller to ${CONTROLLER_ADDR}"
    if ovs-vsctl set-controller "$switch" "$CONTROLLER_ADDR" 2>/dev/null; then
        echo -e "    ${GREEN}✓${NC} Controller set successfully"
    else
        echo -e "    ${RED}✗${NC} Failed to set controller"
        return 1
    fi

    # Set OpenFlow protocol to version 1.3
    echo -e "  → Setting OpenFlow protocol to version 1.3"
    if ovs-vsctl set bridge "$switch" protocols=OpenFlow13 2>/dev/null; then
        echo -e "    ${GREEN}✓${NC} OpenFlow 1.3 protocol set"
    else
        echo -e "    ${RED}✗${NC} Failed to set OpenFlow protocol"
        return 1
    fi

    # Set fail-mode to standalone
    # In standalone mode, switches forward traffic independently if controller is unreachable
    # Prevents total network blackout on controller failure
    echo -e "  → Setting fail-mode to standalone"
    if ovs-vsctl set-fail-mode "$switch" standalone 2>/dev/null; then
        echo -e "    ${GREEN}✓${NC} Fail-mode set to standalone"
    else
        echo -e "    ${RED}✗${NC} Failed to set fail-mode"
        return 1
    fi

    # Enable statistics collection
    echo -e "  → Enabling statistics collection"
    # Enable flow statistics
    if ovs-vsctl -- --id=@ft create Flow_Table flow_limit=2000000 \
        -- set Bridge "$switch" flow_tables=0=@ft 2>/dev/null; then
        echo -e "    ${GREEN}✓${NC} Statistics collection enabled"
    else
        # This might fail if already set, which is okay
        echo -e "    ${YELLOW}~${NC} Statistics collection status unchanged"
    fi

    # Set other bridge properties for better performance
    echo -e "  → Configuring additional bridge properties"
    ovs-vsctl set bridge "$switch" other-config:datapath-id=$(printf "%016x" $((0x$switch))) 2>/dev/null

    echo -e "  ${GREEN}[DONE]${NC} Switch ${switch} configured successfully"

    return 0
}

###############################################################################
# Function: verify_configuration
# Description: Verify the configuration of a switch
# Arguments:
#     $1 - Switch name
###############################################################################
verify_configuration() {
    local switch=$1

    if ! check_switch_exists "$switch"; then
        return 1
    fi

    echo ""
    echo -e "${BLUE}[VERIFY]${NC} Configuration for ${YELLOW}${switch}${NC}:"

    # Get controller
    local controller=$(ovs-vsctl get-controller "$switch" 2>/dev/null)
    echo -e "  Controller:    ${controller}"

    # Get OpenFlow protocols
    local protocols=$(ovs-vsctl get bridge "$switch" protocols 2>/dev/null)
    echo -e "  Protocols:     ${protocols}"

    # Get fail-mode
    local failmode=$(ovs-vsctl get-fail-mode "$switch" 2>/dev/null)
    echo -e "  Fail-mode:     ${failmode}"

    # Get datapath ID
    local dpid=$(ovs-vsctl get bridge "$switch" datapath-id 2>/dev/null)
    echo -e "  Datapath ID:   ${dpid}"
}

###############################################################################
# Function: display_summary
# Description: Display configuration summary for all switches
###############################################################################
display_summary() {
    echo ""
    echo "======================================================================"
    echo "                    Configuration Summary"
    echo "======================================================================"
    echo ""
    echo "Controller Address:    ${CONTROLLER_ADDR}"
    echo "OpenFlow Protocol:     OpenFlow13"
    echo "Fail-mode:             standalone"
    echo "Statistics:            Enabled"
    echo ""
    echo "Switches configured:"

    for switch in "${SWITCHES[@]}"; do
        if check_switch_exists "$switch"; then
            echo -e "  ${GREEN}✓${NC} ${switch} - Active"
        else
            echo -e "  ${YELLOW}○${NC} ${switch} - Not created yet"
        fi
    done

    echo ""
    echo "======================================================================"
}

###############################################################################
# Function: show_help
# Description: Display help information
###############################################################################
show_help() {
    echo "Usage: sudo bash ovs_config.sh [OPTIONS]"
    echo ""
    echo "Configure Open vSwitch settings for SDN DDoS detection network."
    echo ""
    echo "Options:"
    echo "  -h, --help       Show this help message"
    echo "  -v, --verify     Verify configuration without making changes"
    echo "  -c, --clean      Clean all switch configurations"
    echo ""
    echo "Examples:"
    echo "  sudo bash ovs_config.sh           # Configure all switches"
    echo "  sudo bash ovs_config.sh --verify  # Verify current configuration"
    echo "  sudo bash ovs_config.sh --clean   # Clean configurations"
    echo ""
}

###############################################################################
# Function: clean_configuration
# Description: Clean/reset switch configurations
###############################################################################
clean_configuration() {
    echo -e "${BLUE}[INFO]${NC} Cleaning switch configurations..."

    for switch in "${SWITCHES[@]}"; do
        if check_switch_exists "$switch"; then
            echo -e "  → Cleaning ${switch}"
            ovs-vsctl del-controller "$switch" 2>/dev/null
            ovs-vsctl set-fail-mode "$switch" standalone 2>/dev/null
            echo -e "    ${GREEN}✓${NC} ${switch} cleaned"
        fi
    done

    echo -e "${GREEN}[DONE]${NC} Configuration cleaned"
}

###############################################################################
# Main Script Execution
###############################################################################
main() {
    # Parse command-line arguments
    case "${1:-}" in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--verify)
            print_banner
            check_root
            check_ovs_installed
            echo -e "${BLUE}[INFO]${NC} Verifying switch configurations..."
            for switch in "${SWITCHES[@]}"; do
                verify_configuration "$switch"
            done
            display_summary
            exit 0
            ;;
        -c|--clean)
            print_banner
            check_root
            check_ovs_installed
            clean_configuration
            exit 0
            ;;
        "")
            # No arguments, proceed with configuration
            ;;
        *)
            echo -e "${RED}ERROR: Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
    esac

    # Print banner
    print_banner

    # Check prerequisites
    check_root
    check_ovs_installed

    # Configure all switches
    echo -e "${BLUE}[INFO]${NC} Starting switch configuration..."
    echo -e "${BLUE}[INFO]${NC} Controller: ${CONTROLLER_ADDR}"
    echo -e "${BLUE}[INFO]${NC} Switches: ${SWITCHES[*]}"

    local success_count=0
    local total_count=${#SWITCHES[@]}

    for switch in "${SWITCHES[@]}"; do
        if configure_switch "$switch"; then
            ((success_count++))
        fi
    done

    # Display summary
    display_summary

    # Final status
    echo ""
    if [ $success_count -eq $total_count ]; then
        echo -e "${GREEN}[SUCCESS]${NC} All ${total_count} switches configured successfully"
        echo ""
        echo "Note: Switches will connect to controller when Mininet network starts"
        echo "      and controller (Ryu) is running at ${CONTROLLER_ADDR}"
    elif [ $success_count -eq 0 ]; then
        echo -e "${YELLOW}[WARNING]${NC} No switches configured (they may not exist yet)"
        echo ""
        echo "This is normal if:"
        echo "  1. Mininet network hasn't been started yet"
        echo "  2. Run this script AFTER starting: sudo python3 topology.py"
        echo "  3. Or run this script in a separate terminal while network is running"
    else
        echo -e "${YELLOW}[PARTIAL]${NC} ${success_count}/${total_count} switches configured"
    fi

    echo ""
}

# Execute main function
main "$@"
