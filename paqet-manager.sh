#!/bin/bash
#=================================================
# Paqet Tunnel Manager
# Version: 7.0
# Raw packet-level tunneling for bypassing network restrictions
# GitHub: https://github.com/hanselime/paqet
# Manager GitHub: https://github.com/0fariid0/Paqet-Tunnel-Manager
#=================================================

# ================================================
# CONFIGURATION DEFAULTS (Easily modifiable)
# ================================================

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly WHITE='\033[1;37m'
readonly ORANGE='\033[0;33m'
readonly PURPLE='\033[0;35m'
readonly NC='\033[0m'

# Script Configuration
readonly SCRIPT_VERSION="7.0"
readonly MANAGER_NAME="paqet-manager"
readonly MANAGER_PATH="/usr/local/bin/$MANAGER_NAME"

# Paths
readonly CONFIG_DIR="/etc/paqet"
readonly SERVICE_DIR="/etc/systemd/system"
readonly BIN_DIR="/usr/local/bin"
readonly INSTALL_DIR="/opt/paqet"
readonly BACKUP_DIR="/root/paqet-backups"

# Repositories
readonly GITHUB_REPO="hanselime/paqet"
readonly MANAGER_GITHUB_REPO="0fariid0/Paqet-Tunnel-Manager"
readonly SERVICE_NAME="paqet"

# Kernel optimization settings
readonly SYSCTL_FILE="/etc/sysctl.d/99-paqet-tunnel.conf"
readonly LIMITS_FILE="/etc/security/limits.d/99-paqet.conf"
readonly BACKUP_SYSCTL="${BACKUP_DIR}/sysctl-99-paqet.backup-$(date +%Y%m%d-%H%M%S)"
readonly BACKUP_LIMITS="${BACKUP_DIR}/limits-99-paqet.backup-$(date +%Y%m%d-%H%M%S)"

# Default Values
readonly DEFAULT_LISTEN_PORT="8888"
readonly DEFAULT_KCP_MODE="fast"
readonly DEFAULT_ENCRYPTION="aes-128-gcm"
readonly DEFAULT_CONNECTIONS="4"
readonly DEFAULT_MTU="1150"
readonly DEFAULT_PCAP_SOCKBUF_SERVER="8388608"
readonly DEFAULT_PCAP_SOCKBUF_CLIENT="4194304"
readonly DEFAULT_TRANSPORT_TCPBUF="8192"
readonly DEFAULT_TRANSPORT_UDPBUF="4096"
readonly DEFAULT_AUTO_RESTART_INTERVAL="1hour"
readonly DEFAULT_V2RAY_PORTS="9090"
readonly DEFAULT_SOCKS5_PORT="1080"

# Logging defaults (paqet config) + automatic log cleanup
readonly DEFAULT_LOG_LEVEL="info"              # debug|info|warn|error
readonly DEFAULT_JOURNAL_VACUUM_TIME="7d"      # e.g. 7d, 14d, 30d
readonly DEFAULT_JOURNAL_VACUUM_SIZE="300M"    # e.g. 200M, 1G

# Manager settings file (persists defaults)
readonly MANAGER_SETTINGS_FILE="${CONFIG_DIR}/manager-settings.conf"

# Extra Paqet core builds
readonly PAQET_OPTIMIZED_AMD64_URL="https://github.com/0fariid0/Paqet-Tunnel-Manager/releases/download/2.0.0/paqet-linux-amd64-v2.2.0-optimize.tar.gz"

# Runtime settings (loaded from MANAGER_SETTINGS_FILE if present)
PAQET_DEFAULT_LOG_LEVEL="$DEFAULT_LOG_LEVEL"
PAQET_JOURNAL_VACUUM_TIME="$DEFAULT_JOURNAL_VACUUM_TIME"
PAQET_JOURNAL_VACUUM_SIZE="$DEFAULT_JOURNAL_VACUUM_SIZE"


# KCP Mode Descriptions
declare -A KCP_MODES=(
    ["0"]="normal:normal:Normal speed / Normal latency / Low usage"
    ["1"]="fast:fast:Balanced speed / Low latency / Normal usage"
    ["2"]="fast2:fast2:High speed / Lower latency / Medium usage"
    ["3"]="fast3:fast3:Max speed / Very low latency / High CPU"
    ["4"]="manual:manual:Advanced settings"
)

# Encryption Options
declare -A ENCRYPTION_OPTIONS=(
    ["1"]="aes-128-gcm:Very high security / Very fast / Recommended"
    ["2"]="aes:High security / Medium speed / General use"
    ["3"]="aes-128:High security / Fast / Low CPU usage"
    ["4"]="aes-192:Very high security / Medium speed / Moderate CPU usage"
    ["5"]="aes-256:Maximum security / Slower / Higher CPU usage"
    ["6"]="none:No encryption / Max speed / Insecure"
    ["7"]="null:No encryption / Max speed / Insecure"
)

# Auto-restart intervals
declare -A RESTART_INTERVALS=(
    ["1min"]="*/1 * * * *"
    ["5min"]="*/5 * * * *"
    ["15min"]="*/15 * * * *"
    ["30min"]="*/30 * * * *"
    ["1hour"]="0 */1 * * *"
    ["12hour"]="0 */12 * * *"
    ["1day"]="0 0 * * *"
)

# IP detection services
readonly IP_SERVICES=(
    "ifconfig.me"
    "icanhazip.com"
    "api.ipify.org"
    "checkip.amazonaws.com"
    "ipinfo.io/ip"
)

# Test domains for DNS
readonly TEST_DOMAINS=(
    "google.com"
    "github.com"
    "cloudflare.com"
    "wikipedia.org"
)

# DNS servers for testing
readonly DNS_SERVERS=(
    "8.8.8.8"
    "1.1.1.1"
    "208.67.222.222"
    "system"
)

# MTU test sizes
readonly MTU_TESTS=(
    "1500"
    "1470"
    "1400"
    "1350"
    "1300"
    "1200"
    "1100"
)

# Common ports for testing
readonly COMMON_PORTS=("443" "80" "22" "53")

# Manager versions for switch option
declare -A MANAGER_VERSIONS=(
    ["latest"]="https://raw.githubusercontent.com/0fariid0/Paqet-Tunnel-Manager/main/paqet-manager.sh"
    ["6.0"]="https://raw.githubusercontent.com/0fariid0/Paqet-Tunnel-Manager/main/paqet-manager6-0.sh"
    ["5.1"]="https://raw.githubusercontent.com/0fariid0/Paqet-Tunnel-Manager/main/paqet-manager5-1.sh"
    ["3.8"]="https://raw.githubusercontent.com/0fariid0/Paqet-Tunnel-Manager/main/paqet-manager3-8.sh"
)

# ================================================
# UTILITY FUNCTIONS
# ================================================

# Print functions
print_step() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_info() { echo -e "${CYAN}[i]${NC} $1"; }
print_input() { echo -e "${YELLOW}[?]${NC} $1"; }

# ================================================
# MANAGER SETTINGS (Log level + Log cleanup)
# ================================================

init_manager_settings() {
    mkdir -p "$CONFIG_DIR" 2>/dev/null || true

    if [ ! -f "$MANAGER_SETTINGS_FILE" ]; then
        cat > "$MANAGER_SETTINGS_FILE" << EOF
# Paqet Manager persistent settings
# This file is sourced by paqet-manager and also used by the log-cleanup systemd service.
PAQET_DEFAULT_LOG_LEVEL="$DEFAULT_LOG_LEVEL"
PAQET_JOURNAL_VACUUM_TIME="$DEFAULT_JOURNAL_VACUUM_TIME"
PAQET_JOURNAL_VACUUM_SIZE="$DEFAULT_JOURNAL_VACUUM_SIZE"
EOF
        chmod 600 "$MANAGER_SETTINGS_FILE" 2>/dev/null || true
    fi
}

save_manager_settings() {
    mkdir -p "$CONFIG_DIR" 2>/dev/null || true

    cat > "$MANAGER_SETTINGS_FILE" << EOF
# Paqet Manager persistent settings
PAQET_DEFAULT_LOG_LEVEL="$PAQET_DEFAULT_LOG_LEVEL"
PAQET_JOURNAL_VACUUM_TIME="$PAQET_JOURNAL_VACUUM_TIME"
PAQET_JOURNAL_VACUUM_SIZE="$PAQET_JOURNAL_VACUUM_SIZE"
EOF
    chmod 600 "$MANAGER_SETTINGS_FILE" 2>/dev/null || true
}

normalize_log_level() {
    local input="$1"
    local fallback="${2:-info}"

    input=$(echo "$input" | tr '[:upper:]' '[:lower:]' | xargs)

    case "$input" in
        1|debug) echo "debug" ;;
        2|info|"") echo "info" ;;
        3|warn|warning) echo "warn" ;;
        4|error|err) echo "error" ;;
        *) echo "$fallback" ;;
    esac
}

load_manager_settings() {
    init_manager_settings

    if [ -f "$MANAGER_SETTINGS_FILE" ]; then
        # shellcheck disable=SC1090
        source "$MANAGER_SETTINGS_FILE" 2>/dev/null || true
    fi

    [ -n "$PAQET_DEFAULT_LOG_LEVEL" ] || PAQET_DEFAULT_LOG_LEVEL="$DEFAULT_LOG_LEVEL"
    [ -n "$PAQET_JOURNAL_VACUUM_TIME" ] || PAQET_JOURNAL_VACUUM_TIME="$DEFAULT_JOURNAL_VACUUM_TIME"
    [ -n "$PAQET_JOURNAL_VACUUM_SIZE" ] || PAQET_JOURNAL_VACUUM_SIZE="$DEFAULT_JOURNAL_VACUUM_SIZE"

    PAQET_DEFAULT_LOG_LEVEL=$(normalize_log_level "$PAQET_DEFAULT_LOG_LEVEL" "$DEFAULT_LOG_LEVEL")
}

ask_log_level() {
    local default_level="${1:-info}"
    local input=""

    echo -e "\n${CYAN}Log Level${NC}"
    echo -e "────────────────────────────────────────────────────────────────"
    echo -e "  debug | info | warn | error"
    echo -en "${YELLOW}Enter log level [${default_level}]: ${NC}"
    read -r input
    input="${input:-$default_level}"

    local normalized
    normalized=$(normalize_log_level "$input" "$default_level")

    if [ "$normalized" != "$(echo "$input" | tr '[:upper:]' '[:lower:]' | xargs)" ] && [[ ! "$input" =~ ^[1-4]$ ]]; then
        print_warning "Unknown log level '$input' → using '$normalized'"
    fi

    echo "$normalized"
}

setup_log_cleanup() {
    local silent="${1:-false}"

    # systemd is required for this script anyway, but keep it safe
    command -v systemctl >/dev/null 2>&1 || return 0
    command -v journalctl >/dev/null 2>&1 || return 0

    init_manager_settings
    load_manager_settings

    local service_path="/etc/systemd/system/paqet-log-cleanup.service"
    local timer_path="/etc/systemd/system/paqet-log-cleanup.timer"

    local journalctl_bin
    journalctl_bin=$(command -v journalctl 2>/dev/null || echo "/usr/bin/journalctl")
    local bash_bin
    bash_bin=$(command -v bash 2>/dev/null || echo "/bin/bash")

    # Create/Update service
    cat > "$service_path" << EOF
[Unit]
Description=Paqet Manager - Log Cleanup (journal vacuum) to prevent disk fill

[Service]
Type=oneshot
EnvironmentFile=-$MANAGER_SETTINGS_FILE
ExecStart=$journalctl_bin --rotate
ExecStart=$journalctl_bin --vacuum-time=\${PAQET_JOURNAL_VACUUM_TIME}
ExecStart=$journalctl_bin --vacuum-size=\${PAQET_JOURNAL_VACUUM_SIZE}
# Keep Telegram bot log from growing forever (keeps last 20000 lines)
ExecStart=$bash_bin -c 'f="/var/log/telegram-paqet-bot.log"; if [ -f "\$f" ]; then tail -n 20000 "\$f" > "\${f}.tmp" 2>/dev/null && cat "\${f}.tmp" > "\$f" 2>/dev/null && rm -f "\${f}.tmp" 2>/dev/null; fi'
EOF

    # Create/Update timer
    cat > "$timer_path" << EOF
[Unit]
Description=Paqet Manager - Scheduled Log Cleanup

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=30m

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now paqet-log-cleanup.timer >/dev/null 2>&1 || true

    if [ "$silent" != "true" ]; then
        print_success "Log cleanup timer enabled (daily). Journal: time=${PAQET_JOURNAL_VACUUM_TIME}, size=${PAQET_JOURNAL_VACUUM_SIZE}"
        print_info "You can check: systemctl status paqet-log-cleanup.timer  |  journalctl --disk-usage"
    fi
}

cfg_set_log_level() {
    local f="$1"
    local newlevel="$2"

    [ -f "$f" ] || return 1
    newlevel=$(normalize_log_level "$newlevel" "$DEFAULT_LOG_LEVEL")

    local tmp
    tmp=$(mktemp 2>/dev/null) || return 1

    awk -v newlevel="$newlevel" '
        BEGIN { in_log=0; done=0 }
        /^log:[[:space:]]*$/ {
            print
            in_log=1
            next
        }
        in_log && /^[[:space:]]{2}level:/ && done==0 {
            printf "  level: \"%s\"\n", newlevel
            done=1
            next
        }
        in_log && /^[^[:space:]]/ {
            if (done==0) {
                printf "  level: \"%s\"\n", newlevel
                done=1
            }
            in_log=0
            print
            next
        }
        { print }
        END {
            if (done==0) {
                if (in_log==0) print "log:"
                printf "  level: \"%s\"\n", newlevel
            }
        }
    ' "$f" > "$tmp" && mv "$tmp" "$f"

    return 0
}


# Pause with custom message
pause() {
    local msg="${1:-Press Enter to continue...}"
    echo ""
    read -p "$msg" </dev/tty
}

# Clear screen and show banner
show_banner() {
    clear
    echo -e "${MAGENTA}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║     ██████╗  █████╗  ██████╗ ███████╗████████╗               ║"
    echo "║     ██╔══██╗██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝               ║"
    echo "║     ██████╔╝███████║██║   ██║█████╗     ██║                  ║"
    echo "║     ██╔═══╝ ██╔══██║██║▄▄ ██║██╔══╝     ██║                  ║"
    echo "║     ██║     ██║  ██║╚██████╔╝███████╗   ██║                  ║"
    echo "║     ╚═╝     ╚═╝  ╚═╝ ╚══▀▀═╝ ╚══════╝   ╚═╝                  ║"
    echo "║                                                              ║"
    echo "║          Raw Packet Tunnel-- Firewall Bypass                 ║"
    echo "║                                 Manager v${SCRIPT_VERSION}                 ║"
    echo "║                                                              ║"
    echo "║          https://github.com/0fariid0                         ║"    
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    else
        echo "$(uname -s | tr '[:upper:]' '[:lower:]')"
    fi
}

# Detect architecture
detect_arch() {
    local arch
    arch=$(uname -m)
    
    case $arch in
        x86_64|x86-64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l|armhf) echo "armv7" ;;
        i386|i686) echo "386" ;;
        *)
            print_error "Unsupported architecture: $arch"
            return 1
            ;;
    esac
}

# Get public IP
get_public_ip() {
    for service in "${IP_SERVICES[@]}"; do
        local ip
        ip=$(curl -4 -s --max-time 2 "$service" 2>/dev/null)
        if [ -n "$ip" ] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    
    local ip
    ip=$(hostname -I | awk '{print $1}' 2>/dev/null)
    if [ -n "$ip" ] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$ip"
        return 0
    fi
    
    echo "Not Detected"
}

# Get network information
get_network_info() {
    NETWORK_INTERFACE=""
    LOCAL_IP=""
    GATEWAY_IP=""
    GATEWAY_MAC=""
    
    if command -v ip &>/dev/null; then
        NETWORK_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
        LOCAL_IP=$(ip -4 addr show "$NETWORK_INTERFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        GATEWAY_IP=$(ip route | grep default | awk '{print $3}' | head -1)
        
        if [ -n "$GATEWAY_IP" ]; then
            ping -c 1 -W 1 "$GATEWAY_IP" >/dev/null 2>&1 || true
            GATEWAY_MAC=$(ip neigh show "$GATEWAY_IP" 2>/dev/null | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1)
            
            if [ -z "$GATEWAY_MAC" ] && command -v arp &>/dev/null; then
                GATEWAY_MAC=$(arp -n "$GATEWAY_IP" 2>/dev/null | awk "/^$GATEWAY_IP/ {print \$3}" | head -1)
            fi
        fi
    fi
    
    NETWORK_INTERFACE="${NETWORK_INTERFACE:-eth0}"
}

# Validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local IFS='.'
        read -ra octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [[ $octet -lt 0 || $octet -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Validate port
validate_port() {
    local port=$1
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

# Clean port list
clean_port_list() {
    local ports="$1"
    ports=$(echo "$ports" | tr -d ' ')
    local cleaned=""
    
    IFS=',' read -ra port_array <<< "$ports"
    for port in "${port_array[@]}"; do
        if validate_port "$port"; then
            cleaned="${cleaned:+$cleaned,}$port"
        else
            print_warning "Invalid port '$port' removed from list"
        fi
    done
    
    echo "$cleaned"
}

# Clean config name
clean_config_name() {
    local name="$1"
    name=$(echo "$name" | tr -cd '[:alnum:]-_')
    echo "${name:-default}"
}

# Check port conflict
check_port_conflict() {
    local port="$1"
    
    if ss -tuln 2>/dev/null | grep -q ":${port} "; then
        print_warning "Port $port is already in use!"
        
        local pid
        pid=$(lsof -t -i:"$port" 2>/dev/null | head -1)
        if [ -n "$pid" ]; then
            local pname
            pname=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
            print_info "Process: $pname (PID: $pid)"
            
            echo ""
            read -p "Kill this process? (y/N): " kill_choice
            
            if [[ "$kill_choice" =~ ^[Yy]$ ]]; then
                kill -9 "$pid" 2>/dev/null || true
                sleep 1
                print_success "Process killed"
            else
                print_error "Cannot continue with port in use"
                return 1
            fi
        fi
    fi
    return 0
}

normalize_host_for_compare() {
    local host="$1"
    host=$(echo "$host" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
    host="${host#[}"; host="${host%]}"
    case "$host" in
        ""|"localhost"|"0.0.0.0"|"::") echo "127.0.0.1" ;;
        *) echo "$host" ;;
    esac
}

normalize_port() {
    local input="$1"
    input=$(echo "$input" | tr -cd '0-9')
    [[ "$input" =~ ^[1-9][0-9]{0,4}$ && "$input" -le 65535 ]] && echo "$input" || echo ""
}

# ────────────────────────────────────────────────────────────────
# Check for dangerous forward rules that point back to Paqet listener
# Prevents traffic loop / infinite bandwidth consumption
# ────────────────────────────────────────────────────────────────
validate_forward_rules() {
    # Only relevant for Port Forwarding mode
    [[ "$traffic_type" != "1" ]] && return 0

    local srv_host srv_port
    srv_host=$(normalize_host_for_compare "$server_ip")
    srv_port=$(normalize_port "$server_port")

    [ -z "$srv_host" ] || [ -z "$srv_port" ] && return 0

    echo -e "${CYAN}Checking forward rules for traffic loop prevention...${NC}"

    local dangerous=0
    IFS=',' read -ra PORTS <<< "$forward_ports"

    for p in "${PORTS[@]}"; do
        p=$(echo "$p" | tr -d '[:space:]')   # Remove whitespace

        if ! validate_port "$p"; then
            continue
        fi

        # Main case: if forward port equals server port
        if [ "$p" = "$srv_port" ]; then
            print_error "⚠️ TRAFFIC LOOP DETECTED!"
            echo -e "   • Local port: ${YELLOW}$p${NC}"
            echo -e "   • Paqet server port: ${YELLOW}$server_ip:$server_port${NC}"
            echo -e "   This will create an infinite traffic loop and consume all bandwidth!"
            ((dangerous++))
        fi
    done

    if (( dangerous > 0 )); then
        echo ""
        print_error "❌ Configuration aborted due to loop detection."
        echo -e "${YELLOW}Solution:${NC}"
        echo -e "  • Change your forward ports (e.g., 443, 8443, 2053, etc.)"
        echo -e "  • Make sure no port matches the tunnel port (${YELLOW}$server_port${NC})"
        echo -e "  • Forward ports should point to actual services (v2ray/xray/...)"
        pause
        return 1
    fi

    print_success "No dangerous forward rules found ✓"
    return 0
}

# Generate secret key
generate_secret_key() {
    if command -v openssl &>/dev/null; then
        openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32
    else
        tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 32
    fi
}

# Get latest Paqet version from GitHub
get_latest_paqet_version() {
    local version
    version=$(curl -s "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep -o '"tag_name": "[^"]*"' | cut -d'"' -f4 2>/dev/null)    
    if [ -n "$version" ]; then
        echo "$version"
    else
        echo "v1.0.0-alpha.16"
    fi
}

# Compare floats (with bc fallback)
compare_floats() {
    local value=$1
    local threshold=$2
    local comparison=$3
    
    if ! command -v bc &>/dev/null; then
        local value_int=${value%.*}
        local threshold_int=${threshold%.*}
        
        case $comparison in
            "lt") [[ $value_int -lt $threshold_int ]] ;;
            "le") [[ $value_int -le $threshold_int ]] ;;
            "gt") [[ $value_int -gt $threshold_int ]] ;;
            "ge") [[ $value_int -ge $threshold_int ]] ;;
            *) return 1 ;;
        esac
        return $?
    fi
    
    case $comparison in
        "lt") (($(echo "$value < $threshold" | bc -l 2>/dev/null || echo 0))) ;;
        "le") (($(echo "$value <= $threshold" | bc -l 2>/dev/null || echo 0))) ;;
        "gt") (($(echo "$value > $threshold" | bc -l 2>/dev/null || echo 0))) ;;
        "ge") (($(echo "$value >= $threshold" | bc -l 2>/dev/null || echo 0))) ;;
        *) return 1 ;;
    esac
}

# ================================================
# CONFIGURATION FUNCTIONS
# ================================================

# Configure iptables
configure_iptables() {
    local port="$1"
    local protocol="$2"
    
    print_step "Configuring iptables for port $port protocol $protocol..."
    
    if ! command -v iptables &>/dev/null; then
        print_warning "iptables not found, skipping"
        return 0
    fi
    
    local protocols=()
    [ "$protocol" = "both" ] && protocols=("tcp" "udp") || protocols=("$protocol")
    
    for proto in "${protocols[@]}"; do
        iptables -t raw -D PREROUTING -p "$proto" --dport "$port" -j NOTRACK 2>/dev/null || true
        iptables -t raw -D OUTPUT -p "$proto" --sport "$port" -j NOTRACK 2>/dev/null || true
        
        iptables -t raw -A PREROUTING -p "$proto" --dport "$port" -j NOTRACK
        iptables -t raw -A OUTPUT -p "$proto" --sport "$port" -j NOTRACK
        
        if [ "$proto" = "tcp" ]; then
            iptables -t mangle -D OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP 2>/dev/null || true
            iptables -t mangle -A OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP
        fi
    done
    
    print_success "iptables configured for $protocol on port $port"
    save_iptables
}

# Create systemd service
create_systemd_service() {
    local config_name="$1"
    local service_name="paqet-${config_name}"
    
    cat > "$SERVICE_DIR/${service_name}.service" << EOF
[Unit]
Description=Paqet Tunnel (${config_name})
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=$BIN_DIR/paqet run -c $CONFIG_DIR/${config_name}.yaml
Restart=always
RestartSec=5
LimitNOFILE=65535
Environment="GOMAXPROCS=0"

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    print_success "Service created: ${service_name}"
}

# ================================================
# CRONJOB MANAGEMENT
# ================================================

# Add auto-restart cronjob
add_auto_restart_cronjob() {
    local service_name="$1"
    local cron_interval="$2"
    local cron_command="systemctl restart ${service_name}"
    
    local cron_line="${RESTART_INTERVALS[$cron_interval]} $cron_command"
    [ -z "$cron_line" ] && { print_error "Invalid cron interval"; return 1; }
    
    if crontab -l 2>/dev/null | grep -q "$cron_command"; then
        crontab -l 2>/dev/null | grep -v "$cron_command" | crontab -
    fi
    
    (crontab -l 2>/dev/null; echo "$cron_line") | crontab -
    
    if [ $? -eq 0 ]; then
        print_success "Cronjob added: $cron_interval restart for $service_name"
        return 0
    else
        print_error "Failed to add cronjob"
        return 1
    fi
}

# Remove cronjob
remove_cronjob() {
    local service_name="$1"
    local cron_command="systemctl restart ${service_name}"
    
    if crontab -l 2>/dev/null | grep -q "$cron_command"; then
        crontab -l 2>/dev/null | grep -v "$cron_command" | crontab -
        print_success "Cronjob removed for $service_name"
        return 0
    fi
    print_info "No cronjob found for $service_name"
    return 1
}

# View cronjob
view_cronjob() {
    local service_name="$1"
    local cron_command="systemctl restart ${service_name}"
    
    echo -e "${YELLOW}Cronjobs for $service_name:${NC}"
    if crontab -l 2>/dev/null | grep -q "$cron_command"; then
        crontab -l 2>/dev/null | grep "$cron_command"
    else
        print_info "No cronjob found"
    fi
}

# Manage cronjob menu
manage_cronjob() {
    local service_name="$1"
    local display_name="$2"
    
    while true; do
        clear
        show_banner
        echo -e "${YELLOW}Manage Cronjob for: $display_name${NC}\n"
        
        echo -e "${CYAN}Current cronjob:${NC}"
        view_cronjob "$service_name"
        echo -e "\n${CYAN}Add/Change Cronjob:${NC}"
        
        local i=1
        for interval in "${!RESTART_INTERVALS[@]}"; do
            echo " $((i++)). $interval"
        done
        echo " $i. Remove cronjob"
        echo " 0. Back"
        echo ""
        
        read -p "Choose option [0-$i]: " cron_choice
        
        if [ "$cron_choice" = "0" ]; then
            return
        elif [ "$cron_choice" -eq "$i" ]; then
            remove_cronjob "$service_name"
            pause
        elif [ "$cron_choice" -ge 1 ] && [ "$cron_choice" -lt "$i" ]; then
            local idx=1
            for interval in "${!RESTART_INTERVALS[@]}"; do
                if [ "$cron_choice" -eq "$idx" ]; then
                    add_auto_restart_cronjob "$service_name" "$interval"
                    break
                fi
                ((idx++))
            done
            pause
        else
            print_error "Invalid choice"
            sleep 1
        fi
    done
}



# ================================================
# WATCHER MANAGEMENT (Log-based restart on pattern)
# - Creates/Removes systemd drop-in override per tunnel
# - Stores per-tunnel settings in: $CONFIG_DIR/watcher/<tunnel>.conf
# ================================================

# Prefer existing watcher script if user already created it
if [ -f "/root/paqet/paqet_watcher.py" ]; then
    WATCHER_SCRIPT="/root/paqet/paqet_watcher.py"
else
    WATCHER_SCRIPT="$INSTALL_DIR/paqet_watcher.py"
fi
WATCHER_CFG_DIR="$CONFIG_DIR/watcher"
WATCHER_DEFAULT_GRACE=5
WATCHER_DEFAULT_PATTERN="%!s"
WATCHER_DEFAULT_RESTART_DELAY=2

_watcher_python_bin() {
    command -v python3 2>/dev/null || echo "/usr/bin/python3"
}

_watcher_pause() {
    if command -v pause >/dev/null 2>&1; then
        pause
    else
        echo ""
        read -p "Press Enter to continue..."
    fi
}

_watcher_live_logs() {
    local unit="$1"
    echo -e "\n${YELLOW}Live logs for ${unit} — Press Ctrl+C to return...${NC}\n"
    # Keep the manager running when Ctrl+C is pressed (journalctl will stop, then we return to menu)
    trap 'echo -e "\n${CYAN}[i] Returning to Watcher menu...${NC}\n"' INT
    journalctl -u "$unit" -f -n 50 --output=short-iso
    trap - INT
}

_watcher_escape_squotes() {
    # Escape single quotes for bash single-quoted strings
    printf "%s" "$1" | sed "s/'/'\"'\"'/g"
}

_watcher_escape_systemd_percent() {
    # In systemd unit files, '%' is special. Use '%%' for literal '%'.
    printf "%s" "$1" | sed 's/%/%%/g'
}

_watcher_cfg_file() {
    local tunnel="$1"
    echo "$WATCHER_CFG_DIR/${tunnel}.conf"
}

_watcher_ensure_script() {
    # If the watcher python file is missing, generate it automatically.
    if [ -f "$WATCHER_SCRIPT" ]; then
        return 0
    fi

    mkdir -p "$(dirname "$WATCHER_SCRIPT")" 2>/dev/null || true

    cat > "$WATCHER_SCRIPT" << 'PYWATCH'
#!/usr/bin/env python3
import argparse
import os
import signal
import subprocess
import sys
import time


def terminate_process_group(proc: subprocess.Popen, timeout: int = 5) -> None:
    """Terminate whole process group (paqet + children) safely."""
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=timeout)
    except Exception:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            pass


def run_watch_loop(binary: str, config: str, pattern: str, grace: int, restart_delay: int) -> None:
    cmd = [binary, "run", "-c", config]

    while True:
        print(f"[Watcher] Starting: {' '.join(cmd)}", flush=True)
        print(f"[Watcher] Ignoring '{pattern}' for first {grace}s", flush=True)

        if not os.path.exists(binary):
            print(f"[Watcher] ERROR: binary not found: {binary}", flush=True)
            time.sleep(5)
            continue

        if not os.path.exists(config):
            print(f"[Watcher] ERROR: config not found: {config}", flush=True)
            time.sleep(5)
            continue

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )

        start_time = time.time()

        try:
            assert proc.stdout is not None
            for line in iter(proc.stdout.readline, ""):
                sys.stdout.write(line)
                sys.stdout.flush()

                elapsed = time.time() - start_time
                if elapsed >= grace and pattern in line:
                    print(f"\n[Watcher] Detected pattern after grace ({elapsed:.1f}s). Restarting...", flush=True)
                    terminate_process_group(proc)
                    break

            if proc.poll() is not None:
                print(f"[Watcher] Process exited (code={proc.returncode}). Restarting...", flush=True)

        except Exception as e:
            print(f"[Watcher] ERROR while watching logs: {e}", flush=True)
            terminate_process_group(proc)

        time.sleep(restart_delay)


def main():
    ap = argparse.ArgumentParser(description="Watch paqet logs and restart on pattern after grace period.")
    ap.add_argument("--binary", default="/usr/local/bin/paqet", help="Path to paqet binary")
    ap.add_argument("--config", required=True, help="Path to config yaml (e.g. /etc/paqet/server.yaml)")
    ap.add_argument("--pattern", default="%!s", help="Error string/pattern to trigger restart")
    ap.add_argument("--grace", type=int, default=5, help="Grace period seconds")
    ap.add_argument("--restart-delay", type=int, default=2, help="Seconds to wait before restarting")
    args = ap.parse_args()

    run_watch_loop(args.binary, args.config, args.pattern, args.grace, args.restart_delay)


if __name__ == "__main__":
    main()
PYWATCH

    chmod +x "$WATCHER_SCRIPT" 2>/dev/null || true
}

_watcher_load_settings() {
    local tunnel="$1"

    # defaults
    WATCHER_GRACE="$WATCHER_DEFAULT_GRACE"
    WATCHER_PATTERN="$WATCHER_DEFAULT_PATTERN"
    WATCHER_RESTART_DELAY="$WATCHER_DEFAULT_RESTART_DELAY"

    mkdir -p "$WATCHER_CFG_DIR" 2>/dev/null || true
    local f
    f=$(_watcher_cfg_file "$tunnel")

    if [ -f "$f" ]; then
        # shellcheck disable=SC1090
        source "$f" 2>/dev/null || true
        [ -n "$WATCHER_GRACE" ] || WATCHER_GRACE="$WATCHER_DEFAULT_GRACE"
        [ -n "$WATCHER_PATTERN" ] || WATCHER_PATTERN="$WATCHER_DEFAULT_PATTERN"
        [ -n "$WATCHER_RESTART_DELAY" ] || WATCHER_RESTART_DELAY="$WATCHER_DEFAULT_RESTART_DELAY"
    fi
}

_watcher_save_settings() {
    local tunnel="$1"
    local grace="$2"
    local delay="$3"
    local pattern="$4"

    mkdir -p "$WATCHER_CFG_DIR" 2>/dev/null || true
    local f
    f=$(_watcher_cfg_file "$tunnel")

    local pat_esc
    pat_esc=$(_watcher_escape_squotes "$pattern")

    cat > "$f" << EOF
WATCHER_GRACE=${grace}
WATCHER_RESTART_DELAY=${delay}
WATCHER_PATTERN='${pat_esc}'
EOF
}

_watcher_override_dir() {
    local unit="$1"  # example: paqet-ara124.service
    echo "/etc/systemd/system/${unit}.d"
}

_watcher_override_file() {
    local unit="$1"
    echo "$(_watcher_override_dir "$unit")/override.conf"
}

_watcher_is_enabled() {
    local unit="$1"
    local f
    f=$(_watcher_override_file "$unit")

    [ -f "$f" ] && grep -q "$WATCHER_SCRIPT" "$f" 2>/dev/null
}

_watcher_apply_override() {
    local unit="$1"      # paqet-xxx.service
    local tunnel="$2"    # xxx
    local cfg_file="$CONFIG_DIR/${tunnel}.yaml"

    if [ ! -f "$cfg_file" ]; then
        print_error "Config file not found: $cfg_file"
        return 1
    fi

    _watcher_ensure_script

    _watcher_load_settings "$tunnel"

    # Validate numbers
    if ! [[ "$WATCHER_GRACE" =~ ^[0-9]+$ ]]; then WATCHER_GRACE="$WATCHER_DEFAULT_GRACE"; fi
    if ! [[ "$WATCHER_RESTART_DELAY" =~ ^[0-9]+$ ]]; then WATCHER_RESTART_DELAY="$WATCHER_DEFAULT_RESTART_DELAY"; fi

    local py
    py=$(_watcher_python_bin)

    local pattern_systemd
    pattern_systemd=$(_watcher_escape_systemd_percent "$WATCHER_PATTERN")

    local odir
    odir=$(_watcher_override_dir "$unit")
    mkdir -p "$odir" 2>/dev/null || true

    cat > "$odir/override.conf" << EOF
[Service]
Environment=PYTHONUNBUFFERED=1
ExecStart=
ExecStart=${py} ${WATCHER_SCRIPT} --binary ${BIN_DIR}/paqet --config ${cfg_file} --pattern ${pattern_systemd} --grace ${WATCHER_GRACE} --restart-delay ${WATCHER_RESTART_DELAY}
EOF

    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl restart "$unit" >/dev/null 2>&1 || true

    if _watcher_is_enabled "$unit"; then
        print_success "Watcher enabled for ${tunnel} (grace=${WATCHER_GRACE}s, delay=${WATCHER_RESTART_DELAY}s, pattern=${WATCHER_PATTERN})"
        return 0
    fi

    print_warning "Watcher override written, but could not verify enable state. Check: $odir/override.conf"
    return 0
}

_watcher_disable_override() {
    local unit="$1"

    local of
    of=$(_watcher_override_file "$unit")

    if [ -f "$of" ]; then
        rm -f "$of" 2>/dev/null || true
    fi

    local od
    od=$(_watcher_override_dir "$unit")
    rmdir "$od" 2>/dev/null || true

    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl restart "$unit" >/dev/null 2>&1 || true

    print_success "Watcher disabled for ${unit}"
}

manage_watcher() {
    local selected_service="$1"   # paqet-xxx.service
    local tunnel="$2"             # xxx

    while true; do
        show_banner
        echo -e "${YELLOW}Watcher (Auto Restart on Log Pattern)${NC}"
        echo -e "Service: ${CYAN}${selected_service}${NC}"
        echo -e "Tunnel:  ${CYAN}${tunnel}${NC}"
        echo ""

        _watcher_load_settings "$tunnel"

        local enabled="OFF"
        if _watcher_is_enabled "$selected_service"; then
            enabled="ON"
        fi

        echo -e "Status: ${CYAN}${enabled}${NC}"
        echo -e "Config:  grace=${CYAN}${WATCHER_GRACE}s${NC}  delay=${CYAN}${WATCHER_RESTART_DELAY}s${NC}  pattern=${CYAN}${WATCHER_PATTERN}${NC}"
        echo ""

        echo -e "${CYAN}Actions:${NC}"
        echo -e "  1. Enable watcher for this tunnel"
        echo -e "  2. Disable watcher for this tunnel"
        echo -e "  3. Change grace period"
        echo -e "  4. Change restart delay"
        echo -e "  5. Change pattern"
        echo -e "  6. Show override file"
        echo -e "  7. Live logs (Ctrl+C)"
        echo -e "  0. Back"
        echo ""

        read -p "Choose option [0-7]: " wchoice

        case "$wchoice" in
            0) return ;;
            1)
                _watcher_apply_override "$selected_service" "$tunnel"
                _watcher_pause
                ;;
            2)
                _watcher_disable_override "$selected_service"
                _watcher_pause
                ;;
            3)
                echo ""
                read -p "Grace seconds (current: ${WATCHER_GRACE}): " g
                g="${g:-$WATCHER_GRACE}"
                if ! [[ "$g" =~ ^[0-9]+$ ]]; then
                    print_error "Invalid number"
                    _watcher_pause
                    continue
                fi
                _watcher_save_settings "$tunnel" "$g" "$WATCHER_RESTART_DELAY" "$WATCHER_PATTERN"
                print_success "Saved grace=${g} for ${tunnel}"
                # If enabled, re-apply to take effect
                if _watcher_is_enabled "$selected_service"; then
                    _watcher_apply_override "$selected_service" "$tunnel"
                fi
                _watcher_pause
                ;;
            4)
                echo ""
                read -p "Restart delay seconds (current: ${WATCHER_RESTART_DELAY}): " d
                d="${d:-$WATCHER_RESTART_DELAY}"
                if ! [[ "$d" =~ ^[0-9]+$ ]]; then
                    print_error "Invalid number"
                    _watcher_pause
                    continue
                fi
                _watcher_save_settings "$tunnel" "$WATCHER_GRACE" "$d" "$WATCHER_PATTERN"
                print_success "Saved restart-delay=${d} for ${tunnel}"
                if _watcher_is_enabled "$selected_service"; then
                    _watcher_apply_override "$selected_service" "$tunnel"
                fi
                _watcher_pause
                ;;
            5)
                echo ""
                read -p "Pattern (current: ${WATCHER_PATTERN}): " p
                p="${p:-$WATCHER_PATTERN}"
                if [ -z "$p" ]; then
                    print_error "Pattern cannot be empty"
                    _watcher_pause
                    continue
                fi
                _watcher_save_settings "$tunnel" "$WATCHER_GRACE" "$WATCHER_RESTART_DELAY" "$p"
                print_success "Saved pattern=${p} for ${tunnel}"
                if _watcher_is_enabled "$selected_service"; then
                    _watcher_apply_override "$selected_service" "$tunnel"
                fi
                _watcher_pause
                ;;
            6)
                echo ""
                local of
                of=$(_watcher_override_file "$selected_service")
                if [ -f "$of" ]; then
                    echo -e "${CYAN}${of}${NC}"
                    echo ""
                    cat "$of"
                else
                    print_info "Override not found (watcher likely OFF)."
                fi
                _watcher_pause
                ;;
            7)
                _watcher_live_logs "$selected_service"
                ;;
            *)
                print_error "Invalid choice"
                _watcher_pause
                ;;
        esac
    done
}

# ================================================
# SERVICE MANAGEMENT
# ================================================

# Get service details
get_service_details() {
    local service_name="$1"
    local config_name="${service_name#paqet-}"
    local config_file="$CONFIG_DIR/$config_name.yaml"
    
    local type="unknown"
    local mode="fast"
    local mtu="-"
    local conn="-"
    local cron="No"
    
    if [ -f "$config_file" ]; then
        type=$(grep "^role:" "$config_file" 2>/dev/null | awk '{print $2}' | tr -d '"' || echo "unknown")
        
        local mode_line
        mode_line=$(grep "mode:" "$config_file" 2>/dev/null | head -1)
        [ -n "$mode_line" ] && mode=$(echo "$mode_line" | awk '{print $2}' | tr -d '"')
        
        if grep -q "mtu:" "$config_file" 2>/dev/null; then
            local mtu_line
            mtu_line=$(grep "mtu:" "$config_file" 2>/dev/null | head -1)
            [ -n "$mtu_line" ] && mtu=$(echo "$mtu_line" | awk '{print $2}' | tr -d '"')
        fi
        
        if grep -q "conn:" "$config_file" 2>/dev/null; then
            local conn_line
            conn_line=$(grep "conn:" "$config_file" 2>/dev/null | head -1)
            [ -n "$conn_line" ] && conn=$(echo "$conn_line" | awk '{print $2}' | tr -d '"')
        fi
    fi
    
    crontab -l 2>/dev/null | grep -q "systemctl restart $service_name" && cron="Yes"
    
    echo "$type $mode $mtu $conn $cron"
}

# Manage single service
manage_single_service() {
    local selected_service="$1"
    local display_name="$2"
    
    while true; do
        clear
        show_banner
        
        local short_name="${display_name:0:32}"
        [ ${#display_name} -gt 32 ] && short_name="${short_name}..."
        
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
        printf "${GREEN}║ Managing: %-50s ║${NC}\n" "$short_name"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
        
        local status
        status=$(systemctl is-active "$selected_service" 2>/dev/null || echo "unknown")
        
        echo -e "${CYAN}Status:${NC} "
        case "$status" in
            active) echo -e "${GREEN}🟢 Active${NC}" ;;
            failed) echo -e "${RED}🔴 Failed${NC}" ;;
            inactive) echo -e "${YELLOW}🟡 Inactive${NC}" ;;
            *) echo -e "${WHITE}⚪ Unknown${NC}" ;;
        esac
        
        local details
        details=$(get_service_details "${selected_service%.service}")
        local type=$(echo "$details" | awk '{print $1}')
        local mode=$(echo "$details" | awk '{print $2}')
        local mtu=$(echo "$details" | awk '{print $3}')
        local conn=$(echo "$details" | awk '{print $4}')
        local cron=$(echo "$details" | awk '{print $5}')
        
        echo -e "\n${CYAN}Details:${NC}"
        echo -e "${CYAN}┌──────────────────────────────────────────────┐${NC}"
        printf "${CYAN}│${NC} %-16s ${CYAN}:${NC} %-25s ${CYAN}│${NC}\n" "Type" "${type:-unknown}"
        printf "${CYAN}│${NC} %-16s ${CYAN}:${NC} %-25s ${CYAN}│${NC}\n" "KCP Mode" "${mode:-fast}"
        printf "${CYAN}│${NC} %-16s ${CYAN}:${NC} %-25s ${CYAN}│${NC}\n" "MTU" "${mtu:--}"
        printf "${CYAN}│${NC} %-16s ${CYAN}:${NC} %-25s ${CYAN}│${NC}\n" "Connections" "${conn:--}"
        printf "${CYAN}│${NC} %-16s ${CYAN}:${NC} %-25s ${CYAN}│${NC}\n" "Auto-Restart" "${cron:-No}"
        echo -e "${CYAN}└──────────────────────────────────────────────┘${NC}"
        
        echo -e "\n${CYAN}Actions${NC}"
        echo " 1. 🟢 Start"
        echo " 2. 🔴 Stop"
        echo " 3. 🔄 Restart"
        echo " 4. 📊 Show Status"
        echo " 5. 📝 View Recent Logs"
        echo " 6. ✏️  Edit Configuration"
        echo " 7. 📄 View Configuration"
        echo " 8. ⏰ Cronjob Management"
        echo " 9. 👁️  Watcher (Auto Restart on Log Pattern)"
        echo " 10. 🗑️  Delete Service"
        echo " 11. 📡 Live Logs (Follow)"
        echo " 0. ↩️  Back"
        echo ""
        
        read -p "Choose action [0-11]: " action
        
        case "$action" in
            0) return ;;
            1) systemctl start "$selected_service" >/dev/null 2>&1
               print_success "Service started"
               sleep 1.5 ;;
            2) systemctl stop "$selected_service" >/dev/null 2>&1
               print_success "Service stopped"
               sleep 1.5 ;;
            3) systemctl restart "$selected_service" >/dev/null 2>&1
               print_success "Service restarted"
               sleep 1.5 ;;
            4) echo ""
               systemctl status "$selected_service" --no-pager -l
               pause ;;
            5) echo ""
               journalctl -u "$selected_service" -n 25 --no-pager
               pause ;;
            6) local cfg="$CONFIG_DIR/$display_name.yaml"
               if [ -f "$cfg" ]; then
                   echo -e "\n${YELLOW}Editing: $cfg${NC}"
                   local editor="nano"
                   command -v nano &>/dev/null || editor="vi"
                   $editor "$cfg"
                   
                   read -p "Restart service to apply changes? (y/N): " restart_choice
                   if [[ "$restart_choice" =~ ^[Yy]$ ]]; then
                       systemctl restart "$selected_service" >/dev/null 2>&1
                       if systemctl is-active --quiet "$selected_service"; then
                           print_success "Service restarted"
                       else
                           print_error "Service failed to start"
                           systemctl status "$selected_service" --no-pager -l
                       fi
                   fi
               else
                   print_error "Config file not found"
               fi
               pause ;;
            7) local cfg="$CONFIG_DIR/$display_name.yaml"
               if [ -f "$cfg" ]; then
                   echo -e "\n${CYAN}$cfg${NC}\n"
                   cat "$cfg"
               else
                   print_error "Config file not found"
               fi
               pause ;;
            8) manage_cronjob "${selected_service%.service}" "$display_name" ;;
            9) manage_watcher "$selected_service" "$display_name" ;;
                        11) echo -e "\n${YELLOW}Press Ctrl+C to stop live logs...${NC}\n"
                journalctl -u "$selected_service" -n 50 -f
                pause ;;
            10) read -p "Delete this service? (y/N): " confirm
               if [[ "$confirm" =~ ^[Yy]$ ]]; then
                   remove_cronjob "${selected_service%.service}" 2>/dev/null || true
                   systemctl stop "$selected_service" 2>/dev/null || true
                   systemctl disable "$selected_service" 2>/dev/null || true
                   rm -f "$SERVICE_DIR/$selected_service" 2>/dev/null || true
                   rm -f "$CONFIG_DIR/$display_name.yaml" 2>/dev/null || true
                   systemctl daemon-reload 2>/dev/null || true
                   print_success "Service removed"
                   pause
                   return
               fi ;;
            *) print_error "Invalid choice"
               sleep 1 ;;
        esac
    done
}

# Manage all services
manage_services() {
    while true; do
        clear
        show_banner
        
        echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║ Paqet Services - Manage                                                                                   ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════╝${NC}\n"
        
        local services=()
        mapfile -t services < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null |
                              grep -E '^paqet-.*\.service' | awk '{print $1}' || true)
        
        if [[ ${#services[@]} -eq 0 ]]; then
            echo -e "${YELLOW}No Paqet services found.${NC}\n"
            pause
            return
        fi
        
        echo -e "${CYAN}┌─────┬──────────────────────────┬─────────────┬───────────┬────────────────┬────────────┬──────────┬────────┐${NC}"
        echo -e "${CYAN}│  #  │ Service Name             │ Status      │ Type      │ Auto Restart   │ Mode       │ MTU      │ Conn   │${NC}"
        echo -e "${CYAN}├─────┼──────────────────────────┼─────────────┼───────────┼────────────────┼────────────┼──────────┼────────┤${NC}"
        
        local i=1
        for svc in "${services[@]}"; do
            local service_name="${svc%.service}"
            local display_name="${service_name#paqet-}"
            local status
            status=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
            local details
            details=$(get_service_details "$service_name")
            local type=$(echo "$details" | awk '{print $1}')
            local mode=$(echo "$details" | awk '{print $2}')
            local mtu=$(echo "$details" | awk '{print $3}')
            local conn=$(echo "$details" | awk '{print $4}')
            local cron=$(echo "$details" | awk '{print $5}')
            
            local status_color=""
            case "$status" in
                active) status_color="${GREEN}" ;;
                failed) status_color="${RED}" ;;
                inactive) status_color="${YELLOW}" ;;
                *) status_color="${WHITE}" ;;
            esac
            
            local mode_color=""
            case "$mode" in
                normal) mode_color="${CYAN}" ;;
                fast) mode_color="${GREEN}" ;;
                fast2) mode_color="${ORANGE}" ;;
                fast3) mode_color="${PURPLE}" ;;
                manual) mode_color="${RED}" ;;
                *) mode_color="${WHITE}" ;;
            esac
            
            printf "${CYAN}│${NC} %3d ${CYAN}│${NC} %-24s ${CYAN}│${NC} ${status_color}%-11s${NC} ${CYAN}│${NC} %-9s ${CYAN}│${NC} %-14s ${CYAN}│${NC} ${mode_color}%-10s${NC} ${CYAN}│${NC} %-8s ${CYAN}│${NC} %-6s ${CYAN}│${NC}\n" \
                "$i" "${display_name:0:24}" "$status" "${type:-unknown}" "${cron:-No}" "${mode:-fast}" "${mtu:--}" "${conn:--}"
            ((i++))
        done
        
        echo -e "${CYAN}└─────┴──────────────────────────┴─────────────┴───────────┴────────────────┴────────────┴──────────┴────────┘${NC}\n"
        echo -e "${YELLOW}Options:${NC}"
        echo -e "${YELLOW}Options:${NC}"
        echo -e " 0. ↩️ Back to Main Menu"
        echo -e " 1–${#services[@]}. Select a service to manage"
        echo -e " L. 🧾 Log Management (Level / Cleanup / Live Logs)"
        echo ""
        
        read -p "Enter choice (0 to cancel): " choice

        if [[ "$choice" =~ ^[Ll]$ ]]; then
            log_management_menu
            continue
        fi

        [ "$choice" = "0" ] && return
        
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#services[@]} )); then
            print_error "Invalid selection"
            sleep 1.5
            continue
        fi
        
        local selected_service="${services[$((choice-1))]}"
        local service_name="${selected_service%.service}"
        local display_name="${service_name#paqet-}"
        manage_single_service "$selected_service" "$display_name"
    done
}


# ================================================
# LOG MANAGEMENT (Per-Tunnel Log Level / Live Logs / Cleanup)
# ================================================

# Journald + logrotate (no extra systemd services created)
JOURNALD_DROPIN_DIR="/etc/systemd/journald.conf.d"
JOURNALD_DROPIN_FILE="$JOURNALD_DROPIN_DIR/99-paqet-manager.conf"
LOGROTATE_TELEGRAM_FILE="/etc/logrotate.d/telegram-paqet-bot"

DEFAULT_JOURNAL_MAX_USE="300M"
DEFAULT_JOURNAL_RETENTION="7day"
DEFAULT_TELEGRAM_ROTATE_COUNT="7"
DEFAULT_TELEGRAM_ROTATE_FREQ="daily"
DEFAULT_TELEGRAM_ROTATE_SIZE="50M"

cleanup_legacy_log_services() {
    # Remove old log-cleanup units created by older script versions (so they don't show as paqet-*.service)
    if systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '{print $1}' | grep -qx "paqet-log-cleanup.service" \
       || [ -f "$SERVICE_DIR/paqet-log-cleanup.service" ] || [ -f "$SERVICE_DIR/paqet-log-cleanup.timer" ]; then
        systemctl disable --now paqet-log-cleanup.timer >/dev/null 2>&1 || true
        systemctl disable --now paqet-log-cleanup.service >/dev/null 2>&1 || true
        rm -f "$SERVICE_DIR/paqet-log-cleanup.service" "$SERVICE_DIR/paqet-log-cleanup.timer" >/dev/null 2>&1 || true
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
}

_safe_backup_file() {
    local f="$1"
    [ -f "$f" ] || return 0
    mkdir -p "$BACKUP_DIR" >/dev/null 2>&1 || true
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    cp -a "$f" "$BACKUP_DIR/$(basename "$f").bak-$ts" >/dev/null 2>&1 || true
}

_log_cleanup_enabled() {
    [ -f "$JOURNALD_DROPIN_FILE" ] || [ -f "$LOGROTATE_TELEGRAM_FILE" ]
}

_log_read_kv() {
    # usage: _log_read_kv <file> <key>
    local f="$1" k="$2"
    [ -f "$f" ] || return 1
    grep -E "^[[:space:]]*${k}=" "$f" 2>/dev/null | tail -n 1 | cut -d'=' -f2- | xargs
}

_log_show_cleanup_status() {
    local enabled="OFF"
    _log_cleanup_enabled && enabled="ON"

    local maxuse retention
    maxuse=$(_log_read_kv "$JOURNALD_DROPIN_FILE" "SystemMaxUse")
    retention=$(_log_read_kv "$JOURNALD_DROPIN_FILE" "MaxRetentionSec")

    maxuse="${maxuse:-$DEFAULT_JOURNAL_MAX_USE}"
    retention="${retention:-$DEFAULT_JOURNAL_RETENTION}"

    echo -e "${CYAN}Auto Log Cleanup:${NC} ${GREEN}${enabled}${NC}"
    echo -e "${CYAN}Journald Limits:${NC} SystemMaxUse=${YELLOW}${maxuse}${NC}  |  MaxRetentionSec=${YELLOW}${retention}${NC}"
    if [ -f "$LOGROTATE_TELEGRAM_FILE" ]; then
        local freq rotate_count size
        freq=$(grep -E '^\s*(daily|weekly|monthly|yearly)\s*$' "$LOGROTATE_TELEGRAM_FILE" 2>/dev/null | head -n 1 | xargs)
        rotate_count=$(grep -E '^\s*rotate\s+' "$LOGROTATE_TELEGRAM_FILE" 2>/dev/null | head -n 1 | awk '{print $2}')
        size=$(grep -E '^\s*size\s+' "$LOGROTATE_TELEGRAM_FILE" 2>/dev/null | head -n 1 | awk '{print $2}')
        freq="${freq:-$DEFAULT_TELEGRAM_ROTATE_FREQ}"
        rotate_count="${rotate_count:-$DEFAULT_TELEGRAM_ROTATE_COUNT}"
        size="${size:-$DEFAULT_TELEGRAM_ROTATE_SIZE}"
        echo -e "${CYAN}Bot Logrotate:${NC} freq=${YELLOW}${freq}${NC}  |  rotate=${YELLOW}${rotate_count}${NC}  |  size=${YELLOW}${size}${NC}"
    else
        echo -e "${CYAN}Bot Logrotate:${NC} ${YELLOW}OFF${NC} (file not installed)"
    fi
}

_log_restart_journald() {
    systemctl restart systemd-journald >/dev/null 2>&1 || true
}

_log_write_journald_dropin() {
    local maxuse="$1"
    local retention="$2"
    mkdir -p "$JOURNALD_DROPIN_DIR" >/dev/null 2>&1 || true

    cat > "$JOURNALD_DROPIN_FILE" << EOF
[Journal]
SystemMaxUse=$maxuse
MaxRetentionSec=$retention
EOF
    _log_restart_journald
}

_log_write_telegram_logrotate() {
    local freq="$1"
    local rotate_count="$2"
    local size="$3"

    cat > "$LOGROTATE_TELEGRAM_FILE" << EOF
/var/log/telegram-paqet-bot.log {
    $freq
    rotate $rotate_count
    size $size
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF
}

_enable_log_cleanup_defaults() {
    _log_write_journald_dropin "$DEFAULT_JOURNAL_MAX_USE" "$DEFAULT_JOURNAL_RETENTION"
    _log_write_telegram_logrotate "$DEFAULT_TELEGRAM_ROTATE_FREQ" "$DEFAULT_TELEGRAM_ROTATE_COUNT" "$DEFAULT_TELEGRAM_ROTATE_SIZE"
    print_success "Auto log cleanup enabled (journald limits + bot logrotate)."
}

_disable_log_cleanup() {
    rm -f "$JOURNALD_DROPIN_FILE" "$LOGROTATE_TELEGRAM_FILE" >/dev/null 2>&1 || true
    _log_restart_journald
    print_success "Auto log cleanup disabled."
}

_configure_log_cleanup() {
    clear
    show_banner
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                  Configure Auto Log Cleanup                  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"

    local cur_maxuse cur_retention
    cur_maxuse=$(_log_read_kv "$JOURNALD_DROPIN_FILE" "SystemMaxUse")
    cur_retention=$(_log_read_kv "$JOURNALD_DROPIN_FILE" "MaxRetentionSec")
    cur_maxuse="${cur_maxuse:-$DEFAULT_JOURNAL_MAX_USE}"
    cur_retention="${cur_retention:-$DEFAULT_JOURNAL_RETENTION}"

    echo -e "${CYAN}Current journald limits:${NC} SystemMaxUse=${YELLOW}${cur_maxuse}${NC}, MaxRetentionSec=${YELLOW}${cur_retention}${NC}"
    echo -e "${YELLOW}Tips:${NC} Examples: 300M, 1G  |  retention: 7day, 14day, 1month"
    echo ""

    local maxuse retention
    read -p "SystemMaxUse (default: ${cur_maxuse}): " maxuse
    read -p "MaxRetentionSec (default: ${cur_retention}): " retention
    maxuse="${maxuse:-$cur_maxuse}"
    retention="${retention:-$cur_retention}"

    echo ""
    echo -e "${CYAN}Bot logrotate settings (telegram-paqet-bot.log):${NC}"
    local freq rotate_count size
    freq=$(grep -E '^\s*(daily|weekly|monthly|yearly)\s*$' "$LOGROTATE_TELEGRAM_FILE" 2>/dev/null | head -n 1 | xargs)
    rotate_count=$(grep -E '^\s*rotate\s+' "$LOGROTATE_TELEGRAM_FILE" 2>/dev/null | head -n 1 | awk '{print $2}')
    size=$(grep -E '^\s*size\s+' "$LOGROTATE_TELEGRAM_FILE" 2>/dev/null | head -n 1 | awk '{print $2}')
    freq="${freq:-$DEFAULT_TELEGRAM_ROTATE_FREQ}"
    rotate_count="${rotate_count:-$DEFAULT_TELEGRAM_ROTATE_COUNT}"
    size="${size:-$DEFAULT_TELEGRAM_ROTATE_SIZE}"

    echo -e "${CYAN}Current:${NC} freq=${YELLOW}${freq}${NC}, rotate=${YELLOW}${rotate_count}${NC}, size=${YELLOW}${size}${NC}"
    echo -e "${YELLOW}freq options:${NC} daily / weekly / monthly"
    echo ""

    read -p "freq (default: ${freq}): " freq_in
    read -p "rotate count (default: ${rotate_count}): " rotate_in
    read -p "size threshold (default: ${size}): " size_in

    freq="${freq_in:-$freq}"
    rotate_count="${rotate_in:-$rotate_count}"
    size="${size_in:-$size}"

    _log_write_journald_dropin "$maxuse" "$retention"
    _log_write_telegram_logrotate "$freq" "$rotate_count" "$size"

    print_success "Auto log cleanup configuration updated."
    pause
}

_run_cleanup_now() {
    local maxuse retention
    maxuse=$(_log_read_kv "$JOURNALD_DROPIN_FILE" "SystemMaxUse")
    retention=$(_log_read_kv "$JOURNALD_DROPIN_FILE" "MaxRetentionSec")
    maxuse="${maxuse:-$DEFAULT_JOURNAL_MAX_USE}"
    retention="${retention:-$DEFAULT_JOURNAL_RETENTION}"

    journalctl --rotate >/dev/null 2>&1 || true
    # journalctl accepts time in many formats; use retention as-is (often works), fallback to 7d.
    journalctl --vacuum-size="$maxuse" >/dev/null 2>&1 || true
    journalctl --vacuum-time="$retention" >/dev/null 2>&1 || journalctl --vacuum-time="7d" >/dev/null 2>&1 || true

    if command -v logrotate >/dev/null 2>&1 && [ -f "$LOGROTATE_TELEGRAM_FILE" ]; then
        logrotate -f "$LOGROTATE_TELEGRAM_FILE" >/dev/null 2>&1 || true
    fi

    print_success "Cleanup executed. (journal rotated/vacuumed, bot logrotate forced if configured)"
    echo -e "  ${CYAN}journalctl --disk-usage${NC}"
    pause
}

_prompt_log_level() {
    echo ""
    echo -e "${YELLOW}Select Log Level:${NC}"
    echo " 1) debug"
    echo " 2) info"
    echo " 3) warn"
    echo " 4) error"
    echo ""
    local c
    read -p "Choice [1-4] (default 2=info): " c
    case "$c" in
        1) echo "debug" ;;
        3) echo "warn" ;;
        4) echo "error" ;;
        *) echo "info" ;;
    esac
}

_log_select_service() {
    # Echo selected service unit (e.g., paqet-xxx.service) or empty on cancel
    local services=()
    mapfile -t services < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null |
                          grep -E '^paqet-.*\.service' | awk '{print $1}' || true)

    if [[ ${#services[@]} -eq 0 ]]; then
        print_warning "No Paqet services found."
        echo ""
        return 1
    fi

    echo -e "\n${CYAN}Select Tunnel:${NC}"
    local i=1
    for svc in "${services[@]}"; do
        local display_name="${svc%.service}"
        display_name="${display_name#paqet-}"
        local st
        st=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
        printf " %2d) %-28s [%s]\n" "$i" "$display_name" "$st"
        ((i++))
    done
    echo " 0) Cancel"
    echo ""
    local choice
    read -p "Choose [0-${#services[@]}]: " choice
    [ "$choice" = "0" ] && return 1
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#services[@]} )); then
        print_error "Invalid selection"
        return 1
    fi
    echo "${services[$((choice-1))]}"
    return 0
}

_change_log_level_one_or_all() {
    local services=()
    mapfile -t services < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null |
                          grep -E '^paqet-.*\.service' | awk '{print $1}' || true)

    if [[ ${#services[@]} -eq 0 ]]; then
        print_warning "No Paqet services found."
        pause
        return
    fi

    echo -e "\n${YELLOW}Apply log level to:${NC}"
    echo " 1) All tunnels"
    echo " 2) One tunnel"
    echo " 0) Cancel"
    echo ""
    local target
    read -p "Choice [0-2]: " target
    [ "$target" = "0" ] && return

    local level
    level=$(_prompt_log_level)

    local selected=()
    if [ "$target" = "1" ]; then
        selected=("${services[@]}")
    elif [ "$target" = "2" ]; then
        local svc
        svc=$(_log_select_service) || { pause; return; }
        selected=("$svc")
    else
        print_error "Invalid choice"
        sleep 1
        return
    fi

    local ok=0 fail=0
    for svc in "${selected[@]}"; do
        local tunnel="${svc%.service}"
        tunnel="${tunnel#paqet-}"
        local cfg="$CONFIG_DIR/$tunnel.yaml"
        if [ ! -f "$cfg" ]; then
            ((fail++))
            continue
        fi
        _safe_backup_file "$cfg"
        if cfg_set_log_level "$cfg" "$level" >/dev/null 2>&1; then
            ((ok++))
        else
            ((fail++))
        fi
    done

    print_success "Log level set to '${level}'  (OK: $ok, Failed: $fail)"
    echo ""
    read -p "Restart affected services now? (y/N): " r
    if [[ "$r" =~ ^[Yy]$ ]]; then
        for svc in "${selected[@]}"; do
            systemctl restart "$svc" >/dev/null 2>&1 || true
        done
        print_success "Restart command sent."
    fi
    pause
}

_view_recent_logs_selected() {
    local svc
    svc=$(_log_select_service) || { pause; return; }
    echo -e "\n${YELLOW}Recent logs for ${svc}:${NC}\n"
    journalctl -u "$svc" -n 50 --no-pager
    pause
}

_live_logs_selected() {
    local svc
    svc=$(_log_select_service) || { pause; return; }
    echo -e "\n${YELLOW}Live logs for ${svc} (Ctrl+C to stop)${NC}\n"
    journalctl -u "$svc" -n 50 -f
    pause
}

log_management_menu() {
    # Make sure legacy units don't pollute the service list
    cleanup_legacy_log_services

    while true; do
        clear
        show_banner

        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                       Log Management                         ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"

        _log_show_cleanup_status
        echo ""

        echo -e "${YELLOW}Options:${NC}"
        echo -e " 1) 📝 Change Log Level (One / All tunnels)"
        echo -e " 2) 📡 Live Logs (Select tunnel)"
        echo -e " 3) 🧾 Recent Logs (Select tunnel)"
        echo -e " 4) 🧹 Enable Auto Log Cleanup"
        echo -e " 5) 🛑 Disable Auto Log Cleanup"
        echo -e " 6) ⚙️  Configure Auto Log Cleanup Settings"
        echo -e " 7) ▶️  Run Cleanup Now"
        echo -e " 8) 📦 Show Journal Disk Usage"
        echo -e " 0) ↩️  Back"
        echo ""

        local c
        read -p "Choose [0-8]: " c
        case "$c" in
            0) return ;;
            1) _change_log_level_one_or_all ;;
            2) _live_logs_selected ;;
            3) _view_recent_logs_selected ;;
            4) _enable_log_cleanup_defaults; pause ;;
            5) _disable_log_cleanup; pause ;;
            6) _configure_log_cleanup ;;
            7) _run_cleanup_now ;;
            8) echo ""; journalctl --disk-usage; pause ;;
            *) print_error "Invalid choice"; sleep 1 ;;
        esac
    done
}

# ================================================
# KCP MANUAL SETTINGS
# ================================================
get_manual_kcp_settings() {
    local nodelay=""
    while true; do
        read -p "[1] nodelay [0-2, default 1, 0=skip]: " input
        if [ -z "$input" ]; then
            nodelay="1"
            echo -e "  ${GREEN}→ Using default: 1${NC}" >&2
            break
        elif [ "$input" = "0" ]; then
            nodelay=""
            echo -e "  ${YELLOW}→ Skipped${NC}" >&2
            break
        elif [[ "$input" =~ ^[0-2]$ ]]; then
            nodelay="$input"
            echo -e "  ${GREEN}→ Set to: $input${NC}" >&2
            break
        else
            echo -e "  ${RED}✗ Invalid: Value must be 0, 1 or 2${NC}" >&2
        fi
    done
    
    local interval=""
    while true; do
        read -p "[2] interval (ms) [default 20, 0=skip]: " input
        if [ -z "$input" ]; then
            interval="20"
            echo -e "  ${GREEN}→ Using default: 20${NC}" >&2
            break
        elif [ "$input" = "0" ]; then
            interval=""
            echo -e "  ${YELLOW}→ Skipped${NC}" >&2
            break
        elif [[ "$input" =~ ^[0-9]+$ ]] && [ "$input" -ge 5 ] && [ "$input" -le 60000 ]; then
            interval="$input"
            echo -e "  ${GREEN}→ Set to: $input${NC}" >&2
            break
        else
            echo -e "  ${RED}✗ Invalid: Range 5–60000 ms${NC}" >&2
        fi
    done
    
    local resend=""
    while true; do
        read -p "[3] resend [0-∞, default 1, 0=skip]: " input
        if [ -z "$input" ]; then
            resend="1"
            echo -e "  ${GREEN}→ Using default: 1${NC}" >&2
            break
        elif [ "$input" = "0" ]; then
            resend=""
            echo -e "  ${YELLOW}→ Skipped${NC}" >&2
            break
        elif [[ "$input" =~ ^[0-9]+$ ]]; then
            resend="$input"
            echo -e "  ${GREEN}→ Set to: $input${NC}" >&2
            break
        else
            echo -e "  ${RED}✗ Invalid: Must be non-negative number${NC}" >&2
        fi
    done
    
    local nocongestion=""
    while true; do
        read -p "[4] nocongestion [0/1, default 1, 0=skip]: " input
        if [ -z "$input" ]; then
            nocongestion="1"
            echo -e "  ${GREEN}→ Using default: 1${NC}" >&2
            break
        elif [ "$input" = "0" ]; then
            nocongestion=""
            echo -e "  ${YELLOW}→ Skipped${NC}" >&2
            break
        elif [[ "$input" =~ ^[01]$ ]]; then
            nocongestion="$input"
            echo -e "  ${GREEN}→ Set to: $input${NC}" >&2
            break
        else
            echo -e "  ${RED}✗ Invalid: Only 0 or 1 allowed${NC}" >&2
        fi
    done
    
    local rcvwnd=""
    while true; do
        read -p "[5] rcvwnd [default 2048, 0=skip]: " input
        if [ -z "$input" ]; then
            rcvwnd="2048"
            echo -e "  ${GREEN}→ Using default: 2048${NC}" >&2
            break
        elif [ "$input" = "0" ]; then
            rcvwnd=""
            echo -e "  ${YELLOW}→ Skipped${NC}" >&2
            break
        elif [[ "$input" =~ ^[0-9]+$ ]] && [ "$input" -ge 128 ]; then
            rcvwnd="$input"
            echo -e "  ${GREEN}→ Set to: $input${NC}" >&2
            break
        else
            echo -e "  ${RED}✗ Invalid: Minimum 128${NC}" >&2
        fi
    done
    
    local sndwnd=""
    while true; do
        read -p "[6] sndwnd [default 2048, 0=skip]: " input
        if [ -z "$input" ]; then
            sndwnd="2048"
            echo -e "  ${GREEN}→ Using default: 2048${NC}" >&2
            break
        elif [ "$input" = "0" ]; then
            sndwnd=""
            echo -e "  ${YELLOW}→ Skipped${NC}" >&2
            break
        elif [[ "$input" =~ ^[0-9]+$ ]] && [ "$input" -ge 128 ]; then
            sndwnd="$input"
            echo -e "  ${GREEN}→ Set to: $input${NC}" >&2
            break
        else
            echo -e "  ${RED}✗ Invalid: Minimum 128${NC}" >&2
        fi
    done
    
    local wdelay=""
    while true; do
        read -p "[7] wdelay (true/false) [default false, 0=skip]: " input
        if [ -z "$input" ]; then
            wdelay="false"
            echo -e "  ${GREEN}→ Using default: false${NC}" >&2
            break
        elif [ "$input" = "0" ]; then
            wdelay=""
            echo -e "  ${YELLOW}→ Skipped${NC}" >&2
            break
        elif [[ "${input,,}" = "false" ]]; then
            wdelay="false"
            echo -e "  ${GREEN}→ Set to: false${NC}" >&2
            break
        elif [[ "${input,,}" = "true" ]]; then
            wdelay="true"
            echo -e "  ${GREEN}→ Set to: true${NC}" >&2
            break
        else
            echo -e "  ${RED}✗ Invalid: Only true or false${NC}" >&2
        fi
    done
    
    local acknodelay=""
    while true; do
        read -p "[8] acknodelay (true/false) [default true, 0=skip]: " input
        if [ -z "$input" ]; then
            acknodelay="true"
            echo -e "  ${GREEN}→ Using default: true${NC}" >&2
            break
        elif [ "$input" = "0" ]; then
            acknodelay=""
            echo -e "  ${YELLOW}→ Skipped${NC}" >&2
            break
        elif [[ "${input,,}" = "true" ]]; then
            acknodelay="true"
            echo -e "  ${GREEN}→ Set to: true${NC}" >&2
            break
        elif [[ "${input,,}" = "false" ]]; then
            acknodelay="false"
            echo -e "  ${GREEN}→ Set to: false${NC}" >&2
            break
        else
            echo -e "  ${RED}✗ Invalid: Only true or false${NC}" >&2
        fi
    done
    
    local smuxbuf=""
    echo -en "[9] smuxbuf [default 4194304, 0=skip]: " >&2
    read -r smuxbuf_input
    if [ -z "$smuxbuf_input" ]; then
        smuxbuf="4194304"
        echo -e "  ${GREEN}→ Using default: 4194304${NC}" >&2
    elif [ "$smuxbuf_input" = "0" ]; then
        smuxbuf=""
        echo -e "  ${YELLOW}→ Skipped${NC}" >&2
    else
        smuxbuf="$smuxbuf_input"
        echo -e "  ${GREEN}→ Set to: $smuxbuf_input${NC}" >&2
    fi
    
    local streambuf=""
    echo -en "[10] streambuf [default 2097152, 0=skip]: " >&2
    read -r streambuf_input
    if [ -z "$streambuf_input" ]; then
        streambuf="2097152"
        echo -e "  ${GREEN}→ Using default: 2097152${NC}" >&2
    elif [ "$streambuf_input" = "0" ]; then
        streambuf=""
        echo -e "  ${YELLOW}→ Skipped${NC}" >&2
    else
        streambuf="$streambuf_input"
        echo -e "  ${GREEN}→ Set to: $streambuf_input${NC}" >&2
    fi
    
    local dshard=""
    echo -en "[11] dshard (FEC data) [default 10, 0=skip]: " >&2
    read -r dshard_input
    if [ -z "$dshard_input" ]; then
        dshard="10"
        echo -e "  ${GREEN}→ Using default: 10${NC}" >&2
    elif [ "$dshard_input" = "0" ]; then
        dshard=""
        echo -e "  ${YELLOW}→ Skipped${NC}" >&2
    else
        dshard="$dshard_input"
        echo -e "  ${GREEN}→ Set to: $dshard_input${NC}" >&2
    fi
    
    local pshard=""
    echo -en "[12] pshard (FEC parity) [default 3, 0=skip]: " >&2
    read -r pshard_input
    if [ -z "$pshard_input" ]; then
        pshard="3"
        echo -e "  ${GREEN}→ Using default: 3${NC}" >&2
    elif [ "$pshard_input" = "0" ]; then
        pshard=""
        echo -e "  ${YELLOW}→ Skipped${NC}" >&2
    else
        pshard="$pshard_input"
        echo -e "  ${GREEN}→ Set to: $pshard_input${NC}" >&2
    fi

    echo "" >&2

    # Only output parameters that have values
    echo "mode: \"manual\""
    [ -n "$nodelay" ] && echo "nodelay: $nodelay"
    [ -n "$interval" ] && echo "interval: $interval"
    [ -n "$resend" ] && echo "resend: $resend"
    [ -n "$nocongestion" ] && echo "nocongestion: $nocongestion"
    [ -n "$rcvwnd" ] && echo "rcvwnd: $rcvwnd"
    [ -n "$sndwnd" ] && echo "sndwnd: $sndwnd"
    [ -n "$wdelay" ] && echo "wdelay: $wdelay"
    [ -n "$acknodelay" ] && echo "acknodelay: $acknodelay"
    [ -n "$smuxbuf" ] && echo "smuxbuf: $smuxbuf"
    [ -n "$streambuf" ] && echo "streambuf: $streambuf"
    [ -n "$dshard" ] && echo "dshard: $dshard"
    [ -n "$pshard" ] && echo "pshard: $pshard"
}

# ================================================
# CONFIGURATION MENUS
# ================================================

# Configure as Server
configure_server() {
    while true; do
        clear
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║ Configure as Server (Abroad/Kharej)                          ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
        
        get_network_info
        local public_ip
        public_ip=$(get_public_ip)
        
        echo -e "${YELLOW}Detected Network Information${NC}"
        echo -e "┌──────────────────────────────────────────────────────────────┐"
        printf "│ %-12s : %-44s │\n" "Interface" "${NETWORK_INTERFACE:-Not found}"
        printf "│ %-12s : %-44s │\n" "Local IP" "${LOCAL_IP:-Not found}"
        printf "│ %-12s : %-44s │\n" "Public IP" "$public_ip"
        printf "│ %-12s : %-44s │\n" "Gateway MAC" "${GATEWAY_MAC:-Not found}"
        echo -e "└──────────────────────────────────────────────────────────────┘\n"
        
        echo -e "${CYAN}Server Configuration${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        
        # [1/12] Service Name
        echo -en "${YELLOW}[1/12] Service Name (e.g: myserver) : ${NC}"
        read -r config_name
        config_name=$(clean_config_name "${config_name:-server}")
        echo -e "[1/12] Service Name : ${CYAN}$config_name${NC}"
        
        if [ -f "$CONFIG_DIR/${config_name}.yaml" ]; then
            print_warning "Config '$config_name' already exists!"
            read -p "Overwrite? (y/N): " ow
            [[ ! "$ow" =~ ^[Yy]$ ]] && continue
        fi
        
        # [2/12] Listen Port
        echo -en "${YELLOW}[2/12] Listen Port (default: $DEFAULT_LISTEN_PORT) : ${NC}"
        read -r port
        port="${port:-$DEFAULT_LISTEN_PORT}"
        
        if ! validate_port "$port"; then
            print_error "Invalid port"
            sleep 1.5
            continue
        fi
        echo -e "[2/12] Listen Port : ${CYAN}$port${NC}"
        
        if ! check_port_conflict "$port"; then
            pause "Press Enter to retry..."
            continue
        fi
        
        # [3/12] Secret Key
        local secret_key
        secret_key=$(generate_secret_key)
        echo -e "${YELLOW}[3/12] Secret Key : ${GREEN}$secret_key${NC} (press Enter for auto-generate)"
        read -p "Use this key? (Y/n): " use
        
        if [[ "$use" =~ ^[Nn]$ ]]; then
            echo -en "${YELLOW}[3/12] Secret Key : ${NC}"
            read -r secret_key
            if [ ${#secret_key} -lt 8 ]; then
                print_error "Too short (min 8 characters)"
                continue
            fi
        fi
        echo -e "[3/12] Secret Key : ${GREEN}$secret_key${NC}"
        
        # [4/12] KCP Mode
        echo -e "\n${CYAN}KCP Mode Selection${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        for mode_key in 0 1 2 3 4; do
            IFS=':' read -r name desc <<< "${KCP_MODES[$mode_key]}"
            echo " [${mode_key}] ${name} - ${desc}"
        done
        echo ""

        local mode_choice
        read -p "[4/12] Choose KCP mode [0-4] (default 1): " mode_choice
        mode_choice="${mode_choice:-1}"

        local mode_name
        local kcp_fragment=""

        case $mode_choice in
            0) mode_name="normal" ;;
            1) mode_name="fast" ;;
            2) mode_name="fast2" ;;
            3) mode_name="fast3" ;;
            4) 
                mode_name="manual"
                echo -e "\n${YELLOW}Manual KCP Advanced Parameters${NC}"
                echo -e "────────────────────────────────────────────────────────────────"
                kcp_fragment=$(get_manual_kcp_settings)
                ;;
            *) mode_name="fast" ;;
        esac
        echo -e "[4/12] KCP Mode : ${CYAN}$mode_name${NC}"
        
        # [5/12] Connections
        echo -en "${YELLOW}[5/12] Connections [1-32, 0=skip] (default $DEFAULT_CONNECTIONS): ${NC}"
        read -r conn_input
        local conn=""
        if [ -z "$conn_input" ]; then
            conn="$DEFAULT_CONNECTIONS"
            echo -e "[5/12] Connections : ${CYAN}$DEFAULT_CONNECTIONS (default)${NC}"
        elif [ "$conn_input" = "0" ]; then
            conn=""
            echo -e "[5/12] Connections : ${CYAN}- (skipped)${NC}"
        elif [[ "$conn_input" =~ ^[1-9][0-9]?$ ]] && [ "$conn_input" -ge 1 ] && [ "$conn_input" -le 32 ]; then
            conn="$conn_input"
            echo -e "[5/12] Connections : ${CYAN}$conn_input${NC}"
        else
            conn="$DEFAULT_CONNECTIONS"
            echo -e "${YELLOW}Invalid, using default $DEFAULT_CONNECTIONS${NC}"
            echo -e "[5/12] Connections : ${CYAN}$DEFAULT_CONNECTIONS (corrected)${NC}"
        fi
        
        # [6/12] MTU
        echo -en "${YELLOW}[6/12] MTU [100-9000, 0=skip] (default $DEFAULT_MTU): ${NC}"
        read -r mtu_input
        local mtu=""
        if [ -z "$mtu_input" ]; then
            mtu="$DEFAULT_MTU"
            echo -e "[6/12] MTU : ${CYAN}$DEFAULT_MTU (default)${NC}"
        elif [ "$mtu_input" = "0" ]; then
            mtu=""
            echo -e "[6/12] MTU : ${CYAN}- (skipped)${NC}"
        elif [[ "$mtu_input" =~ ^[0-9]+$ ]] && [ "$mtu_input" -ge 100 ] && [ "$mtu_input" -le 9000 ]; then
            mtu="$mtu_input"
            echo -e "[6/12] MTU : ${CYAN}$mtu_input${NC}"
        else
            mtu="$DEFAULT_MTU"
            echo -e "${YELLOW}Invalid, using default $DEFAULT_MTU${NC}"
            echo -e "[6/12] MTU : ${CYAN}$DEFAULT_MTU (corrected)${NC}"
        fi
        
        # [7/12] Encryption
        echo -e "\n${CYAN}Encryption Selection${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        for enc_key in 1 2 3 4 5 6 7; do
            IFS=':' read -r enc_name enc_desc <<< "${ENCRYPTION_OPTIONS[$enc_key]}"
            echo " [${enc_key}] ${enc_name} - ${enc_desc}"
        done
        echo ""
        
        local enc_choice
        read -p "[7/12] Choose encryption [1-7] (default 1): " enc_choice
        enc_choice="${enc_choice:-1}"
        
        local block
        IFS=':' read -r block _ <<< "${ENCRYPTION_OPTIONS[$enc_choice]}"
        block="${block:-aes-128-gcm}"
        echo -e "[7/12] Encryption : ${CYAN}$block${NC}"
        
        # [8/12] pcap sockbuf
        echo -en "${YELLOW}[8/12] pcap sockbuf [Enter=skip, 0=skip]: ${NC}"
        read -r pcap_input
        local pcap_sockbuf=""
        
        if [ -n "$pcap_input" ] && [ "$pcap_input" != "0" ]; then
            # فقط اگر عدد معتبر وارد کرد
            if [[ "$pcap_input" =~ ^[0-9]+$ ]]; then
                pcap_sockbuf="$pcap_input"
                echo -e "[8/12] pcap sockbuf : ${CYAN}$pcap_input${NC}"
            else
                print_warning "Invalid number, skipping pcap sockbuf"
                echo -e "[8/12] pcap sockbuf : ${CYAN}skipped${NC}"
            fi
        else
            echo -e "[8/12] pcap sockbuf : ${CYAN}skipped${NC}"
        fi
        
        # [9/12] transport tcpbuf
        echo -en "${YELLOW}[9/12] transport tcpbuf [Enter=skip, 0=skip]: ${NC}"
        read -r tcpbuf_input
        local transport_tcpbuf=""
        
        if [ -n "$tcpbuf_input" ] && [ "$tcpbuf_input" != "0" ]; then
            if [[ "$tcpbuf_input" =~ ^[0-9]+$ ]]; then
                transport_tcpbuf="$tcpbuf_input"
                echo -e "[9/12] transport tcpbuf : ${CYAN}$tcpbuf_input${NC}"
            else
                print_warning "Invalid number, skipping transport tcpbuf"
                echo -e "[9/12] transport tcpbuf : ${CYAN}skipped${NC}"
            fi
        else
            echo -e "[9/12] transport tcpbuf : ${CYAN}skipped${NC}"
        fi
        
        # [10/12] transport udpbuf
        echo -en "${YELLOW}[10/12] transport udpbuf [Enter=skip, 0=skip]: ${NC}"
        read -r udpbuf_input
        local transport_udpbuf=""
        
        if [ -n "$udpbuf_input" ] && [ "$udpbuf_input" != "0" ]; then
            if [[ "$udpbuf_input" =~ ^[0-9]+$ ]]; then
                transport_udpbuf="$udpbuf_input"
                echo -e "[10/12] transport udpbuf : ${CYAN}$udpbuf_input${NC}"
            else
                print_warning "Invalid number, skipping transport udpbuf"
                echo -e "[10/12] transport udpbuf : ${CYAN}skipped${NC}"
            fi
        else
            echo -e "[10/12] transport udpbuf : ${CYAN}skipped${NC}"
        fi
        
        # Apply configuration
        echo -e "\n${CYAN}Applying Configuration${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        
        if [ ! -f "$BIN_DIR/paqet" ]; then
            install_paqet || continue
        fi
        
        configure_iptables "$port" "tcp"
        mkdir -p "$CONFIG_DIR"

# Select log level (default from manager settings)
local log_level
log_level=$(ask_log_level "$PAQET_DEFAULT_LOG_LEVEL")
        
        # Build server config with proper indentation
        {
            echo "# Paqet Server Configuration"
            echo "role: \"server\""
            echo "log:"
            echo "  level: \"${log_level}\""
            echo "listen:"
            echo "  addr: \":$port\""
            echo "network:"
            echo "  interface: \"$NETWORK_INTERFACE\""
            echo "  ipv4:"
            echo "    addr: \"$LOCAL_IP:$port\""
            echo "    router_mac: \"$GATEWAY_MAC\""
            echo "  tcp:"
            echo "    local_flag: [\"PA\"]"
            
            if [[ -n "$pcap_sockbuf" ]]; then
                echo "  pcap:"
                echo "    sockbuf: $pcap_sockbuf"
            fi
            
            echo "transport:"
            echo "  protocol: \"kcp\""
            
            [[ -n "$conn" ]] && echo "  conn: $conn"
            [[ -n "$transport_tcpbuf" ]] && echo "  tcpbuf: $transport_tcpbuf"
            [[ -n "$transport_udpbuf" ]] && echo "  udpbuf: $transport_udpbuf"
            
            echo "  kcp:"
            echo "    key: \"$secret_key\""
            
            if [ "$mode_name" = "manual" ] && [ -n "$kcp_fragment" ]; then
                # For manual mode, add block and mtu separately
                echo "    mode: \"manual\""
                echo "    block: \"$block\""
                [[ -n "$mtu" ]] && echo "    mtu: $mtu"
                # Add remaining manual settings from kcp_fragment
                while IFS= read -r line; do
                    if [[ -n "$line" ]] && ! echo "$line" | grep -q "mode:"; then
                        echo "    $line"
                    fi
                done <<< "$kcp_fragment"
            else
                # For non-manual modes
                echo "    mode: \"$mode_name\""
                echo "    block: \"$block\""
                [[ -n "$mtu" ]] && echo "    mtu: $mtu"
            fi
        } > "$CONFIG_DIR/${config_name}.yaml"
        
        echo -e "[+] Configuration saved : ${CYAN}$CONFIG_DIR/${config_name}.yaml${NC}"
        
        create_systemd_service "$config_name"
        local svc="paqet-${config_name}"
        systemctl enable "$svc" --now >/dev/null 2>&1
        
        if systemctl is-active --quiet "$svc"; then
            print_success "Server started successfully"
            add_auto_restart_cronjob "$svc" "$DEFAULT_AUTO_RESTART_INTERVAL" >/dev/null 2>&1
            
            echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${GREEN}║ Server Ready                                                  ║${NC}"
            echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
            
            echo -e "${YELLOW}Server Information${NC}"
            echo -e "┌──────────────────────────────────────────────────────────────┐"
            printf "│ %-14s : %-44s │\n" "Public IP" "$public_ip"
            printf "│ %-14s : %-44s │\n" "Listen Port" "$port"
            printf "│ %-14s : %-44s │\n" "Connections" "${conn:-1}"
            printf "│ %-14s : %-44s │\n" "Auto Restart" "Every ${DEFAULT_AUTO_RESTART_INTERVAL}"
            echo -e "└──────────────────────────────────────────────────────────────┘\n"
            
            echo -e "${YELLOW}Secret Key (Client Configuration)${NC}"
            echo -e "┌──────────────────────────────────────────────────────────────┐"
            printf "│ %-60s │\n" "$secret_key"
            echo -e "└──────────────────────────────────────────────────────────────┘\n"
            
            echo -e "${YELLOW}KCP Configuration${NC}"
            echo -e "┌──────────────────────────────────────────────────────────────┐"
            printf "│ %-14s : %-44s │\n" "Mode" "$mode_name"
            printf "│ %-14s : %-44s │\n" "Encryption" "$block"
            printf "│ %-14s : %-44s │\n" "MTU" "${mtu:-1350}"
            echo -e "└──────────────────────────────────────────────────────────────┘\n"
            
            echo ""
            echo -e "${GREEN}✅ Server setup completed successfully!${NC}"
            echo -e "${CYAN}Options:${NC}"
            echo -e " 1. Press ${GREEN}Enter${NC} to go to service management for $config_name"
            echo -e " 2. Type ${YELLOW}menu${NC} to return to main menu"
            echo -e " 3. Type ${YELLOW}exit${NC} to exit"
            echo ""
            
            read -p "Your choice [Enter/menu/exit]: " post_choice
            
            case "${post_choice,,}" in
                ""|enter)
                    echo -e "${GREEN}➡️ Taking you to service management for $config_name...${NC}"
                    sleep 1
                    manage_single_service "$svc" "$config_name"
                    ;;
                menu)
                    echo -e "${CYAN}Returning to main menu...${NC}"
                    sleep 1
                    return 0
                    ;;
                exit)
                    echo -e "${GREEN}Goodbye!${NC}"
                    exit 0
                    ;;
                *)
                    echo -e "${YELLOW}Invalid choice. Returning to main menu...${NC}"
                    sleep 2
                    return 0
                    ;;
            esac
        else
            print_error "Service failed to start"
            systemctl status "$svc" --no-pager -l
            pause
        fi
        return 0
    done
}

# Configure as Client
configure_client() {
    while true; do
        clear
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║ Configure as Client (Iran/Domestic)                           ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
        
        get_network_info
        local public_ip
        public_ip=$(get_public_ip)
        
        echo -e "${YELLOW}Detected Network Information${NC}"
        echo -e "┌──────────────────────────────────────────────────────────────┐"
        printf "│ %-12s : %-44s │\n" "Interface" "${NETWORK_INTERFACE:-Not found}"
        printf "│ %-12s : %-44s │\n" "Local IP" "${LOCAL_IP:-Not found}"
        printf "│ %-12s : %-44s │\n" "Public IP" "$public_ip"
        printf "│ %-12s : %-44s │\n" "Gateway MAC" "${GATEWAY_MAC:-Not found}"
        echo -e "└──────────────────────────────────────────────────────────────┘\n"
        
        echo -e "${CYAN}Client Configuration${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        
        # [1/15] Service Name
        echo -en "${YELLOW}[1/15] Service Name (e.g: myclient) : ${NC}"
        read -r config_name
        config_name=$(clean_config_name "${config_name:-client}")
        echo -e "[1/15] Service Name : ${CYAN}$config_name${NC}"
        
        if [ -f "$CONFIG_DIR/${config_name}.yaml" ]; then
            print_warning "Config already exists!"
            read -p "Overwrite? (y/N): " ow
            [[ ! "$ow" =~ ^[Yy]$ ]] && continue
        fi
        
        # [2/15] Server IP
        echo -en "${YELLOW}[2/15] Server IP (kharej e.g: 45.76.123.89) : ${NC}"
        read -r server_ip
        [ -z "$server_ip" ] && { print_error "Server IP required"; continue; }
        validate_ip "$server_ip" || { print_error "Invalid IP format"; continue; }
        echo -e "[2/15] Server IP : ${CYAN}$server_ip${NC}"
        
        # [3/15] Server Port
        echo -en "${YELLOW}[3/15] Server Port (default: $DEFAULT_LISTEN_PORT) : ${NC}"
        read -r server_port
        server_port="${server_port:-$DEFAULT_LISTEN_PORT}"
        validate_port "$server_port" || { print_error "Invalid port"; continue; }
        echo -e "[3/15] Server Port : ${CYAN}$server_port${NC}"
        
        # [4/15] Secret Key
        echo -en "${YELLOW}[4/15] Secret Key (from server) : ${NC}"
        read -r secret_key
        [ -z "$secret_key" ] && { print_error "Secret key required"; continue; }
        echo -e "[4/15] Secret Key : ${GREEN}$secret_key${NC}"
        
        # [5/15] KCP Mode
        echo -e "\n${CYAN}KCP Mode Selection${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        for mode_key in 0 1 2 3 4; do
            IFS=':' read -r name desc <<< "${KCP_MODES[$mode_key]}"
            echo " [${mode_key}] ${name} - ${desc}"
        done
        echo ""

        local mode_choice
        read -p "[5/15] Choose KCP mode [0-4] (default 1): " mode_choice
        mode_choice="${mode_choice:-1}"

        local mode_name
        local kcp_fragment=""

        case $mode_choice in
            0) mode_name="normal" ;;
            1) mode_name="fast" ;;
            2) mode_name="fast2" ;;
            3) mode_name="fast3" ;;
            4) 
                mode_name="manual"
                echo -e "\n${YELLOW}Manual KCP Advanced Parameters${NC}"
                echo -e "────────────────────────────────────────────────────────────────"
                kcp_fragment=$(get_manual_kcp_settings)
                ;;
            *) mode_name="fast" ;;
        esac
        echo -e "[5/15] KCP Mode : ${CYAN}$mode_name${NC}"
        
        # [6/15] Connections
        echo -en "${YELLOW}[6/15] Connections [1-32, 0=skip] (default $DEFAULT_CONNECTIONS): ${NC}"
        read -r conn_input
        local conn=""
        if [ -z "$conn_input" ]; then
            conn="$DEFAULT_CONNECTIONS"
            echo -e "[6/15] Connections : ${CYAN}$DEFAULT_CONNECTIONS (default)${NC}"
        elif [ "$conn_input" = "0" ]; then
            conn=""
            echo -e "[6/15] Connections : ${CYAN}- (skipped)${NC}"
        elif [[ "$conn_input" =~ ^[1-9][0-9]?$ ]] && [ "$conn_input" -ge 1 ] && [ "$conn_input" -le 32 ]; then
            conn="$conn_input"
            echo -e "[6/15] Connections : ${CYAN}$conn_input${NC}"
        else
            conn="$DEFAULT_CONNECTIONS"
            echo -e "${YELLOW}Invalid, using default $DEFAULT_CONNECTIONS${NC}"
            echo -e "[6/15] Connections : ${CYAN}$DEFAULT_CONNECTIONS (corrected)${NC}"
        fi
        
        # [7/15] MTU
        echo -en "${YELLOW}[7/15] MTU [100-9000, 0=skip] (default $DEFAULT_MTU): ${NC}"
        read -r mtu_input
        local mtu=""
        if [ -z "$mtu_input" ]; then
            mtu="$DEFAULT_MTU"
            echo -e "[7/15] MTU : ${CYAN}$DEFAULT_MTU (default)${NC}"
        elif [ "$mtu_input" = "0" ]; then
            mtu=""
            echo -e "[7/15] MTU : ${CYAN}- (skipped)${NC}"
        elif [[ "$mtu_input" =~ ^[0-9]+$ ]] && [ "$mtu_input" -ge 100 ] && [ "$mtu_input" -le 9000 ]; then
            mtu="$mtu_input"
            echo -e "[7/15] MTU : ${CYAN}$mtu_input${NC}"
        else
            mtu="$DEFAULT_MTU"
            echo -e "${YELLOW}Invalid, using default $DEFAULT_MTU${NC}"
            echo -e "[7/15] MTU : ${CYAN}$DEFAULT_MTU (corrected)${NC}"
        fi
        
        # [8/15] Encryption
        echo -e "\n${CYAN}Encryption Selection${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        for enc_key in 1 2 3 4 5 6 7; do
            IFS=':' read -r enc_name enc_desc <<< "${ENCRYPTION_OPTIONS[$enc_key]}"
            echo " [${enc_key}] ${enc_name} - ${enc_desc}"
        done
        echo ""
        
        local enc_choice
        read -p "[8/15] Choose encryption [1-7] (default 1): " enc_choice
        enc_choice="${enc_choice:-1}"
        
        local block
        IFS=':' read -r block _ <<< "${ENCRYPTION_OPTIONS[$enc_choice]}"
        block="${block:-aes-128-gcm}"
        echo -e "[8/15] Encryption : ${CYAN}$block${NC}"
        
         # [9/15] pcap sockbuf
        echo -en "${YELLOW}[9/15] pcap sockbuf [Enter=skip, 0=skip]: ${NC}"
        read -r pcap_input
        local pcap_sockbuf=""
        
        if [ -n "$pcap_input" ] && [ "$pcap_input" != "0" ]; then
            if [[ "$pcap_input" =~ ^[0-9]+$ ]]; then
                pcap_sockbuf="$pcap_input"
                echo -e "[9/15] pcap sockbuf : ${CYAN}$pcap_input${NC}"
            else
                print_warning "Invalid number, skipping pcap sockbuf"
                echo -e "[9/15] pcap sockbuf : ${CYAN}skipped${NC}"
            fi
        else
            echo -e "[9/15] pcap sockbuf : ${CYAN}skipped${NC}"
        fi
        
        # [10/15] transport tcpbuf
        echo -en "${YELLOW}[10/15] transport tcpbuf [Enter=skip, 0=skip]: ${NC}"
        read -r tcpbuf_input
        local transport_tcpbuf=""
        
        if [ -n "$tcpbuf_input" ] && [ "$tcpbuf_input" != "0" ]; then
            if [[ "$tcpbuf_input" =~ ^[0-9]+$ ]]; then
                transport_tcpbuf="$tcpbuf_input"
                echo -e "[10/15] transport tcpbuf : ${CYAN}$tcpbuf_input${NC}"
            else
                print_warning "Invalid number, skipping transport tcpbuf"
                echo -e "[10/15] transport tcpbuf : ${CYAN}skipped${NC}"
            fi
        else
            echo -e "[10/15] transport tcpbuf : ${CYAN}skipped${NC}"
        fi
        
        # [11/15] transport udpbuf
        echo -en "${YELLOW}[11/15] transport udpbuf [Enter=skip, 0=skip]: ${NC}"
        read -r udpbuf_input
        local transport_udpbuf=""
        
        if [ -n "$udpbuf_input" ] && [ "$udpbuf_input" != "0" ]; then
            if [[ "$udpbuf_input" =~ ^[0-9]+$ ]]; then
                transport_udpbuf="$udpbuf_input"
                echo -e "[11/15] transport udpbuf : ${CYAN}$udpbuf_input${NC}"
            else
                print_warning "Invalid number, skipping transport udpbuf"
                echo -e "[11/15] transport udpbuf : ${CYAN}skipped${NC}"
            fi
        else
            echo -e "[11/15] transport udpbuf : ${CYAN}skipped${NC}"
        fi
        
        # [12/15] Traffic Type
        echo -e "\n${CYAN}Traffic Type Selection${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        echo -e " ${GREEN}[1]${NC} Port Forwarding - Forward specific ports"
        echo -e " ${GREEN}[2]${NC} SOCKS5 Proxy - Create a SOCKS5 proxy"
        echo ""
        
        local traffic_type
        read -p "[12/15] Choose traffic type [1-2] (default 1): " traffic_type
        traffic_type="${traffic_type:-1}"
        
        local forward_entries=()
        local socks5_entries=()
        local display_ports=""
        local SOCKS5_PORT=""
        local SOCKS5_USER=""
        local SOCKS5_PASS=""
        
        case $traffic_type in
            1)
                echo -e "\n${CYAN}Port Forwarding Configuration${NC}"
                echo -e "────────────────────────────────────────────────────────────────"
                
                echo -en "${YELLOW}[13/15] Forward Ports (comma separated) [default $DEFAULT_V2RAY_PORTS]: ${NC}"
                read -r forward_ports
                forward_ports=$(clean_port_list "${forward_ports:-$DEFAULT_V2RAY_PORTS}")
                [ -z "$forward_ports" ] && { print_error "No valid ports"; continue; }
                echo -e "[13/15] Forward Ports : ${CYAN}$forward_ports${NC}"
                
                echo -e "\n${CYAN}Protocol Selection${NC}"
                echo -e "────────────────────────────────────────────────────────────────"
                echo " [1] tcp - TCP only (default)"
                echo " [2] udp - UDP only"
                echo " [3] tcp/udp - Both"
                echo ""
                
                IFS=',' read -ra PORTS <<< "$forward_ports"
                for p in "${PORTS[@]}"; do
                    p=$(echo "$p" | tr -d '[:space:]')
                    echo -en "${YELLOW}Port $p → protocol [1-3] : ${NC}"
                    read -r proto_choice
                    proto_choice="${proto_choice:-1}"
                    
                    case $proto_choice in
                        1)
                            forward_entries+=("  - listen: \"0.0.0.0:$p\"\n    target: \"127.0.0.1:$p\"\n    protocol: \"tcp\"")
                            display_ports+=" $p (TCP)"
                            configure_iptables "$p" "tcp"
                            ;;
                        2)
                            forward_entries+=("  - listen: \"0.0.0.0:$p\"\n    target: \"127.0.0.1:$p\"\n    protocol: \"udp\"")
                            display_ports+=" $p (UDP)"
                            configure_iptables "$p" "udp"
                            ;;
                        3)
                            forward_entries+=("  - listen: \"0.0.0.0:$p\"\n    target: \"127.0.0.1:$p\"\n    protocol: \"tcp\"")
                            forward_entries+=("  - listen: \"0.0.0.0:$p\"\n    target: \"127.0.0.1:$p\"\n    protocol: \"udp\"")
                            display_ports+=" $p (TCP+UDP)"
                            configure_iptables "$p" "both"
                            ;;
                        *)
                            forward_entries+=("  - listen: \"0.0.0.0:$p\"\n    target: \"127.0.0.1:$p\"\n    protocol: \"tcp\"")
                            display_ports+=" $p (TCP)"
                            configure_iptables "$p" "tcp"
                            ;;
                    esac
                done
                echo -e "[13/15] Protocol(s) : ${CYAN}${display_ports# }${NC}"
                ;;
                
            2)
                echo -e "\n${CYAN}SOCKS5 Proxy Configuration${NC}"
                echo -e "────────────────────────────────────────────────────────────────"
                
                echo -en "${YELLOW}[13/15] SOCKS5 Proxy Port (default $DEFAULT_SOCKS5_PORT): ${NC}"
                read -r socks_port
                socks_port="${socks_port:-$DEFAULT_SOCKS5_PORT}"
                validate_port "$socks_port" || { print_error "Invalid port"; continue; }
                echo -e "[13/15] SOCKS5 Port : ${CYAN}$socks_port${NC}"
                
                check_port_conflict "$socks_port" || { pause "Press Enter to retry..."; continue; }
                configure_iptables "$socks_port" "tcp"
                
                echo -e "\n${CYAN}SOCKS5 Authentication (Optional)${NC}"
                echo -e "────────────────────────────────────────────────────────────────"
                echo -e "${YELLOW}Leave empty for no authentication${NC}"
                
                echo -en "${YELLOW}SOCKS5 Username: ${NC}"
                read -r socks_user
                
                if [ -n "$socks_user" ]; then
                    echo -en "${YELLOW}SOCKS5 Password: ${NC}"
                    read -r socks_pass
                    
                    if [ -z "$socks_pass" ]; then
                        print_error "Password required if username is set"
                        continue
                    fi
                    
                    echo -e "Authentication: ${GREEN}Enabled${NC}"
                    SOCKS5_USER="$socks_user"
                    SOCKS5_PASS="$socks_pass"
                    socks5_entries+=("  - listen: \"127.0.0.1:$socks_port\"\n    username: \"$socks_user\"\n    password: \"$socks_pass\"")
                else
                    echo -e "Authentication: ${YELLOW}Disabled${NC}"
                    socks5_entries+=("  - listen: \"127.0.0.1:$socks_port\"")
                fi
                
                SOCKS5_PORT="$socks_port"
                ;;
                
            *)
                print_error "Invalid choice"
                continue
                ;;
        esac

        if [[ "$traffic_type" == "1" ]]; then
            if ! validate_forward_rules; then
                echo -e "\n${RED}⚠️  TRAFFIC LOOP DETECTED!${NC}"
                echo -e "  • Server endpoint: $server_ip:$server_port"
                echo -e "  • Forward ports: $forward_ports"
                echo -e "${YELLOW}Make sure none of the forward ports match the server port.${NC}"
                echo -e "${YELLOW}Forward ports should point to your actual services (V2Ray, web servers, etc.), not the Paqet tunnel.${NC}"
                pause
                continue
            fi
        fi

        # Apply configuration
        echo -e "\n${CYAN}Applying Configuration${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        
        if [ ! -f "$BIN_DIR/paqet" ]; then
            install_paqet || continue
        fi
        
        mkdir -p "$CONFIG_DIR"

# Select log level (default from manager settings)
local log_level
log_level=$(ask_log_level "$PAQET_DEFAULT_LOG_LEVEL")
        
        # Build client config with proper indentation
        {
            echo "# Paqet Client Configuration"
            echo "role: \"client\""
            echo "log:"
            echo "  level: \"${log_level}\""
            
            if [ ${#forward_entries[@]} -gt 0 ]; then
                echo "forward:"
                for entry in "${forward_entries[@]}"; do
                    echo -e "$entry"
                done
            fi
            
            if [ ${#socks5_entries[@]} -gt 0 ]; then
                echo "socks5:"
                for entry in "${socks5_entries[@]}"; do
                    echo -e "$entry"
                done
            fi
            
            echo "network:"
            echo "  interface: \"$NETWORK_INTERFACE\""
            echo "  ipv4:"
            echo "    addr: \"$LOCAL_IP:0\""
            echo "    router_mac: \"$GATEWAY_MAC\""
            echo "  tcp:"
            echo "    local_flag: [\"PA\"]"
            echo "    remote_flag: [\"PA\"]"
            
            if [[ -n "$pcap_sockbuf" ]]; then
                echo "  pcap:"
                echo "    sockbuf: $pcap_sockbuf"
            fi
            
            echo "server:"
            echo "  addr: \"$server_ip:$server_port\""
            echo "transport:"
            echo "  protocol: \"kcp\""
            
            [[ -n "$conn" ]] && echo "  conn: $conn"
            [[ -n "$transport_tcpbuf" ]] && echo "  tcpbuf: $transport_tcpbuf"
            [[ -n "$transport_udpbuf" ]] && echo "  udpbuf: $transport_udpbuf"
            
            echo "  kcp:"
            echo "    key: \"$secret_key\""
            
            if [ "$mode_name" = "manual" ] && [ -n "$kcp_fragment" ]; then
                echo "    mode: \"manual\""
                echo "    block: \"$block\""
                [[ -n "$mtu" ]] && echo "    mtu: $mtu"
                while IFS= read -r line; do
                    if [[ -n "$line" ]] && ! echo "$line" | grep -q "mode:"; then
                        echo "    $line"
                    fi
                done <<< "$kcp_fragment"
            else
                echo "    mode: \"$mode_name\""
                echo "    block: \"$block\""
                [[ -n "$mtu" ]] && echo "    mtu: $mtu"
            fi
        } > "$CONFIG_DIR/${config_name}.yaml"
        
        echo -e "[+] Configuration saved : ${CYAN}$CONFIG_DIR/${config_name}.yaml${NC}"
        
        create_systemd_service "$config_name"
        local svc="paqet-${config_name}"
        systemctl enable "$svc" --now >/dev/null 2>&1
        
        if systemctl is-active --quiet "$svc"; then
            print_success "Client started successfully"
            add_auto_restart_cronjob "$svc" "$DEFAULT_AUTO_RESTART_INTERVAL" >/dev/null 2>&1
            
            echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${GREEN}║ Client Ready                                                   ║${NC}"
            echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
            
            echo -e "${YELLOW}Client Information${NC}"
            echo -e "┌──────────────────────────────────────────────────────────────┐"
            printf "│ %-16s : %-42s │\n" "This Server" "$public_ip"
            printf "│ %-16s : %-42s │\n" "Remote Server" "$server_ip:$server_port"
            
            if [ "$traffic_type" = "1" ] && [ ${#forward_entries[@]} -gt 0 ]; then
                printf "│ %-16s : %-42s │\n" "Forward Ports" "${display_ports# }"
            elif [ "$traffic_type" = "2" ] && [ ${#socks5_entries[@]} -gt 0 ]; then
                printf "│ %-16s : %-42s │\n" "SOCKS5 Port" "$SOCKS5_PORT"
                if [ -n "$SOCKS5_USER" ]; then
                    printf "│ %-16s : %-42s │\n" "SOCKS5 User" "$SOCKS5_USER"
                    printf "│ %-16s : %-42s │\n" "SOCKS5 Pass" "********"
                else
                    printf "│ %-16s : %-42s │\n" "Authentication" "None"
                fi
            fi
            
            printf "│ %-16s : %-42s │\n" "Connections" "${conn:-1}"
            printf "│ %-16s : %-42s │\n" "Auto Restart" "Every ${DEFAULT_AUTO_RESTART_INTERVAL}"
            echo -e "└──────────────────────────────────────────────────────────────┘\n"
            
            echo -e "${YELLOW}KCP Configuration${NC}"
            echo -e "┌──────────────────────────────────────────────────────────────┐"
            printf "│ %-14s : %-44s │\n" "Mode" "$mode_name"
            printf "│ %-14s : %-44s │\n" "Encryption" "$block"
            printf "│ %-14s : %-44s │\n" "MTU" "${mtu:-1350}"
            echo -e "└──────────────────────────────────────────────────────────────┘\n"
            
            echo ""
            echo -e "${GREEN}✅ Client setup completed successfully!${NC}"
            echo -e "${CYAN}Options:${NC}"
            echo -e " 1. Press ${GREEN}Enter${NC} to go to service management for $config_name"
            echo -e " 2. Type ${YELLOW}menu${NC} to return to main menu"
            echo -e " 3. Type ${YELLOW}exit${NC} to exit"
            echo ""
            
            read -p "Your choice [Enter/menu/exit]: " post_choice
            
            case "${post_choice,,}" in
                ""|enter)
                    echo -e "${GREEN}➡️ Taking you to service management for $config_name...${NC}"
                    sleep 1
                    manage_single_service "$svc" "$config_name"
                    ;;
                menu)
                    echo -e "${CYAN}Returning to main menu...${NC}"
                    sleep 1
                    return 0
                    ;;
                exit)
                    echo -e "${GREEN}Goodbye!${NC}"
                    exit 0
                    ;;
                *)
                    echo -e "${YELLOW}Invalid choice. Returning to main menu...${NC}"
                    sleep 2
                    return 0
                    ;;
            esac
        else
            print_error "Client failed to start"
            systemctl status "$svc" --no-pager -l
            pause
        fi
        return 0
    done
}

# ================================================
# TEST FUNCTIONS
# ================================================

# Test internet connectivity
test_internet_connectivity() {
    echo -e "\n${YELLOW}Internet Connectivity Test${NC}"
    echo -e "────────────────────────────────────────────────────────────────"
    
    print_step "Testing internet connectivity...\n"
    
    local test_hosts=("8.8.8.8" "1.1.1.1" "208.67.222.222")
    local success_count=0
    local total_tests=${#test_hosts[@]}
    
    for host in "${test_hosts[@]}"; do
        echo -n " Testing connection to $host: "
        if ping -c 2 -W 1 "$host" &>/dev/null; then
            echo -e "${GREEN}✓ CONNECTED${NC}"
            ((success_count++))
        else
            echo -e "${RED}✗ FAILED${NC}"
        fi
    done
    
    echo -e "\n${CYAN}Test Results:${NC}"
    if [ "$success_count" -eq "$total_tests" ]; then
        print_success "✅ Internet connectivity: EXCELLENT (${success_count}/${total_tests})"
    elif [ "$success_count" -ge $((total_tests / 2)) ]; then
        print_warning "⚠️ Internet connectivity: PARTIAL (${success_count}/${total_tests})"
    else
        print_error "❌ Internet connectivity: POOR (${success_count}/${total_tests})"
    fi
    
    if [ "$success_count" -gt 0 ]; then
        echo -e "\n${YELLOW}Speed Test${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        local speed_test
        speed_test=$(timeout 10 curl -o /dev/null -w "%{speed_download}" --max-filesize 10485760 https://speedtest.ftp.otenet.gr/files/test10Mb.db 2>/dev/null || echo "0")
        
        if [ "$speed_test" != "0" ] && [ -n "$speed_test" ]; then
            if command -v bc &>/dev/null; then
                local speed_mbps
                speed_mbps=$(echo "scale=2; $speed_test * 8 / 10fariid0" | bc 2>/dev/null || echo "0")
                
                if (( $(echo "$speed_mbps > 10" | bc -l 2>/dev/null) )); then
                    echo -e " ${GREEN}✅ Download speed: ${speed_mbps} Mbps${NC}"
                elif (( $(echo "$speed_mbps > 1" | bc -l 2>/dev/null) )); then
                    echo -e " ${YELLOW}⚠️ Download speed: ${speed_mbps} Mbps${NC}"
                else
                    echo -e " ${RED}❌ Download speed: ${speed_mbps} Mbps${NC}"
                fi
            else
                local speed_mbps_int=$(( (${speed_test%.*} * 8) / 10fariid0 ))
                if [ "$speed_mbps_int" -gt 10 ]; then
                    echo -e " ${GREEN}✅ Download speed: ~${speed_mbps_int} Mbps${NC}"
                elif [ "$speed_mbps_int" -gt 1 ]; then
                    echo -e " ${YELLOW}⚠️ Download speed: ~${speed_mbps_int} Mbps${NC}"
                else
                    echo -e " ${RED}❌ Download speed: ~${speed_mbps_int} Mbps${NC}"
                fi
            fi
        else
            echo -e " ${YELLOW}⚠️ Speed test failed or timed out${NC}"
        fi
    fi
}

# Test DNS resolution
test_dns_resolution() {
    echo -e "\n${YELLOW}DNS Resolution Test${NC}"
    echo -e "────────────────────────────────────────────────────────────────"
    
    print_step "Testing DNS resolution...\n"
    
    echo -e "${CYAN}Testing domain resolution:${NC}\n"
    
    local resolved_count=0
    local total_domains=${#TEST_DOMAINS[@]}
    
    for domain in "${TEST_DOMAINS[@]}"; do
        echo -n " $domain: "
        if timeout 3 dig +short "$domain" &>/dev/null; then
            echo -e "${GREEN}✓ RESOLVED${NC}"
            ((resolved_count++))
        else
            echo -e "${RED}✗ FAILED${NC}"
        fi
    done
    
    echo -e "\n${CYAN}Testing DNS servers:${NC}\n"
    
    for dns in "${DNS_SERVERS[@]}"; do
        echo -n " $dns: "
        if [ "$dns" = "system" ]; then
            if timeout 3 nslookup google.com &>/dev/null; then
                echo -e "${GREEN}✓ WORKING${NC}"
            else
                echo -e "${RED}✗ FAILED${NC}"
            fi
        else
            if timeout 3 dig +short google.com @"$dns" &>/dev/null; then
                echo -e "${GREEN}✓ WORKING${NC}"
            else
                echo -e "${RED}✗ FAILED${NC}"
            fi
        fi
    done
    
    echo -e "\n${CYAN}Summary:${NC}"
    if [ "$resolved_count" -eq "$total_domains" ]; then
        print_success "✅ DNS resolution: PERFECT (${resolved_count}/${total_domains})"
    elif [ "$resolved_count" -ge $((total_domains / 2)) ]; then
        print_warning "⚠️ DNS resolution: PARTIAL (${resolved_count}/${total_domains})"
    else
        print_error "❌ DNS resolution: POOR (${resolved_count}/${total_domains})"
    fi
}

# Extract ping stats
extract_ping_stats() {
    local ping_output="$1"
    local rtt_line
    rtt_line=$(echo "$ping_output" | grep "rtt min/avg/max/mdev")
    
    if [ -n "$rtt_line" ]; then
        local stats
        stats=$(echo "$rtt_line" | sed 's/.*= //' | sed 's/ ms//')
        echo "$stats" | tr '/' ' '
    else
        echo "0 0 0 0"
    fi
}

# Test Paqet tunnel
test_paqet_tunnel() {
    clear
    echo -e "\n${YELLOW}Test Paqet Tunnel Connection${NC}"
    echo -e "────────────────────────────────────────────────────────────────"
    
    echo -e "${CYAN}This test will check if you can establish a Paqet tunnel between two servers.${NC}\n"
    
    echo -en "${YELLOW}Remote Server IP Address: ${NC}"
    read -r remote_ip
    
    [ -z "$remote_ip" ] && { print_error "IP address required"; return; }
    validate_ip "$remote_ip" || { print_error "Invalid IP address format"; return; }
    
    echo -e "\n${YELLOW}Starting comprehensive Paqet tunnel test to $remote_ip...${NC}\n"
    
    # 1. Basic connectivity
    print_step "1. Testing basic ICMP connectivity..."
    
    local ping_output
    ping_output=$(ping -c 5 -W 2 "$remote_ip" 2>&1)
    local avg_ping=""
    local packet_loss="100"
    
    if [ $? -eq 0 ] || echo "$ping_output" | grep -q "transmitted"; then
        packet_loss=$(echo "$ping_output" | grep -o "[0-9]*% packet loss" | grep -o "[0-9]*" || echo "0")
        
        if echo "$ping_output" | grep -q "rtt min/avg/max/mdev"; then
            avg_ping=$(echo "$ping_output" | grep "rtt min/avg/max/mdev" | awk -F'/' '{print $5}')
        fi
        
        print_success "✅ Basic ICMP connectivity: SUCCESS"
        echo -e " ${CYAN}Details:${NC} Avg RTT: ${avg_ping:-N/A} ms, Packet loss: ${packet_loss}%"
    else
        print_warning "⚠️ Basic ICMP: FAILED (may be blocked)"
    fi
    
    # 2. Test common ports
    echo -e "\n${YELLOW}2. Testing common ports...${NC}"
    local paqet_ports_found=0
    
    for port in "${COMMON_PORTS[@]}"; do
        echo -n " Port $port: "
        if timeout 3 bash -c "</dev/tcp/$remote_ip/$port" 2>/dev/null; then
            echo -e "${GREEN}OPEN${NC}"
            ((paqet_ports_found++))
        else
            echo -e "${CYAN}Closed/Filtered${NC}"
        fi
        sleep 0.1
    done
    
    if [ $paqet_ports_found -eq 0 ]; then
        print_warning "⚠️ No common ports found open"
    else
        print_success "✅ Found $paqet_ports_found open port(s)"
    fi
    
    # 3. MTU testing
    echo -e "\n${YELLOW}3. MTU and packet loss analysis...${NC}"
    echo -e "${CYAN}Testing different MTU sizes (10 packets each):${NC}\n"
    
    local best_mtu=""
    local best_loss=100
    local best_ping=9999
    
    for mtu in "${MTU_TESTS[@]}"; do
        local payload_size=$((mtu - 28))
        [ $payload_size -lt 0 ] && continue
        
        echo -n " MTU $mtu: "
        local ping_output
        ping_output=$(ping -c 10 -W 1 -M do -s "$payload_size" "$remote_ip" 2>&1)
        
        if echo "$ping_output" | grep -q "transmitted"; then
            local sent received loss_percent
            sent=$(echo "$ping_output" | grep transmitted | awk '{print $1}')
            received=$(echo "$ping_output" | grep transmitted | awk '{print $4}')
            loss_percent=$(( (sent - received) * 100 / sent ))
            
            local stats
            stats=$(extract_ping_stats "$ping_output")
            local min_avg_max_mdev
            read -r min_avg_max_mdev <<< "$stats"
            
            if [ "$received" -eq "$sent" ]; then
                echo -e "${GREEN}PERFECT${NC} - 0% loss"
                if [ -z "$best_mtu" ] || [ "$loss_percent" -lt "$best_loss" ] || 
                   { [ "$loss_percent" -eq "$best_loss" ] && [ "$avg_ping" -lt "$best_ping" ]; }; then
                    best_mtu="$mtu"
                    best_loss="$loss_percent"
                    best_ping="$avg_ping"
                fi
            elif [ "$loss_percent" -le 10 ]; then
                echo -e "${GREEN}GOOD${NC} - ${loss_percent}% loss"
                if [ "$loss_percent" -lt "$best_loss" ]; then
                    best_mtu="$mtu"
                    best_loss="$loss_percent"
                    best_ping="$avg_ping"
                fi
            elif [ "$loss_percent" -le 30 ]; then
                echo -e "${YELLOW}FAIR${NC} - ${loss_percent}% loss"
            else
                echo -e "${RED}POOR${NC} - ${loss_percent}% loss"
            fi
        else
            echo -e "${RED}FAILED${NC}"
        fi
    done
    
    # 4. Summary
    echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║ Test Summary & Recommendations                                 ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${CYAN}Connection Quality:${NC}"
    if [ -n "$avg_ping" ]; then
        if compare_floats "$avg_ping" "50" "lt"; then
            echo -e " ${GREEN}✅ Latency: EXCELLENT (< 50ms)${NC}"
        elif compare_floats "$avg_ping" "150" "lt"; then
            echo -e " ${GREEN}✅ Latency: GOOD (< 150ms)${NC}"
        elif compare_floats "$avg_ping" "300" "lt"; then
            echo -e " ${YELLOW}⚠️ Latency: FAIR (< 300ms)${NC}"
        else
            echo -e " ${YELLOW}⚠️ Latency: HIGH (> 300ms)${NC}"
        fi
    fi
    
    if [ -n "$packet_loss" ]; then
        if [ "$packet_loss" -eq 0 ]; then
            echo -e " ${GREEN}✅ Packet Loss: EXCELLENT (0%)${NC}"
        elif [ "$packet_loss" -le 5 ]; then
            echo -e " ${GREEN}✅ Packet Loss: GOOD (≤ 5%)${NC}"
        elif [ "$packet_loss" -le 15 ]; then
            echo -e " ${YELLOW}⚠️ Packet Loss: FAIR (≤ 15%)${NC}"
        else
            echo -e " ${RED}❌ Packet Loss: HIGH (> 15%)${NC}"
        fi
    fi
    
    echo -e "\n${CYAN}MTU Recommendations:${NC}"
    if [ -n "$best_mtu" ]; then
        if [ "$best_loss" -eq 0 ]; then
            echo -e " ${GREEN}✅ Best MTU: $best_mtu (0% loss)${NC}"
        else
            echo -e " ${YELLOW}⚠️ Best MTU: $best_mtu (${best_loss}% loss)${NC}"
        fi
        
        if [ "$best_mtu" -ge 1400 ]; then
            echo -e " ${GREEN}• Primary: 1400 (optimal)${NC}"
            echo -e " ${GREEN}• Secondary: 1350 (balanced)${NC}"
            echo -e " ${CYAN}• Fallback: 1300 (stable)${NC}"
        elif [ "$best_mtu" -ge 1300 ]; then
            echo -e " ${GREEN}• Primary: 1350 (balanced)${NC}"
            echo -e " ${GREEN}• Secondary: 1300 (stable)${NC}"
            echo -e " ${CYAN}• Fallback: 1200 (reliable)${NC}"
        else
            echo -e " ${YELLOW}• Primary: 1200 (reliable)${NC}"
            echo -e " ${YELLOW}• Secondary: 1100 (ultra stable)${NC}"
            echo -e " ${CYAN}• Fallback: 1000 (guaranteed)${NC}"
        fi
    else
        echo -e " ${RED}❌ Could not determine optimal MTU${NC}"
        echo -e " ${CYAN}Recommendation: Use MTU 1200 as default${NC}"
    fi
}

# Test connection menu
test_connection() {
    clear
    show_banner
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║ Test Paqet Connection                                         ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${CYAN}Connection Test Options:${NC}"
    echo -e "────────────────────────────────────────────────────────────────"
    echo " 1. Test Paqet tunnel connection (server to server)"
    echo " 2. Test internet connectivity"
    echo " 3. Test DNS resolution"
    echo " 0. Back to Main Menu"
    echo ""
    
    while true; do
        read -p "Choose option [0-3]: " test_choice
        
        case $test_choice in
            1)
                test_paqet_tunnel
                pause
                return
                ;;
            2)
                test_internet_connectivity
                pause
                return
                ;;
            3)
                test_dns_resolution
                pause
                return
                ;;
            0)
                return
                ;;
            *)
                print_error "Invalid choice. Please enter 0-3."
                ;;
        esac
    done
}

# ================================================
# INSTALLATION FUNCTIONS
# ================================================

# Check dependencies
check_dependencies() {
    local missing_deps=()
    local os
    os=$(detect_os)
    
    local common_deps=("curl" "wget" "iptables" "lsof" "jq")
    
    case $os in
        ubuntu|debian)
            common_deps+=("libpcap-dev" "iproute2" "cron" "dig")
            ;;
        centos|rhel|fedora|rocky|almalinux)
            common_deps+=("libpcap-devel" "iproute" "cronie" "bind-utils")
            ;;
    esac
    
    for dep in "${common_deps[@]}"; do
        if ! command -v "$dep" &>/dev/null && 
           ! dpkg -l | grep -q "$dep" 2>/dev/null && 
           ! rpm -q "$dep" &>/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -eq 0 ]; then
        return 0
    else
        echo "${missing_deps[@]}"
        return 1
    fi
}

# Install dependencies
install_dependencies() {
    clear
    show_banner
    print_step "Installing dependencies..."
    
    local os
    os=$(detect_os)
    
    case $os in
        ubuntu|debian)
            print_info "Updating package lists..."
            apt update -qq >/dev/null 2>&1 || true
            
            print_info "Installing base packages..."
            apt install -y curl wget jq libpcap-dev iptables lsof iproute2 cron dnsutils >/dev/null 2>&1 || {
                print_warning "Some base packages may have failed to install"
            }
            
            # Install iptables persistence
            install_iptables_persistent
            ;;
            
        centos|rhel|fedora|rocky|almalinux)
            print_info "Installing base packages..."
            yum install -y curl wget jq libpcap-devel iptables lsof iproute cronie bind-utils >/dev/null 2>&1 || {
                print_warning "Some base packages may have failed to install"
            }
            
            # Install iptables persistence
            install_iptables_persistent
            ;;
            
        *)
            print_warning "Unknown OS. Please install manually: libpcap iptables curl cron dnsutils"
            print_warning "Also ensure iptables rules persist after reboot on your system"
            ;;
    esac
    
    print_success "Dependency installation completed"
    pause
    return
}

# ================================================
# IPTABLES PERSISTENCE FUNCTIONS
# ================================================

install_iptables_persistent() {
    print_step "Installing iptables persistence..."
    local os=$(detect_os)
    case $os in
        ubuntu|debian)
            if dpkg -l | grep -q "iptables-persistent"; then
                print_success "iptables-persistent is already installed"
            else
                print_info "Installing iptables-persistent (non-interactive)..."
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq >/dev/null 2>&1
                apt-get install -y iptables-persistent >/dev/null 2>&1
                
                if [ $? -eq 0 ]; then
                    print_success "iptables-persistent installed successfully"
                    save_iptables
                else
                    print_warning "Failed to install iptables-persistent"
                    print_info "iptables rules will NOT persist after reboot unless you install it manually"
                fi
            fi
            ;;
            
        centos|rhel|fedora|rocky|almalinux)
            local pkg="iptables-services"
            if ! rpm -q "$pkg" >/dev/null 2>&1; then
                print_info "Installing $pkg..."
                if command -v yum >/dev/null 2>&1; then
                    yum install -y "$pkg" >/dev/null 2>&1
                elif command -v dnf >/dev/null 2>&1; then
                    dnf install -y "$pkg" >/dev/null 2>&1
                fi
                
                if [ $? -eq 0 ]; then
                    print_success "$pkg installed"
                    systemctl enable iptables >/dev/null 2>&1
                    save_iptables
                else
                    print_warning "Failed to install $pkg"
                fi
            else
                print_success "$pkg is already installed"
            fi
            ;;
            
        *)
            print_warning "Unknown OS - iptables persistence may require manual setup"
            print_info "Please install iptables-persistent (Debian/Ubuntu) or iptables-services (RHEL-based)"
            ;;
    esac
    
    # Final save attempt in all cases
    save_iptables
}

# Install Paqet binary
install_paqet() {
    clear
    show_banner
    print_step "Paqet Core Installation\n"
    
    local os
    os=$(detect_os)
    local arch
    arch=$(detect_arch) || return 1
    
    # Get current version if installed
    local current_version="Not installed"
    if [ -f "$BIN_DIR/paqet" ]; then
        current_version=$("$BIN_DIR/paqet" version 2>/dev/null | grep "^Version:" | head -1 | cut -d':' -f2 | xargs)
        [ -z "$current_version" ] && current_version="unknown"
    fi
    
    # Get latest version from GitHub
    local latest_version
    latest_version=$(get_latest_paqet_version)
    
    echo -e "${YELLOW}System Information:${NC}"
    echo -e " OS: ${CYAN}$os${NC}"
    echo -e " Arch: ${CYAN}$arch${NC}"
    echo -e " Current Version: ${CYAN}$current_version${NC}"
    echo -e " Latest Version: ${CYAN}$latest_version${NC}\n"
    mkdir -p "/root/paqet"
    local arch_name=""
    case $arch in
        amd64) arch_name="amd64" ;;
        arm64) arch_name="arm64" ;;
        armv7) arch_name="arm32" ;;
        386) arch_name="386" ;;
        *) arch_name="$arch" ;;
    esac
    
    local expected_file="paqet-linux-${arch_name}-${latest_version}.tar.gz"
    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${latest_version}/${expected_file}"
    
    echo -e "${YELLOW}Download URL:${NC} ${CYAN}$download_url${NC}\n"
    
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN} paqet core${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Installation Options paqet core:${NC}"
    echo -e " 1) ${GREEN}Download/Update from GitHub (latest: $latest_version)${NC}"
    echo -e " 2) ${CYAN}Use local file from /root/paqet/${NC}"
    echo -e " 3) ${PURPLE}Download from custom URL${NC}"
    echo -e " 8) ${ORANGE}Download optimized core (amd64) [v2.2.0-optimize]${NC}"
    echo -e ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN} paqet manager${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Installation Options paqet manager:${NC}"
    echo -e " 4) ${BLUE}Install script${NC}"
    echo -e " 5) ${BLUE}Update script${NC}"
    echo -e " 6) ${BLUE}Switch version${NC}"
    echo -e " 7) ${RED}Uninstall script${NC}"
    echo -e ""
    echo -e " 0) ${YELLOW}↩️ Back to main menu${NC}\n"
    
    read -p "Choose option [0-8]: " install_choice
    
    case $install_choice in
        1)
            print_info "Downloading latest version ($latest_version) from GitHub for $os/$arch_name..."
            
            if ! curl -fsSL "$download_url" -o "/tmp/paqet.tar.gz" 2>/dev/null; then
                print_error "Download failed from GitHub"
                echo -e "\n${YELLOW}Please check:${NC}"
                echo -e " 1. Internet connection"
                echo -e " 2. GitHub repository access"
                echo -e " 3. The version $latest_version exists"
                echo -e "\n${YELLOW}You can also:${NC}"
                echo -e " - Try again later"
                echo -e " - Download manually from: $download_url"
                echo -e " - Save to: /root/paqet/$expected_file"
                echo -e " - Then use option 2 to install from local file"
                pause
                return 1
            else
                print_success "Downloaded version ${latest_version}"
                cp "/tmp/paqet.tar.gz" "/root/paqet/$expected_file" 2>/dev/null && \
                print_info "Saved copy to /root/paqet/$expected_file for future use"
            fi
            ;;
        2)
            local local_files=()
            if [ -d "/root/paqet" ]; then
                while IFS= read -r file; do
                    if [[ "$file" =~ paqet-linux-.*\.tar\.gz$ ]]; then
                        local_files+=("$file")
                    fi
                done < <(find "/root/paqet" -name "*.tar.gz" -type f 2>/dev/null | sort)
            fi
            
            if [ ${#local_files[@]} -eq 0 ]; then
                print_error "No valid paqet archives found in /root/paqet"
                echo -e "\n${YELLOW}Expected filename format:${NC} paqet-linux-{arch}-{version}.tar.gz"
                echo -e "${YELLOW}Example:${NC} paqet-linux-amd64-v1.0.0-alpha.16.tar.gz"
                pause
                return 1
            fi
            
            echo -e "\n${YELLOW}Found local paqet archives:${NC}\n"
            
            for i in "${!local_files[@]}"; do
                local filename
                filename=$(basename "${local_files[$i]}")
                local filesize
                filesize=$(du -h "${local_files[$i]}" | cut -f1)
                local file_arch=""
                if [[ "$filename" =~ linux-([^-]+)- ]]; then
                    file_arch="${BASH_REMATCH[1]}"
                fi
                
                if [ "$file_arch" = "$arch_name" ]; then
                    echo -e " $((i+1)). ${GREEN}$filename${NC} (${filesize}) - ${GREEN}✓ Compatible${NC}"
                else
                    echo -e " $((i+1)). ${YELLOW}$filename${NC} (${filesize}) - ${YELLOW}⚠️ Not compatible (need: $arch_name)${NC}"
                fi
            done
            
            echo ""
            read -p "Select file [1-${#local_files[@]}]: " file_choice
            
            if [[ "$file_choice" -ge 1 ]] && [[ "$file_choice" -le ${#local_files[@]} ]]; then
                local selected_file="${local_files[$((file_choice-1))]}"
                local selected_filename=$(basename "$selected_file")
                if [[ "$selected_filename" =~ linux-([^-]+)- ]]; then
                    local file_arch="${BASH_REMATCH[1]}"
                    if [ "$file_arch" != "$arch_name" ]; then
                        print_warning "This file is for architecture '$file_arch', but your system is '$arch_name'"
                        read -p "Continue anyway? (y/N): " force_install
                        if [[ ! "$force_install" =~ ^[Yy]$ ]]; then
                            continue
                        fi
                    fi
                fi
                
                print_success "Using: $selected_filename"
                cp "$selected_file" "/tmp/paqet.tar.gz"
            else
                print_error "Invalid selection"
                pause
                return 1
            fi
            ;;
        3)
            echo ""
            echo -en "${YELLOW}Enter custom URL: ${NC}"
            read -r custom_url
            
            if [ -z "$custom_url" ]; then
                print_error "URL cannot be empty"
                pause
                return 1
            fi
            
            print_info "Downloading from custom URL..."
            if ! curl -fsSL "$custom_url" -o "/tmp/paqet.tar.gz" 2>/dev/null; then
                print_error "Download failed"
                echo -e "\n${YELLOW}Please check:${NC}"
                echo -e " 1. URL is correct"
                echo -e " 2. Internet connection"
                pause
                return 1
            else
                print_success "Downloaded from custom URL"
            fi
            ;;

8)
    if [ "$arch_name" != "amd64" ]; then
        print_error "This optimized build is only available for amd64. Your arch: $arch_name"
        echo -e "${YELLOW}Tip:${NC} Use option 1 for the official GitHub build, or option 3 for a custom URL."
        pause
        return 1
    fi

    print_info "Downloading optimized build (v2.2.0-optimize) from Paqet-Tunnel-Manager release..."

    if ! curl -fsSL "$PAQET_OPTIMIZED_AMD64_URL" -o "/tmp/paqet.tar.gz" 2>/dev/null; then
        print_error "Download failed"
        echo -e "\n${YELLOW}URL:${NC} $PAQET_OPTIMIZED_AMD64_URL"
        pause
        return 1
    else
        print_success "Downloaded optimized build"
        local opt_filename
        opt_filename=$(basename "$PAQET_OPTIMIZED_AMD64_URL")
        cp "/tmp/paqet.tar.gz" "/root/paqet/$opt_filename" 2>/dev/null && \
        print_info "Saved copy to /root/paqet/$opt_filename for future use"
    fi
    ;;

        4)
            install_manager_script
            return 0
            ;;
        5)
            update_manager_script
            return 0
            ;;
        6)
            switch_manager_version
            return 0
            ;;
        7)
            uninstall_manager_script
            return 0
            ;;
        0)
            return 0
            ;;
        *)
            print_error "Invalid choice"
            pause
            return 1
            ;;
    esac

    mkdir -p "$INSTALL_DIR"
    print_step "Extracting archive..."
    rm -rf "$INSTALL_DIR"/*    
    tar -xzf "/tmp/paqet.tar.gz" -C "$INSTALL_DIR" 2>/dev/null || {
        print_error "Failed to extract archive"
        echo -e "\n${YELLOW}Possible issues:${NC}"
        echo -e " 1. Corrupted download"
        echo -e " 2. Wrong file format"
        echo -e " 3. Incompatible archive"
        rm -f "/tmp/paqet.tar.gz"
        pause
        return 1
    }
    
    print_success "Archive extracted to $INSTALL_DIR"
    local binary_file=""
    local standard_binary="$INSTALL_DIR/paqet_linux_${arch_name}"
    if [ -f "$standard_binary" ]; then
        binary_file="$standard_binary"
    else
        binary_file=$(find "$INSTALL_DIR" -type f -name "*paqet*" -exec file {} \; | grep -i "executable" | cut -d: -f1 | head -1)
    fi

    if [ -z "$binary_file" ] || [ ! -f "$binary_file" ]; then
        for file in "$INSTALL_DIR"/*; do
            if [ -f "$file" ] && [ -x "$file" ]; then
                binary_file="$file"
                break
            fi
        done
    fi
    
    if [ -n "$binary_file" ] && [ -f "$binary_file" ]; then
        print_info "Found binary: $(basename "$binary_file")"
        rm -f "$BIN_DIR/paqet"
        cp "$binary_file" "$BIN_DIR/paqet"
        chmod +x "$BIN_DIR/paqet"
        
        print_success "Paqet installed to $BIN_DIR/paqet"
        
        local new_version
        new_version=$("$BIN_DIR/paqet" version 2>/dev/null | grep "^Version:" | head -1 | cut -d':' -f2 | xargs)
        if [ -n "$new_version" ]; then
            print_info "Installed version: ${CYAN}$new_version${NC}"
            
            if [ "$new_version" != "$latest_version" ]; then
                print_warning "Expected version $latest_version but got $new_version"
            fi
        else
            print_warning "Could not determine installed version"
        fi
    else
        print_error "Binary not found in archive"
        echo -e "\n${YELLOW}Archive contents:${NC}"
        ls -la "$INSTALL_DIR"
        local any_file=$(find "$INSTALL_DIR" -type f | head -1)
        if [ -n "$any_file" ]; then
            print_info "Trying to make file executable: $any_file"
            chmod +x "$any_file"
            if [ -x "$any_file" ] && file "$any_file" | grep -q "executable"; then
                cp "$any_file" "$BIN_DIR/paqet"
                print_success "Paqet installed using alternative method"
            fi
        else
            pause
            return 1
        fi
    fi
    
    # پاک کردن فایل موقت
    rm -f "/tmp/paqet.tar.gz"
    
    print_success "Paqet core installation completed!"
    pause
    return 0
}

# Install manager script
install_manager_script() {
    clear
    show_banner
    print_step "Installing Paqet Manager script...\n"
    
    local manager_url="https://raw.githubusercontent.com/${MANAGER_GITHUB_REPO}/main/paqet-manager.sh"
    
    print_info "Downloading from: $manager_url"
    
    if curl -fsSL "$manager_url" -o "$MANAGER_PATH" 2>/dev/null; then
        chmod +x "$MANAGER_PATH"
        print_success "✅ Paqet Manager installed to $MANAGER_PATH"
        echo -e "\n${GREEN}You can now run the manager using command:${NC}"
        echo -e " ${CYAN}paqet-manager${NC}"
        echo -e "\n${YELLOW}Note: You may need to log out and back in for the command to be available.${NC}"
    else
        print_error "Failed to download manager script"
        pause
        return 1
    fi
    
    pause
    return 0
}

# Update manager script
update_manager_script() {
    clear
    show_banner
    print_step "Updating Paqet Manager script...\n"
    
    if [ ! -f "$MANAGER_PATH" ]; then
        print_warning "Manager script not found at $MANAGER_PATH"
        read -p "Install it now? (y/N): " install_now
        if [[ "$install_now" =~ ^[Yy]$ ]]; then
            install_manager_script
        fi
        return
    fi
    
    mkdir -p "$BACKUP_DIR"
    local backup_path="${BACKUP_DIR}/paqet-manager.backup-$(date +%Y%m%d-%H%M%S)"
    cp "$MANAGER_PATH" "$backup_path"
    print_info "Backup created at $backup_path"
    
    local manager_url="https://raw.githubusercontent.com/${MANAGER_GITHUB_REPO}/main/paqet-manager.sh"
    
    print_info "Downloading latest version..."
    
    if curl -fsSL "$manager_url" -o "$MANAGER_PATH" 2>/dev/null; then
        chmod +x "$MANAGER_PATH"
        print_success "✅ Paqet Manager updated successfully!"
        echo -e "\n${GREEN}Manager updated to latest version${NC}"
        echo -e "${YELLOW}Backup saved at:${NC} $backup_path"
        
        local new_version
        new_version=$(grep "SCRIPT_VERSION=" "$MANAGER_PATH" | head -1 | cut -d'"' -f2)
        [ -n "$new_version" ] && echo -e "${CYAN}New version:${NC} $new_version"
    else
        print_error "Failed to download manager script"
        mv "$backup_path" "$MANAGER_PATH" 2>/dev/null
        pause
        return 1
    fi
    
    pause
    return 0
}

# Switch manager version
switch_manager_version() {
    clear
    show_banner
    print_step "Switch Paqet Manager Version\n"
    
    echo -e "${YELLOW}Available versions:${NC}"
    echo -e "────────────────────────────────────────────────────────────────"
    
    local sorted_versions=()
    while IFS= read -r line; do
        sorted_versions+=("$line")
    done < <(for v in "${!MANAGER_VERSIONS[@]}"; do echo "$v"; done | sort -rV)
    
    local i=1
    declare -A version_map
    
    local current_version=""
    [ -f "$MANAGER_PATH" ] && current_version=$(grep "SCRIPT_VERSION=" "$MANAGER_PATH" 2>/dev/null | head -1 | cut -d'"' -f2)
    
    for version in "${sorted_versions[@]}"; do
        if [ "$version" = "$current_version" ]; then
            printf " %2d. ${CYAN}%s${NC} ${GREEN}(current)${NC}\n" "$i" "$version"
        else
            printf " %2d. ${CYAN}%s${NC}\n" "$i" "$version"
        fi
        version_map[$i]="$version"
        ((i++))
    done
    
    echo -e "\n 0) ${YELLOW}↩️ Back${NC}\n"
    
    read -p "Select version [0-$((i-1))]: " version_choice
    
    [ "$version_choice" = "0" ] && return 0
    
    if ! [[ "$version_choice" =~ ^[0-9]+$ ]] || (( version_choice < 1 || version_choice >= i )); then
        print_error "Invalid selection"
        pause
        return 1
    fi
    
    local selected_version="${version_map[$version_choice]}"
    local selected_url="${MANAGER_VERSIONS[$selected_version]}"
    
    print_info "Switching to version $selected_version..."
    
    if [ -f "$MANAGER_PATH" ]; then
        mkdir -p "$BACKUP_DIR"
        local backup_path="${BACKUP_DIR}/paqet-manager.backup-$(date +%Y%m%d-%H%M%S)"
        cp "$MANAGER_PATH" "$backup_path"
        print_info "Backup created at $backup_path"
    fi
    
    if curl -fsSL "$selected_url" -o "$MANAGER_PATH" 2>/dev/null; then
        chmod +x "$MANAGER_PATH"
        print_success "✅ Switched to version $selected_version"
        echo -e "\n${GREEN}Manager version changed successfully!${NC}"
        echo -e "${YELLOW}Backup saved at:${NC} $backup_path"
    else
        print_error "Failed to download version $selected_version"
        pause
        return 1
    fi
    
    pause
    return 0
}

# Uninstall manager script
uninstall_manager_script() {
    clear
    show_banner
    print_step "Uninstall Paqet Manager\n"
    
    if [ ! -f "$MANAGER_PATH" ]; then
        print_info "Manager script not found at $MANAGER_PATH"
        pause
        return 0
    fi
    
    echo -e "${RED}WARNING: This will remove the Paqet Manager command.${NC}"
    echo -e "${YELLOW}The manager script will be deleted from:${NC} $MANAGER_PATH\n"
    
    read -p "Are you sure you want to uninstall? (y/N): " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_info "Uninstall cancelled"
        pause
        return 0
    fi
    
    mkdir -p "$BACKUP_DIR"
    local backup_path="${BACKUP_DIR}/paqet-manager.backup-$(date +%Y%m%d-%H%M%S)"
    cp "$MANAGER_PATH" "$backup_path"
    print_info "Backup created at $backup_path"
    
    rm -f "$MANAGER_PATH"
    
    if [ ! -f "$MANAGER_PATH" ]; then
        print_success "✅ Paqet Manager uninstalled successfully"
        echo -e "\n${YELLOW}Backup saved at:${NC} $backup_path"
        echo -e "${YELLOW}To restore, run:${NC} cp $backup_path $MANAGER_PATH"
    else
        print_error "Failed to uninstall"
    fi
    
    pause
    return 0
}

# ================================================
# KERNEL OPTIMIZATION FUNCTIONS
# ================================================

# Apply full kernel optimizations
apply_kernel_optimizations() {
    clear
    show_banner
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║ Apply Kernel Optimizations (Recommended)                 ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}\n"
    
    print_step "Applying full kernel optimizations..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        print_error "This must be run as root"
        return 1
    fi
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    
    # Backup existing configs
    [ -f "$SYSCTL_FILE" ] && cp "$SYSCTL_FILE" "$BACKUP_SYSCTL" && print_info "Backed up $SYSCTL_FILE"
    [ -f "$LIMITS_FILE" ] && cp "$LIMITS_FILE" "$BACKUP_LIMITS" && print_info "Backed up $LIMITS_FILE"
    
    print_step "Creating sysctl configuration..."
    
    # Create sysctl config
    cat > "$SYSCTL_FILE" << 'EOF'
# Paqet Tunnel - Kernel Optimizations
# Network core settings
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.core.optmem_max = 25165824

# TCP settings
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1

# Connection tracking
net.netfilter.nf_conntrack_max = 2097152
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180

# IP settings
net.ipv4.ip_forward = 1
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# File limits
fs.file-max = 4194304
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 524288
EOF
    
    print_success "Sysctl configuration created at $SYSCTL_FILE"
    
    # Apply sysctl
    print_step "Applying sysctl settings..."
    if sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1; then
        print_success "Sysctl settings applied successfully"
    else
        print_warning "Some sysctl settings could not be applied"
    fi
    
    # Check if BBR is available, fallback to cubic
    if ! sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
        print_warning "BBR congestion control not available in current kernel"
        print_step "Falling back to cubic..."
        sed -i 's/bbr/cubic/' "$SYSCTL_FILE"
        sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null 2>&1
        print_info "Using cubic congestion control instead"
    fi
    
    # Create limits.conf
    print_step "Creating system limits configuration..."
    cat > "$LIMITS_FILE" << 'EOF'
# Paqet Tunnel - System Limits
*               soft    nofile          1048576
*               hard    nofile          1048576
root            soft    nofile          1048576
root            hard    nofile          1048576
*               soft    nproc           unlimited
*               hard    nproc           unlimited
root            soft    nproc           unlimited
root            hard    nproc           unlimited
EOF
    
    print_success "System limits configured at $LIMITS_FILE"
    
    # Apply limits (will take effect on new sessions)
    print_info "System limits will take effect for new sessions"
    
    echo -e "\n${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✅ Kernel optimizations applied successfully!${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}\n"
    
    echo -e "${YELLOW}Backup files:${NC}"
    [ -f "$BACKUP_SYSCTL" ] && echo -e "  • $BACKUP_SYSCTL"
    [ -f "$BACKUP_LIMITS" ] && echo -e "  • $BACKUP_LIMITS"
    
    echo -e "\n${YELLOW}Applied settings:${NC}"
    echo -e "  • TCP Congestion Control: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'N/A')"
    echo -e "  • Default QDisc: $(sysctl -n net.core.default_qdisc 2>/dev/null || echo 'N/A')"
    echo -e "  • Max File Descriptors: $(sysctl -n fs.file-max 2>/dev/null || echo 'N/A')"
    echo -e "  • IP Forwarding: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 'N/A')"
    
    echo -e "\n${CYAN}Note: Some changes may require a reboot to take full effect.${NC}"
    
    pause
}

# Remove kernel optimizations
remove_kernel_optimizations() {
    clear
    show_banner
    echo -e "${RED}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║ Remove Kernel Optimizations                               ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════╝${NC}\n"
    
    print_warning "This will remove all Paqet kernel optimizations and restore system defaults."
    echo ""
    
    read -p "Are you sure? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_info "Operation cancelled"
        pause
        return
    fi
    
    print_step "Removing kernel optimizations..."
    
    # Remove sysctl file
    if [ -f "$SYSCTL_FILE" ]; then
        rm -f "$SYSCTL_FILE"
        print_success "Removed $SYSCTL_FILE"
    else
        print_info "Sysctl file not found"
    fi
    
    # Remove limits file
    if [ -f "$LIMITS_FILE" ]; then
        rm -f "$LIMITS_FILE"
        print_success "Removed $LIMITS_FILE"
    else
        print_info "Limits file not found"
    fi
    
    # Reload system settings
    print_step "Reloading system settings..."
    sysctl --system >/dev/null 2>&1
    
    # Reset to system defaults
    sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null 2>&1
    sysctl -w net.core.default_qdisc=pfifo_fast >/dev/null 2>&1
    
    print_success "System defaults restored"
    echo -e "\n${YELLOW}Note: A reboot is recommended for complete reset.${NC}"
    
    pause
}

# View current kernel status
view_kernel_status() {
    clear
    show_banner
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║ Kernel Optimization Status                                ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}\n"
    
    print_step "Current Kernel Optimization Status"
    
    echo -e "\n${YELLOW}TCP Congestion Control:${NC}"
    echo -e "  • Current: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'N/A')"
    echo -e "  • Available: $(sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | cut -d'=' -f2 | xargs || echo 'N/A')"
    
    echo -e "\n${YELLOW}Buffer Sizes:${NC}"
    echo -e "  • net.core.rmem_max: $(sysctl -n net.core.rmem_max 2>/dev/null || echo 'N/A')"
    echo -e "  • net.core.wmem_max: $(sysctl -n net.core.wmem_max 2>/dev/null || echo 'N/A')"
    echo -e "  • net.ipv4.tcp_rmem: $(sysctl -n net.ipv4.tcp_rmem 2>/dev/null || echo 'N/A')"
    echo -e "  • net.ipv4.tcp_wmem: $(sysctl -n net.ipv4.tcp_wmem 2>/dev/null || echo 'N/A')"
    
    echo -e "\n${YELLOW}File Descriptors:${NC}"
    echo -e "  • Current session: $(ulimit -n)"
    echo -e "  • System max: $(sysctl -n fs.file-max 2>/dev/null || echo 'N/A')"
    
    echo -e "\n${YELLOW}Network Settings:${NC}"
    echo -e "  • IP Forwarding: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 'N/A')"
    echo -e "  • Default QDisc: $(sysctl -n net.core.default_qdisc 2>/dev/null || echo 'N/A')"
    echo -e "  • Local Port Range: $(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null || echo 'N/A')"
    
    echo -e "\n${YELLOW}Configuration Files:${NC}"
    if [ -f "$SYSCTL_FILE" ]; then
        echo -e "  • ${GREEN}✓ $SYSCTL_FILE${NC}"
        echo -e "    └─ Modified: $(date -r "$SYSCTL_FILE" '+%Y-%m-%d %H:%M:%S')"
    else
        echo -e "  • ${RED}✗ $SYSCTL_FILE (not found)${NC}"
    fi
    
    if [ -f "$LIMITS_FILE" ]; then
        echo -e "  • ${GREEN}✓ $LIMITS_FILE${NC}"
        echo -e "    └─ Modified: $(date -r "$LIMITS_FILE" '+%Y-%m-%d %H:%M:%S')"
    else
        echo -e "  • ${RED}✗ $LIMITS_FILE (not found)${NC}"
    fi
    
    pause
}

# ================================================
# OPTIMIZATION FUNCTIONS
# ================================================

# Legacy BBR only installation
install_bbr_legacy() {
    clear
    show_banner
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║ Install BBR Only (Legacy)                                 ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${YELLOW}This will install only BBR congestion control.${NC}"
    echo -e "${YELLOW}For full optimization, use option 1 instead.${NC}\n"
    
    read -p "Do you want to install BBR only? (y/N): " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}BBR installation cancelled.${NC}"
        pause
        return
    fi
    
    print_step "Downloading and installing BBR (legacy)..."
    
    if wget --no-check-certificate https://github.com/teddysun/across/raw/master/bbr.sh -O /tmp/bbr.sh 2>/dev/null; then
        chmod +x /tmp/bbr.sh
        print_success "BBR installer downloaded"
        
        echo -e "\n${YELLOW}The BBR installer will now run.${NC}"
        echo -e "${YELLOW}Follow the on-screen instructions.${NC}"
        echo -e "\n${CYAN}Note: This may require a system reboot.${NC}\n"
        
        pause "Press Enter to continue with BBR installation..."
        
        /tmp/bbr.sh
        
        echo -e "\n${GREEN}✅ BBR installation completed!${NC}\n"
        echo -e "${YELLOW}If the installer requested a reboot, please restart your server.${NC}"
        
        rm -f /tmp/bbr.sh
    else
        print_error "Failed to download BBR installer"
        echo -e "\n${YELLOW}You can install BBR manually with:${NC}"
        echo -e "${CYAN}wget --no-check-certificate https://github.com/teddysun/across/raw/master/bbr.sh && chmod +x bbr.sh && ./bbr.sh${NC}"
    fi
    
    pause
}

# Install DNS Finder
install_dns_finder() {
    clear
    show_banner
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║ Install DNS Finder                                       ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${YELLOW}This tool finds the best DNS servers for Iran by testing latency.${NC}"
    echo -e "${YELLOW}It will help improve your internet speed and connectivity.${NC}\n"
    
    read -p "Do you want to find the best DNS servers? (y/N): " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}DNS Finder installation cancelled.${NC}"
        pause
        return
    fi
    
    print_step "Downloading and running DNS Finder..."
    
    if bash <(curl -Ls https://github.com/alinezamifar/IranDNSFinder/raw/refs/heads/main/dns.sh); then
        print_success "✅ DNS Finder completed successfully!"
        echo -e "\n${YELLOW}The tool has tested various DNS servers and shown the best options.${NC}"
    else
        print_error "Failed to run DNS Finder"
        echo -e "\n${YELLOW}You can run DNS Finder manually with:${NC}"
        echo -e "${CYAN}bash <(curl -Ls https://github.com/alinezamifar/IranDNSFinder/raw/refs/heads/main/dns.sh)${NC}"
    fi
    
    pause
    return
}

# Install Mirror Selector
install_mirror_selector() {
    clear
    show_banner
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║ Install Mirror Selector                                  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}\n"
    
    local os
    os=$(detect_os)
    if [[ "$os" != "ubuntu" ]] && [[ "$os" != "debian" ]]; then
        print_error "This tool is only for Ubuntu/Debian based systems"
        echo -e "${YELLOW}Your OS is: $os${NC}"
        pause
        return
    fi
    
    echo -e "${YELLOW}This tool finds the fastest apt repository mirror for your location.${NC}"
    echo -e "${YELLOW}It will significantly improve package download speeds.${NC}\n"
    
    read -p "Do you want to find the fastest apt mirror? (y/N): " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Mirror Selector installation cancelled.${NC}"
        pause
        return
    fi
    
    print_step "Downloading and running Mirror Selector..."
    
    if bash <(curl -Ls https://github.com/alinezamifar/DetectUbuntuMirror/raw/refs/heads/main/DUM.sh); then
        print_success "✅ Mirror Selector completed successfully!"
        echo -e "\n${YELLOW}The tool has tested various mirrors and selected the fastest one.${NC}"
    else
        print_error "Failed to run Mirror Selector"
        echo -e "\n${YELLOW}You can run Mirror Selector manually with:${NC}"
        echo -e "${CYAN}bash <(curl -Ls https://github.com/alinezamifar/DetectUbuntuMirror/raw/refs/heads/main/DUM.sh)${NC}"
    fi
    
    pause
    return
}

# Optimization menu
# Optimization menu
optimize_server() {
    while true; do
        clear
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║ Server Optimization Tools                                ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}\n"
        
        echo -e "${CYAN}1.${NC} ${GREEN}Kernel Optimization (Recommended)${NC} - Full kernel tuning (BBR + buffers + limits)"
        echo -e "${CYAN}2.${NC} ${PURPLE}DNS Finder${NC} - Find the best DNS servers for Iran"
        echo -e "${CYAN}3.${NC} ${ORANGE}Mirror Selector${NC} - Find the fastest apt repository mirror"
        echo -e "${CYAN}4.${NC} ${BLUE}BBR Only (Legacy)${NC} - Install only BBR congestion control"
        echo -e "${CYAN}0.${NC} ↩️ Back to Main Menu"
        echo ""
        
        read -p "Select option [0-4]: " choice
        
        case $choice in
            1) 
                while true; do
                    clear
                    show_banner
                    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
                    echo -e "${GREEN}║ Kernel Optimization Menu                                 ║${NC}"
                    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}\n"
                    
                    echo -e " 1. Apply full kernel optimizations (BBR + buffers + limits)"
                    echo -e " 2. Remove kernel optimizations (restore defaults)"
                    echo -e " 3. View current kernel status"
                    echo -e " 0. Back to optimization menu"
                    echo ""
                    
                    read -p "Select option [0-3]: " kernel_choice
                    
                    case $kernel_choice in
                        1) apply_kernel_optimizations ;;
                        2) remove_kernel_optimizations ;;
                        3) view_kernel_status ;;
                        0) break ;;
                        *) print_error "Invalid option"; sleep 1 ;;
                    esac
                done
                ;;
            2) install_dns_finder ;;
            3) install_mirror_selector ;;
            4) install_bbr_legacy ;;
            0) return ;;
            *) print_error "Invalid option"; sleep 1 ;;
        esac
    done
}

# ================================================
# MANAGE ALL SERVICES
# ================================================
manage_all_services() {
    while true; do
        clear
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                 Manage All Paqet Services                    ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
        
        local services=()
        mapfile -t services < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null |
                              grep -E '^paqet-.*\.service' | awk '{print $1}' || true)
        
        if [[ ${#services[@]} -eq 0 ]]; then
            echo -e "${YELLOW}No Paqet services found.${NC}\n"
            pause
            return
        fi
        
        echo -e "${CYAN}Found ${#services[@]} Paqet service(s):${NC}\n"
        
        local i=1
        for svc in "${services[@]}"; do
            local service_name="${svc%.service}"
            local display_name="${service_name#paqet-}"
            local status
            status=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
            
            local status_color=""
            case "$status" in
                active) status_color="${GREEN}" ;;
                failed) status_color="${RED}" ;;
                inactive) status_color="${YELLOW}" ;;
                *) status_color="${WHITE}" ;;
            esac
            
            printf " %2d. ${CYAN}%-25s${NC} [${status_color}%s${NC}]\n" "$i" "$display_name" "$status"
            ((i++))
        done
        
        echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}🔒 CONNECTION PROTECTION${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        echo -e " ${GREEN}[1]${NC} 🛡️ Apply Connection Protection (Anti-RST + NOTRACK | Recommended)"
        echo -e " ${GREEN}[2]${NC} ❌ Remove Protection Rules"
        
        echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}🔄 NAT PORT FORWARDING${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        echo -e " ${GREEN}[3]${NC} 🌐 Multi-Port Forward (specific ports)"
        echo -e " ${GREEN}[4]${NC} 🌍 All-Ports Forward (except excluded)"
        echo -e " ${GREEN}[5]${NC} 📋 View NAT Rules"
        echo -e " ${GREEN}[6]${NC} 🗑️ Remove Forwarding by Destination IP"
        echo -e " ${GREEN}[7]${NC} 💣 Flush All NAT Rules"
        
        echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}🚀 SERVICE CONTROL${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        echo -e " ${GREEN}[8]${NC} ▶️  Start All Services"
        echo -e " ${GREEN}[9]${NC} ⏹️  Stop All Services"
        echo -e " ${GREEN}[10]${NC} 🔄 Restart All Services"
        
        echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}📊 MONITORING & DIAGNOSTICS${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        echo -e " ${GREEN}[11]${NC} 📋 Live Log Monitoring (All Services)"
        echo -e " ${GREEN}[12]${NC} 📊 Test MTU / Packet Loss"
        
        echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}⚙️  BULK CONFIGURATION${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        echo -e " ${GREEN}[13]${NC} 🔧 Change Mode All Services"
        echo -e " ${GREEN}[14]${NC} 🔌 Change Connections All Services"
        echo -e " ${GREEN}[15]${NC} 📦 Change MTU All Services"
        echo -e " ${GREEN}[16]${NC} 🔒 Change Block All Services"
        
        echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
        echo -e " ${GREEN}[17]${NC} 🗑️  Delete All Tunnels"
        echo -e " ${GREEN}[0]${NC} ↩️ Back to Main Menu"
        echo ""
        
        read -p "Choose option [0-17]: " mgmt_choice
        
        case $mgmt_choice in
            1) apply_connection_protection ;;
            2) remove_connection_protection ;;
            3) add_nat_forward_multi_port ;;
            4) add_nat_forward_all_ports ;;
            5) view_nat_rules ;;
            6) remove_nat_forward_by_dest ;;
            7) flush_nat_rules ;;
            8) start_all_services "${services[@]}" ;;
            9) stop_all_services "${services[@]}" ;;
            10) restart_all_services "${services[@]}" ;;
            11) live_log_all_services "${services[@]}" ;;
            12) test_mtu ;;
            13) change_mode_all_services ;;
            14) change_conn_all_services ;;
            15) set_global_mtu ;;
            16) change_block_all_services ;;
            17) delete_all_tunnels "${services[@]}" ;;
            0) return ;;
            *) print_error "Invalid choice"; sleep 1.5 ;;
        esac
    done
}

# ================================================
# BULK CONFIGURATION FUNCTIONS
# ================================================

start_all_services() {
    local services=("$@")
    echo -e "\n${YELLOW}Starting all Paqet services...${NC}"
    
    local success_count=0
    local fail_count=0
    
    for svc in "${services[@]}"; do
        local service_name="${svc%.service}"
        local display_name="${service_name#paqet-}"
        
        echo -n " Starting $display_name... "
        
        if systemctl start "$svc" >/dev/null 2>&1; then
            sleep 1
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                echo -e "${GREEN}✅ SUCCESS${NC}"
                ((success_count++))
            else
                echo -e "${RED}❌ FAILED (not running)${NC}"
                ((fail_count++))
            fi
        else
            echo -e "${RED}❌ FAILED${NC}"
            ((fail_count++))
        fi
    done
    
    echo -e "\n${CYAN}Results:${NC}"
    echo -e " ${GREEN}✅ Success:${NC} $success_count service(s)"
    echo -e " ${RED}❌ Failed:${NC} $fail_count service(s)"
    pause
}

stop_all_services() {
    local services=("$@")
    echo -e "\n${YELLOW}Stopping all Paqet services...${NC}"
    
    local success_count=0
    local fail_count=0
    
    for svc in "${services[@]}"; do
        local service_name="${svc%.service}"
        local display_name="${service_name#paqet-}"
        
        echo -n " Stopping $display_name... "
        
        if systemctl stop "$svc" >/dev/null 2>&1; then
            sleep 1
            if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
                echo -e "${GREEN}✅ SUCCESS${NC}"
                ((success_count++))
            else
                echo -e "${RED}❌ FAILED (still running)${NC}"
                ((fail_count++))
            fi
        else
            echo -e "${RED}❌ FAILED${NC}"
            ((fail_count++))
        fi
    done
    
    echo -e "\n${CYAN}Results:${NC}"
    echo -e " ${GREEN}✅ Success:${NC} $success_count service(s)"
    echo -e " ${RED}❌ Failed:${NC} $fail_count service(s)"
    pause
}

change_mode_all_services() {
    clear
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Change KCP Mode for ALL Services${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}\n"
    echo -e "${CYAN}Available KCP Modes:${NC}"
    echo -e "────────────────────────────────────────────────────────────────"
    echo -e " ${GREEN}[1]${NC} normal  - Normal speed / Normal latency / Low usage"
    echo -e " ${GREEN}[2]${NC} fast    - Balanced speed / Low latency / Normal usage"
    echo -e " ${GREEN}[3]${NC} fast2   - High speed / Lower latency / Medium usage"
    echo -e " ${GREEN}[4]${NC} fast3   - Max speed / Very low latency / High CPU"
    echo -e " ${GREEN}[5]${NC} manual  - Advanced settings"
    echo ""
    
    read -p "Select new mode [1-5]: " mode_choice
    
    local new_mode=""
    case $mode_choice in
        1) new_mode="normal" ;;
        2) new_mode="fast" ;;
        3) new_mode="fast2" ;;
        4) new_mode="fast3" ;;
        5) 
            echo -e "\n${YELLOW}Manual mode requires individual configuration.${NC}"
            echo -e "${YELLOW}Please configure each service separately.${NC}"
            pause
            return
            ;;
        *) print_error "Invalid choice"; return ;;
    esac
    
    echo -e "\n${YELLOW}Applying mode '$new_mode' to all configurations...${NC}"
    
    local configs=()
    while IFS= read -r -d '' file; do
        configs+=("$file")
    done < <(find "$CONFIG_DIR" -name "*.yaml" -type f -print0 2>/dev/null)
    
    local modified=0
    for config in "${configs[@]}"; do
        local config_name=$(basename "$config" .yaml)
        
        if grep -q "mode:" "$config"; then
            sed -i "s/mode:.*/mode: \"$new_mode\"/" "$config"
            echo -e " ${GREEN}✓${NC} Updated $config_name"
            ((modified++))
        else
            if grep -q "kcp:" "$config"; then
                sed -i "/kcp:/a \    mode: \"$new_mode\"" "$config"
                echo -e " ${GREEN}✓${NC} Added mode to $config_name"
                ((modified++))
            fi
        fi
    done
    
    echo -e "\n${GREEN}✅ Mode set to '$new_mode' on $modified configuration(s)${NC}"
    
    read -p "Restart all services to apply changes? (y/N): " restart_choice
    if [[ "$restart_choice" =~ ^[Yy]$ ]]; then
        local services=()
        mapfile -t services < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null |
                              grep -E '^paqet-.*\.service' | awk '{print $1}' || true)
        restart_all_services "${services[@]}"
    fi
    
    pause
}

change_conn_all_services() {
    clear
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Change Connections Count for ALL Services${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}\n"
    
    echo -e "${CYAN}Current connections per service:${NC}"
    echo -e "────────────────────────────────────────────────────────────────"
    
    local configs=()
    while IFS= read -r -d '' file; do
        configs+=("$file")
        local config_name=$(basename "$file" .yaml)
        local current_conn=$(grep "^conn:" "$file" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"')
        echo -e " ${config_name}: ${current_conn:-Not set (using default: $DEFAULT_CONNECTIONS)}"
    done < <(find "$CONFIG_DIR" -name "*.yaml" -type f -print0 2>/dev/null)
    
    echo -e "\n${CYAN}Enter new connections value [1-32]:${NC}"
    read -p "New connections count: " new_conn
    
    if ! [[ "$new_conn" =~ ^[1-9][0-9]?$ ]] || [ "$new_conn" -lt 1 ] || [ "$new_conn" -gt 32 ]; then
        print_error "Invalid value. Must be between 1 and 32"
        pause
        return
    fi
    
    echo -e "\n${YELLOW}Applying connections=$new_conn to all configurations...${NC}"
    
    local modified=0
    for config in "${configs[@]}"; do
        local config_name=$(basename "$config" .yaml)
        
        if grep -q "^conn:" "$config"; then
            sed -i "s/^conn:.*/conn: $new_conn/" "$config"
            echo -e " ${GREEN}✓${NC} Updated $config_name"
            ((modified++))
        else
            # Add under transport section
            if grep -q "transport:" "$config"; then
                sed -i "/transport:/a \  conn: $new_conn" "$config"
                echo -e " ${GREEN}✓${NC} Added conn to $config_name"
                ((modified++))
            fi
        fi
    done
    
    echo -e "\n${GREEN}✅ Connections set to $new_conn on $modified configuration(s)${NC}"
    
    read -p "Restart all services to apply changes? (y/N): " restart_choice
    if [[ "$restart_choice" =~ ^[Yy]$ ]]; then
        local services=()
        mapfile -t services < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null |
                              grep -E '^paqet-.*\.service' | awk '{print $1}' || true)
        restart_all_services "${services[@]}"
    fi
    
    pause
}

change_block_all_services() {
    clear
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Change Block/Encryption for ALL Services${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}\n"
    
    echo -e "${CYAN}Available Encryption Options:${NC}"
    echo -e "────────────────────────────────────────────────────────────────"
    echo -e " ${GREEN}[1]${NC} aes-128-gcm - Very high security / Very fast / Recommended"
    echo -e " ${GREEN}[2]${NC} aes         - High security / Medium speed / General use"
    echo -e " ${GREEN}[3]${NC} aes-128     - High security / Fast / Low CPU usage"
    echo -e " ${GREEN}[4]${NC} aes-192     - Very high security / Medium speed / Moderate CPU"
    echo -e " ${GREEN}[5]${NC} aes-256     - Maximum security / Slower / Higher CPU"
    echo -e " ${GREEN}[6]${NC} none        - No encryption / Max speed / Insecure"
    echo -e " ${GREEN}[7]${NC} null        - No encryption / Max speed / Insecure"
    echo ""
    
    read -p "Select encryption [1-7]: " enc_choice
    
    local new_block=""
    case $enc_choice in
        1) new_block="aes-128-gcm" ;;
        2) new_block="aes" ;;
        3) new_block="aes-128" ;;
        4) new_block="aes-192" ;;
        5) new_block="aes-256" ;;
        6) new_block="none" ;;
        7) new_block="null" ;;
        *) print_error "Invalid choice"; return ;;
    esac
    
    echo -e "\n${YELLOW}Applying block='$new_block' to all configurations...${NC}"
    
    local configs=()
    while IFS= read -r -d '' file; do
        configs+=("$file")
    done < <(find "$CONFIG_DIR" -name "*.yaml" -type f -print0 2>/dev/null)
    
    local modified=0
    for config in "${configs[@]}"; do
        local config_name=$(basename "$config" .yaml)
        
        if grep -q "block:" "$config"; then
            sed -i "s/block:.*/block: \"$new_block\"/" "$config"
            echo -e " ${GREEN}✓${NC} Updated $config_name"
            ((modified++))
        else
            if grep -q "kcp:" "$config"; then
                sed -i "/kcp:/a \    block: \"$new_block\"" "$config"
                echo -e " ${GREEN}✓${NC} Added block to $config_name"
                ((modified++))
            fi
        fi
    done
    
    echo -e "\n${GREEN}✅ Block/Encryption set to '$new_block' on $modified configuration(s)${NC}"
    
    read -p "Restart all services to apply changes? (y/N): " restart_choice
    if [[ "$restart_choice" =~ ^[Yy]$ ]]; then
        local services=()
        mapfile -t services < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null |
                              grep -E '^paqet-.*\.service' | awk '{print $1}' || true)
        restart_all_services "${services[@]}"
    fi
    
    pause
}


# ================================================
# LOG MANAGEMENT FUNCTIONS
# ================================================

change_log_level_all_services() {
    clear
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Change Log Level (Default + Apply to All Configs)${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}\n"

    load_manager_settings

    echo -e "${CYAN}Current default log level:${NC} ${GREEN}${PAQET_DEFAULT_LOG_LEVEL}${NC}"

    local new_level
    new_level=$(ask_log_level "$PAQET_DEFAULT_LOG_LEVEL")
    new_level=$(normalize_log_level "$new_level" "$PAQET_DEFAULT_LOG_LEVEL")

    echo -e "\n${GREEN}Selected:${NC} $new_level"
    PAQET_DEFAULT_LOG_LEVEL="$new_level"
    save_manager_settings
    print_success "Default log level saved to: $MANAGER_SETTINGS_FILE"

    read -p "Apply this log level to ALL existing Paqet configs now? (Y/n): " apply_choice
    apply_choice="${apply_choice:-Y}"

    if [[ "$apply_choice" =~ ^[Yy]$ ]]; then
        local configs=()
        while IFS= read -r -d '' file; do
            configs+=("$file")
        done < <(find "$CONFIG_DIR" -name "*.yaml" -type f -print0 2>/dev/null)

        if [[ ${#configs[@]} -eq 0 ]]; then
            print_warning "No YAML configs found in $CONFIG_DIR"
        else
            echo -e "\n${YELLOW}Updating ${#configs[@]} config(s)...${NC}"
            local modified=0
            for config in "${configs[@]}"; do
                local config_name
                config_name=$(basename "$config" .yaml)
                if cfg_set_log_level "$config" "$new_level"; then
                    echo -e " ${GREEN}✓${NC} Updated $config_name"
                    ((modified++))
                else
                    echo -e " ${RED}✗${NC} Failed $config_name"
                fi
            done
            echo -e "\n${GREEN}✅ Log level set to '$new_level' on $modified configuration(s)${NC}"
        fi

        read -p "Restart all Paqet services to apply changes? (y/N): " restart_choice
        if [[ "$restart_choice" =~ ^[Yy]$ ]]; then
            local services=()
            mapfile -t services < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null |
                                  grep -E '^paqet-.*\.service' | awk '{print $1}' || true)
            restart_all_services "${services[@]}"
        fi
    fi

    pause
}

configure_log_cleanup_settings() {
    clear
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Setup / Configure Auto Log Cleanup${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}\n"

    load_manager_settings

    echo -e "${CYAN}This will create/enable a systemd timer that runs daily and:${NC}"
    echo -e "  • Rotates + vacuums the systemd journal (prevents disk fill)"
    echo -e "  • Trims Telegram bot log file to keep it small (if exists)"
    echo ""

    echo -e "${CYAN}Current settings:${NC}"
    echo -e "  Journal vacuum time : ${GREEN}${PAQET_JOURNAL_VACUUM_TIME}${NC}"
    echo -e "  Journal max size    : ${GREEN}${PAQET_JOURNAL_VACUUM_SIZE}${NC}"
    echo ""

    local new_time new_size
    read -p "Journal retention time (example: 7d, 14d, 30d) [${PAQET_JOURNAL_VACUUM_TIME}]: " new_time
    read -p "Journal max size (example: 300M, 1G) [${PAQET_JOURNAL_VACUUM_SIZE}]: " new_size

    new_time="${new_time:-$PAQET_JOURNAL_VACUUM_TIME}"
    new_size="${new_size:-$PAQET_JOURNAL_VACUUM_SIZE}"

    PAQET_JOURNAL_VACUUM_TIME="$new_time"
    PAQET_JOURNAL_VACUUM_SIZE="$new_size"
    save_manager_settings

    setup_log_cleanup "false"

    read -p "Run cleanup once right now? (y/N): " run_now
    if [[ "$run_now" =~ ^[Yy]$ ]]; then
        systemctl start paqet-log-cleanup.service >/dev/null 2>&1 || true
        print_success "Cleanup executed. Check disk usage:"
        echo -e "  ${CYAN}journalctl --disk-usage${NC}"
    fi

    pause
}

# ================================================
# CONNECTION PROTECTION FUNCTIONS
# ================================================
apply_connection_protection() {
    clear
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Apply Connection Protection (Anti-RST + NOTRACK)${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}\n"
    
    print_step "Scanning active Paqet configurations..."
    
    local configs=()
    while IFS= read -r -d '' file; do
        configs+=("$file")
    done < <(find "$CONFIG_DIR" -name "*.yaml" -type f -print0 2>/dev/null)
    
    if [[ ${#configs[@]} -eq 0 ]]; then
        print_warning "No Paqet configuration files found in $CONFIG_DIR"
        pause
        return 1
    fi
    
    echo -e "${CYAN}Found ${#configs[@]} configuration(s)${NC}\n"
    
    local server_protected=0
    local client_protected=0
    local rules_added=0
    local rules_skipped=0
    
    for config in "${configs[@]}"; do
        local config_name=$(basename "$config" .yaml)
        local role=$(grep "^role:" "$config" | awk '{print $2}' | tr -d '"' 2>/dev/null)
        
        echo -n "  Processing $config_name (${role:-unknown})... "
        
        if [[ "$role" != "server" && "$role" != "client" ]]; then
            echo -e "${YELLOW}skipped (unknown role)${NC}"
            continue
        fi
        
        if [ "$role" = "server" ]; then
            # Server: extract listen port
            local port=$(grep -A5 "listen:" "$config" | grep "addr:" | \
                         sed -n 's/.*:\([0-9]*\)".*/\1/p' | head -1 | tr -d ' ')
            
            if ! validate_port "$port"; then
                echo -e "${YELLOW}⚠ No valid port found${NC}"
                continue
            fi
            
            # Apply protection rules (check before add)
            local added=0
            
            iptables -t raw -C PREROUTING -p tcp --dport "$port" -j NOTRACK 2>/dev/null || {
                iptables -t raw -A PREROUTING -p tcp --dport "$port" -j NOTRACK
                ((added++))
            }
            iptables -t raw -C OUTPUT -p tcp --sport "$port" -j NOTRACK 2>/dev/null || {
                iptables -t raw -A OUTPUT -p tcp --sport "$port" -j NOTRACK
                ((added++))
            }
            iptables -t mangle -C OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP 2>/dev/null || {
                iptables -t mangle -A OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP
                ((added++))
            }
            iptables -t mangle -C PREROUTING -p tcp --dport "$port" --tcp-flags RST RST -j DROP 2>/dev/null || {
                iptables -t mangle -A PREROUTING -p tcp --dport "$port" --tcp-flags RST RST -j DROP
                ((added++))
            }
            
            if [ $added -gt 0 ]; then
                echo -e "${GREEN}✓ Protected (port $port, $added new rules)${NC}"
                ((rules_added += added))
                ((server_protected++))
            else
                echo -e "${CYAN}already protected${NC}"
                ((rules_skipped++))
            fi
            
        elif [ "$role" = "client" ]; then
            # Client: extract server addr
            local server=$(grep -A2 "server:" "$config" | grep "addr:" | \
                           awk '{print $2}' | tr -d '"' | head -1)
            
            if [[ -z "$server" || ! "$server" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$ ]]; then
                echo -e "${YELLOW}⚠ Invalid or missing server address${NC}"
                continue
            fi
            
            local sip=$(echo "$server" | cut -d: -f1)
            local sport=$(echo "$server" | cut -d: -f2)
            
            if ! validate_ip "$sip" || ! validate_port "$sport"; then
                echo -e "${YELLOW}⚠ Invalid server address: $server${NC}"
                continue
            fi
            
            # Apply client-side protection
            local added=0
            
            iptables -t raw -C OUTPUT -p tcp -d "$sip" --dport "$sport" -j NOTRACK 2>/dev/null || {
                iptables -t raw -A OUTPUT -p tcp -d "$sip" --dport "$sport" -j NOTRACK
                ((added++))
            }
            iptables -t raw -C PREROUTING -p tcp -s "$sip" --sport "$sport" -j NOTRACK 2>/dev/null || {
                iptables -t raw -A PREROUTING -p tcp -s "$sip" --sport "$sport" -j NOTRACK
                ((added++))
            }
            iptables -t mangle -C OUTPUT -p tcp -d "$sip" --dport "$sport" --tcp-flags RST RST -j DROP 2>/dev/null || {
                iptables -t mangle -A OUTPUT -p tcp -d "$sip" --dport "$sport" --tcp-flags RST RST -j DROP
                ((added++))
            }
            iptables -t mangle -C PREROUTING -p tcp -s "$sip" --sport "$sport" --tcp-flags RST RST -j DROP 2>/dev/null || {
                iptables -t mangle -A PREROUTING -p tcp -s "$sip" --sport "$sport" --tcp-flags RST RST -j DROP
                ((added++))
            }
            
            if [ $added -gt 0 ]; then
                echo -e "${GREEN}✓ Protected (server $sip:$sport, $added new rules)${NC}"
                ((rules_added += added))
                ((client_protected++))
            else
                echo -e "${CYAN}already protected${NC}"
                ((rules_skipped++))
            fi
        fi
    done
    
    echo -e "\n${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Protection Summary:${NC}"
    echo -e " ${GREEN}✓${NC} Servers protected: $server_protected"
    echo -e " ${GREEN}✓${NC} Clients protected: $client_protected"
    echo -e " ${GREEN}✓${NC} New iptables rules added: $rules_added"
    echo -e " ${CYAN}i${NC} Rules already existed (skipped): $rules_skipped"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    
    # Save rules persistently
    if command -v iptables-save &>/dev/null; then
        mkdir -p /etc/iptables 2>/dev/null
        iptables-save > /etc/iptables/rules.v4 2>/dev/null && \
            print_success "Iptables rules saved to /etc/iptables/rules.v4"
        
        # Try netfilter-persistent if installed
        if command -v netfilter-persistent &>/dev/null; then
            netfilter-persistent save 2>/dev/null && \
                print_success "Rules saved via netfilter-persistent"
        fi
    else
        print_warning "iptables-save not found - rules not persisted after reboot"
    fi
    
    save_iptables

    echo ""
    read -p "Restart all Paqet services now? (y/N): " restart_choice
    if [[ "$restart_choice" =~ ^[Yy]$ ]]; then
        local services=()
        mapfile -t services < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null |
                              grep -E '^paqet-.*\.service' | awk '{print $1}' || true)
        
        for svc in "${services[@]}"; do
            systemctl restart "$svc" 2>/dev/null && \
                echo -e "  Restarted: ${CYAN}${svc%.service}${NC}"
        done
        
        if [[ ${#services[@]} -gt 0 ]]; then
            print_success "All Paqet services restarted"
        else
            print_info "No Paqet services found to restart"
        fi
    fi
    
    pause
    return 0
}
remove_connection_protection() {
    clear
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Remove Connection Protection Rules${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}\n"
    
    print_warning "This will remove all Paqet-related iptables protection rules."
    echo ""
    read -p "Are you sure? (y/N): " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_info "Operation cancelled"
        pause
        return
    fi
    
    local rules_removed=0
    
    # Find and remove all Paqet-related rules
    # Method 1: Remove rules based on port ranges (common paqet ports)
    for table in raw mangle; do
        # Get all rules in the table
        while IFS= read -r rule; do
            if [[ "$rule" == *"paqet"* ]] || [[ "$rule" == *"NOTRACK"* ]] || [[ "$rule" == *"RST"* ]]; then
                # This is a simplistic approach - better to track specific rules
                iptables -t "$table" -F 2>/dev/null && ((rules_removed+=10))
                break
            fi
        done < <(iptables -t "$table" -L 2>/dev/null | head -20)
    done
    
    # More precise: Flush only specific chains if we want to be careful
    iptables -t raw -F 2>/dev/null && ((rules_removed+=5))
    iptables -t mangle -F 2>/dev/null && ((rules_removed+=5))
    
    print_success "Removed protection rules (approx $rules_removed rules flushed)"
    
    # Save iptables rules (now empty)
    if command -v iptables-save &>/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/iptables.up.rules 2>/dev/null || true
        print_success "Iptables rules saved (protection removed)"
    fi
    
    pause
}

# ================================================
# MTU MANAGEMENT FUNCTIONS
# ================================================

set_global_mtu() {
    clear
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Set Global MTU for ALL Paqet Tunnels${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}\n"
    
    echo -e "${CYAN}MTU Recommendations:${NC}"
    echo -e " • 1500: Default Ethernet (may be detected/fragmented)"
    echo -e " • 1400: Good balance for most connections"
    echo -e " • 1350: Recommended for Iran (avoids fragmentation)"
    echo -e " • 1300: More stable in restricted networks"
    echo -e " • 1280: IPv6 minimum MTU (very stable)"
    echo -e " • 1200: Ultra stable for heavily filtered connections"
    echo ""
    
    local current_mtu=""
    local configs=()
    while IFS= read -r -d '' file; do
        configs+=("$file")
        # Try to get current MTU from first config
        if [ -z "$current_mtu" ]; then
            current_mtu=$(grep "mtu:" "$file" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"')
        fi
    done < <(find "$CONFIG_DIR" -name "*.yaml" -type f -print0 2>/dev/null)
    
    if [[ ${#configs[@]} -eq 0 ]]; then
        print_warning "No configuration files found in $CONFIG_DIR"
        pause
        return
    fi
    
    echo -e "${YELLOW}Current MTU:${NC} ${current_mtu:-Not set (using default)}"
    echo -e "${YELLOW}Total configs:${NC} ${#configs[@]}\n"
    
    local new_mtu=""
    while true; do
        read -p "Enter new MTU [1000-1500] (recommend 1280-1350): " input_mtu
        
        if [ -z "$input_mtu" ]; then
            print_error "MTU cannot be empty"
            continue
        fi
        
        if [[ "$input_mtu" =~ ^[0-9]+$ ]] && [ "$input_mtu" -ge 1000 ] && [ "$input_mtu" -le 1500 ]; then
            new_mtu="$input_mtu"
            break
        else
            print_error "Invalid MTU. Must be between 1000 and 1500"
        fi
    done
    
    echo -e "\n${YELLOW}Applying MTU $new_mtu to all configurations...${NC}"
    
    local modified=0
    for config in "${configs[@]}"; do
        local config_name=$(basename "$config" .yaml)
        
        # Check if file has mtu setting
        if grep -q "mtu:" "$config"; then
            # Update existing mtu
            sed -i "s/mtu:.*/mtu: $new_mtu/" "$config"
            echo -e " ${GREEN}✓${NC} Updated $config_name"
        else
            # Add mtu under kcp section
            if grep -q "kcp:" "$config"; then
                # Find kcp section and add mtu after it with proper indentation
                sed -i "/kcp:/a\    mtu: $new_mtu" "$config"
                echo -e " ${GREEN}✓${NC} Added mtu to $config_name"
            else
                # No kcp section? Add it at the end
                echo "" >> "$config"
                echo "transport:" >> "$config"
                echo "  kcp:" >> "$config"
                echo "    mtu: $new_mtu" >> "$config"
                echo -e " ${YELLOW}⚠${NC} Created kcp section in $config_name"
            fi
        fi
        ((modified++))
    done
    
    echo -e "\n${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✅ MTU set to $new_mtu on $modified configuration(s)${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}\n"
    
    echo -e "${YELLOW}Note: Changes are saved to config files but services are not restarted.${NC}"
    read -p "Restart all services now to apply changes? (y/N): " restart_choice
    
    if [[ "$restart_choice" =~ ^[Yy]$ ]]; then
        restart_all_services "${services[@]}"
    fi
    
    pause
}

test_mtu() {
    clear
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}MTU / Packet Loss Test${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}\n"    
    echo -e "${CYAN}This test checks different MTU sizes against target servers.${NC}"
    echo -e "${CYAN}Smaller MTUs are more stable but slightly slower.${NC}\n"

    local client_configs=()
    local server_ips=()
    local server_names=()

    while IFS= read -r -d '' file; do
        if grep -q "role:.*client" "$file" 2>/dev/null; then
            client_configs+=("$file")
            local config_name=$(basename "$file" .yaml)
            local server_line=$(grep -A2 "server:" "$file" | grep "addr:" | head -1)
            local server=$(echo "$server_line" | awk '{print $2}' | tr -d '"')
            
            if [ -n "$server" ]; then
                local sip=$(echo "$server" | cut -d: -f1)
                if validate_ip "$sip"; then
                    server_ips+=("$sip")
                    server_names+=("$config_name → $sip")
                fi
            fi
        fi
    done < <(find "$CONFIG_DIR" -name "*.yaml" -type f -print0 2>/dev/null)

    echo -e "${YELLOW}Select test target:${NC}"
    echo -e "────────────────────────────────────────────────────────────────"
    
    local menu_options=()
    local i=1

    echo -e " ${GREEN}[$i]${NC} Manual IP entry"
    menu_options+=("manual")
    ((i++))
    
    if [ ${#server_names[@]} -gt 0 ]; then
        echo -e "\n${CYAN}Detected client configurations:${NC}"
        for idx in "${!server_names[@]}"; do
            echo -e " ${GREEN}[$i]${NC} ${server_names[$idx]}"
            menu_options+=("client_$idx")
            ((i++))
        done
    fi

    echo -e "\n ${GREEN}[0]${NC} ↩️ Back"
    echo ""
    
    local target_ip=""
    local choice
    read -p "Choose option [0-$((i-1))]: " choice
    
    [ "$choice" = "0" ] && return
    
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -ge "$i" ]; then
        print_error "Invalid choice"
        pause
        return
    fi
    
    local selected="${menu_options[$((choice-1))]}"
    
    case "$selected" in
        "manual")
            echo -en "\n${YELLOW}Enter target IP address: ${NC}"
            read -r manual_ip
            manual_ip=$(echo "$manual_ip" | tr -d ' ')
            if validate_ip "$manual_ip"; then
                target_ip="$manual_ip"
                run_mtu_test "$target_ip" "Manual target: $manual_ip"
            else
                print_error "Invalid IP address"
                pause
                return
            fi
            ;;
        *)
            # Client selection
            if [[ "$selected" =~ ^client_([0-9]+)$ ]]; then
                local client_idx="${BASH_REMATCH[1]}"
                target_ip="${server_ips[$client_idx]}"
                run_mtu_test "$target_ip" "${server_names[$client_idx]}"
            fi
            ;;
    esac
    pause
}

run_mtu_test() {
    local target_ip="$1"
    local target_name="$2"
    local silent_mode="${3:-normal}"

    if [[ "$target_ip" == *":"* ]]; then
        target_ip=$(echo "$target_ip" | cut -d: -f1)
    fi
    
    if [ "$silent_mode" = "normal" ]; then
        clear
        echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}MTU Test for: $target_name${NC}"
        echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}\n"
    fi
    
    local test_results=()
    local best_mtu=""
    local best_loss=100
    local best_ping=""
    
    echo -e "${CYAN}┌──────────┬──────────────┬─────────────┬──────────────┬─────────────────┐${NC}"
    echo -e "${CYAN}│ MTU Size │ Payload Size │ Packet Loss │   Ping (ms)  │     Status      │${NC}"
    echo -e "${CYAN}├──────────┼──────────────┼─────────────┼──────────────┼─────────────────┤${NC}"
    
    local test_sizes=(
        "1472:1500"
        "1400:1428"
        "1350:1378"
        "1300:1328"
        "1280:1308"
        "1200:1228"
        "1100:1128"
        "1000:1028"
    )
    
    for test in "${test_sizes[@]}"; do
        local payload="${test%%:*}"
        local mtu="${test##*:}"
        local ping_output
        ping_output=$(ping -c 5 -W 1 -M do -s "$payload" "$target_ip" 2>&1)
        local loss="100"
        local avg_ping="-"
        local status

        if echo "$ping_output" | grep -q "0% packet loss"; then
            loss="0"
            if echo "$ping_output" | grep -q "rtt"; then
                avg_ping=$(echo "$ping_output" | grep "rtt" | awk -F'/' '{print $5}' | cut -d'.' -f1)
                [ -z "$avg_ping" ] && avg_ping=$(echo "$ping_output" | grep "rtt" | sed -n 's/.*= \([0-9.]*\)\/[0-9.]*\/[0-9.]*\/[0-9.]* ms.*/\1/p' | cut -d'.' -f1)
            fi
            status="${GREEN}✓ PERFECT${NC}"

            if [ "$mtu" -gt "${best_mtu:-0}" ]; then
                best_mtu="$mtu"
                best_loss="$loss"
                best_ping="$avg_ping"
            fi
            
        elif echo "$ping_output" | grep -q "[0-9]\+% packet loss"; then
            loss=$(echo "$ping_output" | grep -o "[0-9]\+% packet loss" | grep -o "[0-9]\+")
            if echo "$ping_output" | grep -q "rtt"; then
                avg_ping=$(echo "$ping_output" | grep "rtt" | awk -F'/' '{print $5}' | cut -d'.' -f1)
            fi
            
            if [ "$loss" -le 10 ]; then
                status="${GREEN}✓ GOOD${NC}"
                if [ -z "$best_mtu" ] || [ "$loss" -lt "$best_loss" ]; then
                    best_mtu="$mtu"
                    best_loss="$loss"
                    best_ping="$avg_ping"
                fi
            elif [ "$loss" -le 30 ]; then
                status="${YELLOW}⚠ FAIR${NC}"
                if [ -z "$best_mtu" ] || [ "$loss" -lt "$best_loss" ]; then
                    best_mtu="$mtu"
                    best_loss="$loss"
                    best_ping="$avg_ping"
                fi
            else
                status="${RED}✗ POOR${NC}"
            fi
            
        elif echo "$ping_output" | grep -q "packets transmitted" && echo "$ping_output" | grep -q "received"; then
            local transmitted received
            transmitted=$(echo "$ping_output" | grep -o "[0-9]\+ packets transmitted" | grep -o "[0-9]\+")
            received=$(echo "$ping_output" | grep -o "[0-9]\+ packets received" | grep -o "[0-9]\+")
            
            if [ -n "$transmitted" ] && [ -n "$received" ] && [ "$transmitted" -gt 0 ] 2>/dev/null; then
                loss=$(( (transmitted - received) * 100 / transmitted ))
                
                if echo "$ping_output" | grep -q "rtt"; then
                    avg_ping=$(echo "$ping_output" | grep "rtt" | awk -F'/' '{print $5}' | cut -d'.' -f1)
                fi
                
                if [ "$loss" -eq 0 ]; then
                    status="${GREEN}✓ PERFECT${NC}"
                    if [ "$mtu" -gt "${best_mtu:-0}" ]; then
                        best_mtu="$mtu"
                        best_loss="$loss"
                        best_ping="$avg_ping"
                    fi
                elif [ "$loss" -le 10 ]; then
                    status="${GREEN}✓ GOOD${NC}"
                    if [ -z "$best_mtu" ] || [ "$loss" -lt "$best_loss" ]; then
                        best_mtu="$mtu"
                        best_loss="$loss"
                        best_ping="$avg_ping"
                    fi
                elif [ "$loss" -le 30 ]; then
                    status="${YELLOW}⚠ FAIR${NC}"
                    if [ -z "$best_mtu" ] || [ "$loss" -lt "$best_loss" ]; then
                        best_mtu="$mtu"
                        best_loss="$loss"
                        best_ping="$avg_ping"
                    fi
                else
                    status="${RED}✗ POOR${NC}"
                fi
            else
                status="${RED}✗ FAILED${NC}"
            fi
        else
            status="${RED}✗ FAILED${NC}"
        fi
        
        test_results+=("$mtu:$loss:$avg_ping")

        printf "│ %-8s │ %-12s │ " "$mtu" "$payload"
        printf "%-11s │ " "${loss}%"
        printf "%-12s │ " "$avg_ping"
        echo -e " $status      │"
    done
    
    echo -e "${CYAN}└──────────┴──────────────┴─────────────┴──────────────┴─────────────────┘${NC}\n"

    if [ -z "$best_mtu" ] || [ "$best_loss" -eq 100 ]; then
        local min_loss=100
        for result in "${test_results[@]}"; do
            local mtu=$(echo "$result" | cut -d: -f1)
            local loss=$(echo "$result" | cut -d: -f2)
            if [[ "$loss" =~ ^[0-9]+$ ]] && [ "$loss" -lt "$min_loss" ]; then
                min_loss="$loss"
                best_mtu="$mtu"
                best_loss="$loss"
            fi
        done
    fi
    
    if [ "$silent_mode" = "normal" ]; then
        echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}Recommendations for $target_name${NC}"
        echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}\n"
        
        if [ -n "$best_mtu" ] && [ "$best_loss" -lt 100 ]; then
            if [ "$best_loss" -eq 0 ]; then
                echo -e " ${GREEN}✓ Best MTU: $best_mtu (0% loss, ${best_ping:-?}ms)${NC}"
            else
                echo -e " ${YELLOW}⚠ Best MTU: $best_mtu (${best_loss}% loss, ${best_ping:-?}ms)${NC}"
            fi
            
            echo -e "\n${CYAN}Recommended MTU settings:${NC}"
            local recommended=""
            
            if [ "$best_mtu" -ge 1428 ]; then
                echo -e " • ${GREEN}Recommended: 1350${NC} (best balance)"
                recommended="1350"
            elif [ "$best_mtu" -ge 1378 ]; then
                echo -e " • ${GREEN}Recommended: 1350${NC} (stable)"
                recommended="1350"
            elif [ "$best_mtu" -ge 1308 ]; then
                echo -e " • ${GREEN}Recommended: 1300${NC} (very stable)"
                recommended="1300"
            elif [ "$best_mtu" -ge 1228 ]; then
                echo -e " • ${GREEN}Recommended: 1280${NC} (ultra stable)"
                recommended="1280"
            else
                echo -e " • ${GREEN}Recommended: 1200${NC} (maximum compatibility)"
                recommended="1200"
            fi
            
            echo ""
            read -p "Apply recommended MTU ($recommended) to this server's client config? (y/N): " apply_mtu
            
            if [[ "$apply_mtu" =~ ^[Yy]$ ]]; then
                local target_config=""
                while IFS= read -r -d '' file; do
                    if grep -q "$target_ip" "$file" 2>/dev/null; then
                        target_config="$file"
                        break
                    fi
                done < <(find "$CONFIG_DIR" -name "*.yaml" -type f -print0 2>/dev/null)
                
                if [ -n "$target_config" ]; then
                    local backup_file="${target_config}.backup-$(date +%Y%m%d-%H%M%S)"
                    cp "$target_config" "$backup_file"
                    print_info "Backup created: $(basename "$backup_file")"

                    if grep -q "mtu:" "$target_config"; then
                        sed -i "s/mtu:.*/mtu: $recommended/" "$target_config"
                    else
                        if grep -q "kcp:" "$target_config"; then
                            sed -i "/kcp:/a\    mtu: $recommended" "$target_config"
                        else
                            sed -i "/transport:/a \  kcp:\n    mtu: $recommended" "$target_config"
                        fi
                    fi
                    print_success "MTU set to $recommended in $(basename "$target_config")"

                    local config_name=$(basename "$target_config" .yaml)
                    local service_name="paqet-${config_name}.service"
                    
                    if systemctl list-unit-files 2>/dev/null | grep -q "$service_name"; then
                        echo ""
                        read -p "Restart this service now? (y/N): " restart_svc
                        if [[ "$restart_svc" =~ ^[Yy]$ ]]; then
                            systemctl restart "$service_name"
                            if systemctl is-active --quiet "$service_name"; then
                                print_success "Service restarted successfully"
                            else
                                print_error "Service failed to restart"
                            fi
                        fi
                    fi
                else
                    print_warning "Could not find config file for this server"
                fi
            fi
        else
            echo -e " ${RED}✗ No successful MTU test${NC}"
            echo -e " • The target server may be unreachable or blocking ICMP"
            echo -e " • Recommended MTU: 1200 (safe default)"
        fi
    fi
    
    if [ "$silent_mode" = "silent" ]; then
        local summary="SUMMARY: $target_name → Best MTU: ${best_mtu:-None} (${best_loss:-100}% loss)"
        echo "$summary"
        echo "BEST_MTU:${best_mtu:-1200}"
    fi
}

# Helper function to restart all services
restart_all_services() {
    local services=("$@")
    echo -e "\n${YELLOW}Restarting all Paqet services...${NC}"
    
    local success_count=0
    local fail_count=0
    
    for svc in "${services[@]}"; do
        local service_name="${svc%.service}"
        local display_name="${service_name#paqet-}"
        
        echo -n " Restarting $display_name... "
        
        if systemctl restart "$svc" >/dev/null 2>&1; then
            sleep 1
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                echo -e "${GREEN}✅ SUCCESS${NC}"
                ((success_count++))
            else
                echo -e "${RED}❌ FAILED (not running)${NC}"
                ((fail_count++))
            fi
        else
            echo -e "${RED}❌ FAILED${NC}"
            ((fail_count++))
        fi
    done
    
    echo -e "\n${CYAN}Results:${NC}"
    echo -e " ${GREEN}✅ Success:${NC} $success_count service(s)"
    echo -e " ${RED}❌ Failed:${NC} $fail_count service(s)"
}

# Helper function for live logs
live_log_all_services() {
    local services=("$@")
    echo -e "\n${YELLOW}Live Log Monitoring - All Paqet Tunnels${NC}"
    echo -e "────────────────────────────────────────────────────────────────"
    echo -e "${CYAN}Showing logs from all paqet services (Ctrl+C to exit)${NC}\n"
    sleep 2
    
    local journal_args=""
    for svc in "${services[@]}"; do
        journal_args="$journal_args -u $svc"
    done
    
    journalctl $journal_args -f --output=short-iso
    echo -e "\n${YELLOW}Returned from log monitoring${NC}"
    pause
}

# Helper function to delete all tunnels
delete_all_tunnels() {
    local services=("$@")
    echo -e "\n${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                          WARNING!                            ║${NC}"
    echo -e "${RED}║    This will delete ALL Paqet tunnels and configurations!    ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${YELLOW}Services to be deleted:${NC}"
    for svc in "${services[@]}"; do
        local service_name="${svc%.service}"
        local display_name="${service_name#paqet-}"
        echo -e " - ${CYAN}$display_name${NC}"
    done
    
    echo ""
    read -p "Are you ABSOLUTELY SURE? (type 'yes' to confirm): " confirm
    
    if [ "$confirm" != "yes" ]; then
        echo -e "${YELLOW}Operation cancelled.${NC}"
        pause
        return
    fi
    
    echo ""
    print_step "Stopping and removing all services..."
    
    local deleted_count=0
    
    for svc in "${services[@]}"; do
        local service_name="${svc%.service}"
        local display_name="${service_name#paqet-}"
        local config_file="$CONFIG_DIR/$display_name.yaml"
        
        echo -n " Removing $display_name... "
        
        remove_cronjob "$service_name" >/dev/null 2>&1 || true
        systemctl stop "$svc" >/dev/null 2>&1 || true
        systemctl disable "$svc" >/dev/null 2>&1 || true
        
        if [ -f "$SERVICE_DIR/$svc" ]; then
            rm -f "$SERVICE_DIR/$svc" >/dev/null 2>&1 || true
        fi
        
        if [ -f "$config_file" ]; then
            rm -f "$config_file" >/dev/null 2>&1 || true
        fi
        
        echo -e "${GREEN}✅ Removed${NC}"
        ((deleted_count++))
    done
    
    systemctl daemon-reload >/dev/null 2>&1
    
    echo -e "\n${CYAN}Results:${NC}"
    echo -e " ${GREEN}✅ Deleted:${NC} $deleted_count service(s)"
    print_success "All tunnels deleted successfully!"
    pause
}

# ================================================
# NAT PORT FORWARDING FUNCTIONS
# ================================================

ensure_ip_forwarding() {
    local current=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    if [ "$current" != "1" ]; then
        print_step "Enabling IP forwarding..."
        echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/30-ip_forward.conf
        sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
        sysctl --system > /dev/null 2>&1
        print_success "IP forwarding enabled"
    fi
}

add_nat_forward_multi_port() {
    clear
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Multi-Port NAT Forward${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}\n"
    
    echo -e "${CYAN}Forward specific ports (TCP+UDP) to a destination server${NC}"
    echo ""
    
    local dest_ip
    while true; do
        echo -e "${YELLOW}Enter destination server IP (e.g. 1.2.3.4). Press Enter to cancel:${NC}"
        read -p "> " dest_ip
        [ -z "$dest_ip" ] && { print_info "Cancelled."; pause; return 0; }
        if validate_ip "$dest_ip"; then
            break
        fi
        print_error "Invalid IP address format. Try again or press Enter to cancel."
    done
    
    local ports
    while true; do
        echo -e "${YELLOW}Enter ports to forward (comma-separated, e.g. 443,8443,2053):${NC}"
        read -p "> " ports
        [ -z "$ports" ] && { print_error "Ports required"; continue; }
        ports=$(echo "$ports" | tr -d ' ')
        if [[ "$ports" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
            break
        fi
        print_error "Invalid port format. Use comma-separated numbers (e.g. 443,8443)."
    done
    
    ensure_ip_forwarding
    
    print_step "Adding NAT forwarding rules: ports $ports -> $dest_ip ..."
    
    # TCP
    iptables -t nat -A PREROUTING -p tcp --match multiport --dports $ports -j DNAT --to-destination $dest_ip
    iptables -t nat -A POSTROUTING -p tcp --match multiport --dports $ports -j MASQUERADE
    # UDP
    iptables -t nat -A PREROUTING -p udp --match multiport --dports $ports -j DNAT --to-destination $dest_ip
    iptables -t nat -A POSTROUTING -p udp --match multiport --dports $ports -j MASQUERADE
    
    save_iptables
    print_success "NAT forwarding added: ports $ports -> $dest_ip (TCP+UDP)"
    pause
}

add_nat_forward_all_ports() {
    clear
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}All-Ports NAT Forward${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}\n"
    
    echo -e "${CYAN}Forward ALL ports to a destination, except specified exclusions${NC}"
    echo ""
    
    local relay_ip
    while true; do
        echo -e "${YELLOW}Enter THIS server's IP (relay IP). Press Enter to cancel:${NC}"
        read -p "> " relay_ip
        [ -z "$relay_ip" ] && { print_info "Cancelled."; pause; return 0; }
        if validate_ip "$relay_ip"; then
            break
        fi
        print_error "Invalid IP address format. Try again or press Enter to cancel."
    done
    
    local dest_ip
    while true; do
        echo -e "${YELLOW}Enter destination server IP. Press Enter to cancel:${NC}"
        read -p "> " dest_ip
        [ -z "$dest_ip" ] && { print_info "Cancelled."; pause; return 0; }
        if validate_ip "$dest_ip"; then
            break
        fi
        print_error "Invalid IP address format. Try again or press Enter to cancel."
    done
    
    local exclude_ports
    while true; do
        echo -e "${YELLOW}Enter ports to EXCLUDE (comma-separated, e.g. 22,80). Press Enter to cancel:${NC}"
        read -p "> " exclude_ports
        [ -z "$exclude_ports" ] && { print_info "Cancelled."; pause; return 0; }
        exclude_ports=$(echo "$exclude_ports" | tr -d ' ')
        if [[ "$exclude_ports" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
            break
        fi
        print_error "Invalid port format. Use comma-separated numbers (e.g. 22,80)."
    done
    
    # Warn about SSH
    if ! echo ",$exclude_ports," | grep -q ",22,"; then
        print_warning "⚠️  Port 22 (SSH) is NOT in your exclusion list!"
        echo -e "${RED}You may lose SSH access if port 22 is forwarded.${NC}"
        read -p "Continue without excluding port 22? (y/N): " skip_ssh_warn
        if [[ ! "$skip_ssh_warn" =~ ^[Yy]$ ]]; then
            print_info "Cancelled. Add port 22 to your exclusion list."
            pause
            return 1
        fi
    fi
    
    ensure_ip_forwarding
    
    print_step "Adding all-ports NAT forwarding to $dest_ip (excluding $exclude_ports)..."
    
    # First: redirect excluded ports back to this server (keeps them local)
    iptables -t nat -A PREROUTING -p tcp --match multiport --dports $exclude_ports -j DNAT --to-destination $relay_ip
    iptables -t nat -A PREROUTING -p udp --match multiport --dports $exclude_ports -j DNAT --to-destination $relay_ip
    # Then: catch-all forward everything else to destination
    iptables -t nat -A PREROUTING -p tcp -j DNAT --to-destination $dest_ip
    iptables -t nat -A PREROUTING -p udp -j DNAT --to-destination $dest_ip
    iptables -t nat -A POSTROUTING -j MASQUERADE
    
    save_iptables
    print_success "All-ports NAT forwarding added to $dest_ip (excluding $exclude_ports)"
    pause
}

view_nat_rules() {
    clear
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Current NAT Table Rules${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}\n"
    
    if iptables -t nat -L -v --line-numbers 2>/dev/null | grep -q "Chain"; then
        iptables -t nat -L -v --line-numbers 2>/dev/null || print_error "Failed to read NAT rules"
    else
        print_info "No NAT rules found"
    fi
    
    echo ""
    pause
}

remove_nat_forward_by_dest() {
    clear
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Remove NAT Forwarding Rules by Destination${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}\n"
    
    view_nat_rules
    echo ""
    
    echo -e "${YELLOW}Enter destination IP to remove rules for. Press Enter to cancel:${NC}"
    read -p "> " dest_ip
    if [ -z "$dest_ip" ]; then
        print_info "Cancelled."
        pause
        return 0
    fi
    
    if ! validate_ip "$dest_ip"; then
        print_error "Invalid IP address"
        pause
        return 1
    fi
    
    print_step "Removing NAT rules targeting $dest_ip..."
    
    local removed=0
    
    # Remove PREROUTING rules targeting this IP (reverse order to preserve line numbers)
    local pre_rules
    pre_rules=$(iptables -t nat -L PREROUTING --line-numbers -n 2>/dev/null | grep "to:${dest_ip}" | awk '{print $1}' | sort -rn)
    for num in $pre_rules; do
        iptables -t nat -D PREROUTING $num 2>/dev/null && ((removed++))
    done
    
    # Remove POSTROUTING rules that reference this IP (if any)
    local post_rules
    post_rules=$(iptables -t nat -L POSTROUTING --line-numbers -n 2>/dev/null | grep "to:${dest_ip}" | awk '{print $1}' | sort -rn)
    for num in $post_rules; do
        iptables -t nat -D POSTROUTING $num 2>/dev/null && ((removed++))
    done
    
    if [ $removed -gt 0 ]; then
        save_iptables
        print_success "Removed $removed NAT rule(s) targeting $dest_ip"
    else
        print_warning "No NAT rules found targeting $dest_ip"
    fi
    
    pause
}

flush_nat_rules() {
    clear
    echo -e "\n${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                     WARNING!                                  ║${NC}"
    echo -e "${RED}║         This will flush ALL iptables NAT rules!               ║${NC}"
    echo -e "${RED}║   Connection protection rules (raw/mangle) will NOT be affected${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}\n"
    
    read -p "Are you sure? (type 'yes' to confirm): " confirm
    if [ "$confirm" != "yes" ]; then
        print_info "Flush cancelled"
        pause
        return
    fi
    
    print_step "Flushing NAT table..."
    iptables -t nat -F
    iptables -t nat -X 2>/dev/null || true
    
    save_iptables
    print_success "All NAT rules flushed"
    
    echo ""
    read -p "Also disable IP forwarding? (y/N): " disable_fwd
    if [[ "$disable_fwd" =~ ^[Yy]$ ]]; then
        echo "net.ipv4.ip_forward=0" > /etc/sysctl.d/30-ip_forward.conf
        sysctl -w net.ipv4.ip_forward=0 > /dev/null 2>&1
        sysctl --system > /dev/null 2>&1
        print_success "IP forwarding disabled"
    fi
    
    pause
}

save_iptables() {
    if ! command -v iptables-save >/dev/null 2>&1; then
        print_warning "iptables-save not found - rules will NOT persist after reboot!"
        return 1
    fi

    mkdir -p /etc/iptables 2>/dev/null

    if iptables-save > /etc/iptables/rules.v4 2>/dev/null; then
        chmod 600 /etc/iptables/rules.v4 2>/dev/null
        print_success "iptables rules saved to /etc/iptables/rules.v4"
    else
        print_error "Failed to save iptables rules!"
        return 1
    fi

    # Try distribution-specific persistence tools
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 && \
            print_info "Rules also saved via netfilter-persistent"
    elif command -v service >/dev/null 2>&1 && systemctl is-active iptables >/dev/null 2>&1; then
        service iptables save >/dev/null 2>&1 && \
            print_info "Rules saved via iptables service"
    fi

    return 0
}

# ================================================
# UNINSTALL & UTILITY FUNCTIONS
# ================================================

# Uninstall Paqet
uninstall_paqet() {
    clear
    show_banner
    echo -e "${RED}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║ Uninstall Paqet                                          ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════╝${NC}\n"
    
    read -p "Are you sure? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        return
    fi
    
    print_step "Stopping services..."
    
    local services=()
    mapfile -t services < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null |
                          grep -E '^paqet-.*\.service' | awk '{print $1}' || true)
    
    for service in "${services[@]}"; do
        systemctl stop "$service" 2>/dev/null || true
        systemctl disable "$service" 2>/dev/null || true
        rm -f "$SERVICE_DIR/$service" 2>/dev/null || true
    done
    
    for service in "${services[@]}"; do
        local service_name="${service%.service}"
        remove_cronjob "$service_name" 2>/dev/null || true
    done
    
    systemctl daemon-reload
    
    print_step "Removing files..."
    rm -f "$BIN_DIR/paqet" 2>/dev/null || true
    
    read -p "Remove configuration files? (y/N): " remove_configs
    if [[ "$remove_configs" =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR" 2>/dev/null || true
        rm -rf "$INSTALL_DIR" 2>/dev/null || true
        print_success "All files removed"
    else
        print_info "Configuration preserved in $CONFIG_DIR/"
    fi
    
    print_success "✅ Paqet uninstalled"
    pause
    return
}
# ================================================
# TELEGRAM BOT CONFIGURATION
# ================================================

readonly BOT_CONFIG_DIR="/etc/telegram-paqet-bot"
readonly BOT_CONFIG_FILE="$BOT_CONFIG_DIR/config.conf"
readonly BOT_LOG_FILE="/var/log/telegram-paqet-bot.log"
readonly BOT_SERVICE="telegram-paqet-bot"
readonly BOT_SCRIPT="/usr/local/bin/telegram-paqet-bot"

# ================================================
# BOT CORE FUNCTIONS
# ================================================

# Read yes/no confirmation
read_confirm() {
    local prompt="$1"
    local varname="$2"
    local default="$3"
    local value=""
    
    while true; do
        if [ "$default" = "y" ]; then
            echo -e "${YELLOW}${prompt} (Y/n):${NC}"
        elif [ "$default" = "n" ]; then
            echo -e "${YELLOW}${prompt} (y/N):${NC}"
        else
            echo -e "${YELLOW}${prompt} (y/n):${NC}"
        fi
        read -p "> " value < /dev/tty
        
        if [ -z "$value" ] && [ -n "$default" ]; then
            value="$default"
        fi
        
        case "$value" in
            [Yy]|[Yy][Ee][Ss]) eval "$varname=true"; return 0 ;;
            [Nn]|[Nn][Oo]) eval "$varname=false"; return 0 ;;
            *) print_error "Please enter 'y' for yes or 'n' for no."; echo "" ;;
        esac
    done
}

# Initialize bot configuration
init_bot_config() {
    mkdir -p "$BOT_CONFIG_DIR"
    if [ ! -f "$BOT_CONFIG_FILE" ]; then
        cat > "$BOT_CONFIG_FILE" << EOF
# Paqet Telegram Bot Configuration
# Last updated: $(date)
BOT_TOKEN=""
CHAT_ID=""
ENABLE_BOT="false"
ENABLE_BOOT_REPORT="true"
ENABLE_SERVICE_WATCH="true"
WATCH_INTERVAL="60"
SOCKS5_PROXY=""
USE_SOCKS5="false"
EOF
        chmod 600 "$BOT_CONFIG_FILE"
        print_success "Bot configuration created at $BOT_CONFIG_FILE"
    fi
}

# Load bot configuration
load_bot_config() {
    if [ -f "$BOT_CONFIG_FILE" ]; then
        source "$BOT_CONFIG_FILE"
    else
        BOT_TOKEN=""
        CHAT_ID=""
        ENABLE_BOT="false"
        ENABLE_BOOT_REPORT="true"
        ENABLE_SERVICE_WATCH="true"
        WATCH_INTERVAL="60"
        SOCKS5_PROXY=""
        USE_SOCKS5="false"
    fi
}

# Save bot configuration
save_bot_config() {
    cat > "$BOT_CONFIG_FILE" << EOF
# Paqet Telegram Bot Configuration
# Last updated: $(date)
BOT_TOKEN="$BOT_TOKEN"
CHAT_ID="$CHAT_ID"
ENABLE_BOT="$ENABLE_BOT"
ENABLE_BOOT_REPORT="$ENABLE_BOOT_REPORT"
ENABLE_SERVICE_WATCH="$ENABLE_SERVICE_WATCH"
WATCH_INTERVAL="$WATCH_INTERVAL"
SOCKS5_PROXY="$SOCKS5_PROXY"
USE_SOCKS5="$USE_SOCKS5"
EOF
    chmod 600 "$BOT_CONFIG_FILE"
    print_success "Bot configuration saved"
}

# ================================================
# Detect SOCKS5 proxy from client configs
# ================================================
detect_socks5_proxy() {
    local socks5_found=""
    local socks5_port=""
    echo "Checking Paqet client configs for SOCKS5 proxy..." >> "$BOT_LOG_FILE"
    
    # Find all client configs
    while IFS= read -r -d '' file; do
        if grep -q "role:.*client" "$file" 2>/dev/null; then
            local config_name=$(basename "$file" .yaml)
            echo "Checking client: $config_name" >> "$BOT_LOG_FILE"
            
            # Look for socks5 section
            if grep -q "socks5:" "$file"; then
                # Extract port from socks5 listen address
                socks5_port=$(grep -A2 "socks5:" "$file" | grep "listen:" | grep -oE ':[0-9]+' | tr -d ':' | head -1)
                
                if [ -n "$socks5_port" ]; then
                    socks5_found="127.0.0.1:$socks5_port"
                    echo "Found SOCKS5 proxy in $config_name on port $socks5_port" >> "$BOT_LOG_FILE"
                    break
                fi
            fi
        fi
    done < <(find "$CONFIG_DIR" -name "*.yaml" -type f -print0 2>/dev/null)
    echo "$socks5_found"
}

# ================================================
# Add SOCKS5 to first client if not exists
# ================================================
add_socks5_to_client() {
    local first_client=""
    local client_file=""
    local result=""
    
    # Find first client config
    while IFS= read -r -d '' file; do
        if grep -q "role:.*client" "$file" 2>/dev/null; then
            first_client=$(basename "$file" .yaml)
            client_file="$file"
            break
        fi
    done < <(find "$CONFIG_DIR" -name "*.yaml" -type f -print0 2>/dev/null)
    
    if [ -n "$client_file" ]; then
        echo "Adding SOCKS5 proxy to client: $first_client" >> "$BOT_LOG_FILE"
        
        # Check if socks5 section already exists
        if grep -q "socks5:" "$client_file"; then
            echo "SOCKS5 already exists in this config" >> "$BOT_LOG_FILE"
            # Extract existing port
            local existing_port=$(grep -A2 "socks5:" "$client_file" | grep "listen:" | grep -oE ':[0-9]+' | tr -d ':' | head -1)
            result="127.0.0.1:$existing_port"
        else
            # Add socks5 section before network or at the end
            if grep -q "network:" "$client_file"; then
                # Insert before network section
                sed -i '/network:/i\
socks5:\
  - listen: "127.0.0.1:1080"\
' "$client_file"
            else
                # Add at the end
                echo "" >> "$client_file"
                echo "socks5:" >> "$client_file"
                echo "  - listen: \"127.0.0.1:1080\"" >> "$client_file"
            fi
            echo "SOCKS5 proxy added to $first_client on port 1080" >> "$BOT_LOG_FILE"
            
            # Restart the client service
            systemctl restart "paqet-$first_client" 2>/dev/null
            echo "Service paqet-$first_client restarted" >> "$BOT_LOG_FILE"
            
            result="127.0.0.1:1080"
        fi
    fi
    echo "$result"
}

# Send Telegram message with multiple fallbacks
send_telegram_message() {
    local message="$1"
    local parse_mode="${2:-HTML}"
    
    if [ "$ENABLE_BOT" != "true" ] || [ -z "$BOT_TOKEN" ] || [ -z "$CHAT_ID" ]; then
        return 1
    fi

    message=$(echo -e "$message" | sed 's/"/\\"/g')
    
    local success=1
    local response
    
    # ============================================
    # METHOD 1: Through detected SOCKS5 proxy
    # ============================================
    if [ "$USE_SOCKS5" = "true" ] && [ -n "$SOCKS5_PROXY" ]; then
        response=$(curl -s --max-time 8 --socks5-hostname "$SOCKS5_PROXY" \
            -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
            -H "Content-Type: application/json" \
            -d "$(printf '{"chat_id":"%s","text":"%s","parse_mode":"%s"}' "$CHAT_ID" "$message" "$parse_mode")" 2>&1)
        
        if echo "$response" | grep -q '"ok":true'; then
            success=0
            echo "[$(date)] Message sent via SOCKS5 proxy" >> "$BOT_LOG_FILE"
        fi
    fi
    
    # ============================================
    # METHOD 2: Through behzad.workers.dev (Proxy)
    # ============================================
    if [ $success -ne 0 ]; then
        response=$(curl -s --max-time 8 \
            -X POST "https://telegram.behzad.workers.dev/bot$BOT_TOKEN/sendMessage" \
            -H "Content-Type: application/json" \
            -d "$(printf '{"chat_id":"%s","text":"%s","parse_mode":"%s"}' "$CHAT_ID" "$message" "$parse_mode")" 2>&1)
        
        if echo "$response" | grep -q '"ok":true'; then
            success=0
            echo "[$(date)] Message sent via behzad.workers.dev" >> "$BOT_LOG_FILE"
        fi
    fi
    
    # ============================================
    # METHOD 3: Direct connection (No proxy)
    # ============================================
    if [ $success -ne 0 ]; then
        response=$(curl -s --max-time 5 \
            -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
            -H "Content-Type: application/json" \
            -d "$(printf '{"chat_id":"%s","text":"%s","parse_mode":"%s"}' "$CHAT_ID" "$message" "$parse_mode")" 2>&1)
        
        if echo "$response" | grep -q '"ok":true'; then
            success=0
            echo "[$(date)] Message sent directly" >> "$BOT_LOG_FILE"
        fi
    fi
    
    # ============================================
    # METHOD 4: Through workers.dev with URL-encoded (Last resort)
    # ============================================
    if [ $success -ne 0 ]; then
        response=$(curl -s --max-time 8 \
            -X POST "https://telegram.behzad.workers.dev/bot$BOT_TOKEN/sendMessage" \
            --data-urlencode "chat_id=$CHAT_ID" \
            --data-urlencode "text=$message" \
            --data-urlencode "parse_mode=$parse_mode" 2>&1)
        
        if echo "$response" | grep -q '"ok":true'; then
            success=0
            echo "[$(date)] Message sent via workers.dev (URL-encoded)" >> "$BOT_LOG_FILE"
        fi
    fi
    
    if [ $success -eq 0 ]; then
        return 0
    else
        echo "[$(date)] Failed to send message. Last response: $response" >> "$BOT_LOG_FILE"
        return 1
    fi
}

# Debug function
print_debug() {
    if [ "$BOT_DEBUG" = "true" ]; then
        echo "[DEBUG] $1" >> "$BOT_LOG_FILE"
    fi
}

# Create bot main script
create_bot_script() {
    cat > "$BOT_SCRIPT" << 'EOF'
#!/bin/bash

# Paqet Telegram Bot - Control Panel + Optional Monitor
# Auto-generated by Paqet Manager (embedded)

BOT_CONFIG="/etc/telegram-paqet-bot/config.conf"
LOG_FILE="/var/log/telegram-paqet-bot.log"
LAST_STATE_FILE="/etc/telegram-paqet-bot/last_state"
OFFSET_FILE="/etc/telegram-paqet-bot/offset"
PENDING_FILE="/etc/telegram-paqet-bot/pending"
PAQET_CONFIG_DIR="/etc/paqet"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

need_bin() {
    command -v "$1" >/dev/null 2>&1
}

load_config() {
    if [ -f "$BOT_CONFIG" ]; then
        # shellcheck disable=SC1090
        source "$BOT_CONFIG"
    else
        log "ERROR: Config file not found at $BOT_CONFIG"
        exit 1
    fi

    : "${BOT_TOKEN:=}"
    : "${CHAT_ID:=}"
    : "${ENABLE_BOT:=false}"
    : "${ENABLE_BOOT_REPORT:=true}"
    : "${ENABLE_SERVICE_WATCH:=true}"
    : "${WATCH_INTERVAL:=60}"
    : "${SOCKS5_PROXY:=}"
    : "${USE_SOCKS5:=false}"
}

tg_base_urls() {
    # Direct Telegram API (recommended for inline keyboards)
    echo "https://api.telegram.org/bot${BOT_TOKEN}"
}

tg_post_json() {
    # Usage: tg_post_json METHOD JSON_PAYLOAD
    local method="$1"
    local payload="$2"
    local response=""
    local ok=1

    # 1) SOCKS5 (if enabled)
    if [ "${USE_SOCKS5}" = "true" ] && [ -n "${SOCKS5_PROXY}" ]; then
        response=$(curl -4 -s --max-time 12 --socks5-hostname "${SOCKS5_PROXY}" \
            -X POST "https://api.telegram.org/bot${BOT_TOKEN}/${method}" \
            -H "Content-Type: application/json" \
            -d "$payload" 2>&1) || true
        if echo "$response" | grep -q '"ok":true'; then
            ok=0
        fi
    fi

    # 2) Try bases (workers + direct) without proxy
    if [ $ok -ne 0 ]; then
        while read -r base; do
            response=$(curl -4 -s --max-time 12 \
                -X POST "${base}/${method}" \
                -H "Content-Type: application/json" \
                -d "$payload" 2>&1) || true
            if echo "$response" | grep -q '"ok":true'; then
                ok=0
                break
            fi
        done < <(tg_base_urls)
    fi

    echo "$response"
    return $ok
}

tg_get() {
    # Usage: tg_get METHOD?querystring
    local method_qs="$1"
    local response=""
    local ok=1

    if [ "${USE_SOCKS5}" = "true" ] && [ -n "${SOCKS5_PROXY}" ]; then
        response=$(curl -4 -s --max-time 25 --socks5-hostname "${SOCKS5_PROXY}" \
            "https://api.telegram.org/bot${BOT_TOKEN}/${method_qs}" 2>&1) || true
        if echo "$response" | grep -q '"ok":true'; then
            ok=0
        fi
    fi

    if [ $ok -ne 0 ]; then
        while read -r base; do
            response=$(curl -4 -s --max-time 25 "${base}/${method_qs}" 2>&1) || true
            if echo "$response" | grep -q '"ok":true'; then
                ok=0
                break
            fi
        done < <(tg_base_urls)
    fi

    echo "$response"
    return $ok
}

send_message() {
    local chat_id="$1"
    local text="$2"
    local reply_markup_json="${3:-}"
    local parse_mode="${4:-HTML}"

    [ -z "$chat_id" ] && return 1

    local payload
    if [ -n "$reply_markup_json" ]; then
        payload=$(jq -nc --arg chat_id "$chat_id" --arg text "$text" --arg pm "$parse_mode" --argjson rm "$reply_markup_json" \
            '{chat_id:$chat_id,text:$text,parse_mode:$pm,reply_markup:$rm,disable_web_page_preview:true}')
    else
        payload=$(jq -nc --arg chat_id "$chat_id" --arg text "$text" --arg pm "$parse_mode" \
            '{chat_id:$chat_id,text:$text,parse_mode:$pm,disable_web_page_preview:true}')
    fi
    tg_post_json "sendMessage" "$payload" >/dev/null || log "sendMessage failed"
}

edit_message() {
    local chat_id="$1"
    local message_id="$2"
    local text="$3"
    local reply_markup_json="${4:-}"
    local parse_mode="${5:-HTML}"

    local payload
    if [ -n "$reply_markup_json" ]; then
        payload=$(jq -nc --arg chat_id "$chat_id" --arg text "$text" --arg pm "$parse_mode" --arg message_id "$message_id" --argjson rm "$reply_markup_json" \
            '{chat_id:$chat_id,message_id:($message_id|tonumber),text:$text,parse_mode:$pm,reply_markup:$rm,disable_web_page_preview:true}')
    else
        payload=$(jq -nc --arg chat_id "$chat_id" --arg text "$text" --arg pm "$parse_mode" --arg message_id "$message_id" \
            '{chat_id:$chat_id,message_id:($message_id|tonumber),text:$text,parse_mode:$pm,disable_web_page_preview:true}')
    fi
    tg_post_json "editMessageText" "$payload" >/dev/null || log "editMessageText failed"
}

answer_callback() {
    local cb_id="$1"
    local text="${2:-}"
    local alert="${3:-false}"

    local payload
    payload=$(jq -nc --arg cb_id "$cb_id" --arg text "$text" --argjson alert "$alert" \
        '{callback_query_id:$cb_id,text:$text,show_alert:$alert}')
    tg_post_json "answerCallbackQuery" "$payload" >/dev/null || true
}

# -----------------------------
# Paqet helpers
# -----------------------------
list_paqet_services() {
    systemctl list-unit-files --type=service --no-legend "paqet*" 2>/dev/null \
        | awk '{print $1}' \
        | sed '/^$/d'
}

normalize_unit() {
    local u="$1"
    if [[ "$u" != *.service ]]; then
        echo "${u}.service"
    else
        echo "$u"
    fi
}

html_escape() {
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# -----------------------------
# Config edit helpers (stateful)
# -----------------------------
pending_get() { [ -f "$PENDING_FILE" ] && cat "$PENDING_FILE" || echo ""; }
pending_set() { echo "$1" > "$PENDING_FILE"; }
pending_clear() { rm -f "$PENDING_FILE" 2>/dev/null || true; }

cfg_name_from_unit() {
    local u="${1%.service}"
    echo "${u#paqet-}"
}
cfg_file_from_unit() {
    echo "${PAQET_CONFIG_DIR}/$(cfg_name_from_unit "$1").yaml"
}

is_valid_port() {
    local p="$1"
    [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ]
}

is_valid_ip() {
    local ip="$1"
    [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    read -r o1 o2 o3 o4 <<< "$ip"
    for o in "$o1" "$o2" "$o3" "$o4"; do
        [[ "$o" -ge 0 && "$o" -le 255 ]] || return 1
    done
    return 0
}

cfg_role() {
    local f="$1"
    local r
    r=$(grep -m1 '^role:' "$f" 2>/dev/null | awk '{print $2}' | tr -d '"')
    echo "${r:-unknown}"
}

cfg_get_listen_port() {
    local f="$1"
    awk '
        /^listen:[[:space:]]*$/ {in_listen=1; next}
        in_listen && /^[[:space:]]{2}addr:/ {
            gsub(/.*":/,""); gsub(/".*/,""); print; exit
        }
        /^[^[:space:]]/ {in_listen=0}
    ' "$f" 2>/dev/null
}

cfg_get_server_addr() {
    local f="$1"
    awk '
        /^server:[[:space:]]*$/ {in_srv=1; next}
        in_srv && /^[[:space:]]{2}addr:/ {
            gsub(/.*"/,""); gsub(/".*/,""); print; exit
        }
        /^[^[:space:]]/ {in_srv=0}
    ' "$f" 2>/dev/null
}

cfg_get_forward_summary() {
    local f="$1"
    awk '
        /^forward:[[:space:]]*$/ {in_fwd=1; next}
        in_fwd && /^[^[:space:]]/ {exit}
        in_fwd && /listen:/ {
            if (match($0, /:([0-9]+)"/, m)) { port=m[1] }
        }
        in_fwd && /protocol:/ {
            proto=$2; gsub(/"/,"",proto)
            if (port!="") { print port "/" proto }
            port=""
        }
    ' "$f" 2>/dev/null | paste -sd, - 2>/dev/null
}

# Minimal iptables NOTRACK helper (best-effort)
iptables_add_notrack() {
    local port="$1"
    local proto="$2"

    command -v iptables >/dev/null 2>&1 || return 0
    [ -z "$port" ] && return 0

    local protos=()
    [ "$proto" = "both" ] && protos=("tcp" "udp") || protos=("$proto")

    for p in "${protos[@]}"; do
        iptables -t raw -D PREROUTING -p "$p" --dport "$port" -j NOTRACK 2>/dev/null || true
        iptables -t raw -D OUTPUT -p "$p" --sport "$port" -j NOTRACK 2>/dev/null || true
        iptables -t raw -A PREROUTING -p "$p" --dport "$port" -j NOTRACK 2>/dev/null || true
        iptables -t raw -A OUTPUT -p "$p" --sport "$port" -j NOTRACK 2>/dev/null || true

        if [ "$p" = "tcp" ]; then
            iptables -t mangle -D OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP 2>/dev/null || true
            iptables -t mangle -A OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP 2>/dev/null || true
        fi
    done

    # Persistence (best effort)
    if [ -d /etc/iptables ] && command -v iptables-save >/dev/null 2>&1; then
        mkdir -p /etc/iptables 2>/dev/null || true
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        chmod 600 /etc/iptables/rules.v4 2>/dev/null || true
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1 || true
        elif command -v service >/dev/null 2>&1 && systemctl is-active iptables >/dev/null 2>&1; then
            service iptables save >/dev/null 2>&1 || true
        fi
    fi
}

cfg_set_server_ip() {
    local f="$1"
    local newip="$2"
    local tmp
    tmp=$(mktemp)

    awk -v newip="$newip" '
        BEGIN{in_srv=0; done=0}
        /^server:[[:space:]]*$/ {print; in_srv=1; next}
        in_srv && /^[[:space:]]{2}addr:/ && done==0 {
            line=$0
            gsub(/.*"/,"",line); gsub(/".*/,"",line)
            # line now like host:port
            n=split(line, a, ":")
            port=a[n]
            printf "  addr: \"%s:%s\"\n", newip, port
            done=1
            next
        }
        /^[^[:space:]]/ {in_srv=0}
        {print}
    ' "$f" > "$tmp" && mv "$tmp" "$f"
}

cfg_set_server_port() {
    local f="$1"
    local newport="$2"
    local tmp
    tmp=$(mktemp)

    awk -v newport="$newport" '
        BEGIN{in_srv=0; done=0}
        /^server:[[:space:]]*$/ {print; in_srv=1; next}
        in_srv && /^[[:space:]]{2}addr:/ && done==0 {
            line=$0
            gsub(/.*"/,"",line); gsub(/".*/,"",line)
            n=split(line, a, ":")
            # host could include : if ipv6; we keep everything except last element
            host=""
            for (i=1;i<n;i++) { host = (host=="" ? a[i] : host ":" a[i]) }
            if (host=="") host=a[1]
            printf "  addr: \"%s:%s\"\n", host, newport
            done=1
            next
        }
        /^[^[:space:]]/ {in_srv=0}
        {print}
    ' "$f" > "$tmp" && mv "$tmp" "$f"
}

cfg_set_listen_port() {
    local f="$1"
    local newport="$2"
    local tmp
    tmp=$(mktemp)

    awk -v newport="$newport" '
        BEGIN{in_listen=0; in_net=0; in_ipv4=0}
        /^listen:[[:space:]]*$/ {print; in_listen=1; next}
        in_listen && /^[[:space:]]{2}addr:/ {
            print "  addr: \":" newport "\""
            in_listen=0
            next
        }

        /^network:[[:space:]]*$/ {print; in_net=1; in_ipv4=0; next}
        in_net && /^[[:space:]]{2}ipv4:[[:space:]]*$/ {print; in_ipv4=1; next}
        in_ipv4 && /^[[:space:]]{4}addr:/ {
            line=$0
            gsub(/.*"/,"",line); gsub(/".*/,"",line)
            split(line, a, ":")
            ip=a[1]
            printf "    addr: \"%s:%s\"\n", ip, newport
            in_ipv4=0
            next
        }

        /^[^[:space:]]/ {in_listen=0; in_net=0; in_ipv4=0}
        {print}
    ' "$f" > "$tmp" && mv "$tmp" "$f"
}

build_forward_section_file() {
    local spec="$1"
    local outfile="$2"
    local spec_clean
    spec_clean=$(echo "$spec" | tr -d '[:space:]')

    [ -z "$spec_clean" ] && return 1

    # Get tunnel port to prevent loops
    local server_addr tunnel_port
    server_addr="$(cfg_get_server_addr "$CFG_FILE_ACTIVE")"
    tunnel_port="${server_addr##*:}"

    echo "forward:" > "$outfile"

    IFS=',' read -ra items <<< "$spec_clean"
    local any=0
    for it in "${items[@]}"; do
        [ -z "$it" ] && continue
        local port proto
        port="$it"
        proto="tcp"
        if [[ "$it" == */* ]]; then
            port="${it%%/*}"
            proto="${it##*/}"
        fi
        proto="${proto,,}"
        case "$proto" in
            tcp|udp|both|tcpudp|tcp/udp) : ;;
            *) proto="tcp" ;;
        esac
        [ "$proto" = "tcpudp" ] && proto="both"
        [ "$proto" = "tcp/udp" ] && proto="both"

        is_valid_port "$port" || return 2

        # loop prevention: forward port must not equal tunnel port
        if [ -n "$tunnel_port" ] && [ "$port" = "$tunnel_port" ]; then
            return 3
        fi

        any=1
        if [ "$proto" = "both" ]; then
            cat >> "$outfile" <<EOFSEC
  - listen: "0.0.0.0:${port}"
    target: "127.0.0.1:${port}"
    protocol: "tcp"
  - listen: "0.0.0.0:${port}"
    target: "127.0.0.1:${port}"
    protocol: "udp"
EOFSEC
        else
            cat >> "$outfile" <<EOFSEC
  - listen: "0.0.0.0:${port}"
    target: "127.0.0.1:${port}"
    protocol: "${proto}"
EOFSEC
        fi
    done

    [ $any -eq 1 ] || return 1
    return 0
}

replace_forward_section() {
    local cfg="$1"
    local secfile="$2"
    local tmp
    tmp=$(mktemp)

    awk -v secfile="$secfile" '
        function printsec() {
            while ((getline l < secfile) > 0) print l
            close(secfile)
        }
        BEGIN{in_fwd=0; inserted=0}
        /^forward:[[:space:]]*$/ {
            if (!inserted) { printsec(); inserted=1 }
            in_fwd=1
            next
        }
        in_fwd==1 {
            # skip old forward block lines until next top-level key
            if ($0 ~ /^[^[:space:]]/) { in_fwd=0 }
            else { next }
        }
        (!inserted && /^network:[[:space:]]*$/) {
            printsec(); inserted=1
        }
        { print }
        END {
            if (!inserted) { printsec() }
        }
    ' "$cfg" > "$tmp" && mv "$tmp" "$cfg"
}


svc_status_detail() {
    local unit
    unit="$(normalize_unit "$1")"
    systemctl status "$unit" --no-pager -l 2>/dev/null | head -n 20 | html_escape
}



svc_state() { systemctl is-active "$1" 2>/dev/null || echo "unknown"; }
svc_enabled() { systemctl is-enabled "$1" 2>/dev/null || echo "unknown"; }

format_all_status() {
    local out="📊 <b>وضعیت سرویس‌ها</b>\n\n"
    local any=0
    while read -r u; do
        [ -z "$u" ] && continue
        any=1
        local st en
        st=$(svc_state "$u")
        en=$(svc_enabled "$u")
        if [ "$st" = "active" ]; then
            out+="✅ <b>${u}</b> — <code>${st}</code> | <code>${en}</code>\n"
        else
            out+="❌ <b>${u}</b> — <code>${st}</code> | <code>${en}</code>\n"
        fi
    done < <(list_paqet_services)
    [ $any -eq 0 ] && out+="⚠️ هیچ سرویس <code>paqet-*.service</code> پیدا نشد.\n"
    echo -e "$out"
}

# -----------------------------
# Cronjob helpers (per-service)
# -----------------------------
cron_expr_for() {
    local v="$1"
    if [[ "$v" =~ ^[0-9]+$ ]]; then
        if [ "$v" -ge 1 ] && [ "$v" -le 59 ]; then
            echo "*/${v} * * * *"
            return 0
        fi
    fi
    case "$v" in
        1min) echo "*/1 * * * *" ;;
        5min) echo "*/5 * * * *" ;;
        15min) echo "*/15 * * * *" ;;
        30min) echo "*/30 * * * *" ;;
        1hour) echo "0 */1 * * *" ;;
        12hour) echo "0 */12 * * *" ;;
        1day) echo "0 0 * * *" ;;
        *) echo "" ;;
    esac
}

cron_current() {
    local unit="$1"
    local cmd="systemctl restart ${unit%.service}"
    crontab -l 2>/dev/null | grep -F "$cmd" | head -1 || true
}

cron_set() {
    local unit="$1"
    local interval="$2"
    local expr
    expr=$(cron_expr_for "$interval")
    [ -z "$expr" ] && return 1

    local cmd="systemctl restart ${unit%.service}"
    local line="${expr} ${cmd}"

    if crontab -l 2>/dev/null | grep -Fq "$cmd"; then
        crontab -l 2>/dev/null | grep -Fv "$cmd" | crontab - 2>/dev/null || true
    fi
    (crontab -l 2>/dev/null; echo "$line") | crontab - 2>/dev/null
}

cron_remove() {
    local unit="$1"
    local cmd="systemctl restart ${unit%.service}"
    if crontab -l 2>/dev/null | grep -Fq "$cmd"; then
        crontab -l 2>/dev/null | grep -Fv "$cmd" | crontab - 2>/dev/null || true
        return 0
    fi
    return 1
}

# -----------------------------
# Keyboards (Inline buttons)
# -----------------------------
kb_main() {
    cat << 'JSON'
{"inline_keyboard":[
  [{"text":"🧰 سرویس‌ها","callback_data":"menu:services"},{"text":"📊 وضعیت کلی","callback_data":"menu:status"}],
  [{"text":"➕ بیشتر","callback_data":"menu:more"}]
]}
JSON
}

kb_back_home() {
    cat << 'JSON'
{"inline_keyboard":[
  [{"text":"🏠 منوی اصلی","callback_data":"menu:home"}]
]}
JSON
}

kb_more() {
    cat << 'JSON'
{"inline_keyboard":[
  [{"text":"🔁 daemon-reload","callback_data":"more:daemon_reload"}],
  [{"text":"✅ enable همه","callback_data":"more:enable_all"},{"text":"🚫 disable همه","callback_data":"more:disable_all"}],
  [{"text":"⬅️ بازگشت","callback_data":"menu:home"}]
]}
JSON
}

kb_services_list() {
    local units_json
    units_json="$(list_paqet_services | jq -R . | jq -s .)"

    jq -nc --argjson units "$units_json" '
        def rows($arr):
            [range(0; ($arr|length); 2) as $i |
                ($arr[$i:$i+2]
                    | map({
                        text: (.|rtrimstr(".service")),
                        callback_data: ("svc:" + . + ":menu")
                    })
                )
            ];
        {inline_keyboard: (rows($units) + [[{text:"🏠 منوی اصلی", callback_data:"menu:home"}]])}
    '
}

kb_service_panel() {
    local unit="$1"
    cat << JSON
{"inline_keyboard":[
  [{"text":"🟢 Start","callback_data":"svc:${unit}:start"},{"text":"🔴 Stop","callback_data":"svc:${unit}:stop"}],
  [{"text":"🔄 Restart","callback_data":"svc:${unit}:restart"},{"text":"📊 Status","callback_data":"svc:${unit}:status"}],
  [{"text":"⏰ Cronjob","callback_data":"cron:${unit}:menu"}],
  [{"text":"✏️ ویرایش کانفیگ","callback_data":"cfg:${unit}:menu"}],
  [{"text":"⬅️ لیست سرویس‌ها","callback_data":"menu:services"},{"text":"🏠 منوی اصلی","callback_data":"menu:home"}]
]}
JSON
}

kb_cron_panel() {
    local unit="$1"
    cat << JSON
{"inline_keyboard":[
  [{"text":"1min","callback_data":"cron:${unit}:set:1min"},{"text":"5min","callback_data":"cron:${unit}:set:5min"},{"text":"15min","callback_data":"cron:${unit}:set:15min"}],
  [{"text":"30min","callback_data":"cron:${unit}:set:30min"},{"text":"1hour","callback_data":"cron:${unit}:set:1hour"}],
  [{"text":"12hour","callback_data":"cron:${unit}:set:12hour"},{"text":"1day","callback_data":"cron:${unit}:set:1day"}],
  [{"text":"🗑 حذف کرونجاب","callback_data":"cron:${unit}:remove"}],
  [{"text":"⬅️ بازگشت","callback_data":"svc:${unit}:menu"},{"text":"🏠 منوی اصلی","callback_data":"menu:home"}]
]}
JSON
}

kb_cfg_menu() {
    local unit="$1"
    local cfg_file
    cfg_file="$(cfg_file_from_unit "$unit")"
    local role
    role="$(cfg_role "$cfg_file")"

    if [ "$role" = "client" ]; then
        cat << JSON
{"inline_keyboard":[
  [{"text":"🌍 تغییر IP سرور","callback_data":"cfg:${unit}:set:server_ip"},{"text":"🔌 تغییر پورت سرور","callback_data":"cfg:${unit}:set:server_port"}],
  [{"text":"🔀 ویرایش پورت‌های فوروارد","callback_data":"cfg:${unit}:set:forward_ports"}],
  [{"text":"⬅️ بازگشت","callback_data":"svc:${unit}:menu"},{"text":"🏠 منوی اصلی","callback_data":"menu:home"}]
]}
JSON
    elif [ "$role" = "server" ]; then
        cat << JSON
{"inline_keyboard":[
  [{"text":"🔌 تغییر پورت Listen","callback_data":"cfg:${unit}:set:listen_port"}],
  [{"text":"⬅️ بازگشت","callback_data":"svc:${unit}:menu"},{"text":"🏠 منوی اصلی","callback_data":"menu:home"}]
]}
JSON
    else
        cat << JSON
{"inline_keyboard":[
  [{"text":"⬅️ بازگشت","callback_data":"svc:${unit}:menu"},{"text":"🏠 منوی اصلی","callback_data":"menu:home"}]
]}
JSON
    fi
}

page_cfg_menu() {
    local unit="$1"
    local cfg_file
    cfg_file="$(cfg_file_from_unit "$unit")"
    local role
    role="$(cfg_role "$cfg_file")"

    local msg="✏️ <b>ویرایش کانفیگ</b>\n\n"
    msg+="🧰 سرویس: <code>${unit%.service}</code>\n"
    msg+="📄 فایل: <code>${cfg_file}</code>\n"
    msg+="🏷 نقش: <code>${role}</code>\n\n"

    if [ ! -f "$cfg_file" ]; then
        msg+="❌ فایل کانفیگ پیدا نشد.\n"
        echo -e "$msg"
        return
    fi

    if [ "$role" = "client" ]; then
        local srv
        srv="$(cfg_get_server_addr "$cfg_file")"
        local fwd
        fwd="$(cfg_get_forward_summary "$cfg_file")"
        msg+="🌐 Server: <code>${srv:-نامشخص}</code>\n"
        msg+="🔀 Forward: <code>${fwd:-ندارد}</code>\n\n"
        msg+="راهنما:\n"
        msg+="• برای تغییر IP/پورت سرور، دکمه‌ها رو بزن.\n"
        msg+="• برای فوروارد، فرمت: <code>443/tcp,53/udp,8443/both</code>\n"
        msg+="  (اگر /tcp یا /udp نذاری، پیش‌فرض tcp هست)\n"
        msg+="• برای لغو عملیات در حالت ورود، <code>لغو</code> یا <code>/cancel</code> بفرست.\n"
    elif [ "$role" = "server" ]; then
        local lp
        lp="$(cfg_get_listen_port "$cfg_file")"
        msg+="🔌 Listen Port: <code>${lp:-نامشخص}</code>\n\n"
        msg+="راهنما:\n"
        msg+="• تغییر پورت Listen باعث ری‌استارت سرویس میشه.\n"
        msg+="• برای لغو عملیات در حالت ورود، <code>لغو</code> یا <code>/cancel</code> بفرست.\n"
    else
        msg+="ℹ️ نقش نامشخصه؛ فقط می‌تونی برگردی.\n"
    fi

    echo -e "$msg"
}


# -----------------------------
# Render pages
# -----------------------------
page_home() {
    echo -e "🤖 <b>Paqet Control Panel</b>\n\n"\
"با دکمه‌ها می‌تونی سرویس‌ها رو مدیریت کنی.\n"\
"✅ Start/Stop/Restart\n"\
"⏰ Cronjob Auto-Restart\n\n"\
"برای شروع، یکی از گزینه‌ها رو بزن."
}

page_services() {
    echo -e "🧰 <b>انتخاب سرویس</b>\n\n"\
"یکی از سرویس‌های Paqet رو انتخاب کن:"
}

page_service() {
    local unit="$1"
    local st en
    st=$(svc_state "$unit")
    en=$(svc_enabled "$unit")
    local short="${unit%.service}"

    echo -e "🧰 <b>${short}</b>\n\n"\
"وضعیت: <code>${st}</code>\n"\
"Enabled: <code>${en}</code>\n\n"\
"عملیات رو انتخاب کن:"
}

page_cron() {
    local unit="$1"
    local short="${unit%.service}"
    local cur
    cur=$(cron_current "$unit")
    if [ -n "$cur" ]; then
        cur="✅ <code>${cur}</code>"
    else
        cur="❌ <i>کرونجاب فعال نیست</i>"
    fi
    echo -e "⏰ <b>Cronjob برای ${short}</b>\n\n"\
"وضعیت فعلی:\n${cur}\n\n"\
"یک بازه زمانی انتخاب کن یا حذفش کن:"
}

# -----------------------------
# Actions
# -----------------------------
do_service_action() {
    local unit="$1"
    unit="$(normalize_unit "$unit")"
    local action="$2"

    case "$action" in
        start|stop|restart) systemctl "$action" "$unit" >/dev/null 2>&1 || true ;;
        status) : ;;
        *) return 1 ;;
    esac
    return 0
}

# -----------------------------
# Monitoring (optional, lightweight)
# -----------------------------
state_read() {
    declare -gA STATE=()
    if [ -f "$LAST_STATE_FILE" ]; then
        while IFS='|' read -r u st; do
            [ -z "$u" ] && continue
            STATE["$u"]="$st"
        done < "$LAST_STATE_FILE"
    fi
}

state_write() {
    : > "$LAST_STATE_FILE"
    while read -r u; do
        [ -z "$u" ] && continue
        echo "${u}|$(svc_state "$u")" >> "$LAST_STATE_FILE"
    done < <(list_paqet_services)
}

check_services_changes() {
    state_read
    local changed=0
    local msg="🔔 <b>تغییر وضعیت سرویس‌ها</b>\n\n"
    while read -r u; do
        [ -z "$u" ] && continue
        local now prev
        now=$(svc_state "$u")
        prev="${STATE[$u]:-}"
        if [ -n "$prev" ] && [ "$now" != "$prev" ]; then
            changed=1
            msg+="• <b>${u}</b>: <code>${prev}</code> ➜ <code>${now}</code>\n"
        fi
    done < <(list_paqet_services)

    [ $changed -eq 1 ] && send_message "$CHAT_ID" "$msg" ""
    state_write
}

send_boot_report() {
    local host
    host=$(hostname)
    local up
    up=$(uptime -p 2>/dev/null || true)
    local msg="🚀 <b>Server Boot Report</b>\n\n🏷 <b>${host}</b>\n🕒 $(date '+%Y-%m-%d %H:%M:%S')\n⏱ ${up}"
    send_message "$CHAT_ID" "$msg" ""
}

# -----------------------------
# Updates loop
# -----------------------------
read_offset() { [ -f "$OFFSET_FILE" ] && cat "$OFFSET_FILE" || echo "0"; }
write_offset() { echo "$1" > "$OFFSET_FILE"; }

handle_message_text() {
    local chat_id="$1"
    local text="$2"

    [ "$chat_id" != "$CHAT_ID" ] && return 0

    # If we are in an edit flow, treat normal messages as input
    local pending
    pending="$(pending_get)"
    if [ -n "$pending" ]; then
        local trimmed
        trimmed="$(echo "$text" | tr -d '\r')"

        if [[ "${trimmed,,}" =~ ^(/cancel|cancel|لغو)$ ]]; then
            pending_clear
            send_message "$chat_id" "✅ <b>لغو شد</b>\n\nبرای ادامه /menu رو بفرست." "$(kb_main)"
            return 0
        fi

        IFS='|' read -r _p unit field <<< "$pending"
        unit="$(normalize_unit "$unit")"
        local cfg_file
        cfg_file="$(cfg_file_from_unit "$unit")"

        if [ ! -f "$cfg_file" ]; then
            pending_clear
            send_message "$chat_id" "❌ فایل کانفیگ پیدا نشد: <code>${cfg_file}</code>" "$(kb_main)"
            return 0
        fi

        # Make cfg file path available to forward builder
        CFG_FILE_ACTIVE="$cfg_file"

        case "$field" in
            server_ip)
                local newip
                newip="$(echo "$trimmed" | tr -d '[:space:]')"
                if ! is_valid_ip "$newip"; then
                    send_message "$chat_id" "❌ IP نامعتبره. مثال درست: <code>45.76.123.89</code>\nبرای لغو: <code>لغو</code>" ""
                    return 0
                fi
                cfg_set_server_ip "$cfg_file" "$newip"
                systemctl restart "$unit" >/dev/null 2>&1 || true
                pending_clear
                send_message "$chat_id" "✅ IP سرور آپدیت شد.\n\n$(page_cfg_menu "$unit")" "$(kb_cfg_menu "$unit")"
                return 0
                ;;
            server_port)
                local newport
                newport="$(echo "$trimmed" | tr -d '[:space:]')"
                if ! is_valid_port "$newport"; then
                    send_message "$chat_id" "❌ پورت نامعتبره. بازه: <code>1-65535</code>\nبرای لغو: <code>لغو</code>" ""
                    return 0
                fi
                cfg_set_server_port "$cfg_file" "$newport"
                systemctl restart "$unit" >/dev/null 2>&1 || true
                pending_clear
                send_message "$chat_id" "✅ پورت سرور آپدیت شد.\n\n$(page_cfg_menu "$unit")" "$(kb_cfg_menu "$unit")"
                return 0
                ;;
            listen_port)
                local newport
                newport="$(echo "$trimmed" | tr -d '[:space:]')"
                if ! is_valid_port "$newport"; then
                    send_message "$chat_id" "❌ پورت نامعتبره. بازه: <code>1-65535</code>\nبرای لغو: <code>لغو</code>" ""
                    return 0
                fi
                cfg_set_listen_port "$cfg_file" "$newport"
                # best-effort iptables for server listen port (tcp)
                iptables_add_notrack "$newport" "tcp"
                systemctl restart "$unit" >/dev/null 2>&1 || true
                pending_clear
                send_message "$chat_id" "✅ پورت Listen آپدیت شد.\n\n$(page_cfg_menu "$unit")" "$(kb_cfg_menu "$unit")"
                return 0
                ;;
            forward_ports)
                local spec
                spec="$trimmed"
                local sec tmpsec
                tmpsec="$(mktemp)"
                if ! build_forward_section_file "$spec" "$tmpsec"; then
                    local rc=$?
                    rm -f "$tmpsec" 2>/dev/null || true
                    if [ "$rc" = "2" ]; then
                        send_message "$chat_id" "❌ پورت/فرمت نامعتبره. مثال: <code>443/tcp,53/udp,8443/both</code>\nبرای لغو: <code>لغو</code>" ""
                    elif [ "$rc" = "3" ]; then
                        send_message "$chat_id" "❌ خطر Loop! یکی از پورت‌های فوروارد با پورت تونل یکیه.\nلطفاً پورت‌ها رو عوض کن.\nبرای لغو: <code>لغو</code>" ""
                    else
                        send_message "$chat_id" "❌ لیست پورت‌ها خالی/نامعتبره.\nمثال: <code>443,8443/both</code>\nبرای لغو: <code>لغو</code>" ""
                    fi
                    return 0
                fi

                replace_forward_section "$cfg_file" "$tmpsec"
                rm -f "$tmpsec" 2>/dev/null || true

                # Apply iptables for all current forward entries (best-effort)
                local fwd_now
                fwd_now="$(cfg_get_forward_summary "$cfg_file")"
                IFS=',' read -ra parts <<< "$(echo "$fwd_now" | tr -d '[:space:]')"
                for p in "${parts[@]}"; do
                    local port="${p%%/*}"
                    local proto="${p##*/}"
                    [ -z "$port" ] && continue
                    case "$proto" in
                        tcp) iptables_add_notrack "$port" "tcp" ;;
                        udp) iptables_add_notrack "$port" "udp" ;;
                        *) : ;;
                    esac
                done

                systemctl restart "$unit" >/dev/null 2>&1 || true
                pending_clear
                send_message "$chat_id" "✅ پورت‌های فوروارد آپدیت شد.\n\n$(page_cfg_menu "$unit")" "$(kb_cfg_menu "$unit")"
                return 0
                ;;
            *)
                pending_clear
                send_message "$chat_id" "⚠️ حالت ویرایش نامعتبر بود و ریست شد.\n/menu" "$(kb_main)"
                return 0
                ;;
        esac
    fi

    case "$text" in
        "/start"|"/menu"|"menu"|"پنل"|"panel") send_message "$chat_id" "$(page_home)" "$(kb_main)" ;;
        "/status"|"status") send_message "$chat_id" "$(format_all_status)" "$(kb_back_home)" ;;
        "/help"|"help") send_message "$chat_id" "دستورات:\n/menu\n/status\n\nیا از دکمه‌ها استفاده کن." "$(kb_main)" "HTML" ;;
        *) send_message "$chat_id" "برای مدیریت، /menu رو بفرست یا دکمه‌ها رو استفاده کن." "$(kb_main)" ;;
    esac
}

handle_callback() {
    local cb_id="$1"
    local chat_id="$2"
    local message_id="$3"
    local data="$4"

    if [ "$chat_id" != "$CHAT_ID" ]; then
        answer_callback "$cb_id" "Access denied" true
        return 0
    fi

    answer_callback "$cb_id" "" false

    case "$data" in
        menu:home) edit_message "$chat_id" "$message_id" "$(page_home)" "$(kb_main)" ;;
        menu:status) edit_message "$chat_id" "$message_id" "$(format_all_status)" "$(kb_back_home)" ;;
        menu:services) edit_message "$chat_id" "$message_id" "$(page_services)" "$(kb_services_list)" ;;
        menu:more) edit_message "$chat_id" "$message_id" "➕ <b>بیشتر</b>\n\nعملیات کمتر-استفاده‌شده اینجاست." "$(kb_more)" ;;
        more:daemon_reload) systemctl daemon-reload >/dev/null 2>&1 || true; edit_message "$chat_id" "$message_id" "✅ <b>daemon-reload</b> انجام شد." "$(kb_more)" ;;
        more:enable_all)
            while read -r u; do [ -n "$u" ] && systemctl enable "$u" >/dev/null 2>&1 || true; done < <(list_paqet_services)
            edit_message "$chat_id" "$message_id" "✅ <b>Enable</b> برای همه سرویس‌های Paqet انجام شد." "$(kb_more)"
            ;;
        more:disable_all)
            while read -r u; do [ -n "$u" ] && systemctl disable "$u" >/dev/null 2>&1 || true; done < <(list_paqet_services)
            edit_message "$chat_id" "$message_id" "✅ <b>Disable</b> برای همه سرویس‌های Paqet انجام شد." "$(kb_more)"
            ;;

        cfg:*.service:menu)
            local unit="${data#cfg:}"
            unit="${unit%:menu}"
            edit_message "$chat_id" "$message_id" "$(page_cfg_menu "$unit")" "$(kb_cfg_menu "$unit")"
            ;;
        cfg:*.service:set:server_ip)
            local rest="${data#cfg:}"
            local unit="${rest%%:*}"
            pending_set "edit|${unit}|server_ip"
            edit_message "$chat_id" "$message_id" "🌍 <b>تغییر IP سرور</b>\n\nIP جدید رو ارسال کن.\nمثال: <code>45.76.123.89</code>\n\nلغو: <code>لغو</code> یا <code>/cancel</code>" "$(kb_cfg_menu "$unit")"
            ;;
        cfg:*.service:set:server_port)
            local rest="${data#cfg:}"
            local unit="${rest%%:*}"
            pending_set "edit|${unit}|server_port"
            edit_message "$chat_id" "$message_id" "🔌 <b>تغییر پورت سرور</b>\n\nپورت جدید رو ارسال کن.\nمثال: <code>8888</code>\n\nلغو: <code>لغو</code> یا <code>/cancel</code>" "$(kb_cfg_menu "$unit")"
            ;;
        cfg:*.service:set:listen_port)
            local rest="${data#cfg:}"
            local unit="${rest%%:*}"
            pending_set "edit|${unit}|listen_port"
            edit_message "$chat_id" "$message_id" "🔌 <b>تغییر پورت Listen</b>\n\nپورت جدید رو ارسال کن.\nمثال: <code>8888</code>\n\nلغو: <code>لغو</code> یا <code>/cancel</code>" "$(kb_cfg_menu "$unit")"
            ;;
        cfg:*.service:set:forward_ports)
            local rest="${data#cfg:}"
            local unit="${rest%%:*}"
            pending_set "edit|${unit}|forward_ports"
            edit_message "$chat_id" "$message_id" "🔀 <b>ویرایش پورت‌های فوروارد</b>\n\nلیست پورت‌ها رو با کاما ارسال کن.\nفرمت: <code>443/tcp,53/udp,8443/both</code>\n(اگر /tcp یا /udp نذاری، پیش‌فرض tcp هست)\n\nلغو: <code>لغو</code> یا <code>/cancel</code>" "$(kb_cfg_menu "$unit")"
            ;;
        svc:*.service:menu)
            local unit="${data#svc:}"
            unit="${unit%:menu}"
            edit_message "$chat_id" "$message_id" "$(page_service "$unit")" "$(kb_service_panel "$unit")"
            ;;
        svc:*.service:start|svc:*.service:stop|svc:*.service:restart|svc:*.service:status)
            local tmp="${data#svc:}"
            local unit="${tmp%%:*}"
            local act="${tmp#*:}"
            do_service_action "$unit" "$act"
            if [ "$act" = "status" ]; then
                local details
                details="$(svc_status_detail "$unit")"
                edit_message "$chat_id" "$message_id" "$(page_service "$unit")

<pre>${details}</pre>" "$(kb_service_panel "$unit")"
            else
                local note="✅ انجام شد."
                edit_message "$chat_id" "$message_id" "$(page_service "$unit")
${note}" "$(kb_service_panel "$unit")"
            fi
;;
        cron:*.service:menu)
            local unit="${data#cron:}"
            unit="${unit%:menu}"
            edit_message "$chat_id" "$message_id" "$(page_cron "$unit")" "$(kb_cron_panel "$unit")"
            ;;
        cron:*.service:set:*)
            local rest="${data#cron:}"
            local unit="${rest%%:*}"
            local interval="${data##*:set:}"
            if cron_set "$unit" "$interval"; then
                edit_message "$chat_id" "$message_id" "$(page_cron "$unit")\n\n✅ تنظیم شد: <code>${interval}</code>" "$(kb_cron_panel "$unit")"
            else
                edit_message "$chat_id" "$message_id" "$(page_cron "$unit")\n\n❌ خطا در تنظیم" "$(kb_cron_panel "$unit")"
            fi
            ;;
        cron:*.service:remove)
            local unit="${data#cron:}"
            unit="${unit%:remove}"
            if cron_remove "$unit"; then
                edit_message "$chat_id" "$message_id" "$(page_cron "$unit")\n\n🗑 حذف شد." "$(kb_cron_panel "$unit")"
            else
                edit_message "$chat_id" "$message_id" "$(page_cron "$unit")\n\nℹ️ چیزی برای حذف نبود." "$(kb_cron_panel "$unit")"
            fi
            ;;
        *) edit_message "$chat_id" "$message_id" "⚠️ دستور ناشناخته" "$(kb_main)" ;;
    esac
}

process_updates() {
    local offset="$1"
    local resp
    resp=$(tg_get "getUpdates?timeout=25&offset=${offset}&limit=50") || true
    echo "$resp" | jq -e '.ok==true' >/dev/null 2>&1 || return 0

    local n
    n=$(echo "$resp" | jq '.result|length')
    [ "$n" -eq 0 ] && return 0

    for i in $(seq 0 $((n-1))); do
        local upd_id
        upd_id=$(echo "$resp" | jq -r ".result[$i].update_id")
        [ -n "$upd_id" ] || continue
        offset=$((upd_id+1))
        write_offset "$offset"

        local chat_id text
        chat_id=$(echo "$resp" | jq -r ".result[$i].message.chat.id // empty")
        text=$(echo "$resp" | jq -r ".result[$i].message.text // empty")
        if [ -n "$chat_id" ] && [ -n "$text" ]; then
            handle_message_text "$chat_id" "$text"
            continue
        fi

        local cb_id cb_chat cb_msgid cb_data
        cb_id=$(echo "$resp" | jq -r ".result[$i].callback_query.id // empty")
        cb_chat=$(echo "$resp" | jq -r ".result[$i].callback_query.message.chat.id // empty")
        cb_msgid=$(echo "$resp" | jq -r ".result[$i].callback_query.message.message_id // empty")
        cb_data=$(echo "$resp" | jq -r ".result[$i].callback_query.data // empty")
        if [ -n "$cb_id" ] && [ -n "$cb_chat" ] && [ -n "$cb_msgid" ] && [ -n "$cb_data" ]; then
            handle_callback "$cb_id" "$cb_chat" "$cb_msgid" "$cb_data"
        fi
    done
}

main() {
    mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$LAST_STATE_FILE")"
    touch "$LOG_FILE" "$LAST_STATE_FILE" "$OFFSET_FILE" 2>/dev/null || true

    if ! need_bin curl || ! need_bin jq || ! need_bin systemctl; then
        log "ERROR: Missing requirements. Need: curl, jq, systemctl"
        exit 1
    fi

    load_config

    local last_watch=0
    local boot_sent="false"

    while true; do
        load_config

        if [ "$ENABLE_BOT" != "true" ] || [ -z "$BOT_TOKEN" ] || [ -z "$CHAT_ID" ]; then
            sleep 30
            continue
        fi

        if [ "$ENABLE_BOOT_REPORT" = "true" ] && [ "$boot_sent" = "false" ]; then
            send_boot_report
            boot_sent="true"
            state_write
        fi

        local offset
        offset=$(read_offset)
        process_updates "$offset" || true

        if [ "$ENABLE_SERVICE_WATCH" = "true" ]; then
            local now
            now=$(date +%s)
            local interval="${WATCH_INTERVAL:-60}"
            if [ $((now - last_watch)) -ge "$interval" ]; then
                check_services_changes
                last_watch="$now"
            fi
        fi

        sleep 1
    done
}

main

EOF
    chmod +x "$BOT_SCRIPT"
    touch "$BOT_CONFIG_DIR/last_state"
    chmod 666 "$BOT_CONFIG_DIR/last_state"
    print_success "Bot script created at $BOT_SCRIPT"
}

# Create bot service file
create_bot_service() {
    cat > "/etc/systemd/system/$BOT_SERVICE.service" << EOF
[Unit]
Description=Paqet Telegram Bot Control Panel
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=$BOT_SCRIPT
Restart=always
RestartSec=10
User=root
Group=root
Environment="BOT_CONFIG=$BOT_CONFIG_FILE"

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    print_success "Bot service created"
}

# Remove bot completely
remove_bot() {
    clear
    echo -e "\n${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║              Uninstall Telegram Bot                           ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}\n"
    
    print_warning "This will completely remove the Telegram bot and all its files."
    echo -e "${GREEN}Note: This only removes the Telegram bot files.${NC}"
    echo -e "${GREEN}Your Paqet tunnels and services will NOT be affected.${NC}"
    echo ""
    read_confirm "Are you ABSOLUTELY SURE?" confirm_remove "n"
    
    if [ "$confirm_remove" != "true" ]; then
        print_info "Removal cancelled"
        pause
        return
    fi
    
    print_step "Stopping bot service..."
    systemctl stop $BOT_SERVICE 2>/dev/null
    systemctl disable $BOT_SERVICE 2>/dev/null
    
    print_step "Removing service file..."
    rm -f "/etc/systemd/system/$BOT_SERVICE.service"
    systemctl daemon-reload
    
    print_step "Removing bot script..."
    rm -f "$BOT_SCRIPT"
    
    print_step "Removing configuration and logs..."
    read_confirm "Remove all configuration files and logs?" remove_configs "n"
    
    if [ "$remove_configs" = "true" ]; then
        rm -rf "$BOT_CONFIG_DIR"
        rm -f "$BOT_LOG_FILE"
        print_success "All bot files removed"
    else
        print_info "Configuration preserved at $BOT_CONFIG_DIR"
        print_info "Logs preserved at $BOT_LOG_FILE"
    fi
    
    print_success "✅ Bot uninstalled successfully"
    pause
}

# ================================================
# Install Telegram bot prerequisites (quiet)
# ================================================
install_bot_prereqs_quiet() {
    local os
    os=$(detect_os)
    case $os in
        ubuntu|debian)
            apt-get update -qq >/dev/null 2>&1 || true
            apt-get install -y curl jq cron ca-certificates >/dev/null 2>&1 || true
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if command -v yum >/dev/null 2>&1; then
                yum install -y curl jq cronie ca-certificates >/dev/null 2>&1 || true
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y curl jq cronie ca-certificates >/dev/null 2>&1 || true
            fi
            ;;
        *)
            :
            ;;
    esac
}

# ================================================
# BOT SETUP WIZARD
# ================================================
setup_bot_wizard() {
    clear
    show_banner

    # Ensure bot prerequisites
    install_bot_prereqs_quiet
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              🤖 Telegram Bot Setup Wizard                    ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
    
    print_step "This wizard will configure and start the Telegram bot in one go"
    echo ""
    
    # 1. Get Bot Token
    print_input "Step 1: Enter your Bot Token"
    echo -e "${CYAN}How to get:${NC}"
    echo "  1. Open Telegram and search for @BotFather"
    echo "  2. Send /newbot and follow instructions"
    echo "  3. Copy the token (looks like: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz)"
    echo ""
    local token=""
    if [ -n "$BOT_TOKEN" ]; then
        echo -e "${CYAN}Current token detected: ${BOT_TOKEN:0:15}...${NC}"
        echo -e "${YELLOW}Leave empty to keep current token.${NC}"
    fi

    read -p "Bot Token > " token
    token=$(echo "$token" | tr -d '[:space:]')

    if [ -z "$token" ] && [ -n "$BOT_TOKEN" ]; then
        token="$BOT_TOKEN"
        print_success "Using existing bot token"
    fi

    while [ -z "$token" ]; do
        read -p "Bot Token > " token
        token=$(echo "$token" | tr -d '[:space:]')
        [ -z "$token" ] && print_error "Token cannot be empty"
    done

    BOT_TOKEN="$token"
    print_success "Bot token saved"
    echo ""

    
    # 2. Get Chat ID
    print_input "Step 2: Set your Telegram Chat ID (Auto / Manual)"

    if [ -n "$CHAT_ID" ]; then
        echo -e "${CYAN}Current Chat ID detected: $CHAT_ID${NC}"
        echo -e "${YELLOW}Leave empty to keep it, or type 'auto' to re-detect.${NC}"
    else
        echo -e "${CYAN}Recommended (Auto):${NC}"
        echo "  1. Open your bot in Telegram"
        echo "  2. Send /start to the bot"
        echo "  3. Come back here and press Enter to auto-detect your Chat ID"
    fi
    echo ""

    # Ensure jq exists (required for auto-detect)
    if ! command -v jq &>/dev/null; then
        print_info "jq not found. Installing jq for auto-detect..."
        local os_detect
        os_detect=$(detect_os)
        case $os_detect in
            ubuntu|debian) apt update -qq >/dev/null 2>&1 || true; apt install -y jq >/dev/null 2>&1 || true ;;
            centos|rhel|fedora|rocky|almalinux) yum install -y jq >/dev/null 2>&1 || dnf install -y jq >/dev/null 2>&1 || true ;;
            *) print_warning "Could not auto-install jq on this OS. You can enter Chat ID manually." ;;
        esac
    fi

    local chat_id=""
    read -p "Chat ID > " chat_id
    chat_id=$(echo "$chat_id" | tr -d '[:space:]')

    if [ -z "$chat_id" ] && [ -n "$CHAT_ID" ]; then
        chat_id="$CHAT_ID"
        print_success "Using existing Chat ID"
    fi

    if [ "$chat_id" = "auto" ]; then
        chat_id=""
    fi

    if [ -z "$chat_id" ]; then
        print_step "Auto-detecting Chat ID from getUpdates..."
        local updates=""
        updates=$(curl -4 -s --max-time 10 "https://api.telegram.org/bot${BOT_TOKEN}/getUpdates?limit=10" 2>/dev/null)
        if ! echo "$updates" | grep -q '"ok":true'; then
            updates=$(curl -s --max-time 10 "https://telegram.behzad.workers.dev/bot${BOT_TOKEN}/getUpdates?limit=10" 2>/dev/null)
        fi

        if command -v jq &>/dev/null; then
            chat_id=$(echo "$updates" | jq -r '.result[-1].message.chat.id // .result[-1].callback_query.message.chat.id // empty' 2>/dev/null)
        fi

        if [ -z "$chat_id" ]; then
            print_warning "Auto-detect failed."
            echo -e "${CYAN}Manual method:${NC}"
            echo "  1. Open Telegram and search for @userinfobot"
            echo "  2. Send /start"
            echo "  3. Copy your Chat ID (a number) and paste it here"
            echo ""
            while [ -z "$chat_id" ]; do
                read -p "Chat ID > " chat_id
                chat_id=$(echo "$chat_id" | tr -d '[:space:]')
                [ -z "$chat_id" ] && print_error "Chat ID cannot be empty"
            done
        else
            print_success "Detected Chat ID: $chat_id"
        fi
    fi

    CHAT_ID="$chat_id"
    print_success "Chat ID saved"
    echo ""

    print_input "Step 3: Configuring SOCKS5 proxy for Telegram"
    echo -e "${CYAN}Checking existing client configs for SOCKS5...${NC}"
    
    # Try to detect existing SOCKS5
    local detected_proxy=$(detect_socks5_proxy)
    
    if [ -n "$detected_proxy" ]; then
        SOCKS5_PROXY="$detected_proxy"
        print_success "Found existing SOCKS5 proxy: $SOCKS5_PROXY"
        USE_SOCKS5="true"
    else
        print_warning "No SOCKS5 proxy found in client configs"
        read_confirm "Add SOCKS5 proxy to first client? (recommended)" add_socks5 "y"
        
        if [ "$add_socks5" = "true" ]; then
            local added_proxy=$(add_socks5_to_client)
            if [ -n "$added_proxy" ]; then
                SOCKS5_PROXY="$added_proxy"
                print_success "SOCKS5 proxy added: $SOCKS5_PROXY"
                USE_SOCKS5="true"
            else
                print_error "Failed to add SOCKS5 proxy"
                USE_SOCKS5="false"
                SOCKS5_PROXY=""
            fi
        else
            print_info "Continuing without SOCKS5 proxy"
            USE_SOCKS5="false"
            SOCKS5_PROXY=""
        fi
    fi
    echo ""
    
    # 4. Ask for notification preferences
    print_input "Step 4: Configure notification settings"
    read_confirm "Enable boot reports? (recommended)" ENABLE_BOOT_REPORT "y"
    read_confirm "Enable service status monitoring?" ENABLE_SERVICE_WATCH "y"
    echo ""
    
    # 5. Ask for watch interval
    print_input "Step 5: Set check interval"
    echo -e "${CYAN}How often should the bot check for changes? (30-3600 seconds)${NC}"
    read -p "Interval [60]: " interval
    interval="${interval:-60}"
    if [[ "$interval" =~ ^[0-9]+$ ]] && [ "$interval" -ge 30 ] && [ "$interval" -le 3600 ]; then
        WATCH_INTERVAL="$interval"
    else
        print_warning "Invalid interval, using default: 60 seconds"
        WATCH_INTERVAL="60"
    fi
    echo ""
    
    # 6. Enable bot and save
    ENABLE_BOT="true"
    save_bot_config
    
    # 7. Create bot files
    print_step "Creating bot files..."
    create_bot_script
    create_bot_service
    
    # 8. Start bot service
    print_step "Starting bot service..."
    systemctl enable $BOT_SERVICE >/dev/null 2>&1
    systemctl start $BOT_SERVICE
    sleep 2
    
    # 9. Check status and send test message
    if systemctl is-active --quiet $BOT_SERVICE; then
        print_success "✅ Bot service started successfully!"
        
        print_step "Sending test message..."
        local test_message="✅ <b>Paqet Bot Successfully Installed!</b>\n\n"
        test_message="${test_message}Bot is now active and monitoring your server.\n"
        test_message="${test_message}📋 You will receive:\n"
        test_message="${test_message}• Boot reports when server restarts\n"
        test_message="${test_message}• Service status changes\n"
        test_message="${test_message}• Packet loss alerts\n\n"
        test_message="${test_message}⚙️ Settings:\n"
        test_message="${test_message}• Watch interval: ${WATCH_INTERVAL}s\n"
        test_message="${test_message}• Boot reports: ${ENABLE_BOOT_REPORT}\n"
        test_message="${test_message}• Service watch: ${ENABLE_SERVICE_WATCH}\n"
        
        if [ -n "$SOCKS5_PROXY" ]; then
            test_message="${test_message}• SOCKS5 proxy: ${SOCKS5_PROXY} (enabled)\n"
        fi
        
        test_message="${test_message}\n🚀 Happy tunneling!"
        
        if send_telegram_message "$test_message"; then
            print_success "Test message sent! Check your Telegram"
        else
            print_warning "Test message may have failed. Check your token and chat ID"
            sleep 2
            print_info "If you received the message in Telegram, it's working fine"
        fi
    else
        print_error "❌ Bot service failed to start"
        journalctl -u $BOT_SERVICE -n 20 --no-pager
    fi
    
    echo ""
    print_success "✅ Bot setup completed!"
    pause
}

# ================================================
# BOT MANAGEMENT MENU
# ================================================

telegram_bot_menu() {
    init_bot_config
    load_bot_config
    
    while true; do
        clear
        # show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║              🤖 Telegram Bot Management                      ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
        
        # Status Overview
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║                      STATUS OVERVIEW                         ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
        
        # Bot Status
        if [ "$ENABLE_BOT" = "true" ]; then
            echo -e "  ${GREEN}●${NC} Bot: ${GREEN}ENABLED${NC}"
        else
            echo -e "  ${RED}○${NC} Bot: ${RED}DISABLED${NC}"
        fi
        
        # Configuration Status
        if [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ]; then
            echo -e "  ${GREEN}✓${NC} Configuration: ${GREEN}Complete${NC}"
            echo -e "  ${CYAN}  Token: ${BOT_TOKEN:0:15}...${NC}"
            echo -e "  ${CYAN}  Chat ID: $CHAT_ID${NC}"
        else
            echo -e "  ${RED}✗${NC} Configuration: ${RED}Incomplete${NC}"
        fi
        
        # Service Status
        if systemctl is-active --quiet $BOT_SERVICE 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} Service: ${GREEN}Running${NC}"
            local uptime=$(systemctl show $BOT_SERVICE -p ActiveEnterTimestamp 2>/dev/null | cut -d= -f2)
            [ -n "$uptime" ] && echo -e "  ${CYAN}  Started: $uptime${NC}"
        else
            echo -e "  ${RED}✗${NC} Service: ${RED}Stopped${NC}"
        fi
        
        # SOCKS5 Status
        if [ -n "$SOCKS5_PROXY" ] && [ "$USE_SOCKS5" = "true" ]; then
            echo -e "  ${GREEN}✓${NC} SOCKS5 Proxy: ${CYAN}$SOCKS5_PROXY${NC}"
        fi
        
        echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}MAIN ACTIONS:${NC}"
        echo -e "  ${WHITE}[S]${NC} 🚀 ${GREEN}Setup Bot Wizard${NC} - Complete setup in one go"
        echo -e "  ${WHITE}[R]${NC} 🗑️  ${RED}Remove Bot${NC} - Uninstall completely"
        
        echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}NOTIFICATION SETTINGS:${NC}"
        echo -e "  ${WHITE}[1]${NC} Boot Report [$( [ "$ENABLE_BOOT_REPORT" = "true" ] && echo "✅ ON" || echo "❌ OFF")]"
        echo -e "  ${WHITE}[2]${NC} Service Watch [$( [ "$ENABLE_SERVICE_WATCH" = "true" ] && echo "✅ ON" || echo "❌ OFF")]"
        echo -e "  ${WHITE}[3]${NC} Watch Interval (current: ${CYAN}${WATCH_INTERVAL}s${NC})"
        
        echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}PROXY SETTINGS:${NC}"
        echo -e "  ${WHITE}[4]${NC} Toggle SOCKS5 Proxy [$( [ "$USE_SOCKS5" = "true" ] && echo "✅ ON" || echo "❌ OFF")]"
        echo -e "  ${WHITE}[5]${NC} Set SOCKS5 Proxy (current: ${CYAN}${SOCKS5_PROXY:-Not set}${NC})"
        
        echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}SERVICE CONTROL:${NC}"
        echo -e "  ${WHITE}[6]${NC} Start Bot Service"
        echo -e "  ${WHITE}[7]${NC} Stop Bot Service"
        echo -e "  ${WHITE}[8]${NC} Restart Bot Service"
        echo -e "  ${WHITE}[9]${NC} View Bot Logs"
        echo -e "  ${WHITE}[10]${NC} Test Bot (Send test message)"
        
        echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
        echo -e "  ${WHITE}[0]${NC} ↩️ Back to Main Menu"
        echo ""
        
        read -p "Choose option: " bot_choice
        
        case $bot_choice in
            [Ss]) setup_bot_wizard ;;
            [Rr]) remove_bot ;;
            
            1)
                [ "$ENABLE_BOOT_REPORT" = "true" ] && ENABLE_BOOT_REPORT="false" || ENABLE_BOOT_REPORT="true"
                save_bot_config
                print_success "Boot Report: $([ "$ENABLE_BOOT_REPORT" = "true" ] && echo "ON" || echo "OFF")"
                sleep 1
                ;;
            2)
                [ "$ENABLE_SERVICE_WATCH" = "true" ] && ENABLE_SERVICE_WATCH="false" || ENABLE_SERVICE_WATCH="true"
                save_bot_config
                print_success "Service Watch: $([ "$ENABLE_SERVICE_WATCH" = "true" ] && echo "ON" || echo "OFF")"
                sleep 1
                ;;
            3)
                echo -e "\n${YELLOW}Enter watch interval in seconds (30-3600):${NC}"
                read -p "> " new_interval
                if [[ "$new_interval" =~ ^[0-9]+$ ]] && [ "$new_interval" -ge 30 ] && [ "$new_interval" -le 3600 ]; then
                    WATCH_INTERVAL="$new_interval"
                    save_bot_config
                    print_success "Watch interval set to ${WATCH_INTERVAL}s"
                    
                    if systemctl is-active --quiet $BOT_SERVICE; then
                        systemctl restart $BOT_SERVICE
                        print_info "Bot service restarted to apply new interval"
                    fi
                else
                    print_error "Invalid interval (must be 30-3600)"
                    sleep 2
                fi
                ;;
            4)
                if [ -n "$SOCKS5_PROXY" ]; then
                    [ "$USE_SOCKS5" = "true" ] && USE_SOCKS5="false" || USE_SOCKS5="true"
                    save_bot_config
                    print_success "SOCKS5 Proxy: $([ "$USE_SOCKS5" = "true" ] && echo "ON" || echo "OFF")"
                    sleep 1
                else
                    print_error "Please set SOCKS5 proxy first (option 5)"
                    sleep 2
                fi
                ;;
            5)
                echo -e "\n${YELLOW}Enter SOCKS5 proxy (host:port):${NC}"
                read -p "> " new_proxy
                if [ -n "$new_proxy" ]; then
                    SOCKS5_PROXY="$new_proxy"
                    USE_SOCKS5="true"
                    save_bot_config
                    print_success "SOCKS5 proxy set to $SOCKS5_PROXY"
                    sleep 1
                fi
                ;;
            6)
                if [ ! -f "$BOT_SCRIPT" ]; then
                    create_bot_script
                fi
                if [ ! -f "/etc/systemd/system/$BOT_SERVICE.service" ]; then
                    create_bot_service
                fi
                systemctl start $BOT_SERVICE
                sleep 2
                if systemctl is-active --quiet $BOT_SERVICE; then
                    print_success "Bot service started"
                else
                    print_error "Failed to start bot service"
                    journalctl -u $BOT_SERVICE -n 10 --no-pager
                fi
                sleep 1
                ;;
            7)
                systemctl stop $BOT_SERVICE
                print_info "Bot service stopped"
                sleep 1
                ;;
            8)
                systemctl restart $BOT_SERVICE
                sleep 2
                if systemctl is-active --quiet $BOT_SERVICE; then
                    print_success "Bot service restarted"
                else
                    print_error "Failed to restart bot service"
                fi
                sleep 1
                ;;
            9)
                echo -e "\n${CYAN}Last 20 lines of bot log:${NC}\n"
                if [ -f "$BOT_LOG_FILE" ]; then
                    tail -20 "$BOT_LOG_FILE"
                else
                    journalctl -u $BOT_SERVICE -n 20 --no-pager
                fi
                echo ""
                pause
                ;;
            10)
                if [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ] && [ "$ENABLE_BOT" = "true" ]; then
                    print_step "Sending test message..."
                    local test_msg="✅ <b>Paqet Bot Test</b>\n\n"
                    test_msg+="If you see this, bot is working correctly!\n"
                    test_msg+="Time: $(date '+%Y-%m-%d %H:%M:%S')"
                    
                    if send_telegram_message "$test_msg"; then
                        print_success "Test message sent! Check your Telegram"
                    else
                        print_error "Failed to send message. Check token and chat ID."
                    fi
                else
                    print_error "Bot not properly configured or enabled"
                    print_info "Please run Setup Wizard [S] first"
                fi
                pause
                ;;
            0) return ;;
            *) print_error "Invalid choice"; sleep 1 ;;
        esac
    done
}
# ================================================
# MAIN MENU
# ================================================

main_menu() {
    while true; do
        clear
        show_banner
        
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║ Main Menu                                                ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}\n"
        
        if [ -f "$BIN_DIR/paqet" ]; then
            echo -e "${GREEN}✅ Paqet is installed${NC}"
            local core_version
            core_version=$("$BIN_DIR/paqet" version 2>/dev/null | grep "^Version:" | head -1 | cut -d':' -f2 | xargs)
            if [ -n "$core_version" ]; then
                echo -e "   ${GREEN}└─ Version: ${CYAN}$core_version${NC}"
            fi
        else
            echo -e "${YELLOW}⚠️ Paqet not installed${NC}"
        fi
        
        local missing_deps
        missing_deps=$(check_dependencies)
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ Dependencies are installed${NC}"
        else
            echo -e "${YELLOW}⚠️ Missing dependencies: $missing_deps${NC}"
        fi
        
        echo -e "\n${CYAN}0.${NC}⚙️  Install Paqet Binary / Manager"
        echo -e "${CYAN}1.${NC}📦 Install Dependencies"
        echo -e "${CYAN}2.${NC}🌍 Configure as Server (kharej)"
        echo -e "${CYAN}3.${NC}🇮🇷 Configure as Client (Iran) [Port Forwarding / SOCKS5]"
        echo -e "${CYAN}4.${NC}🛠️  Manage Services"
        echo -e "${CYAN}5.${NC}🔄 Manage All Services (Restart/Logs/Delete)"
        echo -e "${CYAN}6.${NC}📊 Test Connection"
        echo -e "${CYAN}7.${NC}🚀 Optimize Server"
        echo -e "${CYAN}8.${NC}🗑️  Uninstall Paqet"
        echo -e "${CYAN}9.${NC}🤖 Telegram Bot Manager"
        echo -e "${CYAN}10.${NC}🚪 Exit"
        echo ""
        
        read -p "Select option [0-10]: " choice
        
        case $choice in
            0) install_paqet ;;
            1) install_dependencies ;;
            2) configure_server ;;
            3) configure_client ;;
            4) manage_services ;;
            5) manage_all_services ;;
            6) test_connection ;;
            7) optimize_server ;;
            8) uninstall_paqet ;;
            9) telegram_bot_menu ;;
            10)
                echo -e "\n${GREEN}══════════════════════════════════════════════════════════════${NC}"
                echo -e "${GREEN} Goodbye! ${NC}"
                echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}\n"
                exit 0
                ;;
            *) print_error "Invalid option"; sleep 1 ;;
        esac
    done
}

# ================================================
# START
# ================================================

check_root
cleanup_legacy_log_services
main_menu
