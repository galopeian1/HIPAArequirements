#!/bin/bash

# HIPAA Infrastructure Setup Script for Ubuntu Linux
# Establishes the foundational security infrastructure
# Version: 2.0
# Date: $(date +%Y-%m-%d)

set -euo pipefail

# Configuration
SCRIPT_VERSION="2.0"
HEALTHCARE_DIR="/etc/healthcare"
LOG_DIR="/var/log/healthcare"
AUDIT_LOG="/var/log/hipaa-password-audit.log"
SESSION_ID=$(openssl rand -hex 16)
OPERATOR_IP="${SSH_CLIENT%% *}"
OPERATOR_USER="$USER"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log_audit() {
    local action="$1"
    local details="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [SESSION:$SESSION_ID] [OPERATOR:$OPERATOR_USER@$OPERATOR_IP] [ACTION:$action] $details" >> "$AUDIT_LOG"
}

# Error handling
error_exit() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    log_audit "ERROR" "$1"
    exit 1
}

# Success message
success_msg() {
    echo -e "${GREEN}SUCCESS: $1${NC}"
    log_audit "SUCCESS" "$1"
}

# Info message
info_msg() {
    echo -e "${BLUE}INFO: $1${NC}"
    log_audit "INFO" "$1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
}

# Create healthcare system groups
create_healthcare_groups() {
    info_msg "Creating healthcare system groups..."
    
    # Administrative groups
    groupadd -f healthcare-admins
    groupadd -f healthcare-security
    groupadd -f hipaa-officers
    
    # User groups
    groupadd -f healthcare-users
    groupadd -f doctors
    groupadd -f nurses
    groupadd -f researchers
    groupadd -f data-analysts
    groupadd -f it-support
    
    # Data access groups
    groupadd -f phi-read
    groupadd -f phi-write
    groupadd -f deidentified-access
    
    success_msg "Healthcare system groups created"
    log_audit "GROUP_CREATION" "Created all required healthcare system groups"
}

# Set up directory structure
setup_directory_structure() {
    info_msg "Setting up healthcare directory structure..."
    
    # Main healthcare directories
    mkdir -p "$HEALTHCARE_DIR"
    mkdir -p "$HEALTHCARE_DIR/configs"
    mkdir -p "$HEALTHCARE_DIR/policies"
    mkdir -p "$HEALTHCARE_DIR/certificates"
    mkdir -p "$HEALTHCARE_DIR/encrypted_passwords"
    mkdir -p "$HEALTHCARE_DIR/backup"
    
    # Log directories
    mkdir -p "$LOG_DIR"
    mkdir -p "$LOG_DIR/audit"
    mkdir -p "$LOG_DIR/security"
    mkdir -p "$LOG_DIR/research"
    mkdir -p "$LOG_DIR/access"
    
    # Research directories
    mkdir -p "/var/research"
    mkdir -p "/var/research/datasets"
    mkdir -p "/var/research/deidentified"
    mkdir -p "/var/research/analytics"
    mkdir -p "/var/research/publications"
    
    # Set permissions
    chmod 700 "$HEALTHCARE_DIR"
    chmod 700 "$HEALTHCARE_DIR/encrypted_passwords"
    chmod 750 "$LOG_DIR"
    chmod 750 "/var/research"
    
    # Set ownership
    chown -R root:healthcare-admins "$HEALTHCARE_DIR"
    chown -R root:healthcare-admins "$LOG_DIR"
    chown -R root:researchers "/var/research"
    
    success_msg "Directory structure created"
    log_audit "DIRECTORY_SETUP" "Created healthcare directory structure"
}

# Install and configure core security packages
install_core_packages() {
    info_msg "Installing core HIPAA compliance packages..."
    
    # Update package lists
    apt-get update -qq
    
    # Install security packages
    apt-get install -y \
        auditd \
        audispd-plugins \
        libpam-pwquality \
        libpam-faillock \
        gnupg \
        gpg-agent \
        fail2ban \
        aide \
        rkhunter \
        chkrootkit \
        logwatch \
        logrotate \
        rsyslog \
        ntp \
        openssh-server \
        ufw \
        iptables-persistent \
        at \
        cron \
        anacron
    
    # Install LDAP packages if needed
    apt-get install -y \
        ldap-utils \
        libpam-ldapd \
        libnss-ldapd
    
    # Install monitoring and alerting
    apt-get install -y \
        mailutils \
        postfix \
        bsd-mailx
    
    # Enable and start services
    systemctl enable auditd
    systemctl enable fail2ban
    systemctl enable ssh
    systemctl enable ufw
    systemctl enable cron
    systemctl enable rsyslog
    systemctl enable ntp
    
    systemctl start auditd
    systemctl start fail2ban
    systemctl start ssh
    systemctl start cron
    systemctl start rsyslog
    systemctl start ntp
    
    success_msg "Core security packages installed and configured"
    log_audit "PACKAGE_INSTALL" "Installed core HIPAA compliance packages"
}

# Configure system-wide security settings
configure_system_security() {
    info_msg "Configuring system-wide security settings..."
    
    # Configure login definitions
    cat > /etc/login.defs.hipaa << 'EOF'
# HIPAA-compliant login definitions
PASS_MAX_DAYS 60
PASS_MIN_DAYS 1
PASS_WARN_AGE 7
PASS_MIN_LEN 14
LOGIN_RETRIES 3
LOGIN_TIMEOUT 60
CHFN_RESTRICT rwh
UMASK 027
CREATE_HOME yes
USERGROUPS_ENAB yes
ENCRYPT_METHOD SHA512
SHA_CRYPT_MIN_ROUNDS 5000
SHA_CRYPT_MAX_ROUNDS 10000
EOF

    # Backup original and apply HIPAA settings
    cp /etc/login.defs /etc/login.defs.backup
    cp /etc/login.defs.hipaa /etc/login.defs
    
    # Configure PAM password quality
    cat > /etc/security/pwquality.conf << 'EOF'
# HIPAA-compliant password quality requirements
minlen = 14
minclass = 4
maxrepeat = 2
maxclasrepeat = 2
lcredit = -1
ucredit = -1
dcredit = -1
ocredit = -1
dictcheck = 1
usercheck = 1
enforcing = 1
retry = 3
gecoscheck = 1
badwords = password,healthcare,hipaa,admin,root
EOF

    # Configure account lockout
    cat > /etc/security/faillock.conf << 'EOF'
# HIPAA account lockout configuration
audit
silent
deny = 3
fail_interval = 900
unlock_time = 1800
even_deny_root
root_unlock_time = 3600
dir = /var/run/faillock
EOF

    success_msg "System security settings configured"
    log_audit "SYSTEM_SECURITY" "Configured system-wide security settings"
}

# Set up comprehensive audit rules
setup_audit_rules() {
    info_msg "Setting up comprehensive audit rules..."
    
    # Create main HIPAA audit rules
    cat > /etc/audit/rules.d/00-hipaa-base.rules << 'EOF'
# HIPAA Base Audit Rules

# Remove any existing rules
-D

# Set buffer size
-b 8192

# Set failure mode (0=silent, 1=printk, 2=panic)
-f 1

# Monitor authentication events
-w /var/log/auth.log -p wa -k authentication
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# Monitor system administration
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d -p wa -k privilege_escalation

# Monitor healthcare directories
-w /etc/healthcare -p rwxa -k healthcare_config
-w /var/log/healthcare -p rwxa -k healthcare_logs
-w /var/research -p rwxa -k research_data

# Monitor network configuration
-w /etc/network/ -p wa -k network_config