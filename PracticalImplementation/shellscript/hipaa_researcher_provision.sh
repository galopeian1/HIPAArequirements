#!/bin/bash

# HIPAA-Compliant Researcher Provisioning Script for Ubuntu Linux
# Enhanced security implementation with comprehensive audit trails
# Version: 2.0
# Date: $(date +%Y-%m-%d)

set -euo pipefail

# Configuration
SCRIPT_VERSION="2.0"
HEALTHCARE_DIR="/etc/healthcare"
ENCRYPTED_PASS_DIR="$HEALTHCARE_DIR/encrypted_passwords"
AUDIT_LOG="/var/log/hipaa-password-audit.log"
RESEARCH_DATA_DIR="/var/research"
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

# Warning message
warning_msg() {
    echo -e "${YELLOW}WARNING: $1${NC}"
    log_audit "WARNING" "$1"
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

# Validate operator privileges
validate_operator() {
    if ! groups "$OPERATOR_USER" | grep -q "healthcare-admins"; then
        error_exit "Operator $OPERATOR_USER is not a member of healthcare-admins group"
    fi
    log_audit "OPERATOR_VALIDATION" "Validated operator $OPERATOR_USER has healthcare-admins privileges"
}

# Create directory structure for research environment
setup_research_directories() {
    mkdir -p "$HEALTHCARE_DIR"
    mkdir -p "$ENCRYPTED_PASS_DIR"
    mkdir -p "$RESEARCH_DATA_DIR"
    mkdir -p "$RESEARCH_DATA_DIR/datasets"
    mkdir -p "$RESEARCH_DATA_DIR/analytics"
    mkdir -p "$RESEARCH_DATA_DIR/publications"
    mkdir -p "$RESEARCH_DATA_DIR/deidentified"
    mkdir -p "/var/log/healthcare/research"
    
    chmod 700 "$HEALTHCARE_DIR"
    chmod 700 "$ENCRYPTED_PASS_DIR"
    chmod 750 "$RESEARCH_DATA_DIR"
    chmod 755 "$RESEARCH_DATA_DIR/publications"
    chmod 750 "$RESEARCH_DATA_DIR/deidentified"
    chmod 700 "$RESEARCH_DATA_DIR/datasets"
    chmod 700 "$RESEARCH_DATA_DIR/analytics"
    
    chown root:healthcare-admins "$HEALTHCARE_DIR"
    chown root:healthcare-admins "$ENCRYPTED_PASS_DIR"
    chown root:researchers "$RESEARCH_DATA_DIR"
    chown root:researchers "$RESEARCH_DATA_DIR"/*
}

# Install research-specific packages
install_research_dependencies() {
    info_msg "Installing research-specific packages for HIPAA compliance..."
    apt-get update -qq
    apt-get install -y \
        libpam-pwquality \
        auditd \
        audispd-plugins \
        gnupg \
        ldap-utils \
        libpam-ldapd \
        fail2ban \
        logwatch \
        aide \
        rkhunter \
        chkrootkit \
        python3-pip \
        r-base \
        git \
        sqlite3 \
        postgresql-client \
        mysql-client \
        encfs \
        cryptsetup
    
    # Install research-specific Python packages securely
    pip3 install --upgrade pip
    pip3 install pandas numpy scipy matplotlib seaborn jupyter cryptography
    
    systemctl enable auditd
    systemctl start auditd
    log_audit "PACKAGE_INSTALL" "Installed research-specific HIPAA compliance packages"
}

# Generate cryptographically secure password
generate_secure_password() {
    local length=16
    local password=""
    while true; do
        password=$(head -c 1000 /dev/urandom | tr -dc 'A-Za-z0-9!@#$%^&*()_+-=[]{}|;:,.<>?' | head -c "$length")
        
        # Check complexity requirements
        if [[ "$password" =~ [A-Z] ]] && \
           [[ "$password" =~ [a-z] ]] && \
           [[ "$password" =~ [0-9] ]] && \
           [[ "$password" =~ [!@#\$%\^&\*\(\)_+\-=\[\]\{\}\|;:,.\<\>\?] ]]; then
            break
        fi
    done
    echo "$password"
}

# Encrypt password with GPG (AES-256)
encrypt_password() {
    local password="$1"
    local username="$2"
    local encrypted_file="$ENCRYPTED_PASS_DIR/${username}_password.gpg"
    
    echo "$password" | gpg --cipher-algo AES256 --compress-algo 1 --s2k-mode 3 \
        --s2k-digest-algo SHA512 --s2k-count 65536 --symmetric \
        --output "$encrypted_file" --batch --yes --passphrase "$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 32)"
    
    chmod 600 "$encrypted_file"
    chown root:healthcare-admins "$encrypted_file"
    
    # Schedule cleanup after 24 hours
    echo "rm -f $encrypted_file" | at now + 24 hours 2>/dev/null || true
    
    log_audit "PASSWORD_ENCRYPT" "Encrypted temporary password for researcher $username"
}

# Configure research-specific audit rules
configure_research_audit_rules() {
    info_msg "Configuring auditd rules for research environment..."
    
    cat > /etc/audit/rules.d/hipaa-researcher.rules << 'EOF'
# HIPAA Compliance Audit Rules for Research Environment

# Monitor research data directories
-w /var/research -p rwxa -k research_data_access
-w /var/research/datasets -p rwxa -k dataset_access
-w /var/research/analytics -p rwxa -k analytics_access
-w /var/research/deidentified -p rwxa -k deidentified_access

# Monitor healthcare configuration
-w /etc/healthcare -p rwxa -k healthcare_config_access
-w /var/log/healthcare -p rwxa -k healthcare_log_access

# Monitor database access
-w /var/lib/mysql -p rwxa -k database_access
-w /var/lib/postgresql -p rwxa -k database_access
-w /var/lib/sqlite -p rwxa -k database_access

# Monitor authentication and authorization
-w /var/log/auth.log -p wa -k authentication
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudo_changes

# Monitor network configuration
-w /etc/network/ -p wa -k network_config
-w /etc/hosts -p wa -k hosts_changes

# Monitor file transfers and exports
-a always,exit -F arch=b64 -S open -F dir=/var/research -F success=1 -k data_export
-a always,exit -F arch=b64 -S openat -F dir=/var/research -F success=1 -k data_export

# Monitor encryption operations
-w /usr/bin/gpg -p x -k encryption_ops
-w /usr/bin/encfs -p x -k encryption_ops
-w /usr/sbin/cryptsetup -p x -k encryption_ops

# Monitor statistical software execution
-w /usr/bin/python3 -p x -k stats_software
-w /usr/bin/R -p x -k stats_software
-w /usr/bin/jupyter -p x -k stats_software

# Monitor data deidentification tools
-a always,exit -F path=/usr/local/bin/deidentify -F perm=x -k deidentification
-a always,exit -F path=/usr/local/bin/anonymize -F perm=x -k deidentification
EOF

    augenrules --load
    systemctl restart auditd
    log_audit "AUDIT_RULES" "Configured research-specific auditd rules"
}

# Create researcher user account
create_researcher_user() {
    local username="$1"
    local full_name="$2"
    local institution="$3"
    local research_area="$4"
    local irb_number="$5"
    
    info_msg "Creating researcher user account: $username"
    
    # Create user with research-specific groups
    useradd -m -s /bin/bash -c "$full_name - $institution - Research: $research_area - IRB: $irb_number" \
        -G researchers,healthcare-users,data-analysts "$username"
    
    # Generate and set secure password
    local password=$(generate_secure_password)
    echo "$username:$password" | chpasswd
    
    # Encrypt password for temporary storage
    encrypt_password "$password" "$username"
    
    # Force password change on first login
    chage -d 0 "$username"
    chage -M 60 "$username"
    chage -W 7 "$username"
    
    # Set up researcher environment
    setup_researcher_environment "$username"
    
    # Create research-specific compliance documents
    create_research_compliance_docs "$username" "$full_name" "$institution" "$research_area" "$irb_number"
    
    success_msg "Researcher account created: $username"
    info_msg "Temporary password: $password"
    warning_msg "Password will expire in 24 hours and must be changed on first login"
    
    log_audit "USER_CREATION" "Created researcher account: $username ($full_name) - Institution: $institution - Area: $research_area - IRB: $irb_number"
}

# Set up researcher environment
setup_researcher_environment() {
    local username="$1"
    local home_dir="/home/$username"
    
    # Create research-specific directory structure
    mkdir -p "$home_dir/.ssh"
    mkdir -p "$home_dir/research_projects"
    mkdir -p "$home_dir/data_analysis"
    mkdir -p "$home_dir/publications"
    mkdir -p "$home_dir/deidentified_data"
    mkdir -p "$home_dir/secure_notebooks"
    
    # Set secure permissions
    chmod 700 "$home_dir"
    chmod 700 "$home_dir/.ssh"
    chmod 750 "$home_dir/research_projects"
    chmod 750 "$home_dir/data_analysis"
    chmod 755 "$home_dir/publications"
    chmod 750 "$home_dir/deidentified_data"
    chmod 700 "$home_dir/secure_notebooks"
    
    chown -R "$username:$username" "$home_dir"
    
    # Create research-specific HIPAA compliance reminder
    cat > "$home_dir/.profile_research_hipaa" << EOF
#!/bin/bash
# HIPAA Research Compliance Reminder
echo "=============================================="
echo "HIPAA RESEARCH COMPLIANCE REMINDER"
echo "=============================================="
echo "You are accessing a healthcare research system"
echo "containing Protected Health Information (PHI)."
echo ""
echo "RESEARCH-SPECIFIC REQUIREMENTS:"
echo "- All research must be IRB approved"
echo "- Use only deidentified data when possible"
echo