#!/bin/bash

# HIPAA-Compliant Doctor Provisioning Script for Ubuntu Linux
# Enhanced security implementation with comprehensive audit trails
# Version: 2.0
# Date: $(date +%Y-%m-%d)

set -euo pipefail

# Configuration
SCRIPT_VERSION="2.0"
HEALTHCARE_DIR="/etc/healthcare"
ENCRYPTED_PASS_DIR="$HEALTHCARE_DIR/encrypted_passwords"
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

# Create directory structure
setup_directories() {
    mkdir -p "$HEALTHCARE_DIR"
    mkdir -p "$ENCRYPTED_PASS_DIR"
    mkdir -p "/var/log/healthcare"
    chmod 700 "$HEALTHCARE_DIR"
    chmod 700 "$ENCRYPTED_PASS_DIR"
    chown root:healthcare-admins "$HEALTHCARE_DIR"
    chown root:healthcare-admins "$ENCRYPTED_PASS_DIR"
}

# Install required packages
install_dependencies() {
    info_msg "Installing required packages for HIPAA compliance..."
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
        chkrootkit
    systemctl enable auditd
    systemctl start auditd
    log_audit "PACKAGE_INSTALL" "Installed HIPAA compliance packages"
}

# Generate cryptographically secure password
generate_secure_password() {
    local length=16
    # Generate password with required complexity
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
    
    log_audit "PASSWORD_ENCRYPT" "Encrypted temporary password for user $username"
}

# Configure PAM for password complexity
configure_pam_security() {
    info_msg "Configuring PAM security policies..."
    
    # Configure password quality requirements
    cat > /etc/security/pwquality.conf << 'EOF'
# HIPAA-compliant password quality configuration
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
EOF

    # Configure password aging
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
    
    log_audit "PAM_CONFIG" "Configured PAM security policies for HIPAA compliance"
}

# Configure auditd rules
configure_audit_rules() {
    info_msg "Configuring auditd rules for comprehensive monitoring..."
    
    cat > /etc/audit/rules.d/hipaa-doctor.rules << 'EOF'
# HIPAA Compliance Audit Rules for Healthcare Environment

# Monitor file access on healthcare directories
-w /etc/healthcare -p rwxa -k healthcare_config_access
-w /var/log/healthcare -p rwxa -k healthcare_log_access
-w /home -p rwxa -k user_home_access

# Monitor authentication events
-w /var/log/auth.log -p wa -k authentication
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudo_changes

# Monitor network configuration
-w /etc/network/ -p wa -k network_config
-w /etc/hosts -p wa -k hosts_changes
-w /etc/resolv.conf -p wa -k dns_changes

# Monitor system administration
-w /var/log/sudo.log -p wa -k sudo_usage
-w /etc/cron.allow -p wa -k cron_changes
-w /etc/cron.deny -p wa -k cron_changes
-w /etc/cron.d/ -p wa -k cron_changes
-w /etc/cron.daily/ -p wa -k cron_changes

# Monitor file permission changes
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Monitor unsuccessful file access
-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access_denied
-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access_denied
EOF

    augenrules --load
    systemctl restart auditd
    log_audit "AUDIT_RULES" "Configured comprehensive auditd rules for healthcare environment"
}

# Create doctor user account
create_doctor_user() {
    local username="$1"
    local full_name="$2"
    local department="$3"
    local license_number="$4"
    
    info_msg "Creating doctor user account: $username"
    
    # Create user with secure defaults
    useradd -m -s /bin/bash -c "$full_name - $department - License: $license_number" \
        -G doctors,healthcare-users "$username"
    
    # Generate and set secure password
    local password=$(generate_secure_password)
    echo "$username:$password" | chpasswd
    
    # Encrypt password for temporary storage
    encrypt_password "$password" "$username"
    
    # Force password change on first login
    chage -d 0 "$username"
    chage -M 60 "$username"
    chage -W 7 "$username"
    
    # Set up user environment
    setup_user_environment "$username" "doctor"
    
    success_msg "Doctor account created: $username"
    info_msg "Temporary password: $password"
    warning_msg "Password will expire in 24 hours and must be changed on first login"
    
    log_audit "USER_CREATION" "Created doctor account: $username ($full_name) - Department: $department - License: $license_number"
}

# Set up user environment and security
setup_user_environment() {
    local username="$1"
    local role="$2"
    local home_dir="/home/$username"
    
    # Create secure directory structure
    mkdir -p "$home_dir/.ssh"
    mkdir -p "$home_dir/secure_documents"
    mkdir -p "$home_dir/patient_data"
    
    # Set secure permissions
    chmod 700 "$home_dir"
    chmod 700 "$home_dir/.ssh"
    chmod 750 "$home_dir/secure_documents"
    chmod 750 "$home_dir/patient_data"
    
    chown -R "$username:$username" "$home_dir"
    
    # Create HIPAA compliance reminder
    cat > "$home_dir/.profile_hipaa" << EOF
#!/bin/bash
# HIPAA Compliance Reminder
echo "=========================================="
echo "HIPAA COMPLIANCE REMINDER"
echo "=========================================="
echo "You are accessing a healthcare system containing"
echo "Protected Health Information (PHI)."
echo ""
echo "- All activities are monitored and logged"
echo "- Unauthorized access is prohibited"
echo "- Report security incidents immediately"
echo "- Follow data handling procedures"
echo ""
echo "Last security training: Schedule required"
echo "Next training due: $(date -d '+90 days' '+%Y-%m-%d')"
echo "=========================================="
EOF

    # Add HIPAA reminder to user's bashrc
    echo "source ~/.profile_hipaa" >> "$home_dir/.bashrc"
    chown "$username:$username" "$home_dir/.profile_hipaa"
    chown "$username:$username" "$home_dir/.bashrc"
    
    # Create incident response procedures
    create_incident_response_plan "$username" "$role"
    
    log_audit "USER_ENVIRONMENT" "Set up secure environment for $role: $username"
}

# Create incident response plan
create_incident_response_plan() {
    local username="$1"
    local role="$2"
    local home_dir="/home/$username"
    
    cat > "$home_dir/INCIDENT_RESPONSE_PLAN.txt" << EOF
HIPAA INCIDENT RESPONSE PLAN - $role: $username
Generated: $(date)
Session ID: $SESSION_ID

IMMEDIATE RESPONSE (Within 1 Hour):
1. Isolate affected systems
2. Document the incident (time, nature, scope)
3. Contact Security Team: security@healthcare.local
4. Do NOT delete logs or evidence

NOTIFICATION REQUIREMENTS (Within 24 Hours):
- HIPAA Security Officer: hipaa@healthcare.local
- System Administrator: sysadmin@healthcare.local
- Department Manager: manager@healthcare.local

DOCUMENTATION REQUIRED:
- Incident description and timeline
- Affected systems and data
- Actions taken
- Impact assessment
- Lessons learned

BREACH NOTIFICATION:
If PHI is involved, notification to patients and HHS
may be required within 60 days.

EMERGENCY CONTACTS:
- Security Hotline: +1-800-XXX-XXXX
- On-call Administrator: +1-800-XXX-XXXX
- Legal Counsel: +1-800-XXX-XXXX

This plan is confidential and must be secured.
EOF

    chmod 600 "$home_dir/INCIDENT_RESPONSE_PLAN.txt"
    chown "$username:$username" "$home_dir/INCIDENT_RESPONSE_PLAN.txt"
    
    log_audit "INCIDENT_PLAN" "Created incident response plan for $username"
}

# Configure fail2ban for enhanced security
configure_fail2ban() {
    info_msg "Configuring fail2ban for healthcare environment..."
    
    cat > /etc/fail2ban/jail.d/healthcare.conf << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[healthcare-auth]
enabled = true
port = http,https
logpath = /var/log/healthcare/*.log
maxretry = 5
bantime = 7200
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban
    log_audit "FAIL2BAN" "Configured fail2ban for healthcare security"
}

# Set up automated security monitoring
setup_security_monitoring() {
    info_msg "Setting up automated security monitoring..."
    
    # Create monitoring script
    cat > /usr/local/bin/hipaa-security-check.sh << 'EOF'
#!/bin/bash
# HIPAA Security Monitoring Script

LOG_FILE="/var/log/healthcare/security-check.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$DATE] Starting HIPAA security check..." >> "$LOG_FILE"

# Check for failed logins
FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)
if [ "$FAILED_LOGINS" -gt 10 ]; then
    echo "[$DATE] WARNING: $FAILED_LOGINS failed login attempts today" >> "$LOG_FILE"
    # Alert mechanism would go here
fi

# Check for off-hours access
CURRENT_HOUR=$(date '+%H')
if [ "$CURRENT_HOUR" -lt 6 ] || [ "$CURRENT_HOUR" -gt 20 ]; then
    LOGINS=$(grep "Accepted" /var/log/auth.log | grep "$(date '+%b %d %H')" | wc -l)
    if [ "$LOGINS" -gt 0 ]; then
        echo "[$DATE] WARNING: $LOGINS off-hours login(s) detected" >> "$LOG_FILE"
    fi
fi

# Check disk usage on healthcare directories
USAGE=$(df /etc/healthcare | tail -1 | awk '{print $5}' | sed 's/%//')
if [ "$USAGE" -gt 80 ]; then
    echo "[$DATE] WARNING: Healthcare directory usage at $USAGE%" >> "$LOG_FILE"
fi

echo "[$DATE] Security check completed" >> "$LOG_FILE"
EOF

    chmod +x /usr/local/bin/hipaa-security-check.sh
    
    # Add to crontab for weekly execution
    (crontab -l 2>/dev/null; echo "0 2 * * 1 /usr/local/bin/hipaa-security-check.sh") | crontab -
    
    log_audit "SECURITY_MONITORING" "Set up automated security monitoring"
}

# Main provisioning function
main() {
    echo -e "${BLUE}HIPAA-Compliant Doctor Provisioning Script v$SCRIPT_VERSION${NC}"
    echo "Starting provisioning process..."
    
    # Pre-flight checks
    check_root
    validate_operator
    
    # Get user input
    read -p "Enter doctor's username: " username
    read -p "Enter doctor's full name: " full_name
    read -p "Enter department: " department
    read -p "Enter medical license number: " license_number
    
    # Confirm details
    echo -e "\n${YELLOW}Please confirm the following details:${NC}"
    echo "Username: $username"
    echo "Full Name: $full_name"
    echo "Department: $department"
    echo "License Number: $license_number"
    read -p "Continue? (y/N): " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        error_exit "Provisioning cancelled by operator"
    fi
    
    log_audit "PROVISION_START" "Starting doctor provisioning for $username"
    
    # Execute provisioning steps
    setup_directories
    install_dependencies
    configure_pam_security
    configure_audit_rules
    configure_fail2ban
    setup_security_monitoring
    create_doctor_user "$username" "$full_name" "$department" "$license_number"
    
    success_msg "Doctor provisioning completed successfully!"
    info_msg "Session ID: $SESSION_ID"
    info_msg "All activities have been logged to: $AUDIT_LOG"
    
    log_audit "PROVISION_COMPLETE" "Doctor provisioning completed for $username"
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi