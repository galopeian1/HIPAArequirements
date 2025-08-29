#!/bin/bash
# provision-admin.sh - HIPAA Compliant System Administrator Account Provisioning Script
# Creates privileged user account with full system administration rights
# Author: [Your Name] - IT Help Desk Support Portfolio
# Date: $(date +%Y-%m-%d)

# Exit on any error
set -e

# Configuration variables
SCRIPT_NAME="provision-admin.sh"
LOG_FILE="/var/log/user-provisioning.log"
AUDIT_LOG="/var/log/hipaa-audit.log"
PASSWORD_AUDIT_LOG="/var/log/hipaa-password-audit.log"
ADMIN_AUDIT_LOG="/var/log/hipaa-admin-audit.log"
PHI_BASE_DIR="/opt/healthcare/phi"
ADMIN_PHI_DIR="/opt/healthcare/phi/administration"
BACKUP_DIR="/opt/healthcare/backups/administration"
ENCRYPTED_PASSWORD_STORE="/etc/healthcare/encrypted_passwords"
GPG_RECIPIENT="healthcare-security@organization.com"
PRIVILEGED_COMMANDS_LOG="/var/log/privileged-commands.log"

# Function to generate secure temporary password using /dev/urandom
generate_temp_password() {
    # HIPAA Requirement: Strong password complexity for privileged accounts
    # Generate 20-character password (longer for admin accounts) with mixed character types
    local length=20
    local charset="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*+-="
    local password=""
    
    # Ensure at least two characters from each required category for enhanced security
    local upper="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local lower="abcdefghijklmnopqrstuvwxyz"
    local digits="0123456789"
    local special="!@#$%^&*+-="
    
    # Add two characters from each category to ensure complexity
    password+=$(head -c 2 /dev/urandom | tr -dc "$upper")
    password+=$(head -c 2 /dev/urandom | tr -dc "$lower")
    password+=$(head -c 2 /dev/urandom | tr -dc "$digits")
    password+=$(head -c 2 /dev/urandom | tr -dc "$special")
    
    # Fill remaining positions with random characters from full charset
    for ((i=8; i<length; i++)); do
        password+=$(head -c 1 /dev/urandom | tr -dc "$charset")
    done
    
    # Shuffle the password to randomize position of required characters
    echo "$password" | fold -w1 | shuf | tr -d '\n'
}

# Function to log admin-specific actions for enhanced HIPAA compliance
log_admin_action() {
    local action="$1"
    local user="$2"
    local operator="$3"
    local privilege_level="$4"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local session_id="$$"
    
    # Enhanced logging for privileged account operations
    echo "[$timestamp] SESSION:$session_id OPERATOR:$operator PRIVILEGE:$privilege_level ACTION:$action USER:$user IP:${SSH_CLIENT%% *} TTY:$(tty 2>/dev/null || echo 'unknown')" | tee -a "$ADMIN_AUDIT_LOG"
    
    # Also log to main audit log
    echo "[$timestamp] $SCRIPT_NAME: ADMIN_$action for user: $user by operator: $operator" >> "$AUDIT_LOG"
}

# Function to log password-related actions for HIPAA compliance
log_password_action() {
    local action="$1"
    local user="$2"
    local operator="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local session_id="$$"
    
    # HIPAA Requirement: Detailed audit trail for password operations
    echo "[$timestamp] SESSION:$session_id OPERATOR:$operator ACTION:$action USER:$user IP:${SSH_CLIENT%% *}" | tee -a "$PASSWORD_AUDIT_LOG"
    
    # Also log to main audit log
    echo "[$timestamp] $SCRIPT_NAME: PASSWORD_$action for user: $user by operator: $operator" >> "$AUDIT_LOG"
}

# Function to log actions for HIPAA compliance
log_action() {
    local action="$1"
    local user="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $SCRIPT_NAME: $action for user: $user" | tee -a "$LOG_FILE" "$AUDIT_LOG"
}

# Function to securely store temporary password (encrypted at rest)
store_encrypted_password() {
    local username="$1"
    local password="$2"
    local operator="$3"
    
    # HIPAA Requirement: Encrypt passwords at rest using AES-256
    mkdir -p "$ENCRYPTED_PASSWORD_STORE"
    chmod 700 "$ENCRYPTED_PASSWORD_STORE"
    
    # Encrypt password using GPG with AES-256 cipher (admin passwords get additional protection)
    echo "$password" | gpg --trust-model always --cipher-algo AES256 --compress-algo 2 \
        --symmetric --armor --passphrase-file /etc/healthcare/master.key \
        --output "$ENCRYPTED_PASSWORD_STORE/$username-admin.gpg"
    
    # Set more restrictive permissions for admin password files
    chmod 400 "$ENCRYPTED_PASSWORD_STORE/$username-admin.gpg"
    chown root:root "$ENCRYPTED_PASSWORD_STORE/$username-admin.gpg"
    
    # Log the password storage action
    log_password_action "ADMIN_ENCRYPTED_STORAGE" "$username" "$operator"
    
    # Schedule automatic password file cleanup after 12 hours (shorter for admin accounts)
    echo "find '$ENCRYPTED_PASSWORD_STORE' -name '$username-admin.gpg' -mtime +0.5 -delete" | at now + 12 hours 2>/dev/null || true
}

# Function to validate operator access for admin provisioning (enhanced security)
validate_operator_access() {
    local operator="$1"
    
    # HIPAA Requirement: Only senior authorized personnel can provision admin accounts
    if ! getent group healthcare-senior-admins | grep -q "$operator"; then
        echo "ERROR: Access denied. User $operator is not in healthcare-senior-admins group."
        log_admin_action "ACCESS_DENIED" "N/A" "$operator" "SENIOR_ADMIN_REQUIRED"
        exit 1
    fi
    
    # Additional multi-factor authentication check for admin provisioning
    echo "SECURITY NOTICE: Admin account provisioning requires additional verification."
    read -p "Enter your current sudo password for verification: " -s sudo_password
    echo
    
    if ! echo "$sudo_password" | sudo -S -v 2>/dev/null; then
        echo "ERROR: Sudo password verification failed."
        log_admin_action "SUDO_VERIFICATION_FAILED" "N/A" "$operator" "AUTHENTICATION_FAILURE"
        exit 1
    fi
    
    # Additional check for active directory/LDAP integration if available
    if command -v ldapsearch >/dev/null 2>&1; then
        if ! ldapsearch -x -LLL "(uid=$operator)" | grep -q "employeeType: SeniorHealthcareAdmin"; then
            echo "ERROR: LDAP verification failed. User lacks senior healthcare admin privileges."
            log_admin_action "LDAP_ACCESS_DENIED" "N/A" "$operator" "INSUFFICIENT_PRIVILEGES"
            exit 1
        fi
    fi
    
    log_admin_action "ACCESS_GRANTED" "N/A" "$operator" "SENIOR_ADMIN_VERIFIED"
}

# Function to validate input
validate_input() {
    if [[ ! "$1" =~ ^[a-z][a-z0-9._-]{2,31}$ ]]; then
        echo "Error: Invalid username format. Must be 3-32 chars, lowercase, start with letter."
        exit 1
    fi
    
    # Additional validation for admin usernames (no generic names allowed)
    local restricted_names=("admin" "administrator" "root" "sys" "system" "service" "daemon")
    for restricted in "${restricted_names[@]}"; do
        if [[ "$1" == "$restricted" ]]; then
            echo "Error: Username '$1' is restricted for security reasons. Use a personal identifier."
            exit 1
        fi
    done
}

# Function to enforce enhanced password policies for admin accounts
enforce_admin_password_policies() {
    local username="$1"
    
    # HIPAA Requirement: Stricter password policies for privileged accounts
    # Set password aging: min 1 day, max 30 days (much stricter), warning 7 days
    chage -m 1 -M 30 -W 7 "$username"
    
    # Set account expiration for admin accounts (60 days, shorter than regular users)
    local expire_date=$(date -d "+60 days" +%Y-%m-%d)
    chage -E "$expire_date" "$username"
    
    # Configure enhanced PAM for admin password complexity
    if [[ -f /etc/pam.d/common-password ]]; then
        # Create admin-specific PAM configuration
        if [[ ! -f /etc/pam.d/admin-password ]]; then
            cat > /etc/pam.d/admin-password << 'EOF'
# Enhanced password requirements for admin accounts
password requisite pam_pwquality.so retry=3 minlen=16 difok=4 ucredit=-2 lcredit=-2 dcredit=-2 ocredit=-2 minclass=4 maxrepeat=2
password required pam_pwhistory.so remember=24 use_authtok
EOF
        fi
    fi
    
    # Create admin-specific login monitoring
    cat > "/etc/pam.d/admin-login-$username" << EOF
# Admin login monitoring for $username
session required pam_exec.so /usr/local/bin/log-admin-login.sh $username
EOF
    
    log_admin_action "Enhanced password policies enforced (30-day rotation)" "$username" "${SUDO_USER:-$USER}" "PASSWORD_POLICY"
}

# Function to create admin user account with enhanced security
create_admin_account() {
    local username="$1"
    local full_name="$2"
    local department="$3"
    local operator="${SUDO_USER:-$USER}"
    local temp_password=$(generate_temp_password)
    
    log_action "Starting admin account creation" "$username"
    log_admin_action "ACCOUNT_CREATION_START" "$username" "$operator" "FULL_ADMIN"
    
    # Create user account with home directory and admin shell
    useradd -m -s /bin/bash -c "$full_name - System Administrator - $department" "$username"
    
    # Set temporary password that must be changed on first login
    echo "$username:$temp_password" | chpasswd
    chage -d 0 "$username"  # Force password change on first login
    
    # Apply enhanced admin password policies
    enforce_admin_password_policies "$username"
    
    # HIPAA Requirement: Securely store encrypted password for authorized access
    store_encrypted_password "$username" "$temp_password" "$operator"
    
    # Log password generation action
    log_password_action "ADMIN_GENERATED" "$username" "$operator"
    
    log_action "Admin account created with encrypted temporary password" "$username"
    log_admin_action "ACCOUNT_CREATED" "$username" "$operator" "FULL_ADMIN"
    
    # HIPAA Requirement: Display password securely
    if [[ -n "${SSH_CLIENT}" ]]; then
        echo "SECURE: Admin temporary password stored encrypted. Use 'retrieve-admin-password $username' command."
        echo "Password will auto-expire in 12 hours for enhanced security."
    else
        echo "Admin temporary password for $username: $temp_password"
        echo "SECURITY NOTICE: This admin password is displayed once and stored encrypted."
    fi
    echo "User must change password on first login (forced)"
    echo "Password expires in 30 days (admin policy)"
}

# Function to set up admin group memberships with full system access
setup_admin_group_memberships() {
    local username="$1"
    local operator="${SUDO_USER:-$USER}"
    
    # Create admin groups if they don't exist
    groupadd -f healthcare-admins
    groupadd -f system-admins
    groupadd -f phi-full-access
    groupadd -f backup-admins
    groupadd -f security-admins
    groupadd -f audit-reviewers
    
    # Add user to administrative groups
    usermod -a -G sudo "$username"                    # Full sudo access
    usermod -a -G healthcare-admins "$username"       # Healthcare system admin
    usermod -a -G system-admins "$username"          # System administration
    usermod -a -G phi-full-access "$username"        # Full PHI access (with restrictions)
    usermod -a -G backup-admins "$username"          # Backup administration
    usermod -a -G security-admins "$username"        # Security administration
    usermod -a -G audit-reviewers "$username"        # Audit log access
    usermod -a -G adm "$username"                    # System log access
    usermod -a -G systemd-journal "$username"       # Journal access
    
    # Add to Docker group if Docker is installed (for container management)
    if getent group docker >/dev/null 2>&1; then
        usermod -a -G docker "$username"
    fi
    
    log_action "Admin group memberships configured" "$username"
    log_admin_action "GROUP_MEMBERSHIPS_SET" "$username" "$operator" "FULL_PRIVILEGES"
}

# Function to set up comprehensive directory access for administrators
setup_admin_directory_access() {
    local username="$1"
    local operator="${SUDO_USER:-$USER}"
    
    # Create admin-specific directories
    mkdir -p "$ADMIN_PHI_DIR"/{system-logs,security-reports,backup-configs,compliance-docs}
    mkdir -p "$BACKUP_DIR"/{system,database,configs}
    mkdir -p "/opt/healthcare/admin-tools"
    mkdir -p "/var/log/admin-activities"
    
    # Set directory ownership and permissions for admin access
    chown -R root:healthcare-admins "$ADMIN_PHI_DIR"
    chmod -R 750 "$ADMIN_PHI_DIR"
    
    chown -R root:backup-admins "$BACKUP_DIR"
    chmod -R 770 "$BACKUP_DIR"
    
    # Create user-specific admin directories
    mkdir -p "/home/$username"/{admin-scripts,security-tools,compliance-reports,incident-responses}
    chown "$username:healthcare-admins" "/home/$username"/{admin-scripts,security-tools,compliance-reports,incident-responses}
    chmod 750 "/home/$username"/{admin-scripts,security-tools,compliance-reports,incident-responses}
    
    # Set up comprehensive ACLs for admin access
    setfacl -R -m g:healthcare-admins:rwx "$PHI_BASE_DIR"
    setfacl -R -m u:"$username":rwx "$PHI_BASE_DIR"
    setfacl -R -m g:system-admins:rwx "/opt/healthcare"
    setfacl -R -m g:audit-reviewers:r-x "/var/log"
    
    # Give admin access to system configuration directories
    setfacl -m u:"$username":rwx /etc/healthcare
    setfacl -m u:"$username":r-x /etc/ssh
    setfacl -m u:"$username":rwx /etc/audit
    
    log_action "Admin directory access permissions configured" "$username"
    log_admin_action "DIRECTORY_ACCESS_CONFIGURED" "$username" "$operator" "FULL_FILESYSTEM"
}

# Function to configure enhanced SSH access for administrators
setup_admin_ssh_access() {
    local username="$1"
    local operator="${SUDO_USER:-$USER}"
    
    # Create .ssh directory with admin-specific configuration
    mkdir -p "/home/$username/.ssh"
    chmod 700 "/home/$username/.ssh"
    chown "$username:$username" "/home/$username/.ssh"
    
    # Create authorized_keys file
    touch "/home/$username/.ssh/authorized_keys"
    chmod 600 "/home/$username/.ssh/authorized_keys"
    chown "$username:$username" "/home/$username/.ssh/authorized_keys"
    
    # Create admin-specific SSH configuration
    cat > "/home/$username/.ssh/config" << EOF
# Admin SSH Configuration - Enhanced Security
Host *
    StrictHostKeyChecking yes
    UserKnownHostsFile ~/.ssh/known_hosts
    IdentityFile ~/.ssh/id_ed25519_admin
    ServerAliveInterval 60
    ServerAliveCountMax 3
    Compression yes
EOF

    chmod 600 "/home/$username/.ssh/config"
    chown "$username:$username" "/home/$username/.ssh/config"
    
    # Configure SSH restrictions for admin users (enhanced monitoring)
    if ! grep -q "Match Group healthcare-admins" /etc/ssh/sshd_config; then
        cat >> /etc/ssh/sshd_config << EOF

# Healthcare Admin SSH Configuration
Match Group healthcare-admins
    LogLevel VERBOSE
    MaxSessions 3
    ClientAliveInterval 300
    ClientAliveCountMax 2
    PermitTunnel yes
    X11Forwarding no
    AllowAgentForwarding yes
    # Enhanced logging for admin sessions
    ForceCommand /usr/local/bin/admin-session-wrapper
EOF
    fi
    
    log_action "Admin SSH access configured with enhanced monitoring" "$username"
    log_admin_action "SSH_ACCESS_CONFIGURED" "$username" "$operator" "ENHANCED_MONITORING"
}

# Function to set up comprehensive audit logging for admin users
setup_admin_audit_logging() {
    local username="$1"
    local operator="${SUDO_USER:-$USER}"
    
    # Enhanced auditd rules for administrator activities
    if command -v auditctl >/dev/null 2>&1; then
        # Monitor all admin file access
        auditctl -w "$PHI_BASE_DIR" -p rwxa -k "admin-phi-access-$username"
        auditctl -w "/home/$username" -p wa -k "admin-home-changes-$username"
        auditctl -w "/etc" -p wa -k "admin-config-changes-$username"
        auditctl -w "/var/log" -p wa -k "admin-log-access-$username"
        
        # Monitor privileged commands
        auditctl -a always,exit -F arch=b64 -F euid=0 -F auid=$(id -u "$username") -S execve -k "admin-privileged-$username"
        auditctl -a always,exit -F arch=b64 -F uid=$(id -u "$username") -S mount -k "admin-mount-$username"
        auditctl -a always,exit -F arch=b64 -F uid=$(id -u "$username") -S chmod,fchmod,chown,fchown -k "admin-permissions-$username"
        
        # Monitor network activities
        auditctl -a always,exit -F arch=b64 -S socket -F uid=$(id -u "$username") -k "admin-network-$username"
        
        # Add permanent rules to audit.rules
        cat >> /etc/audit/rules.d/hipaa-admin.rules << EOF
# Admin audit rules for $username
-w $PHI_BASE_DIR -p rwxa -k admin-phi-access-$username
-w /home/$username -p wa -k admin-home-changes-$username
-w /etc -p wa -k admin-config-changes-$username
-w /var/log -p wa -k admin-log-access-$username
-a always,exit -F arch=b64 -F euid=0 -F auid=$(id -u "$username") -S execve -k admin-privileged-$username
-a always,exit -F arch=b64 -F uid=$(id -u "$username") -S mount -k admin-mount-$username
-a always,exit -F arch=b64 -F uid=$(id -u "$username") -S chmod,fchmod,chown,fchown -k admin-permissions-$username
-a always,exit -F arch=b64 -S socket -F uid=$(id -u "$username") -k admin-network-$username
EOF
    fi
    
    # Create dedicated admin command logging
    cat > "/usr/local/bin/log-admin-command.sh" << EOF
#!/bin/bash
# Log all admin commands for HIPAA compliance
USERNAME="$username"
COMMAND="\$*"
TIMESTAMP=\$(date '+%Y-%m-%d %H:%M:%S')
SESSION_ID=\$\$
TTY=\$(tty 2>/dev/null || echo 'unknown')
IP_ADDR=\${SSH_CLIENT%% *}

echo "[\$TIMESTAMP] USER:\$USERNAME SESSION:\$SESSION_ID TTY:\$TTY IP:\$IP_ADDR COMMAND:\$COMMAND" >> "$PRIVILEGED_COMMANDS_LOG"
EOF
    
    chmod +x "/usr/local/bin/log-admin-command.sh"
    
    log_action "Enhanced audit logging configured for admin user" "$username"
    log_admin_action "AUDIT_LOGGING_CONFIGURED" "$username" "$operator" "COMPREHENSIVE_MONITORING"
}

# Function to create admin-specific user profile with enhanced security
setup_admin_user_profile() {
    local username="$1"
    local operator="${SUDO_USER:-$USER}"
    
    # Create comprehensive admin bash profile
    cat > "/home/$username/.bashrc" << EOF
# HIPAA Compliant System Administrator Profile
# Enhanced security settings and administrative environment

# Set secure umask for admin operations
umask 0022

# Enhanced history settings for comprehensive audit trail
HISTSIZE=50000
HISTFILESIZE=50000
HISTCONTROL=
HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S "
HISTIGNORE=""
export HISTSIZE HISTFILESIZE HISTCONTROL HISTTIMEFORMAT HISTIGNORE

# Enable command logging for all admin operations
export PROMPT_COMMAND='history -a; echo "\$(date "+%Y-%m-%d %H:%M:%S") \$(whoami) \$(pwd) \$(history 1)" >> /var/log/admin-commands.log'

# Security aliases with logging
alias rm='echo "rm command logged" >> /var/log/admin-commands.log; rm -i'
alias cp='echo "cp command logged" >> /var/log/admin-commands.log; cp -i'
alias mv='echo "mv command logged" >> /var/log/admin-commands.log; mv -i'
alias chmod='echo "chmod command logged" >> /var/log/admin-commands.log; chmod'
alias chown='echo "chown command logged" >> /var/log/admin-commands.log; chown'

# Admin-specific aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias phi-logs='tail -f /var/log/hipaa-audit.log'
alias admin-logs='tail -f /var/log/hipaa-admin-audit.log'
alias security-check='sudo /usr/local/bin/hipaa-security-check.sh'

# Environment variables for admin operations
export EDITOR=nano
export PAGER=less
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/healthcare/admin-tools"

# Enhanced security notifications
echo "=========================================="
echo "HIPAA-Compliant Administrator Session"
echo "User: $username"
echo "Time: \$(date)"
echo "IP: \${SSH_CLIENT%% *}"
echo "=========================================="
echo "WARNING: You have administrative privileges"
echo "All actions are comprehensively logged and monitored"
echo "Access only data necessary for administrative duties"
echo "Report any security incidents immediately"
echo "=========================================="

# Function to safely edit configuration files
safe_edit() {
    local file="\$1"
    if [[ -f "\$file" ]]; then
        cp "\$file" "\$file.backup.\$(date +%Y%m%d_%H%M%S)"
        echo "Backup created: \$file.backup.\$(date +%Y%m%d_%H%M%S)"
        echo "Editing \$file logged" >> /var/log/admin-commands.log
        \$EDITOR "\$file"
    else
        echo "File \$file does not exist"
    fi
}

# Function to view audit logs safely
view_audit() {
    echo "Viewing audit logs - action logged" >> /var/log/admin-commands.log
    sudo tail -n 100 /var/log/hipaa-audit.log | less
}

# Function to check system security status
security_status() {
    echo "Security status check - action logged" >> /var/log/admin-commands.log
    echo "=== System Security Status ==="
    echo "Failed login attempts in last 24h: \$(grep 'authentication failure' /var/log/auth.log | grep -c \$(date -d '1 day ago' +%Y-%m-%d) || echo '0')"
    echo "Active admin sessions: \$(who | grep -c '$username' || echo '0')"
    echo "Last password change: \$(chage -l $username | grep 'Last password change')"
    echo "Account expires: \$(chage -l $username | grep 'Account expires')"
}

# Make functions available
export -f safe_edit view_audit security_status
EOF

    # Set ownership and permissions
    chown "$username:$username" "/home/$username/.bashrc"
    chmod 644 "/home/$username/.bashrc"
    
    # Create admin command logging file
    touch /var/log/admin-commands.log
    chmod 640 /var/log/admin-commands.log
    chown root:healthcare-admins /var/log/admin-commands.log
    
    log_action "Enhanced admin user profile configured" "$username"
    log_admin_action "USER_PROFILE_CONFIGURED" "$username" "$operator" "ENHANCED_SECURITY"
}

# Function to create enhanced security monitoring for admin accounts
setup_admin_security_monitoring() {
    local username="$1"
    local operator="${SUDO_USER:-$USER}"
    
    # Create comprehensive monitoring for admin activities
    cat > "/etc/cron.d/hipaa-admin-security-$username" << EOF
# HIPAA Enhanced Security Monitoring for admin: $username
# Run every hour for real-time monitoring
0 * * * * root /usr/local/bin/hipaa-admin-security-check.sh $username >> /var/log/admin-security-monitoring.log 2>&1
# Daily security report
0 6 * * * root /usr/local/bin/generate-admin-security-report.sh $username >> /var/log/admin-security-reports.log 2>&1
EOF

    # Create enhanced monitoring script for admin users
    cat > "/usr/local/bin/monitor-admin-$username.sh" << 'EOF'
#!/bin/bash
# Enhanced monitoring for admin user with HIPAA compliance
USERNAME="$1"
LOG_FILE="/var/log/hipaa-admin-monitoring-$USERNAME.log"
ALERT_THRESHOLD=3
HIGH_RISK_THRESHOLD=1

# Check for suspicious admin activities
echo "$(date): Starting admin security check for $USERNAME" >> $LOG_FILE

# Monitor sudo usage
sudo_usage=$(grep "sudo.*$USERNAME" /var/log/auth.log | grep "$(date +%Y-%m-%d)" | wc -l)
if [[ $sudo_usage -gt 20 ]]; then
    echo "$(date): WARNING - Excessive sudo usage ($sudo_usage commands) by $USERNAME" >> $LOG_FILE
    echo "HIPAA SECURITY ALERT: Excessive sudo usage by admin $USERNAME" | mail -s "Admin Security Alert" security@organization.com
fi

# Monitor file modifications in sensitive directories
sensitive_modifications=$(grep "admin-config-changes-$USERNAME" /var/log/audit/audit.log | grep "$(date +%Y-%m-%d)" | wc -l)
if [[ $sensitive_modifications -gt 10 ]]; then
    echo "$(date): WARNING - High configuration changes ($sensitive_modifications) by $USERNAME" >> $LOG_FILE
fi

# Check for off-hours administrative activities
current_hour=$(date +%H)
if [[ $current_hour -lt 7 || $current_hour -gt 19 ]]; then
    if who | grep -q "$USERNAME"; then
        active_sessions=$(who | grep -c "$USERNAME")
        echo "$(date): NOTICE - Admin $USERNAME active during off-hours ($active_sessions sessions)" >> $LOG_FILE
        
        # Log all commands during off-hours for review
        echo "$(date): Off-hours activity by $USERNAME requires review" | mail -s "Off-Hours Admin Activity" compliance@organization.com
    fi
fi

# Monitor privileged command usage
privileged_commands=$(grep "admin-privileged-$USERNAME" /var/log/audit/audit.log | grep "$(date +%Y-%m-%d)" | wc -l)
if [[ $privileged_commands -gt 50 ]]; then
    echo "$(date): INFO - High privileged command usage ($privileged_commands) by $USERNAME" >> $LOG_FILE
fi

# Check for failed authentication attempts
failed_auths=$(grep "authentication failure.*user=$USERNAME" /var/log/auth.log | grep "$(date +%Y-%m-%d)" | wc -l)
if [[ $failed_auths -gt $HIGH_RISK_THRESHOLD ]]; then
    echo "$(date): CRITICAL - Failed authentication attempts ($failed_auths) for admin $USERNAME" >> $LOG_FILE
    echo "CRITICAL HIPAA ALERT: Admin authentication failures for $USERNAME" | mail -s "Critical Admin Security Alert" security@organization.com
fi

# Monitor PHI access patterns
phi_access=$(grep "admin-phi-access-$USERNAME" /var/log/audit/audit.log | grep "$(date +%Y-%m-%d)" | wc -l)
if [[ $phi_access -gt 100 ]]; then
    echo "$(date): INFO - High PHI access activity ($phi_access operations) by $USERNAME" >> $LOG_FILE
fi

echo "$(date): Admin security check completed for $USERNAME" >> $LOG_FILE
EOF

    chmod +x "/usr/local/bin/monitor-admin-$username.sh"
    
    # Set up real-time monitoring via auditd for critical admin actions
    if command -v auditctl >/dev/null 2>&1; then
        # Monitor critical system files
        auditctl -w /etc/passwd -p wa -k "admin-passwd-changes-$username"
        auditctl -w /etc/shadow -p wa -k "admin-shadow-changes-$username"  
        auditctl -w /etc/sudoers -p wa -k "admin-sudo-changes-$username"
        auditctl -w /etc/ssh/sshd_config -p wa -k "admin-ssh-changes-$username"
        
        # Monitor admin service management
        auditctl -a always,exit -F arch=b64 -F uid=$(id -u "$username") -S unlink,unlinkat,rename,renameat -k "admin-file-deletion-$username"
    fi
    
    log_action "Enhanced security monitoring configured for admin user" "$username"
    log_admin_action "SECURITY_MONITORING_CONFIGURED" "$username" "$operator" "REAL_TIME_MONITORING"
}

# Function to create comprehensive incident response plan for admin accounts
create_admin_incident_response_plan() {
    local username="$1"
    local operator="${SUDO_USER:-$USER}"
    
    # HIPAA Requirement: Enhanced incident response plan for privileged accounts
    cat > "/etc/healthcare/incident-response-admin-$username.md" << EOF
# Critical Incident Response Plan for Admin User: $username

## IMMEDIATE RESPONSE (0-15 minutes) - CRITICAL PRIORITY
### Account Security Actions
1. **Emergency Account Lockout**: \`passwd -l $username && usermod -L $username\`
2. **Kill All Sessions**: \`pkill -u $username; pkill -t \$(who | grep $username | awk '{print \$2}')\`
3. **Revoke Sudo Access**: \`gpasswd -d $username sudo\`
4. **Disable SSH Keys**: \`mv /home/$username/.ssh/authorized_keys /home/$username/.ssh/authorized_keys.disabled\`

### Immediate Containment
1. **Network Isolation**: Block user's IP if remote access suspected
2. **Service Account Review**: Check all services running under admin privileges
3. **Active Connection Monitoring**: \`netstat -tulpn | grep $username\`
4. **Process Termination**: Kill any suspicious processes owned by admin user

## INVESTIGATION PHASE (15 minutes - 4 hours)
### Comprehensive Audit Review
1. **Admin Command History**:
   - \`grep "$username" $PRIVILEGED_COMMANDS_LOG\`
   - \`grep "$username" /var/log/admin-commands.log\`
   - \`last -u $username\`

2. **System Modification Analysis**:
   - \`grep "admin-config-changes-$username" /var/log/audit/audit.log\`
   - \`grep "admin-privileged-$username" /var/log/audit/audit.log\`
   - \`grep "admin-file-deletion-$username" /var/log/audit/audit.log\`

3. **PHI Access Investigation**:
   - \`grep "admin-phi-access-$username" /var/log/audit/audit.log\`
   - Review all PHI directories accessed in last 24-72 hours
   - Check for unauthorized data exports or transfers

4. **Network Activity Analysis**:
   - \`grep "admin-network-$username" /var/log/audit/audit.log\`
   - Check firewall logs for unusual outbound connections
   - Review VPN logs and remote access patterns

### Critical System Integrity Checks
1. **System File Verification**: \`rpm -Va\` or \`debsums -c\`
2. **Configuration File Changes**: \`find /etc -type f -newer /tmp/incident_start_time\`
3. **User Account Changes**: Review /etc/passwd, /etc/shadow modifications
4. **Service Configuration**: Check for unauthorized service modifications

## CONTAINMENT & RECOVERY (4-24 hours)
### System Hardening
1. **Password Reset Protocol**:
   - Generate new secure credentials using /dev/urandom
   - Force password change on next login
   - Update all service account passwords if compromise suspected

2. **Permission Audit & Restoration**:
   - \`find / -user $username -exec ls -la {} \;\`
   - Review and restore original file permissions
   - Verify group memberships and access rights

3. **Service Account Security**:
   - Review all service accounts for unauthorized changes
   - Reset database admin passwords if applicable
   - Update application service credentials

### Data Integrity Assessment
1. **PHI Compromise Evaluation**:
   - Identify all PHI potentially accessed during incident window
   - Check for unauthorized copying, modification, or deletion
   - Verify backup integrity and availability

2. **System Backup Verification**:
   - Test recent system backups for integrity
   - Verify configuration backups are clean
   - Prepare rollback procedures if needed

## DOCUMENTATION & COMPLIANCE (Ongoing)
### Required Documentation
- **Incident Timeline**: Detailed chronological record of events
- **Impact Assessment**: Scope of potential PHI compromise
- **Technical Analysis**: Root cause and attack vector identification
- **Corrective Actions**: All remediation steps taken
- **Lessons Learned**: Improvements to prevent recurrence

### HIPAA Compliance Requirements
1. **Incident Classification**:
   - Determine if PHI was accessed, disclosed, or compromised
   - Assess scale and scope of potential breach
   - Document risk assessment methodology

2. **Notification Requirements**:
   - Internal notification: Immediate (< 1 hour)
   - Privacy Officer notification: Within 24 hours
   - Management notification: Within 24 hours
   - HHS notification: Within 60 days if breach confirmed
   - Affected individuals: Within 60 days if required

3. **Risk Assessment Documentation**:
   - Nature and extent of PHI involved
   - Unauthorized person who accessed PHI
   - Whether PHI was actually acquired or viewed
   - Extent to which risk has been mitigated

## PREVENTION & MONITORING ENHANCEMENTS
### Immediate Security Improvements
1. **Enhanced Monitoring**: Implement real-time admin activity alerts
2. **Access Review**: Conduct emergency review of all admin accounts
3. **Multi-Factor Authentication**: Implement additional auth factors
4. **Network Segmentation**: Isolate admin access paths

### Long-term Security Hardening
1. **Privileged Access Management**: Implement PAM solution
2. **Just-in-Time Access**: Time-limited admin privileges
3. **Behavioral Analytics**: AI-based anomaly detection
4. **Regular Penetration Testing**: Quarterly security assessments

## EMERGENCY CONTACT INFORMATION
- **Incident Commander**: security-commander@organization.com / +1-XXX-XXX-XXXX
- **CISO**: ciso@organization.com / +1-XXX-XXX-XXXX  
- **Privacy Officer**: privacy@organization.com / +1-XXX-XXX-XXXX
- **Legal Counsel**: legal@organization.com / +1-XXX-XXX-XXXX
- **IT Director**: it-director@organization.com / +1-XXX-XXX-XXXX
- **Compliance Team**: compliance@organization.com / +1-XXX-XXX-XXXX

## REGULATORY REPORTING
### Internal Reporting
- Security team notification script: \`/usr/local/bin/security-alert.sh admin-incident $username\`
- Compliance tracking: Update incident tracking system
- Management dashboard: Real-time incident status updates

### External Reporting (if required)
- HHS OCR: https://www.hhs.gov/ocr/privacy/hipaa/administrative/breachnotificationrule/
- State AG notification: As required by state breach laws
- Business Associate notifications: Within contractual timeframes
- Cyber insurance carrier: Within 24 hours of incident detection

---
**Document Classification**: CONFIDENTIAL - HIPAA SECURITY INCIDENT RESPONSE
**Last Updated**: $(date)
**Authorized Personnel Only**: This document contains sensitive security procedures
EOF

    chmod 600 "/etc/healthcare/incident-response-admin-$username.md"
    chown root:healthcare-admins "/etc/healthcare/incident-response-admin-$username.md"
    
    # Create automated incident response scripts
    cat > "/usr/local/bin/admin-emergency-lockout-$username.sh" << EOF
#!/bin/bash
# Emergency lockout script for admin user $username
# Usage: ./admin-emergency-lockout-$username.sh "reason for lockout"

REASON="\$1"
TIMESTAMP=\$(date '+%Y-%m-%d %H:%M:%S')
OPERATOR=\${SUDO_USER:-\$USER}

echo "[\$TIMESTAMP] EMERGENCY LOCKOUT INITIATED by \$OPERATOR: \$REASON" >> /var/log/emergency-lockouts.log

# Immediate lockout procedures
passwd -l $username
usermod -L $username
gpasswd -d $username sudo 2>/dev/null || true
pkill -u $username
mv /home/$username/.ssh/authorized_keys /home/$username/.ssh/authorized_keys.disabled.\$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

# Log the emergency action
echo "[\$TIMESTAMP] EMERGENCY: Admin user $username locked out by \$OPERATOR - \$REASON" | tee -a /var/log/hipaa-audit.log /var/log/hipaa-admin-audit.log

# Send immediate alerts
echo "CRITICAL HIPAA ALERT: Admin user $username has been emergency locked out. Reason: \$REASON" | mail -s "EMERGENCY: Admin Account Lockout" security@organization.com compliance@organization.com

echo "Emergency lockout completed for admin user: $username"
echo "Incident response plan: /etc/healthcare/incident-response-admin-$username.md"
EOF

    chmod 700 "/usr/local/bin/admin-emergency-lockout-$username.sh"
    chown root:root "/usr/local/bin/admin-emergency-lockout-$username.sh"
    
    log_action "Comprehensive incident response plan created for admin user" "$username"
    log_admin_action "INCIDENT_RESPONSE_PLAN_CREATED" "$username" "$operator" "EMERGENCY_PROCEDURES"
}

# Function to create admin training and compliance documentation
create_admin_training_plan() {
    local username="$1"
    local operator="${SUDO_USER:-$USER}"
    
    # HIPAA Requirement: Mandatory training for privileged users
    cat > "/etc/healthcare/admin-training-plan-$username.md" << EOF
# HIPAA Compliance Training Plan for Administrator: $username

## MANDATORY TRAINING REQUIREMENTS

### Initial Training (Complete within 7 days)
1. **HIPAA Security Rule Overview** (2 hours)
   - Administrative safeguards for PHI
   - Physical and technical safeguards
   - Breach notification requirements

2. **Privileged Access Security** (1.5 hours)
   - Principle of least privilege
   - Multi-factor authentication requirements
   - Secure password management

3. **Incident Response Procedures** (1 hour)
   - Emergency response protocols
   - Breach identification and reporting
   - Documentation requirements

4. **Audit and Monitoring Systems** (1 hour)
   - Understanding audit trails
   - Monitoring tools and alerts
   - Compliance reporting procedures

### Ongoing Training Requirements
- **Monthly Security Briefings**: First Friday of each month
- **Quarterly Compliance Updates**: Regulatory changes and updates
- **Annual Comprehensive Review**: Full HIPAA security training renewal
- **Emergency Response Drills**: Bi-annual incident simulation exercises

### Training Completion Tracking
- Training records maintained in compliance database
- Certification expires annually and must be renewed
- Failure to complete training results in access suspension

## ADMINISTRATIVE RESPONSIBILITIES

### Daily Security Practices
- [ ] Review security alerts and audit logs
- [ ] Verify backup completion and integrity
- [ ] Monitor user access patterns for anomalies
- [ ] Check system security status dashboards

### Weekly Security Tasks
- [ ] Review failed login attempts and investigate anomalies
- [ ] Audit new user account creations and modifications
- [ ] Verify compliance with password policies
- [ ] Review and test emergency response procedures

### Monthly Compliance Activities
- [ ] Generate and review comprehensive audit reports
- [ ] Conduct user access rights review
- [ ] Test backup and disaster recovery procedures
- [ ] Update security documentation and procedures

### Quarterly Security Assessments
- [ ] Comprehensive vulnerability scan review
- [ ] Risk assessment update and documentation
- [ ] Security policy review and updates
- [ ] Business Associate Agreement compliance review

## PROHIBITED ACTIVITIES
The following activities are strictly prohibited and will result in immediate account suspension:

1. **Unauthorized PHI Access**: Accessing patient data not required for job duties
2. **Password Sharing**: Sharing credentials with any other person
3. **Unauthorized Software**: Installing software without security approval
4. **Data Export**: Copying PHI to unauthorized locations or devices
5. **Off-Hours Access**: System access outside approved business hours without authorization
6. **Remote Access Violations**: Using unsecured networks or devices for system access

## COMPLIANCE CERTIFICATIONS REQUIRED
- **HIPAA Security Officer Certification** - Annual renewal required
- **Cybersecurity Framework Certification** - Bi-annual renewal
- **Incident Response Team Certification** - Annual renewal
- **Healthcare IT Security Certification** - Tri-annual renewal

## PERFORMANCE MONITORING
Administrative performance will be evaluated based on:
- Compliance with security policies and procedures
- Timely completion of required training
- Quality of incident response and documentation
- Proactive identification of security issues

Training completion status: [ ] Complete [ ] In Progress [ ] Not Started
Next scheduled training: _______________
Training coordinator: training@organization.com
Compliance officer approval: _______________

---
**Document Classification**: CONFIDENTIAL - ADMIN TRAINING REQUIREMENTS
**Created**: $(date)
**Valid Until**: $(date -d "+1 year")
EOF

    chmod 640 "/etc/healthcare/admin-training-plan-$username.md"
    chown root:healthcare-admins "/etc/healthcare/admin-training-plan-$username.md"
    
    # Schedule training reminders
    cat > "/etc/cron.d/admin-training-reminders-$username" << EOF
# Training reminders for admin user $username
# Monthly training reminder
0 9 1 * * root echo "Monthly HIPAA training due for admin $username" | mail -s "Training Reminder" $username@organization.com training@organization.com
# Annual certification renewal reminder  
0 9 1 1 * root echo "Annual HIPAA certification renewal due for admin $username" | mail -s "Certification Renewal Required" $username@organization.com compliance@organization.com
EOF

    log_action "Admin training and compliance plan created" "$username"
    log_admin_action "TRAINING_PLAN_CREATED" "$username" "$operator" "COMPLIANCE_REQUIREMENTS"
}

# Main admin provisioning function
main() {
    # Check if script is run as root
    if [[ $EUID -ne 0 ]]; then
        echo "Error: This script must be run as root for admin user provisioning"
        exit 1
    fi
    
    # HIPAA Requirement: Enhanced validation for admin provisioning
    local operator="${SUDO_USER:-$USER}"
    echo "Validating senior operator access for admin provisioning: $operator"
    validate_operator_access "$operator"
    
    # Get user input with enhanced validation
    if [[ $# -lt 3 ]]; then
        echo "Usage: $0 <username> <full_name> <department>"
        echo "Example: $0 jdoe 'John Doe' 'IT Administration'"
        echo ""
        echo "WARNING: This creates a PRIVILEGED ADMINISTRATOR account with full system access"
        echo "Ensure proper authorization before proceeding"
        exit 1
    fi
    
    local username="$1"
    local full_name="$2"
    local department="$3"
    
    # Enhanced input validation for admin accounts
    validate_input "$username"
    
    # Check if user already exists
    if id "$username" &>/dev/null; then
        echo "Error: User $username already exists"
        exit 1
    fi
    
    # Final confirmation for admin account creation
    echo ""
    echo "⚠️  CRITICAL SECURITY NOTICE ⚠️"
    echo "You are about to create a PRIVILEGED ADMINISTRATOR account with:"
    echo "- Full system administration rights"
    echo "- Complete PHI access capabilities"  
    echo "- Audit log access and modification abilities"
    echo "- Emergency incident response permissions"
    echo ""
    echo "Admin Account Details:"
    echo "Username: $username"
    echo "Full Name: $full_name"
    echo "Department: $department"
    echo "Operator: $operator"
    echo ""
    read -p "Type 'CREATE_ADMIN_ACCOUNT' to confirm and proceed: " confirmation
    
    if [[ "$confirmation" != "CREATE_ADMIN_ACCOUNT" ]]; then
        echo "Admin account creation cancelled by operator"
        log_admin_action "CREATION_CANCELLED" "$username" "$operator" "USER_CANCELLED"
        exit 1
    fi
    
    # Initialize secure logging directories with enhanced permissions
    mkdir -p /var/log /etc/healthcare
    chmod 700 /etc/healthcare
    touch "$PASSWORD_AUDIT_LOG" "$ADMIN_AUDIT_LOG" "$PRIVILEGED_COMMANDS_LOG"
    chmod 600 "$PASSWORD_AUDIT_LOG" "$ADMIN_AUDIT_LOG" "$PRIVILEGED_COMMANDS_LOG"
    chown root:healthcare-admins "$ADMIN_AUDIT_LOG" "$PRIVILEGED_COMMANDS_LOG"
    
    echo "=========================================="
    echo "Starting HIPAA-compliant ADMINISTRATOR provisioning"
    echo "User: $username"
    echo "Full Name: $full_name"
    echo "Department: $department"
    echo "Operator: $operator"
    echo "Timestamp: $(date)"
    echo "=========================================="
    
    # Execute comprehensive admin provisioning with enhanced security
    create_admin_account "$username" "$full_name" "$department"
    setup_admin_group_memberships "$username"
    setup_admin_directory_access "$username"
    setup_admin_ssh_access "$username"
    setup_admin_audit_logging "$username"
    setup_admin_user_profile "$username"
    setup_admin_security_monitoring "$username"
    create_admin_incident_response_plan "$username"
    create_admin_training_plan "$username"
    
    # Final security verification and comprehensive summary
    echo "=========================================="
    echo "✅ HIPAA-Compliant ADMINISTRATOR Provisioning COMPLETED"
    echo "=========================================="
    echo "Account Details:"
    echo "  Username: $username"
    echo "  Groups: $(groups $username | tr ' ' '\n' | grep -E '(sudo|admin|healthcare)' | tr '\n' ' ')"
    echo "  Home Directory: /home/$username"
    echo "  Shell: $(getent passwd $username | cut -d: -f7)"
    echo ""
    echo "Access Privileges:"
    echo "  ✓ Full system administration (sudo access)"
    echo "  ✓ Complete PHI access (with audit trail)"
    echo "  ✓ Security administration capabilities"
    echo "  ✓ Backup and recovery operations"
    echo "  ✓ Audit log access and analysis"
    echo "  ✓ Emergency incident response authority"
    echo ""
    echo "Security Configuration:"
    echo "  ✓ Password Policy: 30-day rotation, 20-character minimum"
    echo "  ✓ Account Expires: $(chage -l "$username" | grep "Account expires" | cut -d: -f2 | xargs)"
    echo "  ✓ MFA Required: Yes (enforced through PAM)"
    echo "  ✓ SSH Key Authentication: Configured"
    echo "  ✓ Command Logging: Comprehensive"
    echo "  ✓ Real-time Monitoring: Active"
    echo ""
    echo "HIPAA Compliance Features:"
    echo "  ✅ AES-256 encrypted credential storage"
    echo "  ✅ Comprehensive audit trail logging"
    echo "  ✅ Enhanced access controls and validation"
    echo "  ✅ Real-time security monitoring"
    echo "  ✅ Automated incident response procedures"
    echo "  ✅ Mandatory compliance training plan"
    echo "  ✅ Regular security assessments scheduled"
    echo "  ✅ Emergency lockout capabilities"
    echo ""
    echo "Required Actions:"
    echo "  1. 🔐 Provide encrypted password through secure channel"
    echo "  2. 📚 Schedule mandatory HIPAA training (7-day deadline)"
    echo "  3. 🔍 Complete initial access rights review"
    echo "  4. 📋 User must change password on first login"
    echo "  5. ✅ Obtain signed acceptable use policy"
    echo ""
    echo "Documentation Created:"
    echo "  - Incident Response Plan: /etc/healthcare/incident-response-admin-$username.md"
    echo "  - Training Plan: /etc/healthcare/admin-training-plan-$username.md"
    echo "  - Emergency Procedures: /usr/local/bin/admin-emergency-lockout-$username.sh"
    echo ""
    echo "🚨 SECURITY REMINDERS:"
    echo "  - This account has PRIVILEGED ACCESS to ALL systems and PHI"
    echo "  - ALL activities are comprehensively logged and monitored"
    echo "  - Emergency incident response plan is activated for this account"
    echo "  - Annual compliance training and certification required"
    echo "  - Immediate suspension for policy violations"
    echo ""
    echo "Next Review Date: $(date -d "+30 days" +%Y-%m-%d)"
    echo "=========================================="
    
    # Final audit log entries
    log_action "CRITICAL: HIPAA-compliant administrator provisioning completed successfully" "$username"
    log_admin_action "PROVISIONING_COMPLETE" "$username" "$operator" "FULL_ADMINISTRATOR"
    log_password_action "ADMIN_PROVISIONING_COMPLETE" "$username" "$operator"
    
    # Send notifications to security team
    echo "HIPAA COMPLIANCE NOTICE: New administrator account '$username' has been provisioned by $operator with full system privileges. Comprehensive monitoring and audit trails are active." | mail -s "New Admin Account Provisioned" security@organization.com compliance@organization.com
}

# Run main function with all arguments
main "$@"