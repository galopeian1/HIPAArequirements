# HIPAA-Compliant Ubuntu Linux Deployment Guide

This guide provides comprehensive shell scripts for establishing a HIPAA-compliant Ubuntu Linux environment with enhanced security for healthcare organizations.

## Overview

The deployment consists of three main components:

1. **Infrastructure Setup Script** - Establishes the foundational security infrastructure
2. **Doctor Provisioning Script** - Creates secure accounts for hospital doctors
3. **Researcher Provisioning Script** - Creates secure accounts for healthcare researchers
4. **Nurse Provisioning Script** - Creates secure accounts for hospital nurses
5. **Admin Provisioning Script** - Creates a seure account for hospital sysadmin

## Prerequisites

- Ubuntu 24.04.3 LTS (required)
- Root access to the system
- Internet connectivity for package installation

## Quick Start

### 1. Initial Infrastructure Setup

Run the infrastructure setup script first to establish the security foundation:

```bash
sudo chmod +x hipaa_infrastructure_setup.sh
sudo ./hipaa_infrastructure_setup.sh
```

This script will:
- Create all required healthcare user groups
- Install essential security packages
- Configure system-wide security settings
- Set up comprehensive audit rules
- Configure firewall and monitoring
- Create policy templates

### 2. Add Administrator to Healthcare Groups

After infrastructure setup, add your administrator account to the healthcare-admins group:

```bash
sudo usermod -a -G healthcare-admins youradmin
```

### 3. Provision Users

#### For Doctor Accounts
```bash
sudo chmod +x hipaa_doctor_provision.sh
sudo ./hipaa_doctor_provision.sh
```

#### For Researcher Accounts
```bash
sudo chmod +x hipaa_researcher_provision.sh
sudo ./hipaa_researcher_provision.sh
```

## Detailed Features

### Enhanced Password Security

- **Cryptographically Secure Generation**: Uses `/dev/urandom` instead of `openssl rand`
- **Complex Password Requirements**: 
  - Minimum 14-16 characters
  - Uppercase, lowercase, numbers, and special characters required
  - No dictionary words or personal information
- **Password Aging**: 60-day maximum age with 7-day warning
- **Account Lockout**: 3 failed attempts trigger lockout

### Data Encryption (AES-256)

- **GPG Encryption**: Temporary passwords encrypted with AES-256 cipher
- **Secure Storage**: Encrypted files stored in `/etc/healthcare/encrypted_passwords/`
- **Automatic Cleanup**: Encrypted passwords removed after 24 hours
- **Key Management**: Secure key generation and storage

### Access Controls

- **Group-Based Security**: 
  - `healthcare-admins` - System administrators
  - `doctors` - Hospital Doctors
  - `researchers` - Research personnel
  - `nurses` - Hospital Nurses
- **LDAP Integration**: Ready for enterprise directory services
- **Session Tracking**: All access logged with IP addresses and session IDs

### Comprehensive Audit Trails

- **Dedicated Audit Logs**: Separate logs for different activities
- **7-Year Retention**: Compliant with HIPAA requirements
- **Real-time Monitoring**: Auditd rules for file system and network monitoring
- **Automated Alerting**: Email notifications for security events

### Regular Security Assessments

- **Automated Monitoring**: Hourly security checks via cron
- **File Integrity**: AIDE monitoring for unauthorized changes
- **Rootkit Detection**: Regular rkhunter scans
- **Failed Login Tracking**: Automated analysis of authentication failures

### Incident Response Plan

- **Automated Procedures**: Scripts for common incident types
- **Evidence Preservation**: Automatic evidence collection and storage
- **Account Isolation**: Immediate response capabilities
- **Documentation Requirements**: Structured incident logging

## User Environment Features

### Doctor-Specific Features

- Secure home directory structure
- HIPAA compliance reminders on login
- Patient data directories with appropriate permissions
- Medical license tracking in user information
- Incident response procedures

### Researcher-Specific Features

- Research project directories
- Data deidentification tools and templates
- IRB compliance tracking
- Research-specific audit trails
- Data use agreement templates

## Security Monitoring

### Real-Time Alerts

The system monitors for:
- Excessive failed login attempts (>20/day)
- Off-hours administrative activity
- Large data transfers from research directories
- Suspicious network connections
- File integrity violations
- Privilege escalation attempts

### Automated Responses

- Account lockout after failed attempts
- Evidence preservation during incidents
- Automatic log rotation and retention
- Security scan scheduling
- Backup automation

## Configuration Files

### Key Configuration Locations

- `/etc/healthcare/` - Main healthcare configuration directory
- `/var/log/healthcare/` - Healthcare-specific logs
- `/var/research/` - Research data directories
- `/etc/audit/rules.d/hipaa-*.rules` - Audit rules
- `/etc/security/pwquality.conf` - Password policies

### Important Log Files

- `/var/log/hipaa-password-audit.log` - Password generation audit
- `/var/log/healthcare/security.log` - Security events
- `/var/log/healthcare/research.log` - Research activities
- `/var/log/audit/audit.log` - System audit events

## Maintenance Procedures

### Daily Tasks (Automated)

- Security monitoring checks
- Log rotation
- Backup procedures
- Failed login analysis

### Weekly Tasks (Automated)

- AIDE database updates
- Comprehensive security scans
- Rootkit detection
- System integrity checks

### Monthly Tasks (Manual)

- Review security policies
- Audit user access permissions
- Update incident response procedures
- Security awareness training

### Annual Tasks (Manual)

- HIPAA risk assessments
- Policy review and updates
- Staff security training
- Disaster recovery testing

## Compliance Features

### HIPAA Security Rule Compliance

- ✅ Access Control (§164.312(a))
- ✅ Audit Controls (§164.312(b))
- ✅ Integrity (§164.312(c))
- ✅ Person or Entity Authentication (§164.312(d))
- ✅ Transmission Security (§164.312(e))

### Additional Standards Addressed

- **NIST Cybersecurity Framework** compatibility
- **ISO 27001** security controls
- **HITRUST** common security framework elements

## Troubleshooting

### Common Issues

#### Script Permission Errors
```bash
chmod +x script_name.sh
sudo chown root:root script_name.sh
```

#### Group Membership Issues
```bash
# Check user groups
groups username

# Add user to healthcare-admins
sudo usermod -a -G healthcare-admins username
```

#### Audit Log Issues
```bash
# Restart auditd service
sudo systemctl restart auditd

# Check audit rules
sudo auditctl -l
```

#### Password Generation Failures
```bash
# Check /dev/urandom availability
ls -la /dev/urandom

# Verify pwquality configuration
sudo cat /etc/security/pwquality.conf
```

### Log Analysis

#### View Recent Security Events
```bash
sudo tail -f /var/log/healthcare/security.log
```

#### Check Failed Login Attempts
```bash
sudo grep "Failed password" /var/log/auth.log | tail -20
```

#### Monitor PHI Access
```bash
sudo grep "research_data_access" /var/log/audit/audit.log
```

## Customization

### Email Notifications

Update email addresses in monitoring scripts:
```bash
sudo nano /usr/local/bin/hipaa-system-monitor.sh
# Change ALERT_EMAIL variable
```

### Password Policies

Modify password requirements:
```bash
sudo nano /etc/security/pwquality.conf
```

### Audit Rules

Add custom audit rules:
```
