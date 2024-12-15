# macOS Security Logs Guide

## 1. System Security Logs

### Authentication & Authorization
```bash
# User login attempts
log show --predicate 'process == "authd" OR process == "authorization"'

# Security agent activities
log show --predicate 'process == "SecurityAgent"'

# Sudo commands
log show --predicate 'process == "sudo"'

# Terminal authentication
log show --predicate 'process == "login" OR process == "Terminal"'
```

### Kernel Security
```bash
# Kernel security events
log show --predicate 'process == "kernel" AND category == "security"'

# System policy
log show --predicate 'process == "syspolicyd"'

# System integrity protection
log show --predicate 'subsystem == "com.apple.security.syspolicy"'
```

### File System Security
```bash
# File system access
log show --predicate 'category == "fs" AND eventMessage CONTAINS[c] "permission"'

# Directory service events
log show --predicate 'process == "opendirectoryd"'

# File system changes
log show --predicate 'process == "fseventsd"'

# Disk management
log show --predicate 'process == "diskmanagementd"'
```

## 2. Network Security

### Firewall Logs
```bash
# Application firewall
log show --predicate 'process == "socketfilterfw"'

# Network extensions
log show --predicate 'category == "network" AND eventMessage CONTAINS "filter"'

# Connection blocking
log show --predicate 'eventMessage CONTAINS[c] "connection blocked"'
```

### Network Access
```bash
# Network daemon
log show --predicate 'process == "networkd"'

# DNS activity
log show --predicate 'process == "mDNSResponder"'

# Network security events
log show --predicate 'subsystem == "com.apple.network.security"'
```

## 3. Application Security

### Gatekeeper & XProtect
```bash
# Gatekeeper checks
log show --predicate 'eventMessage CONTAINS "Gatekeeper"'

# XProtect malware detection
log show --predicate 'process == "XProtect"'

# System policy security
log show --predicate 'subsystem == "com.apple.security.syspolicy"'
```

### Sandbox Violations
```bash
# Sandbox violations
log show --predicate 'process == "sandboxd"'

# App sandbox events
log show --predicate 'category == "sandbox"'

# Security violations
log show --predicate 'eventMessage CONTAINS[c] "violation"'
```

## 4. Privacy & Data Access

### Privacy Protection
```bash
# TCC (Transparency, Consent, and Control)
log show --predicate 'subsystem == "com.apple.TCC"'

# Privacy preferences
log show --predicate 'process == "tcd"'

# Data access attempts
log show --predicate 'category == "privacy"'
```

### Keychain Access
```bash
# Keychain operations
log show --predicate 'process == "securityd" AND eventMessage CONTAINS "keychain"'

# Certificate validation
log show --predicate 'category == "certificate"'

# Security framework
log show --predicate 'subsystem == "com.apple.security"'
```

## 5. System Integrity

### Code Signing
```bash
# Code signing verification
log show --predicate 'eventMessage CONTAINS "code signing"'

# Signature validation
log show --predicate 'category == "signature"'

# System integrity checks
log show --predicate 'subsystem == "com.apple.security.assessment"'
```

### System Updates
```bash
# Software updates
log show --predicate 'process == "softwareupdated"'

# System security updates
log show --predicate 'category == "update" AND eventMessage CONTAINS "security"'
```

## 6. Additional Security Events

### Common Patterns
```bash
# High-priority security events
log show --predicate 'category == "security" AND eventMessage CONTAINS[c] "critical"'

# Failed operations
log show --predicate 'eventMessage CONTAINS[c] "failed" OR eventMessage CONTAINS[c] "failure"'

# Security breaches
log show --predicate 'eventMessage CONTAINS[c] "breach" OR eventMessage CONTAINS[c] "compromise"'
```

### Time-Based Queries
```bash
# Last hour of security events
log show --predicate 'category == "security"' --last 1h

# Today's security events
log show --predicate 'category == "security"' --start "$(date -v0H -v0M -v0S)" --end "$(date)"
```

## Usage Tips

1. View Live Logs:
```bash
log stream --predicate 'category == "security"'
```

2. Export to File:
```bash
log show --predicate 'category == "security"' --last 24h --style json > security_logs.json
```

3. Filter by Severity:
```bash
log show --predicate 'category == "security" AND eventMessage CONTAINS "error"' --level error
```

4. Combine Predicates:
```bash
log show --predicate '(process == "securityd" OR process == "sandboxd") AND eventMessage CONTAINS[c] "violation"'
```