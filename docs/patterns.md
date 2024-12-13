# Log Pattern Writing Guide

## Basic Pattern Syntax

macOS Security Logger uses the unified logging system's predicate syntax for filtering logs.

### Simple Patterns

1. **Process Name**
```
process == "securityd"
process == "sandboxd"
process == "socketfilterfw"
```

2. **Subsystem**
```
subsystem == "com.apple.security"
subsystem == "com.apple.sandbox"
```

3. **Category**
```
category == "security"
category == "network"
```

### Advanced Patterns

1. **Message Content**
```
eventMessage CONTAINS[c] "security violation"
eventMessage CONTAINS[c] "access denied"
eventMessage BEGINSWITH "Failed authentication"
```

2. **Timestamps**
```
timestamp >= "2024-01-01 00:00:00"
timestamp <= "2024-12-31 23:59:59"
```

3. **Process IDs**
```
processID == 1234
processID > 1000
```

### Combining Patterns

1. **AND Operations**
```
process == "securityd" AND category == "security"
subsystem == "com.apple.security" AND eventMessage CONTAINS "violation"
```

2. **OR Operations**
```
process == "securityd" OR process == "sandboxd"
category == "security" OR category == "authentication"
```

3. **Complex Combinations**
```
(process == "securityd" OR process == "sandboxd") AND 
(category == "security" AND eventMessage CONTAINS[c] "violation")
```

## Pattern Examples by Use Case

### Security Violations
```json
{
    "log_patterns": [
        "category == \"security\" AND eventMessage CONTAINS[c] \"violation\"",
        "process == \"securityd\" AND eventMessage CONTAINS[c] \"failed\"",
        "subsystem == \"com.apple.security\" AND eventMessage CONTAINS[c] \"denied\""
    ]
}
```

### Authentication Monitoring
```json
{
    "log_patterns": [
        "process == \"authd\" AND category == \"authentication\"",
        "eventMessage CONTAINS[c] \"login\" OR eventMessage CONTAINS[c] \"authenticate\"",
        "subsystem == \"com.apple.auth\" AND eventMessage CONTAINS[c] \"failed\""
    ]
}
```

### Network Security
```json
{
    "log_patterns": [
        "process == \"socketfilterfw\" AND category == \"network\"",
        "eventMessage CONTAINS[c] \"connection blocked\"",
        "subsystem == \"com.apple.network\" AND eventMessage CONTAINS[c] \"firewall\""
    ]
}
```

## Pattern Testing

1. **Using log show Command**
```bash
# Test pattern directly
log show --predicate 'process == "securityd"' --last 1h

# Test combined pattern
log show --predicate 'process == "securityd" AND category == "security"' --last 1h
```

2. **Using Verbose Mode**
```bash
# Run logger with verbose flag to see pattern matching
sudo macos-security-logger --verbose
```

## Best Practices

1. **Pattern Design**
   - Start with broad patterns and refine
   - Use case-insensitive matching when appropriate
   - Consider performance impact of complex patterns

2. **Error Prevention**
   - Test patterns before deployment
   - Use proper escaping for special characters
   - Validate JSON syntax in configuration

3. **Optimization**
   - Combine related patterns
   - Use specific process names when possible
   - Limit time ranges for large log volumes