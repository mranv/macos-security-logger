# Last 24 hours
sudo ./target/release/macos-security-logger --verbose --hours 24

# Last 48 hours for specific categories
sudo ./target/release/macos-security-logger --verbose --hours 48 --categories "network_security,system_integrity"

# Custom time range
sudo ./target/release/macos-security-logger --verbose --start-time "2024-12-12 00:00:00" --end-time "2024-12-13 23:59:59"

# Default operation (last 24 hours)
sudo ./target/release/macos-security-logger --verbose