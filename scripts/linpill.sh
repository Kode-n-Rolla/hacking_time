#!/bin/bash

# **Disclaimer**
echo -e "\e[33mExtended Pillaging Script for Penetration Testing\e[0m"
echo -e "\e[33mThis script is intended for authorized penetration testing only.\e[0m"
echo -e "\e[33mEnsure you have explicit permission to run this on the target system.\e[0m"
echo -e "\e[33mUnauthorized use may violate laws and regulations.\e[0m"
echo ""

# **Check for Root Privileges**
if [ "$EUID" -ne 0 ]; then
    echo -e "\e[31mError: This script requires root privileges.\e[0m"
    exit 1
fi

# **Initialize Variables**
HOSTNAME=$(hostname)
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
EXPORT_DIR="/tmp/Pillaging_${HOSTNAME}_${TIMESTAMP}"
mkdir -p "$EXPORT_DIR"
echo -e "\e[32mData will be exported to: $EXPORT_DIR\e[0m"
echo -e "\e[32mStarted at: $(date +'%Y-%m-%d %H:%M:%S')\e[0m"
echo ""

# **Function to Write Output and Export to File**
write_and_export() {
    local SECTION="$1"
    local DATA="$2"
    local FILENAME="$3"
    echo -e "\e[36m=== $SECTION ===\e[0m"
    echo "$DATA"
    echo "$DATA" > "$EXPORT_DIR/$FILENAME.txt"
}

# **Function to Handle Errors Safely**
invoke_safe() {
    local COMMAND="$1"
    local ERROR_MSG="$2"
    eval "$COMMAND" || echo -e "\e[31mError: $ERROR_MSG\e[0m"
}

# **System Information**
echo -e "\e[33mCollecting System Information...\e[0m"

## OS Details
OS_INFO=$(uname -a)
write_and_export "OS Information" "$OS_INFO" "OSInfo"

## Distribution Details
DISTRO_INFO=$(lsb_release -a 2>/dev/null)
write_and_export "Distribution Information" "$DISTRO_INFO" "DistroInfo"

## CPU Information
CPU_INFO=$(lscpu)
write_and_export "CPU Information" "$CPU_INFO" "CPUInfo"

## Memory Information
MEM_INFO=$(free -h)
write_and_export "Memory Information" "$MEM_INFO" "MemInfo"

## Installed Packages
PACKAGES=$(dpkg -l)
write_and_export "Installed Packages" "$PACKAGES" "Packages"

## Running Services
SERVICES=$(systemctl list-units --type=service --state=running)
write_and_export "Running Services" "$SERVICES" "Services"

# **User and Group Information**
echo -e "\e[33mCollecting User and Group Information...\e[0m"

## User Accounts
USERS=$(getent passwd)
write_and_export "User Accounts" "$USERS" "Users"

## Sudoers
SUDOERS=$(getent group sudo | cut -d: -f4)
write_and_export "Sudoers" "$SUDOERS" "Sudoers"

## Password Policy
PASSWD_POLICY=$(cat /etc/security/pwquality.conf 2>/dev/null || echo "Not configured")
write_and_export "Password Policy" "$PASSWD_POLICY" "PasswordPolicy"

# **Network Configuration**
echo -e "\e[33mCollecting Network Information...\e[0m"

## IP Configuration
IP_CONFIG=$(ip addr show)
write_and_export "IP Configuration" "$IP_CONFIG" "IPConfig"

## Listening Ports
LISTENING_PORTS=$(ss -tuln)
write_and_export "Listening Ports" "$LISTENING_PORTS" "ListeningPorts"

## ARP Cache
ARP_CACHE=$(ip neigh)
write_and_export "ARP Cache" "$ARP_CACHE" "ARPCache"

## SMB Shares (if Samba is installed)
if command -v smbclient >/dev/null; then
    SMB_SHARES=$(smbclient -L localhost -N 2>/dev/null)
    if [ -n "$SMB_SHARES" ]; then
        write_and_export "SMB Shares" "$SMB_SHARES" "SMBShares"
    else
        echo "No SMB shares found or Samba not installed."
    fi
fi

## Firewall Rules - IPTables
IPTABLES_RULES=$(iptables -L -v -n)
write_and_export "IPTables Rules" "$IPTABLES_RULES" "IPTablesRules"

## Firewall Rules - UFW (if installed)
if command -v ufw >/dev/null; then
    UFW_STATUS=$(ufw status verbose)
    write_and_export "UFW Status" "$UFW_STATUS" "UFWStatus"
fi

# **Process and Software Analysis**
echo -e "\e[33mCollecting Process and Software Information...\e[0m"

## Running Processes
PROCESSES=$(ps aux)
write_and_export "Running Processes" "$PROCESSES" "Processes"

## Enabled Systemd Services (Autoruns)
SYSTEMD_AUTORUNS=$(systemctl list-unit-files --type=service | grep enabled)
write_and_export "Enabled Systemd Services" "$SYSTEMD_AUTORUNS" "SystemdAutoruns"

## Cron Jobs
CRON_JOBS=$(ls /etc/cron.*/* 2>/dev/null)
write_and_export "Cron Jobs" "$CRON_JOBS" "CronJobs"

## User Crontab Files
CRONTAB_FILES=$(find /var/spool/cron/crontabs -type f 2>/dev/null)
if [ -n "$CRONTAB_FILES" ]; then
    write_and_export "User Crontab Files" "$CRONTAB_FILES" "CrontabFiles"
fi

# **Privilege Escalation Checks**
echo -e "\e[33mPerforming Privilege Escalation Checks...\e[0m"

## Writable PATH Directories
PATH_DIRS=($(echo "$PATH" | tr ':' ' '))
WRITABLE_PATH_DIRS=()
for dir in "${PATH_DIRS[@]}"; do
    if [ -w "$dir" ]; then
        WRITABLE_PATH_DIRS+=("$dir")
    fi
done
if [ ${#WRITABLE_PATH_DIRS[@]} -gt 0 ]; then
    write_and_export "Writable PATH Directories" "$(echo "${WRITABLE_PATH_DIRS[@]}")" "WritablePathDirs"
else
    echo "No writable PATH directories found."
fi

## SUID/SGID Binaries
SUID_SGID=$(find / -perm /6000 -type f 2>/dev/null)
write_and_export "SUID/SGID Binaries" "$SUID_SGID" "SUID_SGID"

# **Sensitive File Search**
echo -e "\e[33mSearching for Sensitive Files...\e[0m"

## Potentially Sensitive Files by Pattern
SENSITIVE_FILES=$(find / -type f -regex ".*\(password\|cred\|secret\|key\|config\)\.\(txt\|doc\|docx\|xml\|ini\|conf\)$" 2>/dev/null)
if [ -n "$SENSITIVE_FILES" ]; then
    write_and_export "Potentially Sensitive Files" "$SENSITIVE_FILES" "SensitiveFiles"
    SENSITIVE_FILE_COUNT=$(echo "$SENSITIVE_FILES" | wc -l)
else
    echo "No sensitive files found."
    SENSITIVE_FILE_COUNT=0
fi

# **Interesting Files by Extension**
echo -e "\e[33mSearching for Interesting Files by Extension...\e[0m"
echo -e "\e[33mThis may take a while depending on the number of files and directories.\e[0m"

## Define Extensions (Extended for Linux)
# Define Extensions
EXTENSIONS=(
    "*.txt" "*.pdf" "*.csv" "*.xml" "*.json" "*.yaml" "*.log" "*.key" "*.pem" "*.cer" "*.crt" "*.p12" "*.jks" "*.sql" "*.sqlite" "*.db" "*.bak" "*.old" "*.backup" "*.sh" "*.py" "*.pl" "*.js" "*.conf" "*.ini" "*.cfg" "*.properties" "*.config" "*.vmdk" "*.vhd" "*.vhdx" "*.ova" "*.ovf" "*.rb" "*.php" "*.save" "*.swp" "*.yml" "*.tar" "*.gz" "*.zip" "*.rar" "*.7z" "*.tgz" "*.tbz2" "*.xz" "*.bz2" "*.deb" "*.env" "*.htpasswd" "*.csr" "*.asc" "*.gpg" "*.pub" "*.known_hosts" "*.keystore" "*.truststore" "*.ovpn" "*.tblk" "*.kdbx" "*.kdb" "*.ppk" "*.wallet" "*.cscfg" "*.sqldump" "*.cnf" "*.pgpass" "*.service"
)

# Build and Execute Find Command with properly escaped parentheses
echo -e "\e[33mSearching for Interesting Files by Extension...\e[0m"
echo -e "\e[33mThis may take a while depending on the number of files and directories.\e[0m"

FIND_CMD="find / -type f \\("
for ext in "${EXTENSIONS[@]}"; do
    FIND_CMD+=" -name '$ext' -o"
done
# Remove the trailing ' -o' and add the closing escaped parenthesis
FIND_CMD="${FIND_CMD% -o} \\) 2>/dev/null"
INTERESTING_FILES=$(eval "$FIND_CMD")
if [ -n "$INTERESTING_FILES" ]; then
    echo "Interesting Files found:"
    echo "$INTERESTING_FILES"
    INTERESTING_FILE_COUNT=$(echo "$INTERESTING_FILES" | wc -l)
    echo "Found $INTERESTING_FILE_COUNT interesting files."
else
    echo "No interesting files found."
    INTERESTING_FILE_COUNT=0
fi

# **Summary of Key Findings**
echo -e "\e[36m=== Summary of Key Findings ===\e[0m"
echo "Interesting Files Found: $INTERESTING_FILE_COUNT"
echo "Sensitive Files Found: $SENSITIVE_FILE_COUNT"
if [ -f "$EXPORT_DIR/WritablePathDirs.txt" ]; then
    WRITABLE_COUNT=$(wc -l < "$EXPORT_DIR/WritablePathDirs.txt")
    echo "Writable PATH Directories: $WRITABLE_COUNT"
else
    echo "Writable PATH Directories: 0"
fi
if [ -f "$EXPORT_DIR/SUID_SGID.txt" ]; then
    SUID_SGID_COUNT=$(wc -l < "$EXPORT_DIR/SUID_SGID.txt")
    echo "SUID/SGID Binaries: $SUID_SGID_COUNT"
else
    echo "SUID/SGID Binaries: 0"
fi

# **Finalization**
echo -e "\e[32mPillaging complete. All data saved to $EXPORT_DIR\e[0m"
echo -e "\e[32mCompleted at: $(date +'%Y-%m-%d %H:%M:%S')\e[0m"
