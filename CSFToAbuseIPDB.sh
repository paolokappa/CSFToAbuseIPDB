#!/usr/bin/sh

# Set your AbuseIPDB API key here.
key="YOUR_AbuseIPDB_API_KEY"
log_file="/var/log/abuseipdb_block.log"

# Function to determine the appropriate AbuseIPDB category based on the trigger and comment
determine_category() {
    local trigger=$1
    local comment=$2
    case "$trigger" in
        LF_SSHD) echo "22,18" ;; # SSH
        LF_TRIGGER) 
            if echo "$comment" | grep -q "(ftpd)"; then
                echo "5"
            elif echo "$comment" | grep -q "(sshd)"; then
                echo "22,18"
            elif echo "$comment" | grep -q "(smtp)"; then
                echo "18,11"
            elif echo "$comment" | grep -q "(httpd)"; then
                echo "21"
            elif echo "$comment" | grep -q "(pop3d)"; then
                echo "18,11"
            elif echo "$comment" | grep -q "(imapd)"; then
                echo "18,11"
            elif echo "$comment" | grep -q "(mysql)"; then
                echo "16,15"
            elif echo "$comment" | grep -q "(named)"; then
                echo "1,2"
            elif echo "$comment" | grep -q "(exim)"; then
                echo "11,18"
            elif echo "$comment" | grep -q "(dovecot)"; then
                echo "18,11"
            else
                echo "18" # Default category for LF_TRIGGER
            fi
            ;;
        LF_DISTATTACK) echo "4,22" ;; # DDoS attack
        LF_DISTFTP) echo "5" ;; # FTP Brute-Force
        LF_WEBMIN_EMAIL_ALERT) echo "15,21" ;; # Webmin attack
        LF_EMAIL_ALERT) echo "11,18" ;; # Email attack
        LF_DISTSMTP) echo "18,11" ;; # SMTP attack
        LF_DISTMYSQL) echo "16,15" ;; # MySQL attack
        LF_EXIMSYNTAX) echo "11,18" ;; # Exim syntax error
        *) echo "18" ;; # Default to SSH if unknown
    esac
}

# Function to log operations to the log file
log_operation() {
    local message=$1
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> $log_file
}

# Rename arguments for readability.
ip_address=$1
ports=$2
direction=$3
message=$6
logs=$7
trigger=$8

# Debug output for tracing
echo "Trigger: $trigger"
category=$(determine_category $trigger "$message")
echo "Category: $category"

# Log the trigger and category determination
log_operation "Trigger: $trigger, Category: $category"

# Extract all unique IP addresses from the logs in case of LF_DISTATTACK
if [ "$trigger" = "LF_DISTATTACK" ]; then
    ips=$(echo "$logs" | grep -oP '(([0-9]{1,3}\.){3}[0-9]{1,3})' | sort -u)
else
    ips=$ip_address
fi

# Loop through all unique IPs and send the data to AbuseIPDB
for ip in $ips; do
    if [ "$trigger" = "LF_DISTATTACK" ]; then
        # Count the number of distributed attacks
        attack_count=$(echo "$logs" | grep -c "$ip")
        # Extract relevant logs for the current IP
        ip_logs=$(echo "$logs" | grep "$ip")
        # Construct the comment string for LF_DISTATTACK
        comment="Detected $attack_count distributed attacks from $ip. LF_DISTATTACK; Logs: $(echo "$ip_logs" | tr '\n' ' ')"
    else
        # Extract relevant logs for the current IP
        ip_logs=$(echo "$logs" | grep "$ip")
        # Construct the comment string for other triggers
        comment="${message}; IP: ${ip}; Ports: ${ports}; Direction: ${direction}; Trigger: ${trigger}; Logs: $(echo "$ip_logs" | tr '\n' ' ')"
    fi
    
    echo "Reporting IP: $ip with comment: $comment"
    log_operation "Reporting IP: $ip with comment: $comment"
    
    response=$(curl -s https://api.abuseipdb.com/api/v2/report \
      --data-urlencode "ip=$ip" \
      -d categories=$category \
      --data-urlencode "comment=$comment" \
      -H "Key: $key" \
      -H "Accept: application/json")
    
    log_operation "Response: $response"
done
