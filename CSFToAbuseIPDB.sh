#!/usr/bin/sh

# Set your AbuseIPDB API key here.
key="YOUR_AbuseIPDB_API_KEY"

# Function to determine the appropriate AbuseIPDB category based on the trigger
determine_category() {
    local trigger=$1
    case "$trigger" in
        LF_SSHD) echo "22,18" ;; # SSH
        LF_TRIGGER) echo "22,18" ;; # SSH Brute-Force
        LF_DISTATTACK) echo "4,22" ;; # DDoS attack
        LF_DISTFTP) echo "5" ;; # FTP Brute-Force
        LF_WEBMIN_EMAIL_ALERT) echo "15,21" ;; # Webmin attack
        LF_EMAIL_ALERT) echo "11,18" ;; # Email attack
        LF_DISTSMTP) echo "18,11" ;; # SMTP attack
        LF_DISTMYSQL) echo "16,15" ;; # MySQL attack
        *) echo "18" ;; # Default to SSH if unknown
    esac
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
category=$(determine_category $trigger)
echo "Category: $category"

# Extract all unique IP addresses from the logs in case of LF_DISTATTACK
if [ "$trigger" = "LF_DISTATTACK" ]; then
    ips=$(echo "$logs" | grep -oP '(?<=rhost=)[\d\.]+' | sort -u)
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
    curl https://api.abuseipdb.com/api/v2/report \
      --data-urlencode "ip=$ip" \
      -d categories=$category \
      --data-urlencode "comment=$comment" \
      -H "Key: $key" \
      -H "Accept: application/json"
done
