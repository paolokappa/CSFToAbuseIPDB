#!/usr/bin/sh

# Set your AbuseIPDB API key here.
key="YOUR_API_KEY_HERE"

# Function to determine the appropriate AbuseIPDB category based on the trigger
determine_category() {
    local trigger=$1
    case "$trigger" in
        LF_SSHD) echo "22,18" ;; # SSH
        LF_TRIGGER) echo "22,18" ;; # SSH Brute-Force
        LF_DISTATTACK) echo "4" ;; # DDoS attack
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

# Concatenate details to form a useful AbuseIPDB comment.
comment="${message}; Ports: ${ports}; Direction: ${direction}; Trigger: ${trigger}; Logs: ${logs}"

# Send the data to AbuseIPDB
curl https://api.abuseipdb.com/api/v2/report \
  --data-urlencode "ip=$ip_address" \
  -d categories=$category \
  --data-urlencode "comment=$comment" \
  -H "Key: $key" \
  -H "Accept: application/json"
