# CSFToAbuseIPDB
This script is designed for ConfigServer Security &amp; Firewall (CSF). It reports suspicious IP addresses to AbuseIPDB based on triggers detected by CSF

# CSF to AbuseIPDB Reporting Script

This script is designed to work with ConfigServer Security & Firewall (CSF) to report suspicious IP addresses to AbuseIPDB. It maps specific CSF triggers to the corresponding AbuseIPDB categories, constructs a detailed comment about the incident, and sends the report to AbuseIPDB using the provided API key.

## How It Works

1. **API Key Configuration:**
   The script requires an AbuseIPDB API key to authenticate requests. Set your API key in the `key` variable.

   ```sh
   key="your_api_key_here"
   ```

2. **Trigger to Category Mapping:**
   The script includes a function `determine_category` that maps CSF triggers to AbuseIPDB categories. Each trigger corresponds to one or more categories.

   ```sh
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
   ```

3. **Argument Renaming:**
   The script renames positional arguments for readability. These arguments are expected to be passed by CSF when invoking the script.

   ```sh
   ip_address=$1
   ports=$2
   direction=$3
   message=$6
   logs=$7
   trigger=$8
   ```

4. **Debugging Output:**
   To aid in debugging, the script prints the trigger and determined category to the console.

   ```sh
   echo "Trigger: $trigger"
   category=$(determine_category $trigger)
   echo "Category: $category"
   ```

5. **Comment Construction:**
   The script concatenates details to form a comprehensive comment about the incident. This comment includes the message, ports, direction, trigger, and logs.

   ```sh
   comment="${message}; Ports: ${ports}; Direction: ${direction}; Trigger: ${trigger}; Logs: ${logs}"
   ```

6. **Report Submission:**
   The script uses `curl` to send a report to AbuseIPDB. The report includes the IP address, categories, and comment, authenticated with the API key.

   ```sh
   curl https://api.abuseipdb.com/api/v2/report \
     --data-urlencode "ip=$ip_address" \
     -d categories=$category \
     --data-urlencode "comment=$comment" \
     -H "Key: $key" \
     -H "Accept: application/json"
   ```

## Installation and Activation

1. **Set the API Key:**
   Replace `your_api_key_here` with your actual AbuseIPDB API key.

2. **Integrate with CSF:**
   Open the `csf.conf` file, which is usually located in `/etc/csf/csf.conf`.

   Add the path to your script to the `BLOCK_REPORT` variable. For example:
   ```sh
   BLOCK_REPORT="/path/to/your/script/abuseipdb_block.sh"
   ```

3. **Restart CSF:**
   After editing `csf.conf`, restart CSF to apply the changes:
   ```sh
   csf -r
   ```

## Usage

The script will be automatically executed by CSF when a trigger occurs. It will print the trigger and category for debugging and submit the report to AbuseIPDB.

## Example

Here is an example log detected by CSF that would invoke the script:

```plaintext
(sshd) Failed SSH login from 103.144.2.231 (HK/Hong Kong/-/-/-/[AS138152 YISU CLOUD LTD]): 1 in the last 3600 secs; Ports: *; Direction: 1; Trigger: LF_TRIGGER; Logs: Jul 7 14:41:46 www sshd[675888]: Invalid user test2 from 103.144.2.231 port 53852
```

The script will determine the category based on the `LF_TRIGGER` and report the IP address to AbuseIPDB with categories 22 and 18.

## Troubleshooting

If you encounter any issues, ensure that:
- The API key is correctly set.
- CSF is configured to invoke the script with the correct arguments.
- The script has execute permissions.

To debug, you can check the console output for the printed trigger and category values to ensure they are correct.

