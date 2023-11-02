#!/bin/bash

# Get user input for the target domain
read -p "Enter the target domain: " domain

# Timestamp for the output file
timestamp=$(date +%Y%m%d%H%M%S)

# Output file name
output_file="${domain}_${timestamp}_shodan_output.txt"

# Initialize an empty output file
> "$output_file"

# Function to run Shodan on an IP address
run_shodan() {
    local ip="$1"
    if [[ ! " ${scanned_ips[@]} " =~ " ${ip} " ]] && ! grep -q "$ip" "$output_file"; then
        echo "Running Shodan on $ip"
        shodan host "$ip" >> "$output_file" 2>/dev/null
        scanned_ips+=("$ip")  # Add the IP to the scanned list
    fi
}

# Step 1: Get subdomains using crt.sh
subdomains=$(curl -s "https://crt.sh/?q=%.$domain&output=json" | jq -r '.[].name_value' | grep -v "CN=" | sort -u)

if [ -z "$subdomains" ]; then
    echo "No subdomains found for $domain. Exiting."
    exit 1
fi

# Step 2: Find IP addresses for each subdomain and run Shodan
for subdomain in $subdomains; do
    host_output=$(host "$subdomain" | grep "has address" | grep "$domain")

    if [ -n "$host_output" ]; then
        ip=$(echo "$host_output" | cut -d" " -f4)
        run_shodan "$ip"
    else
        echo "No IP address found for $subdomain. Skipping."
    fi
done

echo "Shodan scan results saved to $output_file"
