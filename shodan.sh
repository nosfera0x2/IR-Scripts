#!/bin/bash

# Get user input for the target domain
read -p "Enter the target domain: " domain

# Timestamp for the output file
timestamp=$(date +%Y%m%d%H%M%S)

# Output file name
output_file="${domain}_${timestamp}_shodan_output.txt"

# Initialize an array to store scanned IP addresses
scanned_ips=()

# Step 1: Get subdomains using crt.sh
subdomains=$(curl -s "https://crt.sh/?q=%.$domain&output=json" | jq -r '.[].name_value' | grep -v "CN=" | sort -u)

# Step 2: Find IP addresses for each subdomain and run shodan
for subdomain in $subdomains; do
    host "$subdomain" | grep "has address" | grep "$domain" | while read -r line; do
        ip=$(echo "$line" | cut -d" " -f4)
        # Check if the IP has already been scanned
        if [[ ! " ${scanned_ips[@]} " =~ " ${ip} " ]]; then
            echo "Running Shodan on $ip"
            shodan host "$ip" >> "$output_file"
            scanned_ips+=("$ip")  # Add the IP to the scanned list
        fi
    done
done

echo "Shodan scan results saved to $output_file"

