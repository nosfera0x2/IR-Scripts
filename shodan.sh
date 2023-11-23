#!/bin/bash

# Get user input for the target domain
read -p "Enter the target domain: " domain

# Timestamp for the output file
timestamp=$(date +%Y%m%d%H%M%S)

# Output file name
output_file="${domain}_${timestamp}_shodan_output.txt"

# Step 1: Get subdomains using crt.sh
subdomains=$(curl -s "https://crt.sh/?q=%.$domain&output=json" | jq -r '.[].name_value' | grep -v "CN=" | sort -u)

# Print "Hosts found:" and then each host on a new line
echo "Hosts found:"
echo "$subdomains"

# Step 2: Find IP addresses for each subdomain and run shodan
echo "Scanning all *found* IP addresses with Shodan"
for subdomain in $subdomains; do
    host "$subdomain" | grep "has address" | grep "$domain" | while read -r line; do
        ip=$(echo "$line" | cut -d" " -f4)
        shodan host "$ip" >> "$output_file"
    done
done

echo "Shodan scan results saved to $output_file"
