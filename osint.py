import socket
import shodan
import sys
import requests
from collections import defaultdict, Counter
import dns.resolver  # Import the dns.resolver module

def enumerate_subdomains(domain):
    """Fetch subdomains for a given domain using crt.sh."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors
        data = response.json()

        # Extract the unique subdomains from the certificates
        subdomains = set()
        for entry in data:
            names = entry['name_value'].split('\n')
            for name in names:
                if '*' not in name:  # Exclude wildcard subdomains
                    subdomains.add(name)
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        sys.exit(1)
    except ValueError:
        print("Failed to parse JSON response.")
        sys.exit(1)

    return ','.join(subdomains)

def get_root_domain(subdomain):
    """Extract the root domain from a given subdomain, properly handling ccSLDs."""
    parts = subdomain.split('.')
    if parts[-2] in ['com', 'org', 'net', 'gov', 'edu', 'co'] and len(parts) >= 3:
        return '.'.join(parts[-3:])
    elif len(parts) > 2:
        return '.'.join(parts[-2:])
    return subdomain

def resolve_subdomains_to_ips(subdomains):
    """Resolve subdomains to IP addresses, returning a mapping of IPs to subdomains."""
    ip_to_subdomains = defaultdict(list)
    for subdomain in subdomains:
        try:
            ip_address = socket.gethostbyname(subdomain.strip())
            ip_to_subdomains[ip_address].append(subdomain.strip())
        except socket.gaierror:
            pass  # Skip failed resolutions
    return ip_to_subdomains

def query_dns_records(domain):
    """Query DNS records for a given domain using dnspython."""
    dns_records = defaultdict(list)
    try:
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
            if answers.rrset is not None:
                dns_records[record_type].extend([str(rdata) for rdata in answers])
    except dns.resolver.NoAnswer:
        pass
    except Exception as e:
        print(f"Error retrieving DNS info for {domain}: {e}")
    return dns_records

def display_dns_records(domain):
    """Display fetched DNS records in a readable format."""
    dns_records = query_dns_records(domain)
    if dns_records:
        print(f"\nDNS Records for {domain}:\n")
        for record_type, records in dns_records.items():
            print(f"{record_type} Records:")
            for record in records:
                print(f" - {record}\n")
        print("--------------------------------------------\n")
    else:
        print(f"No DNS information available for {domain}.\n")

def query_shodan_for_ips(ip_to_subdomains):
    """Query Shodan for information on each unique IP address."""
    api_key = 'YOUR_SHODAN_API_KEY'  # Hardcoded API key maybe not the best idea.
    if not ip_to_subdomains:
        print("No IPs resolved. Skipping Shodan lookup.")
        return
    
    print(f"Starting Shodan queries for {len(ip_to_subdomains)} IPs...")
    api = shodan.Shodan(api_key)
    for ip, subdomains in ip_to_subdomains.items():
        try:
            print(f"Querying Shodan for IP: {ip}")
            result = api.host(ip)
            shodan_lookup_link = f"https://www.shodan.io/host/{ip}"
            print(shodan_lookup_link)
            print(f"Associated Subdomains: {', '.join(subdomains)}")
            print(f"Organization: {result.get('org', 'n/a')}")
            if result.get('data'):
                print("Services Detected:")
                for service in result['data']:
                    service_info = f"Port: {service['port']}"
                    if 'product' in service:
                        service_info += f", Product: {service['product']}"
                    if 'version' in service:
                        service_info += f", Version: {service['version']}"
                    if 'cpe' in service:
                        cpe_info = ', '.join(service['cpe'])
                        service_info += f", CPE: {cpe_info}"
                    print(service_info)
            else:
                print("No service information available.")
            print("--------------------------------------------\n\n")
        except shodan.APIError as e:
            print(f"Shodan API error for IP {ip}: {e}")
        except Exception as e:
            print(f"Unhandled error for IP {ip}: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    subdomains_str = enumerate_subdomains(domain)
    subdomains = subdomains_str.split(',')
    
    ip_to_subdomains = resolve_subdomains_to_ips(subdomains)
    
    for root_domain in Counter([get_root_domain(sub) for ips in ip_to_subdomains.values() for sub in ips]):
        display_dns_records(root_domain)
    
    query_shodan_for_ips(ip_to_subdomains)
