import whois
import dns.resolver
import socket
import requests
import nmap
import asyncio
import concurrent.futures
import sys
import validators
import logging
from tqdm import tqdm
from colorama import init, Fore, Style
import os

init(autoreset=True)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def print_banner():
    banner = f"""
{Fore.CYAN}
██╗   ██╗ ██████╗ ██████╗  ██╗
██║   ██║██╔════╝██╔═████╗███║
██║   ██║██║     ██║██╔██║╚██║
██║   ██║██║     ████╔╝██║ ██║
╚██████╔╝╚██████╗╚██████╔╝ ██║
 ╚═════╝  ╚═════╝ ╚═════╝  ╚═╝
by BdotTech
{Style.RESET_ALL}
"""
    print(banner)

def extract_domain_info(domain):
    if not validators.domain(domain):
        print(Fore.RED + f"The domain name '{domain}' is not valid.")
        return None
    try:
        domain_info = whois.whois(domain)
        dns_info = dns.resolver.resolve(domain, 'A')
        return {
            "WHOIS": domain_info,
            "DNS": [str(rdata) for rdata in dns_info]
        }
    except whois.parser.PywhoisError as e:
        print(Fore.RED + f"WHOIS error for {domain}: {e}")
        return None
    except dns.resolver.NoAnswer:
        print(Fore.YELLOW + f"No DNS records found for {domain}.")
        return None
    except Exception as e:
        print(Fore.RED + f"Error retrieving domain information for {domain}: {e}")
        return None

def reverse_dns_lookup(ip):
    if not validators.ipv4(ip):
        print(Fore.RED + f"The IP address '{ip}' is not valid.")
        return None
    try:
        domain_name = socket.gethostbyaddr(ip)
        return domain_name[0]
    except socket.herror:
        print(Fore.YELLOW + f"No reverse DNS record found for {ip}.")
        return None
    except Exception as e:
        print(Fore.RED + f"Error during reverse DNS lookup for {ip}: {e}")
        return None

def enumerate_subdomains(domain, subdomains=None):
    found_subdomains = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1

    if subdomains is None:
        print(Fore.CYAN + "🔍 Fetching subdomains from certificate logs...")
        try:
            crt_sh_url = f"https://crt.sh/?q=%25.{domain}&output=json"
            response = requests.get(crt_sh_url)
            if response.status_code == 200:
                cert_data = response.json()
                subdomains = set()
                for entry in cert_data:
                    name = entry['name_value']
                    name = name.replace('*.', '')
                    if validators.domain(name):
                        subdomains.add(name)
                subdomains = list(subdomains)
                print(Fore.GREEN + f"✅ {len(subdomains)} potential subdomains found.")
            else:
                print(Fore.RED + f"Error retrieving subdomains: HTTP {response.status_code}")
                return []
        except Exception as e:
            print(Fore.RED + f"Error retrieving subdomains: {e}")
            return []
    else:
        print(Fore.CYAN + "Enumerating provided subdomains...")

    def check_subdomain(sub):
        try:
            resolver.resolve(sub, 'A')
            print(Fore.GREEN + f"✅ Active subdomain found: {sub}")
            return sub
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.Timeout:
            print(Fore.YELLOW + f"⏳ Timeout resolving {sub}")
            return None
        except Exception as e:
            print(Fore.RED + f"Error resolving {sub}: {e}")
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = list(tqdm(executor.map(check_subdomain, subdomains), total=len(subdomains), desc="Checking subdomains"))
    found_subdomains = [result for result in results if result]
    return found_subdomains

def geolocate_ip(ip):
    if not validators.ipv4(ip):
        print(Fore.RED + f"The IP address '{ip}' is not valid.")
        return None
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return data
            else:
                print(Fore.RED + f"Geolocation error for IP {ip}: {data.get('message', 'Unknown')}")
                return None
        else:
            print(Fore.RED + f"HTTP Error {response.status_code} during geolocation of IP {ip}")
            return None
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Network error during geolocation of IP {ip}: {e}")
        return None

def port_scan(target_ip, port_range='1-1024'):
    if not validators.ipv4(target_ip):
        print(Fore.RED + f"The IP address '{target_ip}' is not valid.")
        return None
    scanner = nmap.PortScanner()
    try:
        print(Fore.CYAN + f"🔎 Scanning ports on {target_ip} for ports {port_range}...")
        scanner.scan(target_ip, port_range)
        if target_ip in scanner.all_hosts():
            return scanner[target_ip]
        else:
            print(Fore.YELLOW + f"No host found for {target_ip}")
            return None
    except nmap.PortScannerError as e:
        print(Fore.RED + f"Nmap error during port scan on {target_ip}: {e}")
        return None
    except Exception as e:
        print(Fore.RED + f"Error during port scan on {target_ip}: {e}")
        return None

def save_results(filename, data):
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(data)
        print(Fore.GREEN + f"💾 Results saved to file '{filename}'.")
    except Exception as e:
        print(Fore.RED + f"Error saving results: {e}")

def full_scan(target):
    results = {}
    print(Fore.CYAN + f"🚀 Starting full scan for {target}...")
    if validators.domain(target):
        results['domain_info'] = extract_domain_info(target)
        results['subdomains'] = enumerate_subdomains(target)
        try:
            ip = socket.gethostbyname(target)
            print(Fore.GREEN + f"✅ IP address of domain {target}: {ip}")
            results['ip'] = ip
        except Exception as e:
            print(Fore.RED + f"Error resolving domain to IP: {e}")
            return
    elif validators.ipv4(target):
        ip = target
        results['reverse_dns'] = reverse_dns_lookup(ip)
    else:
        print(Fore.RED + "The target is neither a valid domain nor a valid IP address.")
        return

    results['geolocation'] = geolocate_ip(ip)
    results['port_scan'] = port_scan(ip)

    print(Fore.BLUE + "\n--- Full Scan Results ---")
    if 'domain_info' in results and results['domain_info']:
        print(Fore.BLUE + f"\n--- WHOIS Information for {target} ---")
        print(results['domain_info']['WHOIS'])
        print(Fore.BLUE + f"\n--- DNS Records for {target} ---")
        for record in results['domain_info']['DNS']:
            print(record)
    if 'subdomains' in results and results['subdomains']:
        print(Fore.BLUE + f"\n--- Subdomains Found for {target} ---")
        for subdomain in results['subdomains']:
            print(subdomain)
    if 'reverse_dns' in results and results['reverse_dns']:
        print(Fore.BLUE + f"\n--- Reverse DNS for {ip} ---")
        print(results['reverse_dns'])
    if 'geolocation' in results and results['geolocation']:
        print(Fore.BLUE + f"\n--- Geolocation for IP {ip} ---")
        for key, value in results['geolocation'].items():
            print(f"{key.capitalize()}: {value}")
    if 'port_scan' in results and results['port_scan']:
        print(Fore.BLUE + f"\n--- Port Scan Results for {ip} ---")
        for proto in results['port_scan'].all_protocols():
            lport = results['port_scan'][proto].keys()
            for port in lport:
                state = results['port_scan'][proto][port]['state']
                print(f"Port {port}/{proto}: {state}")

    save = input("Do you want to save the results? (y/n): ").strip().lower()
    if save == 'y':
        filename = input("Enter the output file name: ").strip()
        save_results(filename, str(results))

def menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print_banner()
        print(Fore.BLUE + "\n--- Main Menu ---")
        print("1. Extract domain information 📝")
        print("2. Reverse DNS lookup 🔄")
        print("3. Subdomain enumeration 🌐")
        print("4. IP geolocation 🗺️")
        print("5. Port scan 🔍")
        print("6. Full scan 🚀")
        print("7. Help ❓")
        print("8. Exit ❌")

        choice = input("Choose an option (1-8): ")
        try:
            if choice == "1":
                domain = input("Enter the domain name: ").strip()
                info = extract_domain_info(domain)
                if info:
                    print(Fore.BLUE + f"\n--- WHOIS Information for {domain} ---")
                    print(info['WHOIS'])
                    print(Fore.BLUE + f"\n--- DNS Records for {domain} ---")
                    for record in info['DNS']:
                        print(record)
                    save = input("Do you want to save the results? (y/n): ").strip().lower()
                    if save == 'y':
                        filename = input("Enter the output file name: ").strip()
                        save_results(filename, str(info))
                else:
                    print(Fore.RED + "Unable to retrieve domain information.")
                input("\nPress Enter to return to the main menu...")
            elif choice == "2":
                ip = input("Enter the IP address: ").strip()
                result = reverse_dns_lookup(ip)
                if result:
                    print(Fore.GREEN + f"Domain name for IP {ip}: {result}")
                else:
                    print(Fore.YELLOW + f"No domain name found for IP {ip}.")
                save = input("Do you want to save the results? (y/n): ").strip().lower()
                if save == 'y':
                    filename = input("Enter the output file name: ").strip()
                    save_results(filename, f"IP: {ip}, Domain: {result}")
                input("\nPress Enter to return to the main menu...")
            elif choice == "3":
                domain = input("Enter the domain name: ").strip()
                source = input("Do you want to manually enter subdomains or enumerate automatically? (manually/all): ").strip().lower()
                if source == 'all':
                    found_subdomains = enumerate_subdomains(domain)
                else:
                    subdomains_input = input("Enter the subdomains to check (comma-separated, e.g., www,mail,ftp): ")
                    subdomains = [f"{sub.strip()}.{domain}" for sub in subdomains_input.split(',') if sub.strip()]
                    if not subdomains:
                        print(Fore.YELLOW + "No subdomains to check.")
                        continue
                    found_subdomains = enumerate_subdomains(domain, subdomains)
                if found_subdomains:
                    print(Fore.BLUE + f"\n--- Subdomains Found for {domain} ---")
                    for subdomain in found_subdomains:
                        print(subdomain)
                    save = input("Do you want to save the results? (y/n): ").strip().lower()
                    if save == 'y':
                        filename = input("Enter the output file name: ").strip()
                        save_results(filename, '\n'.join(found_subdomains))
                else:
                    print(Fore.YELLOW + "No subdomains found.")
                input("\nPress Enter to return to the main menu...")
            elif choice == "4":
                ip = input("Enter the IP address: ").strip()
                location = geolocate_ip(ip)
                if location:
                    print(Fore.BLUE + f"\n--- Geolocation for IP {ip} ---")
                    for key, value in location.items():
                        print(f"{key.capitalize()}: {value}")
                    save = input("Do you want to save the results? (y/n): ").strip().lower()
                    if save == 'y':
                        filename = input("Enter the output file name: ").strip()
                        save_results(filename, str(location))
                else:
                    print(Fore.RED + "Unable to geolocate the IP address.")
                input("\nPress Enter to return to the main menu...")
            elif choice == "5":
                ip = input("Enter the target IP for port scan: ").strip()
                port_range = input("Enter the port range to scan (e.g., 1-1024): ").strip()
                result = port_scan(ip, port_range)
                if result:
                    print(Fore.BLUE + f"\n--- Port Scan Results for {ip} ---")
                    for proto in result.all_protocols():
                        lport = result[proto].keys()
                        for port in lport:
                            state = result[proto][port]['state']
                            print(f"Port {port}/{proto}: {state}")
                    save = input("Do you want to save the results? (y/n): ").strip().lower()
                    if save == 'y':
                        filename = input("Enter the output file name: ").strip()
                        save_results(filename, str(result))
                else:
                    print(Fore.RED + "Unable to scan the IP's ports.")
                input("\nPress Enter to return to the main menu...")
            elif choice == "6":
                target = input("Enter the domain name or IP target for the full scan: ").strip()
                full_scan(target)
                input("\nPress Enter to return to the main menu...")
            elif choice == "7":
                print(Fore.BLUE + "\n--- Help ---")
                print("This script offers several features for network analysis and security:")
                print("1. Extract WHOIS and DNS information for a domain name.")
                print("2. Perform reverse DNS lookup to find the domain name associated with an IP.")
                print("3. Enumerate subdomains for a given domain.")
                print("   - You can either manually enter subdomains or enumerate automatically ('all').")
                print("4. Geolocate an IP address.")
                print("5. Scan open ports on a target IP.")
                print("6. Perform a full scan: runs all the above analyses on a given target.")
                print("7. Show this help.")
                print("8. Exit the program.")
                input("\nPress Enter to return to the main menu...")
            elif choice == "8":
                print(Fore.CYAN + "Exiting the program...")
                sys.exit(0)
            else:
                print(Fore.RED + "Invalid choice, please select a valid option.")
                input("\nPress Enter to return to the main menu...")
        except KeyboardInterrupt:
            print(Fore.RED + "\nOperation canceled by the user.")
            input("\nPress Enter to return to the main menu...")
            continue
        except Exception as e:
            print(Fore.RED + f"An error occurred: {e}")
            input("\nPress Enter to return to the main menu...")
            continue

def main():
    try:
        menu()
    except Exception as e:
        print(Fore.RED + f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
