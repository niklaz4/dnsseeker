import sys
import dns.resolver
import dns.zone
import requests
import json
import socket
import whois
import ssl
import concurrent.futures
import os
from datetime import datetime
from colorama import init, Fore, Style
from tqdm import tqdm
from urllib.parse import urlparse

class DNSSeeker:
    def __init__(self, domain, wordlist=None, nameservers=None):
        #remove http://, https://, and www.
        self.domain = self._clean_domain(domain)
        
        # wordlist padrao se nenhum wordlist for fornecido
        if wordlist is None:
            wordlist = self._create_default_wordlist()
        self.wordlist = wordlist
        
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = nameservers or ['8.8.8.8', '8.8.4.4']
        self.results = {
            'subdomains': [],
            'dns_records': {},
            'vulnerabilities': [],
            'ssl_info': {},
            'whois_info': None,
            'cloud_services': set()
        }

    def _clean_domain(self, domain):
        """Remove http://, https://, and www. from domain"""
        # verifica se URL começa com http:// or https://
        if domain.startswith(('http://', 'https://')):
            domain = urlparse(domain).netloc
        
        # Remove www. se tiver
        if domain.startswith('www.'):
            domain = domain[4:]
            
        return domain

    def _create_default_wordlist(self):
        """Create a default wordlist if none is provided"""
        default_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'ns3', 'ns4', 'test', 'dev', 'developer', 'shop', 'api', 'blog', 'app',
            'support', 'admin', 'web', 'portal', 'ssl', 'secure', 'vpn', 'remote',
            'server', 'cloud', 'git', 'staging', 'prod', 'production', 'internal'
        ]
        
        # Cria um arquivo temporario com subdominios padrões
        temp_wordlist = 'default_subdomains.txt'
        with open(temp_wordlist, 'w') as f:
            f.write('\n'.join(default_subdomains))
            
        return temp_wordlist
        
    def get_subdomains(self):
        """Enhanced subdomain enumeration with multiple techniques"""
        print(f"\n{Fore.CYAN}[*] Starting enumeration with multiple techniques...{Style.RESET_ALL}")
        
        methods = [
            self._brute_force_subdomains,
            self._certificate_transparency_search,
            self._dns_zone_transfer,
            self._search_common_services
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(methods)) as executor:
            list(executor.map(lambda x: x(), methods))
            
    def _brute_force_subdomains(self):
        """Improved brute force with smart wordlist handling"""
        try:
            with open(self.wordlist, 'r') as f:
                subdomains = f.read().splitlines()
            
            print(f"{Fore.YELLOW}[*] Brute forcing {len(subdomains)} potential subdomains...{Style.RESET_ALL}")
            
            with tqdm(total=len(subdomains), desc="Progress") as pbar:
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                    futures = []
                    for subdomain in subdomains:
                        futures.append(
                            executor.submit(self._resolve_subdomain, f"{subdomain.strip()}.{self.domain}")
                        )
                    
                    for future in concurrent.futures.as_completed(futures):
                        result = future.result()
                        if result:
                            self.results['subdomains'].append(result)
                        pbar.update(1)
                        
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Error: Wordlist file not found. Using default wordlist.{Style.RESET_ALL}")
            self.wordlist = self._create_default_wordlist()
            self._brute_force_subdomains()
            
    def _resolve_subdomain(self, subdomain):
        """Enhanced subdomain resolution with additional checks"""
        try:
            result = self.resolver.resolve(subdomain, 'A')
            ip = str(result[0])
            
            # verifica por serviços em nuvem
            cloud_services = {
                'amazonaws.com': 'AWS',
                'azure.com': 'Azure',
                'googlecloud.com': 'GCP',
                'cloudfront.net': 'AWS CloudFront',
                'heroku.com': 'Heroku'
            }
            
            for service_domain, service_name in cloud_services.items():
                if service_domain in ip:
                    self.results['cloud_services'].add(service_name)
            
            return {
                'hostname': subdomain,
                'ip': ip,
                'timestamp': datetime.now().isoformat()
            }
        except:
            return None

    def _certificate_transparency_search(self):
        """Search Certificate Transparency logs"""
        try:
            print(f"{Fore.YELLOW}[*] Searching Certificate Transparency logs...{Style.RESET_ALL}")
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    if entry['name_value'] not in [s['hostname'] for s in self.results['subdomains']]:
                        result = self._resolve_subdomain(entry['name_value'])
                        if result:
                            self.results['subdomains'].append(result)
        except Exception as e:
            print(f"{Fore.RED}[!] Error in CT search: {str(e)}{Style.RESET_ALL}")

    def _dns_zone_transfer(self):
        """Attempt DNS zone transfer with enhanced error handling"""
        print(f"{Fore.YELLOW}[*] Attempting DNS zone transfer...{Style.RESET_ALL}")
        try:
            nameservers = self.resolver.resolve(self.domain, 'NS')
            for ns in nameservers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), self.domain))
                    for name, node in zone.nodes.items():
                        result = self._resolve_subdomain(f"{name}.{self.domain}")
                        if result:
                            self.results['subdomains'].append(result)
                except:
                    continue
        except Exception as e:
            print(f"{Fore.RED}[!] Zone transfer failed: {str(e)}{Style.RESET_ALL}")

    def _search_common_services(self):
        """Search for common service subdomains"""
        print(f"{Fore.YELLOW}[*] Checking common service subdomains...{Style.RESET_ALL}")
        common_services = [
            'api', 'dev', 'stage', 'test', 'prod', 'staging',
            'admin', 'portal', 'vpn', 'mail', 'remote',
            'blog', 'shop', 'store', 'webapp'
        ]
        
        for service in common_services:
            result = self._resolve_subdomain(f"{service}.{self.domain}")
            if result:
                self.results['subdomains'].append(result)

    def analyze_security(self):
        """Comprehensive security analysis"""
        print(f"\n{Fore.CYAN}[*] Starting security analysis...{Style.RESET_ALL}")
        for subdomain_info in self.results['subdomains']:
            subdomain = subdomain_info['hostname']
            
            # subdomain takeover
            if self._check_subdomain_takeover(subdomain):
                self.results['vulnerabilities'].append({
                    'type': 'Subdomain Takeover',
                    'target': subdomain
                })
            
            # verifica configurações de SSL/TLS
            ssl_info = self._check_ssl(subdomain)
            if ssl_info:
                self.results['ssl_info'][subdomain] = ssl_info
                
            # pega registros de DNS
            self._get_dns_records(subdomain)
            
        # pega informaçoes de whois
        self.results['whois_info'] = self._get_whois_info()

    def _check_subdomain_takeover(self, subdomain):
        """Check for potential subdomain takeover"""
        try:
            response = requests.get(f"https://{subdomain}", timeout=5, allow_redirects=True)
            takeover_signatures = [
                "There is no app configured at that hostname",
                "NoSuchBucket",
                "No Such Account",
                "You're Almost There",
                "404 Not Found",
                "Page Not Found"
            ]
            return any(sig in response.text for sig in takeover_signatures)
        except:
            return False

    def _check_ssl(self, hostname):
        """Check SSL/TLS configuration"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'expiry': cert['notAfter'],
                        'subject': dict(x[0] for x in cert['subject']),
                        'version': ssock.version()
                    }
        except:
            return None

    def _get_dns_records(self, hostname):
        """Get various DNS records"""
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA']
        records = {}
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(hostname, record_type)
                records[record_type] = [str(answer) for answer in answers]
            except:
                continue
                
        self.results['dns_records'][hostname] = records

    def _get_whois_info(self):
        """Get WHOIS information"""
        try:
            return whois.whois(self.domain)
        except:
            return None

    def generate_report(self):
        """Generate a comprehensive report"""
        # Cria um arquivo seguro removendo caracteres
        safe_filename = "".join(c for c in self.domain if c.isalnum() or c in ('-', '_', '.'))
        report_filename = f"dnsseeker_report_{safe_filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        print(f"""{Fore.CYAN}
██████╗ ███╗   ██╗███████╗███████╗███████╗███████╗██╗  ██╗███████╗██████╗ 
██╔══██╗████╗  ██║██╔════╝██╔════╝██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██║  ██║██╔██╗ ██║███████╗███████╗█████╗  █████╗  █████╔╝ █████╗  ██████╔╝
██║  ██║██║╚██╗██║╚════██║╚════██║██╔══╝  ██╔══╝  ██╔═██╗ ██╔══╝  ██╔══██╗
██████╔╝██║ ╚████║███████║███████║███████╗███████╗██║  ██╗███████╗██║  ██║
╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}""")
        
        print(f"\n{Fore.GREEN}DNSSeeker - Advanced DNS Enumeration and Security Analysis Tool")
        print(f"Author: N. 'M1racl3' A.")
        print(f"Target Domain: {self.domain}")
        print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}\n")
        
        # imprime subdomínios
        print(f"{Fore.YELLOW}[+] Discovered Subdomains:{Style.RESET_ALL}")
        if self.results['subdomains']:
            for subdomain in self.results['subdomains']:
                print(f"  - {subdomain['hostname']} ({subdomain['ip']})")
        else:
            print("  No subdomains discovered")
            
        # imprime vulnerabilidades, se tiver
        if self.results['vulnerabilities']:
            print(f"\n{Fore.RED}[+] Potential Vulnerabilities:{Style.RESET_ALL}")
            for vuln in self.results['vulnerabilities']:
                print(f"  - {vuln['type']}: {vuln['target']}")
                
        # imprime serviços em nuvem, se tiver
        if self.results['cloud_services']:
            print(f"\n{Fore.BLUE}[+] Detected Cloud Services:{Style.RESET_ALL}")
            for service in self.results['cloud_services']:
                print(f"  - {service}")
                
        # salva tudo em um arquivo .json
        try:
            with open(report_filename, 'w') as f:
                json.dump(self.results, f, indent=4, default=str)
            print(f"\n{Fore.GREEN}[+] Detailed report saved to: {report_filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error saving report: {str(e)}{Style.RESET_ALL}")

def main():
    init()  
    
    if len(sys.argv) != 2:
        print(f"{Fore.RED}Usage: python dnsseeker.py <domain>{Style.RESET_ALL}")
        sys.exit(1)
        
    domain = sys.argv[1]
    scanner = DNSSeeker(domain)
    
    print(f"{Fore.CYAN}Starting DNS enumeration for {domain}...{Style.RESET_ALL}")
    scanner.get_subdomains()
    
    print(f"{Fore.CYAN}Performing security analysis...{Style.RESET_ALL}")
    scanner.analyze_security()
    
    scanner.generate_report()

if __name__ == '__main__':
    main()