import dns.resolver
import dns.reversename
import logging
import asyncio
import socket
import ssl
import ipaddress
from tld import exceptions as tld_exceptions
from tld import get_tld

class AsyncLookupManager:
    def __init__(self):
        self.TIMEOUT_SECONDS = 5
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = dns.resolver.get_default_resolver().nameservers
    
    def is_ipv4(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).version == 4
        except ValueError:
            return False

    def is_valid_domain(self, domain) -> bool:
        try:
            get_tld(domain, fix_protocol=True)
            return True
        except tld_exceptions.TldDomainNotFound:
            return False

    def remove_subdomains(self, domain: str) -> str:
        # remove subdomains
        return ".".join(domain.split(".")[-2:])
    
    async def get_ns_records(self, domain: str) -> list:
        retval = []
    
        try:
            ns_records = self.resolver.resolve(domain, "NS")
            retval= [str(r.target) for r in ns_records]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            try:
                # use TLD instead of subdomain
                ns_records = self.resolver.resolve(self.remove_subdomains(domain), "NS")
                retval = [str(r.target) for r in ns_records]  
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                retval= []
        except Exception as e:
            logging.exception(f"Error getting NS records for {domain}: {str(e)}")
            retval= []

        # apply domain's nameservers to the resolver for future requests.
        if len(retval) > 1:
            for ns in retval:
                if self.is_ipv4(ns):
                    self.resolver.nameservers.append(ns)
                else:
                    self.resolver.nameservers.append(str(dns.resolver.resolve(ns, "A")[0]))
        
        return retval
    
    async def get_a_records(self, domain: str) -> list:
        retval = []
        try:
            a_records = self.resolver.resolve(domain, "A")
            retval = [str(r) for r in a_records]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            retval = []
        except Exception as e:
            logging.exception(f"Error getting A records for {domain}: {str(e)}")
            retval = []

        return retval

    async def get_mx_records(self, domain: str) -> list:
        retval = []
        try:
            mx_records = self.resolver.resolve(domain, "MX")
            retval = [str(r.exchange) for r in mx_records]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            try:
                mx_records = self.resolver.resolve(self.remove_subdomains(domain), "MX")
                retval = [str(r.exchange) for r in mx_records]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                retval = []
        except Exception as e:
            logging.exception(f"Error getting MX records for {domain}: {str(e)}")
            retval = []

        return retval
    

    async def get_cname_record(self, domain: str) -> str | None:
        try:
            cname_record = self.resolver.resolve(domain, "CNAME")
            return str(cname_record.rrset[0].target)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            return None
        except Exception as e:
            logging.exception(f"Error getting CNAME record for {domain}: {str(e)}")
            return None
    

    async def get_txt_records(self, domain: str) -> list:
        retval = []
        try:
            txt_records = self.resolver.resolve(domain, "TXT")
            retval = [str(r.strings) for r in txt_records]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            return []
        except Exception as e:
            logging.exception(f"Error getting TXT records for {domain}: {str(e)}")
            return []

        return retval
    
    async def perform_reverse_lookup(self, ip: str) -> str | None:
        try:
            reverse_name = dns.reversename.from_address(ip)
            return str(dns.resolver.resolve(reverse_name, "PTR")[0], lifetime=self.TIMEOUT_SECONDS)
        except Exception as e:
            logging.exception(f"Error performing reverse lookup for IP {ip}: {str(e)}")
            return None

    async def ssl_certificate_lookup(self, hostname: str) -> dict | None:
        cert = None
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(self.TIMEOUT_SECONDS)
                s.connect((hostname, 443))
                cert = s.getpeercert()
            return cert
        except Exception as e:
            logging.exception(f"Error performing SSL certificate lookup for hostname: {str(hostname)}")
            return None


    async def lookup_domain(self, domain: str) -> dict:
        records = {"mx": [], "ns": [], "cname": None, "txt": [], "a": []}

        # Get NS records
        ns_records = await self.get_ns_records(domain)
        tasks = [
            self.get_a_records(domain),
            self.get_mx_records(domain),
            self.get_cname_record(domain),
            self.get_txt_records(domain),
            self.perform_reverse_lookup(domain),
            self.ssl_certificate_lookup(domain),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        records["ns"] = ns_records
        records["a"] = results[0]
        records["mx"] = results[1]
        records["cname"] = results[2]
        records["txt"] = results[3]
        records["reverse"] = results[4]
        records["ssl"] = results[5]
        return records
    
    async def lookup_ip(self, ip: str) -> dict:
        records = {"mx": [], "ns": [], "cname": None, "txt": [], "a": []}
        domain = await self.perform_reverse_lookup(ip)
        tasks = [
            self.get_ns_records(domain),
            self.get_a_records(domain),
            self.get_mx_records(domain),
            self.get_cname_record(domain),
            self.get_txt_records(domain),
            self.ssl_certificate_lookup(domain),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        records["domain"] = domain
        records["ns"] = results[0]
        records["a"] = results[1]
        records["mx"] = results[2]
        records["cname"] = results[3]
        records["txt"] = results[4]
        records["ssl"] = results[5]
        return records
