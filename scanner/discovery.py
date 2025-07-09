import subprocess
import requests
import socket
import dns.resolver
from requests.exceptions import SSLError

def fetch_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    names = set()
    try:
        r = requests.get(url, timeout=10, headers={'User-Agent':'Mozilla/5.0','Accept':'*/*'})
        if r.status_code == 200:
            for entry in r.json():
                raw = entry.get("name_value", "")
                for nv in raw.split("\n"):
                    name = nv.strip().lower()
                    if name and not name.startswith("*."):
                        names.add(name)
    except:
        pass
    return list(names)

def run_subfinder(domain):
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"], 
            capture_output=True, text=True, timeout=30
        )
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except:
        return []

def resolve_dns(subdomain):
    for rtype in ('A','AAAA','CNAME','MX','TXT'):
        try:
            answer = dns.resolver.resolve(subdomain, rtype, lifetime=5)
            if rtype == 'TXT':
                ip = ' '.join([txt.to_text() for txt in answer])
            else:
                ip = answer[0].to_text()
            return ip, rtype
        except:
            continue
    return '-', 'No resuelve'

def check_spf(subdomain):
    """Check if the subdomain (or its parent) has an SPF record."""
    try:
        answers = dns.resolver.resolve(subdomain, 'TXT', lifetime=5)
        for txt in answers:
            if 'v=spf1' in txt.to_text().lower():
                return True
    except Exception:
        pass
    # also try the domain root
    parts = subdomain.split('.')
    if len(parts) > 2:
        root_domain = '.'.join(parts[-2:])
        try:
            answers = dns.resolver.resolve(root_domain, 'TXT', lifetime=5)
            for txt in answers:
                if 'v=spf1' in txt.to_text().lower():
                    return True
        except Exception:
            pass
    return False

def check_http_status(subdomain):
    """Return HTTP status, connectivity and security header info."""
    headers = {'User-Agent': 'Mozilla/5.0', 'Accept': '*/*'}
    for proto in ('https://', 'http://'):
        try:
            r = requests.head(
                f"{proto}{subdomain}", headers=headers, timeout=5,
                allow_redirects=True
            )
            uses_https = proto == 'https://'
            sec_hdr = any(h in r.headers for h in (
                'Content-Security-Policy',
                'X-Frame-Options',
                'Strict-Transport-Security'
            ))
            return str(r.status_code), True, uses_https, sec_hdr
        except SSLError:
            # try http if https fails due to certificate
            continue
        except Exception:
            continue
    return 'No responde', False, False, False

def discover_subdomains(domain):
    subs = set(fetch_crtsh(domain)) | set(run_subfinder(domain))
    activos = []
    for i, sub in enumerate(sorted(subs), 1):
        ip, record = resolve_dns(sub)
        status_code, connected, uses_https, sec_hdr = check_http_status(sub)
        estado = f"Conectado ({status_code})" if connected else status_code
        sends_mail = record == 'MX' or 'mail' in sub
        spf_ok = check_spf(sub) if sends_mail else False
        activos.append({
            'id': f"SD{i}",
            'subdominio': sub,
            'ip': ip,
            'registro': record,
            'estado': estado,
            'https': uses_https,
            'security_headers': sec_hdr,
            'sends_mail': sends_mail,
            'spf': spf_ok,
        })
    return activos
