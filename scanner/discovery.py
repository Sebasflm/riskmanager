import subprocess
import requests
import socket
import dns.resolver

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

def check_http_status(subdomain):
    headers = {'User-Agent':'Mozilla/5.0','Accept':'*/*'}
    for proto in ('https://','http://'):
        try:
            r = requests.head(f"{proto}{subdomain}", headers=headers, timeout=5, allow_redirects=True)
            return str(r.status_code), True
        except:
            continue
    return 'No responde', False

def discover_subdomains(domain):
    subs = set(fetch_crtsh(domain)) | set(run_subfinder(domain))
    activos = []
    for i, sub in enumerate(sorted(subs), 1):
        ip, record = resolve_dns(sub)
        status_code, connected = check_http_status(sub)
        estado = f"Conectado ({status_code})" if connected else status_code
        activos.append({
            'id': f"SD{i}",
            'subdominio': sub,
            'ip': ip,
            'registro': record,
            'estado': estado
        })
    return activos
