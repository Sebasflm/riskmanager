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
    """Check HTTP and HTTPS connectivity.

    Returns a tuple of:
        status_code (str): HTTP status of the first responding protocol.
        connected (bool): whether the host responded.
        https_ok (bool): whether HTTPS connection succeeded.
        headers (dict): headers from HTTPS response if available.
    """

    headers = {'User-Agent': 'Mozilla/5.0', 'Accept': '*/*'}
    status_code = 'No responde'
    connected = False
    https_ok = False
    resp_headers = {}

    # Try HTTPS first (ignore certificate issues)
    try:
        r = requests.head(
            f"https://{subdomain}",
            headers=headers,
            timeout=5,
            allow_redirects=True,
            verify=False,
        )
        status_code = str(r.status_code)
        connected = True
        https_ok = True
        resp_headers = r.headers
        return status_code, connected, https_ok, resp_headers
    except Exception:
        pass

    # Fallback to HTTP
    try:
        r = requests.head(
            f"http://{subdomain}",
            headers=headers,
            timeout=5,
            allow_redirects=True,
        )
        status_code = str(r.status_code)
        connected = True
    except Exception:
        pass

    return status_code, connected, https_ok, resp_headers

def discover_subdomains(domain):
    subs = set(fetch_crtsh(domain)) | set(run_subfinder(domain))
    activos = []
    for i, sub in enumerate(sorted(subs), 1):
        ip, record = resolve_dns(sub)
        status_code, connected, https_ok, headers = check_http_status(sub)
        estado = f"Conectado ({status_code})" if connected else status_code

        observaciones = []
        if not https_ok:
            observaciones.append('No soporta HTTPS')
        else:
            missing = []
            if 'Strict-Transport-Security' not in headers:
                missing.append('Strict-Transport-Security')
            if 'Content-Security-Policy' not in headers:
                missing.append('Content-Security-Policy')
            if missing:
                observaciones.append('Faltan encabezados: ' + ', '.join(missing))

        activos.append({
            'id': f"SD{i}",
            'subdominio': sub,
            'ip': ip,
            'registro': record,
            'estado': estado,
            'observaciones': '; '.join(observaciones) if observaciones else 'N/A'
        })
    return activos
