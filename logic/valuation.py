def evaluate_assets(activos):
    """
    Evaluates each asset with the CIA+F model and returns valuation results.
    Regulatory factor (F) is 2 if subdomain matches keywords indicating personal data or critical functions.
    ID from activos is preserved.
    """
    valoraciones = []
    # Keywords indicating personal data or critical functions
    normative_keywords = [
        'mail', 'contact', 'login', 'auth', 'register', 'signup',
        'user', 'account', 'secure', 'payment', 'pay', 'dashboard',
        'profile', 'api', 'admin', 'settings', 'personal'
    ]
    for asset in activos:
        id_ = asset.get('id')
        sub = asset.get('subdominio', '').lower()
        # Confidentiality (C)
        C = 3 if asset['registro'] in ['MX', 'TXT'] else 2
        # Integrity (I)
        I = 2 if asset['estado'].startswith('4') or asset['estado'] == 'No responde' else 3
        # Availability (D)
        D = 1 if asset['estado'] == 'No responde' else 3
        # Regulatory factor (F): keyword match
        F = 2 if any(kw in sub for kw in normative_keywords) else 1
        # Calculate asset value
        valor = (C + I + D) * F
        # Classification by ranges
        if valor <= 6:
            clas = 'Bajo'
        elif valor <= 12:
            clas = 'Medio'
        else:
            clas = 'Alto'
        valoraciones.append({
            'id': id_,
            'subdominio': asset.get('subdominio'),
            'C': C,
            'I': I,
            'D': D,
            'F': F,
            'valor': valor,
            'clasificacion': clas
        })
    return valoraciones
