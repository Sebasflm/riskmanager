from logic.constants import normative_keywords


def evaluate_assets(activos):
    """Valuate discovered assets using a simple CIA+F model.

    Each asset already contains DNS record information and an HTTP status which
    are used to derive the CIA values:

    * **Confidentiality (C)**  
      Assets whose DNS record type is ``MX`` or ``TXT`` are considered to hold
      or facilitate access to personal data (mail servers, text records used for
      verification) and therefore receive a value of ``3``.  Any other record
      type results in ``2``.

    * **Integrity (I)**  
      If the HTTP check returned a status code starting with ``4`` or did not
      respond, integrity is deemed lower and the value ``2`` is assigned.
      Otherwise the asset receives ``3``.

    * **Availability (D)**  
      Assets that did not respond to HTTP requests get the lowest availability
      score of ``1``.  Responding assets receive ``3``.

    The **regulatory factor (F)** doubles the total when the subdomain name
    contains keywords typically related to personal information or critical
    functionality.  The ``id`` from ``activos`` is preserved for traceability.
    """
    valoraciones = []
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
        elif valor <= 18:
            clas = 'Alto'
        else:
            clas = 'Crítico'
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
