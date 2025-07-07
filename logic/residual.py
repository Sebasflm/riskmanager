def calculate_residual(tratamientos, valoraciones, riesgos):
    """Compute residual risk after applying treatments.

    Args:
        tratamientos (list): treatment plan items with 'id', 'accion', etc.
        valoraciones (list): asset valuations including 'id' and 'valor'.
        riesgos (list): original risk identification entries.

    Returns:
        list: residual risk entries containing id, subdominio, original risk,
        control applied, probability, impact, residual risk score and
        classification.
    """
    val_map = {v['id']: v for v in valoraciones}
    risk_map = {r['id']: r for r in riesgos}
    residual = []

    for t in tratamientos:
        id_ = t['id']
        sub = t['subdominio']
        control = t['accion']
        original = risk_map.get(id_, {}).get('riesgo', t.get('riesgo', 'N/A'))
        valor = val_map.get(id_, {}).get('valor', 0)

        # Impact based on asset valuation
        if valor <= 6:
            impacto = 1
        elif valor <= 12:
            impacto = 2
        else:
            impacto = 3

        # Probability estimation based on action keywords
        if any(k in control.lower() for k in ['eliminar', 'habilitar', 'configurar', 'agregar', 'autenticaci', 'https', 'mfa']):
            probabilidad = 1
        elif 'revisar' in control.lower():
            probabilidad = 3
        else:
            probabilidad = 2

        riesgo_residual = probabilidad * impacto

        if riesgo_residual == 0:
            clas = 'Nulo'
        elif riesgo_residual <= 2:
            clas = 'Bajo'
        elif riesgo_residual <= 4:
            clas = 'Medio'
        else:
            clas = 'Alto'

        residual.append({
            'id': id_,
            'subdominio': sub,
            'riesgo_original': original,
            'control': control,
            'probabilidad': probabilidad,
            'impacto': impacto,
            'riesgo_residual': riesgo_residual,
            'clasificacion': clas
        })

    return residual
