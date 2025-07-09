# coding: utf-8
"""Residual risk calculation module."""


def _control_reduction(control):
    """Return reduction score for a given control name."""
    robust = {
        'MFA', 'DNSSEC', 'CAA', 'Tokens', 'Rate limiting', 'CSP', 'WAF'
    }
    basic = {
        'HTTPS', 'SPF', 'DKIM', 'DMARC', 'TLS'
    }
    organisational = {
        'Revisión de roles', 'Monitoreo de DNS'
    }
    if control in robust:
        return 8
    if control in basic:
        return 6
    if control in organisational:
        return 3
    # default minimal impact if unknown
    return 1


def _exposure_factor(action):
    """Determine exposure factor after applying the action."""
    text = action.lower()
    if 'eliminar' in text or 'deshabilitar' in text:
        return 0.0
    if any(k in text for k in ['mfa', 'https', 'token', 'auth', 'csp', 'dnssec', 'limitar', 'ip']):
        return 1.0
    if any(k in text for k in ['login', 'password', 'contrase\u00f1a']):
        return 1.5
    return 2.0


def calculate_residual(tratamientos, valoraciones, riesgos):
    """Compute residual risk using the primary control from each treatment.

    Args:
        tratamientos (list): treatment plan items with 'id', 'accion', etc.
        valoraciones (list): asset valuations including 'id' and 'valor'.
        riesgos (list): original risk identification entries.

    Returns:
        list: residual risk entries with id, subdomain, original risk,
        applied control, initial value, reduction (based on
        ``control_principal``), exposure factor,
        residual risk score and classification.
    """
    val_map = {v['id']: v for v in valoraciones}
    risk_map = {r['id']: r for r in riesgos}
    residual = []

    for t in tratamientos:
        id_ = t['id']
        sub = t['subdominio']
        controls = t.get('controles', [])
        primary = t.get('control_principal')
        accion = t.get('accion', '')
        if not primary and controls:
            primary = max(controls, key=_control_reduction)
        control_aplicado = primary if primary else accion
        original = risk_map.get(id_, {}).get('riesgo', t.get('riesgo', 'N/A'))
        valor = val_map.get(id_, {}).get('valor', 0)

        reduccion = _control_reduction(primary) if primary else 0
        exposicion = _exposure_factor(accion)

        residual_score = max(valor - reduccion, 0) * exposicion

        if residual_score <= 7:
            clas = 'Residual Bajo'
            css = 'bajo'
        elif residual_score <= 14:
            clas = 'Residual Medio'
            css = 'medio'
        elif residual_score <= 22:
            clas = 'Residual Alto'
            css = 'alto'
        else:
            clas = 'Residual Crítico'
            css = 'critico'

        residual.append({
            'id': id_,
            'subdominio': sub,
            'riesgo_original': original,
            'control': control_aplicado,
            'valor': valor,
            'reduccion': reduccion,
            'exposicion': exposicion,
            'riesgo_residual': round(residual_score, 2),
            'clasificacion': clas,
            'css': css,
        })

    return residual
