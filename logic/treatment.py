def _control_priority(control):
    """Return a priority score for selecting a primary control.

    Los controles clasificados como "robustos" obtienen una puntuación de 3,
    los "básicos" 2 y los de tipo organizacional 1.  El control con la mayor
    puntuación se marca como ``control_principal``.
    """
    robust = {
        'MFA', 'DNSSEC', 'CAA', 'Tokens', 'Rate limiting', 'CSP'
    }
    basic = {
        'HTTPS', 'SPF', 'DKIM', 'DMARC'
    }
    organisational = {
        'Revisión de roles', 'Monitoreo de DNS'
    }
    if control in robust:
        return 3
    if control in basic:
        return 2
    if control in organisational:
        return 1
    return 0


def generate_treatments(riesgos):
    """Genera un plan de tratamiento para cada riesgo.

    Se asigna un ``control_principal`` eligiendo el control más robusto de la
    lista de controles sugeridos mediante :func:`_control_priority`.
    """
    plan = []

    estrategia_map = {
        'Bajo': 'Aceptar',
        'Medio': 'Mitigar',
        'Alto': 'Transferir',
        'Crítico': 'Evitar'
    }

    for item in riesgos:
        id_ = item['id']
        sub = item['subdominio']
        amenaza = item['amenaza']

        # Acción sugerida, plazo y controles basados en la amenaza
        if 'Secuestro de subdominio' in amenaza:
            accion = 'Eliminar alias huérfano o habilitar servicio seguro'
            plazo = '5 días'
            controles = ['DNSSEC', 'CAA', 'Monitoreo de DNS']
        elif 'Acceso no autorizado' in amenaza:
            accion = 'Implementar autenticación fuerte (MFA) y forzar HTTPS'
            plazo = '3 días'
            controles = ['MFA', 'HTTPS', 'Revisión de roles']
        elif 'Exposición de API' in amenaza:
            accion = 'Agregar validación de tokens y limitar CORS'
            plazo = '4 días'
            controles = ['CSP', 'Tokens', 'Rate limiting']
        elif 'Phishing' in amenaza:
            accion = 'Configurar SPF, DKIM y DMARC en DNS'
            plazo = '7 días'
            controles = ['SPF', 'DKIM', 'DMARC']
        elif 'inactivo' in amenaza:
            accion = 'Eliminar subdominio o implementar servicio con auth'
            plazo = '5 días'
            controles = ['DNSSEC', 'MFA']
        else:
            accion = 'Revisar manualmente y aplicar controles adecuados'
            plazo = '10 días'
            controles = ['MFA', 'DNSSEC', 'CSP']

        clasificacion = item.get('clasificacion', 'Medio')
        estrategia = estrategia_map.get(clasificacion, 'Mitigar')
        control_principal = max(controles, key=_control_priority) if controles else None

        plan.append({
            'id': id_,
            'subdominio': sub,
            'riesgo': item['riesgo'],
            'clasificacion': clasificacion,
            'accion': accion,
            'responsable': 'Seguridad TI',
            'plazo': plazo,
            'estrategia': estrategia,
            'controles': controles,
            'control_principal': control_principal,
            'estado': 'Planificado'
        })

    return plan
