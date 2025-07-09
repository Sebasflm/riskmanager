def generate_treatments(riesgos):
    """
    Genera sugerencias de tratamiento para cada riesgo identificado.
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

        estrategia = estrategia_map.get(item.get('clasificacion', 'Medio'), 'Mitigar')

        plan.append({
            'id': id_,
            'subdominio': sub,
            'riesgo': item['riesgo'],
            'accion': accion,
            'responsable': 'Seguridad TI',
            'plazo': plazo,
            'estrategia': estrategia,
            'controles': controles,
            'estado': 'Planificado'
        })

    return plan
