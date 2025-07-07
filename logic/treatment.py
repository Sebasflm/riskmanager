def generate_treatments(riesgos):
    """
    Genera sugerencias de tratamiento para cada riesgo identificado.
    """
    plan = []
    for item in riesgos:
        id_ = item['id']
        sub = item['subdominio']
        amenaza = item['amenaza']
        # Acción sugerida y plazo basados en la amenaza
        if 'Secuestro de subdominio' in amenaza:
            accion = 'Eliminar alias huérfano o habilitar servicio seguro'
            plazo = '5 días'
        elif 'Acceso no autorizado' in amenaza:
            accion = 'Implementar autenticación fuerte (MFA) y forzar HTTPS'
            plazo = '3 días'
        elif 'Exposición de API' in amenaza:
            accion = 'Agregar validación de tokens y limitar CORS'
            plazo = '4 días'
        elif 'Phishing' in amenaza:
            accion = 'Configurar SPF, DKIM y DMARC en DNS'
            plazo = '7 días'
        elif 'inactivo' in amenaza:
            accion = 'Eliminar subdominio o implementar servicio con auth'
            plazo = '5 días'
        else:
            accion = 'Revisar manualmente y aplicar controles adecuados'
            plazo = '10 días'
        plan.append({
            'id': id_,
            'subdominio': sub,
            'riesgo': item['riesgo'],
            'accion': accion,
            'responsable': 'Seguridad TI',
            'plazo': plazo,
            'estado': 'Planificado'
        })
    return plan
