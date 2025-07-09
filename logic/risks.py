def identify_risks(activos, valoraciones=None):
    """
    Identifica amenazas, vulnerabilidades y riesgos potenciales para cada activo
    con descripciones detalladas y fundamentadas, incluyendo contexto por palabras clave.
    """
    riesgos = []
    val_map = {}
    if valoraciones:
        val_map = {v['id']: v.get('valor', 0) for v in valoraciones}
    # Reglas de contexto basadas en palabras clave del subdominio
    context_rules = [
        (['auth', 'login'], 
         'Acceso no autorizado a funciones de autenticación', 
         'Falta de autenticación fuerte o MFA', 
         'Compromiso de credenciales y datos de usuarios'),
        (['portal'], 
         'Exposición de portal interno sin protección', 
         'Portal accesible públicamente sin autenticación', 
         'Acceso no autorizado a área privada'),
        (['biblioteca'],
         'Exposición de repositorio de documentos internos',
         'Biblioteca digital sin control de acceso',
         'Filtración de documentos sensibles'),
        (['dev', 'development'],
         'Exposición de entorno de desarrollo',
         'Controles de seguridad incompletos y datos de prueba sin protección',
         'Filtración de código y descubrimiento de vulnerabilidades'),
        (['staging', 'preprod'],
         'Exposición de entorno de preproducción',
         'Configuraciones provisionales con seguridad parcial',
         'Compromiso de versiones previas y fuga de información'),
        (['test', 'qa'],
         'Exposición de entorno de pruebas',
         'Seguridad relajada en ambiente de testeo',
         'Filtración de datos de prueba y vectores para producción'),
        (['vpn'],
         'Exposición de puerta de enlace VPN',
         'Credenciales débiles o configuración insegura',
         'Acceso remoto no autorizado a la red interna'),
        (['backup', 'respaldo', 'bk'],
         'Exposición de repositorios de copias de seguridad',
         'Falta de cifrado o controles de acceso en backups',
         'Fuga de datos respaldados y ransomware'),
    ]

    for asset in activos:
        sub = asset['subdominio'].lower()
        reg = asset['registro']
        status = asset['estado']
        amenaza = 'Sin riesgos detectados'
        vulnerabilidad = 'N/A'
        riesgo = 'N/A'

        # Verificación de contexto por palabra clave
        for keywords, a, v, r in context_rules:
            if any(kw in sub for kw in keywords):
                amenaza = a
                vulnerabilidad = v
                riesgo = r
                break
        else:
            # Lógica previa si no coincide con contexto especial
            if reg == 'CNAME' and status == 'No responde':
                amenaza = 'Secuestro de subdominio para phishing y distribución de malware'
                vulnerabilidad = 'Alias DNS huérfano sin servicio activo'
                riesgo = 'Robo de credenciales, exposición de datos sensibles y daño reputacional'
            elif status.startswith('404'):
                amenaza = 'Secuestro de subdominio por error 404'
                vulnerabilidad = 'Recurso HTTP ausente (404 Not Found)'
                riesgo = 'Toma de control del subdominio mediante takeover'
            elif status.startswith('401') or status.startswith('403'):
                amenaza = 'Acceso no autorizado a panel administrativo'
                vulnerabilidad = 'Falta de autenticación o permisos insuficientes'
                riesgo = 'Compromiso del panel y acceso a datos internos'
            elif 'api' in sub and status.startswith('2'):
                amenaza = 'Exposición de API con datos sensibles'
                vulnerabilidad = 'Falta de autenticación o validación de tokens'
                riesgo = 'Fuga de información y abuso de endpoints'
            elif 'mail' in sub or reg == 'MX':
                amenaza = 'Phishing y suplantación de identidad vía correo'
                vulnerabilidad = 'Ausencia o mala configuración de SPF/DKIM/DMARC'
                riesgo = 'Fraude de correo y suplantación institucional'
            elif status == 'No responde':
                amenaza = 'Subdominio inactivo vulnerable a takeover'
                vulnerabilidad = 'Servicio HTTP/HTTPS ausente'
                riesgo = 'Disponibilidad del nombre para un atacante'
        # Impacto basado en valoraciones o cálculo directo
        impacto = val_map.get(asset['id'])
        if impacto is None:
            C = 3 if reg in ['MX', 'TXT'] else 2
            I = 2 if status.startswith('4') or status == 'No responde' else 3
            D = 1 if status == 'No responde' else 3
            F = 2 if any(k in sub for k in ['mail', 'contact', 'login', 'auth', 'register',
                                           'signup', 'user', 'account', 'secure', 'payment',
                                           'pay', 'dashboard', 'profile', 'api', 'admin',
                                           'settings', 'personal']) else 1
            impacto = (C + I + D) * F

        # Probabilidad basada en indicadores de exposición
        if reg == 'CNAME' and status == 'No responde':
            probabilidad = 3
        elif status.startswith('401') or status.startswith('403'):
            probabilidad = 3
        elif status.startswith('404'):
            probabilidad = 2
        elif status == 'No responde':
            probabilidad = 2
        elif status.startswith('2'):
            probabilidad = 3
        else:
            probabilidad = 2

        nivel_riesgo = probabilidad * impacto
        if nivel_riesgo <= 6:
            clasificacion = 'Bajo'
        elif nivel_riesgo <= 25:
            clasificacion = 'Medio'
        elif nivel_riesgo <= 40:
            clasificacion = 'Alto'
        else:
            clasificacion = 'Crítico'

        riesgos.append({
            'id': asset['id'],
            'subdominio': asset['subdominio'],
            'amenaza': amenaza,
            'vulnerabilidad': vulnerabilidad,
            'riesgo': riesgo,
            'probabilidad': probabilidad,
            'impacto': impacto,
            'nivel_riesgo': nivel_riesgo,
            'clasificacion': clasificacion
        })
    return riesgos
