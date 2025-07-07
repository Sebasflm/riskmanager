def identify_risks(activos):
    """
    Identifica amenazas, vulnerabilidades y riesgos potenciales para cada activo
    con descripciones detalladas y fundamentadas, incluyendo contexto por palabras clave.
    """
    riesgos = []
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

        riesgos.append({
            'id': asset['id'],
            'subdominio': asset['subdominio'],
            'amenaza': amenaza,
            'vulnerabilidad': vulnerabilidad,
            'riesgo': riesgo
        })
    return riesgos
