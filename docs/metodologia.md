# Metodología de Gestión de Riesgos

Esta sección describe el enfoque empleado por **RiskManager** para la identificación y tratamiento de riesgos de seguridad cibernética.

## 8. Comunicación y Consulta

La comunicación efectiva es esencial para asegurar que los hallazgos y las recomendaciones lleguen de forma oportuna a todas las partes interesadas. Se manejan dos niveles de interacción: técnica y ejecutiva.

### 8.1 Registro de observaciones y recomendaciones

Durante el proceso se documentan las observaciones por subdominio, junto con recomendaciones técnicas específicas.

### 8.2 Reporte técnico consolidado

| ID | Subdominio        | Valor CIA×F | Nivel de Riesgo | Clasificación | Tratamiento | Observaciones Técnicas                                | Recomendaciones                                  |
|----|-------------------|-------------|-----------------|---------------|-------------|------------------------------------------------------|--------------------------------------------------|
| R1 | admin.empresa.com | 18          | 54              | Crítico       | Mitigar     | Panel sin login, accesible públicamente              | Implementar MFA, limitar acceso por IP           |
| R2 | blog.empresa.com  | 4           | 4               | Bajo          | Aceptar     | Falta de cabeceras CSP, pero sin datos críticos      | Solo documentar y monitorear cada trimestre      |
| R3 | mail.empresa.com  | 14          | 28              | Alto          | Mitigar     | No tiene SPF ni DKIM configurado                     | Agregar validaciones en DNS y monitoreo SMTP     |
| R4 | test.empresa.com  | 8           | 24              | Alto          | Evitar      | CNAME apuntando a servicio inexistente               | Eliminar del DNS                                 |

Este reporte se puede entregar en formato PDF o mostrarse desde el sistema web. Se permite filtrar por dominio, nivel de riesgo o estado de tratamiento.

### 8.3 Reporte ejecutivo para responsables estratégicos

Para la alta dirección se presentan Indicadores Clave de Desempeño (KPIs) que resumen el estado del sistema de riesgos.

**KPI 1 – % de subdominios con controles mínimos activos**

Se calcula con la fórmula:

```
KPI1 = (Subdominios con controles mínimos activos) / (Total de subdominios evaluados)
```

**KPI 2 – % de subdominios sin responsable asignado**

```
KPI2 = (Subdominios sin responsable) / (Total de subdominios evaluados)
```

**KPI 3 – % de subdominios con configuración DNS segura**

```
KPI3 = (Subdominios con configuración DNS segura) / (Total de subdominios evaluados)
```

#### Tabla consolidada de KPI’s

| Métrica                                             | Valor Actual | Meta Sugerida |
|-----------------------------------------------------|--------------|---------------|
| % subdominios con controles mínimos activos         | 71%          | ≥ 90%         |
| % subdominios sin responsable asignado              | 14%          | 0%            |
| % subdominios con configuración DNS segura          | 82%          | ≥ 95%         |

