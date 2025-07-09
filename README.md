# RiskManager

RiskManager es una aplicación web sencilla que descubre subdominios y evalúa su riesgo cibernético. Utiliza Flask y realiza un modelo CIA+F para clasificar activos, identificar amenazas y proponer tratamientos.

## Reporte técnico consolidado

Tras calcular la valoración de cada activo, los riesgos identificados, el plan de tratamiento y el riesgo residual, se genera un **reporte técnico** que reúne toda la información relevante en una única tabla. Esta tabla incluye:

- ID y nombre del subdominio.
- Clasificación del activo según el valor CIA×F.
- Clasificación del riesgo detectado.
- Riesgo residual después de aplicar los controles propuestos.
- Estrategia de tratamiento asignada.
- Observaciones técnicas y recomendaciones.

El reporte puede consultarse en la pestaña "Reporte técnico" de la página de resultados.

### Cálculo del riesgo residual

El riesgo residual se obtiene usando la fórmula:

```
(Valor CIA×F - Reducción Aplicada) × Exposición Técnica
```

La reducción aplicada depende del control más representativo (8 puntos para controles robustos, 6 para básicos y 3 para organizativos). La exposición técnica varía entre 0 (activo eliminado), 1.0, 1.5 y 2.0 según el acceso que conserve el activo.

La clasificación resultante es:

- **Residual Bajo**: 0–7
- **Residual Medio**: 7–14
- **Residual Alto**: 15–22
- **Residual Crítico**: &gt;22
