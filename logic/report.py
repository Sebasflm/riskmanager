# coding: utf-8
"""Build consolidated technical report entries."""


def build_consolidated_report(valoraciones, riesgos, tratamientos, residuales):
    """Merge results to build a single technical report list.

    Args:
        valoraciones (list): asset valuation dictionaries.
        riesgos (list): risk identification dictionaries.
        tratamientos (list): treatment plan dictionaries.
        residuales (list): residual risk dictionaries.

    Returns:
        list: consolidated entries with keys ``id``, ``subdominio``,
        ``clasificacion`` (from valuation), ``riesgo`` (risk level),
        ``riesgo_residual`` (residual classification), ``tratamiento``,
        ``observaciones`` and ``recomendaciones``.
    """
    val_map = {v["id"]: v for v in valoraciones}
    trat_map = {t["id"]: t for t in tratamientos}
    res_map = {r["id"]: r for r in residuales}

    reporte = []
    for r in riesgos:
        id_ = r["id"]
        val = val_map.get(id_, {})
        trat = trat_map.get(id_, {})
        residual = res_map.get(id_, {})
        reporte.append(
            {
                "id": id_,
                "subdominio": r.get("subdominio"),
                "clasificacion": val.get("clasificacion", ""),
                "riesgo": r.get("clasificacion", ""),
                "riesgo_residual": residual.get("clasificacion", ""),
                "tratamiento": trat.get("estrategia", ""),
                "observaciones": r.get("vulnerabilidad", ""),
                "recomendaciones": trat.get("accion", ""),
            }
        )
    return reporte
