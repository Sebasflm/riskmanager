# coding: utf-8
"""Executive KPI calculations based on discovered assets."""


def calculate_kpis(activos):
    """Return KPI values as percentages based on methodology.

    Args:
        activos (list): list of discovered asset dictionaries including
            ``https``, ``security_headers``, ``sends_mail`` and ``spf`` keys.

    Returns:
        dict: KPI names mapped to percentage values rounded to integers.
    """
    total = len(activos)
    if total == 0:
        return {"kpi1": 0, "kpi2": 0, "kpi3": 0}

    protected = 0
    dns_secure = 0
    without_owner = 0  # placeholder, all assets have owner for now

    for a in activos:
        # KPI1: minimal controls active
        if a.get("https") and a.get("security_headers") and (
            not a.get("sends_mail") or a.get("spf")
        ):
            protected += 1

        # KPI3: DNS secure configuration
        record = a.get("registro")
        if record != "CNAME" or a.get("estado") != "No responde":
            if not a.get("sends_mail") or a.get("spf"):
                dns_secure += 1

    kpi1 = round(100 * protected / total)
    kpi2 = round(100 * without_owner / total)
    kpi3 = round(100 * dns_secure / total)

    return {"kpi1": kpi1, "kpi2": kpi2, "kpi3": kpi3}
