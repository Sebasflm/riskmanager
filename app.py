from flask import Flask, render_template, request, redirect, url_for
from scanner.discovery import discover_subdomains
from logic.valuation import evaluate_assets
from logic.risks import identify_risks
from logic.treatment import generate_treatments
from logic.residual import calculate_residual
from logic.kpis import calculate_kpis

app = Flask(__name__)

@app.route("/", methods=["GET","POST"])
def index():
    if request.method == "POST":
        domain = request.form.get("domain")
        if domain:
            return redirect(url_for("results", domain=domain))
    return render_template("index.html")

@app.route("/results/<domain>")
def results(domain):
    activos = discover_subdomains(domain)
    valoraciones = evaluate_assets(activos)
    riesgos = identify_risks(activos, valoraciones)
    tratamientos = generate_treatments(riesgos)
    residuales = calculate_residual(tratamientos, valoraciones, riesgos)
    kpis = calculate_kpis(activos)
    val_map = {v['id']: v for v in valoraciones}
    trat_map = {t['id']: t for t in tratamientos}
    reporte = []
    for r in riesgos:
        id_ = r['id']
        valor = val_map.get(id_, {}).get('valor', 0)
        trat = trat_map.get(id_, {})
        reporte.append({
            'id': id_,
            'subdominio': r['subdominio'],
            'valor': valor,
            'nivel_riesgo': r['nivel_riesgo'],
            'clasificacion': r['clasificacion'],
            'tratamiento': trat.get('estrategia', ''),
            'observaciones': r['vulnerabilidad'],
            'recomendaciones': trat.get('accion', ''),
        })
    return render_template(
        "results.html", domain=domain,
        activos=activos, valoraciones=valoraciones,
        riesgos=riesgos, tratamientos=tratamientos,
        residuales=residuales, kpis=kpis, reporte=reporte
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
