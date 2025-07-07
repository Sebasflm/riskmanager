from flask import Flask, render_template, request, redirect, url_for
from scanner.discovery import discover_subdomains
from logic.valuation import evaluate_assets
from logic.risks import identify_risks
from logic.treatment import generate_treatments

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
    riesgos = identify_risks(activos)
    tratamientos = generate_treatments(riesgos)
    return render_template("results.html", domain=domain,
                           activos=activos, valoraciones=valoraciones,
                           riesgos=riesgos, tratamientos=tratamientos)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
