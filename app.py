from flask import Flask, render_template, request, redirect, url_for, make_response
import csv
import io
from fpdf import FPDF
from scanner.discovery import discover_subdomains
from logic.valuation import evaluate_assets
from logic.risks import identify_risks
from logic.treatment import generate_treatments
from logic.residual import calculate_residual
from logic.report import build_consolidated_report

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
    reporte = build_consolidated_report(valoraciones, riesgos, tratamientos, residuales)
    return render_template(
        "results.html", domain=domain,
        activos=activos, valoraciones=valoraciones,
        riesgos=riesgos, tratamientos=tratamientos,
        residuales=residuales, reporte=reporte
    )


@app.route("/export/<domain>/<fmt>")
def export(domain, fmt):
    activos = discover_subdomains(domain)
    valoraciones = evaluate_assets(activos)
    riesgos = identify_risks(activos, valoraciones)
    tratamientos = generate_treatments(riesgos)
    residuales = calculate_residual(tratamientos, valoraciones, riesgos)
    reporte = build_consolidated_report(valoraciones, riesgos, tratamientos, residuales)

    if fmt == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(['Activos'])
        writer.writerow(['ID', 'Subdominio', 'IP', 'Registro', 'Estado'])
        for a in activos:
            writer.writerow([a['id'], a['subdominio'], a['ip'], a['registro'], a['estado']])
        writer.writerow([])

        writer.writerow(['Valoraciones'])
        writer.writerow(['ID', 'Subdominio', 'C', 'I', 'D', 'F', 'Valor', 'Clasificacion'])
        for v in valoraciones:
            writer.writerow([v['id'], v['subdominio'], v['C'], v['I'], v['D'], v['F'], v['valor'], v['clasificacion']])
        writer.writerow([])

        writer.writerow(['Riesgos'])
        writer.writerow(['Subdominio', 'Amenaza', 'Vulnerabilidad', 'Probabilidad', 'Impacto', 'Nivel', 'Clasificacion'])
        for r in riesgos:
            writer.writerow([r['subdominio'], r['amenaza'], r['vulnerabilidad'], r['probabilidad'], r['impacto'], r['nivel_riesgo'], r['clasificacion']])
        writer.writerow([])

        writer.writerow(['Tratamientos'])
        writer.writerow(['ID', 'Subdominio', 'Riesgo', 'Clasificacion', 'Estrategia', 'Controles', 'Accion', 'Responsable', 'Plazo', 'Estado'])
        for t in tratamientos:
            writer.writerow([t['id'], t['subdominio'], t['riesgo'], t['clasificacion'], t['estrategia'], '; '.join(t['controles']), t['accion'], t['responsable'], t['plazo'], t['estado']])
        writer.writerow([])

        writer.writerow(['Riesgos Residuales'])
        writer.writerow(['ID', 'Subdominio', 'Riesgo Original', 'Control', 'Valor', 'Reduccion', 'Exposicion', 'Riesgo Residual', 'Clasificacion'])
        for rr in residuales:
            writer.writerow([rr['id'], rr['subdominio'], rr['riesgo_original'], rr['control'], rr['valor'], rr['reduccion'], rr['exposicion'], rr['riesgo_residual'], rr['clasificacion']])
        writer.writerow([])

        writer.writerow(['Reporte Tecnico'])
        writer.writerow(['ID', 'Subdominio', 'Clasificacion', 'Riesgo', 'Riesgo Residual', 'Tratamiento', 'Observaciones', 'Recomendaciones'])
        for rep in reporte:
            writer.writerow([rep['id'], rep['subdominio'], rep['clasificacion'], rep['riesgo'], rep['riesgo_residual'], rep['tratamiento'], rep['observaciones'], rep['recomendaciones']])

        csv_data = output.getvalue()
        resp = make_response(csv_data)
        resp.headers['Content-Disposition'] = f'attachment; filename={domain}.csv'
        resp.headers['Content-Type'] = 'text/csv'
        return resp

    if fmt == 'pdf':
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, f'Reporte para {domain}', ln=True)

        pdf.set_font('Arial', 'B', 10)
        pdf.cell(0, 10, 'Activos', ln=True)
        pdf.set_font('Arial', '', 8)
        for a in activos:
            line = f"{a['id']} {a['subdominio']} {a['ip']} {a['registro']} {a['estado']}"
            pdf.multi_cell(0, 5, line)
        pdf.ln(2)

        pdf.set_font('Arial', 'B', 10)
        pdf.cell(0, 10, 'Valoraciones', ln=True)
        pdf.set_font('Arial', '', 8)
        for v in valoraciones:
            line = f"{v['id']} {v['subdominio']} C:{v['C']} I:{v['I']} D:{v['D']} F:{v['F']} Val:{v['valor']} {v['clasificacion']}"
            pdf.multi_cell(0, 5, line)
        pdf.ln(2)

        pdf.set_font('Arial', 'B', 10)
        pdf.cell(0, 10, 'Riesgos', ln=True)
        pdf.set_font('Arial', '', 8)
        for r in riesgos:
            line = f"{r['subdominio']} {r['amenaza']} Prob:{r['probabilidad']} Impacto:{r['impacto']} Nivel:{r['nivel_riesgo']} {r['clasificacion']}"
            pdf.multi_cell(0, 5, line)
        pdf.ln(2)

        pdf.set_font('Arial', 'B', 10)
        pdf.cell(0, 10, 'Tratamientos', ln=True)
        pdf.set_font('Arial', '', 8)
        for t in tratamientos:
            line = f"{t['id']} {t['subdominio']} {t['estrategia']} {t['accion']}"
            pdf.multi_cell(0, 5, line)
        pdf.ln(2)

        pdf.set_font('Arial', 'B', 10)
        pdf.cell(0, 10, 'Riesgo Residual', ln=True)
        pdf.set_font('Arial', '', 8)
        for rr in residuales:
            line = f"{rr['id']} {rr['subdominio']} {rr['riesgo_residual']}"
            pdf.multi_cell(0, 5, line)
        pdf.ln(2)

        pdf.set_font('Arial', 'B', 10)
        pdf.cell(0, 10, 'Reporte Tecnico', ln=True)
        pdf.set_font('Arial', '', 8)
        for rep in reporte:
            line = f"{rep['id']} {rep['subdominio']} {rep['clasificacion']} {rep['riesgo_residual']}"
            pdf.multi_cell(0, 5, line)

        pdf_bytes = pdf.output(dest='S').encode('latin-1')
        resp = make_response(pdf_bytes)
        resp.headers['Content-Disposition'] = f'attachment; filename={domain}.pdf'
        resp.headers['Content-Type'] = 'application/pdf'
        return resp

    return "Formato no soportado", 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
