import sys
import os
import json
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
import argparse

# Üst klasördeki 'main.py' için yol ekleniyor
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from main import scan_target

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        domain = request.form.get("domain")
        if domain:
            args = argparse.Namespace(
                target=domain,
                list=None,
                subdomain=True,
                ports=True,
                dirs=True,
                vuln=True,
                xss=True,
                form=True,
                formtest=True,
                fast=True,
                wordlist=None,
                output=f"{domain.replace('.', '_')}_report.json",  # JSON çıktısı bu isimde olacak
                verbose=False
            )
            scan_target(domain, args)
            report_html = f"{domain.replace('.', '_')}_report.html"  # HTML rapor ismi
            # Tarama tamamlandıktan sonra result sayfasına yönlendiriyoruz
            return render_template("result.html", filename=report_html)
    return render_template("index.html")


@app.route("/report/file/<filename>")
def report_file(filename):
    report_dir = os.path.join("wvs_web", "output")
    html_path = os.path.join(report_dir, filename)
    if not os.path.exists(html_path):
        return "Rapor verisi bulunamadı.", 404
    return send_from_directory(report_dir, filename)


@app.route("/report/list")
def list_reports():
    try:
        report_dir = os.path.join("wvs_web", "output")
        files = [f for f in os.listdir(report_dir) if f.endswith(".html")]
        return render_template("list.html", files=files)
    except Exception as e:
        return f"Hata: {e}", 500


if __name__ == "__main__":
    app.run(debug=True)
