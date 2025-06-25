import sys
import os
import json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, render_template, request, redirect, url_for
from main import scan_target
import argparse

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
                output=None,
                verbose=False
            )
            scan_target(domain, args)
            report_name = f"{domain.replace('.', '_')}_report.html"
            return render_template("result.html", filename=report_name)
    return render_template("index.html")

@app.route("/report/file/<filename>")
def report_file(filename):
    json_path = os.path.join("output", filename.replace(".html", ".json"))
    if not os.path.exists(json_path):
        return "Rapor verisi bulunamadı.", 404

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return render_template("report.html", report=data)

if __name__ == "__main__":
    app.run(debug=True)
