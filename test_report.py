from utils.html_report import generate_html_report

if __name__ == "__main__":
    json_path = "output/example.json"  # Örnek JSON dosyanın yolu
    html_path = generate_html_report(json_path)
    print(f"Rapor oluşturuldu: {html_path}")
