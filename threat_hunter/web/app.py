from flask import Flask, jsonify, request, render_template, Response
from threat_hunter.core.hunt_engine import HuntEngine
from threat_hunter.enrichers.virustotal import VirusTotalEnricher
from threat_hunter.enrichers.abuseipdb import AbuseIPDBEnricher
from threat_hunter.generators.report_generator import ReportGenerator
from dotenv import load_dotenv
from pathlib import Path
from datetime import datetime
import os
import traceback

# Load API keys from .env
load_dotenv()

# Absolute paths so templates are found when run with "python -m"
app_dir = Path(__file__).parent
app = Flask(
    __name__,
    template_folder=str(app_dir / 'templates'),
    static_folder=str(app_dir / 'static'),
)

hunt_engine = HuntEngine()

vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
abuse_api_key = os.getenv('ABUSEIPDB_API_KEY')
vt_enricher = VirusTotalEnricher(api_key=vt_api_key)
abuse_enricher = AbuseIPDBEnricher(api_key=abuse_api_key)

report_gen = ReportGenerator()


def enrich_result(result):
    """Enrich one hunt result. Never raises, so one bad API call can't break the hunt."""
    ioc = result.get('ioc')
    ioc_type = result.get('ioc_type')
    try:
        if ioc_type in ('ipv4', 'ipv6') and abuse_api_key:
            return abuse_enricher.enrich_ip(ioc)
        if ioc_type in ('domain', 'url') and vt_api_key:
            return vt_enricher.enrich_domain(ioc)
        if ioc_type in ('sha256', 'sha1', 'md5') and vt_api_key:
            return vt_enricher.enrich_hash(ioc)
    except Exception as e:
        print(f'[enrich] {ioc} failed: {e}')
        return {'value': ioc, 'status': 'error', 'error': str(e)}
    return None


@app.route('/')
def index():
    return render_template('dashboard.html')


@app.route('/api/hunt', methods=['POST'])
def hunt():
    data = request.get_json(silent=True) or {}
    iocs = [str(i).strip() for i in data.get('iocs', []) if str(i).strip()]
    siem = data.get('siem', 'splunk')
    enrich = bool(data.get('enrich', False))

    if not iocs:
        return jsonify({'error': 'No IOCs provided'}), 400

    results = []
    for ioc in iocs:
        try:
            results.append(hunt_engine.hunt(ioc, siem=siem))
        except Exception as e:
            print(f'[hunt] {ioc} failed: {e}')
            traceback.print_exc()
            results.append({'ioc': ioc, 'ioc_type': 'error', 'siem': siem,
                            'hits': 0, 'status': 'error', 'error': str(e)})

    enrichment_data = []
    if enrich:
        for result in results:
            enriched = enrich_result(result)
            if enriched is not None:
                enrichment_data.append(enriched)

    return jsonify({'results': results, 'enrichment_data': enrichment_data})


REPORT_FORMATS = {
    'json': ('generate_json_report', 'application/json', 'json'),
    'html': ('generate_html_report', 'text/html', 'html'),
    'text': ('generate_text_report', 'text/plain', 'txt'),
}


@app.route('/api/report', methods=['POST'])
def generate_report():
    # The browser sends the results it is showing, so the report always
    # matches the screen (no server-side state lost on Flask reload).
    data = request.get_json(silent=True) or {}
    fmt = data.get('format', 'json')
    results = data.get('results', [])
    enrichment = data.get('enrichment_data', [])

    if fmt not in REPORT_FORMATS:
        return jsonify({'error': f'Unknown format: {fmt}'}), 400
    if not results:
        return jsonify({'error': 'No hunt results. Run a hunt first.'}), 400

    method_name, mimetype, ext = REPORT_FORMATS[fmt]
    try:
        content = getattr(report_gen, method_name)(results, enrichment)
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'Report generation failed: {e}'}), 500

    filename = f"threat_hunt_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
    return Response(
        content,
        mimetype=mimetype,
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'version': '1.0'})


if __name__ == '__main__':
    app.run(debug=True, port=5000, host='127.0.0.1')