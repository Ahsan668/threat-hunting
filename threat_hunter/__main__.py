import json
import os
import sys
from datetime import datetime
from pathlib import Path

import click
from dotenv import load_dotenv

from threat_hunter.core.hunt_engine import HuntEngine
from threat_hunter.enrichers.virustotal import VirusTotalEnricher
from threat_hunter.enrichers.abuseipdb import AbuseIPDBEnricher
from threat_hunter.generators.report_generator import ReportGenerator

load_dotenv()

REPORT_FORMATS = {
    'json': ('generate_json_report', 'json'),
    'html': ('generate_html_report', 'html'),
    'text': ('generate_text_report', 'txt'),
}


def risk_of(hits):
    if hits > 50:
        return 'HIGH'
    if hits > 10:
        return 'MEDIUM'
    return 'LOW'


def enrich_results(results):
    """Enrich hunt results. A failed API call is recorded, never fatal."""
    vt_key = os.getenv('VIRUSTOTAL_API_KEY')
    abuse_key = os.getenv('ABUSEIPDB_API_KEY')
    vt = VirusTotalEnricher(api_key=vt_key)
    abuse = AbuseIPDBEnricher(api_key=abuse_key)

    enrichment = []
    for r in results:
        ioc, ioc_type = r.get('ioc'), r.get('ioc_type')
        try:
            if ioc_type in ('ipv4', 'ipv6') and abuse_key:
                enrichment.append(abuse.enrich_ip(ioc))
            elif ioc_type in ('domain', 'url') and vt_key:
                enrichment.append(vt.enrich_domain(ioc))
            elif ioc_type in ('sha256', 'sha1', 'md5') and vt_key:
                enrichment.append(vt.enrich_hash(ioc))
        except Exception as e:
            click.echo(f'  [!] Enrichment failed for {ioc}: {e}', err=True)
            enrichment.append({'value': ioc, 'status': 'error', 'error': str(e)})
    return enrichment


def run_hunt(iocs, siem, enrich, report, output):
    engine = HuntEngine()
    results = []
    for ioc in iocs:
        try:
            results.append(engine.hunt(ioc, siem=siem))
        except Exception as e:
            click.echo(f'  [!] Hunt failed for {ioc}: {e}', err=True)
            results.append({'ioc': ioc, 'ioc_type': 'error', 'siem': siem,
                            'hits': 0, 'status': 'error'})

    # Results table
    click.echo('')
    click.echo(f"{'IOC':<45} {'TYPE':<8} {'SIEM':<7} {'HITS':>6}  RISK")
    click.echo('-' * 78)
    total = 0
    for r in results:
        hits = int(r.get('hits') or 0)
        total += hits
        click.echo(f"{str(r.get('ioc')):<45} {str(r.get('ioc_type', '')).upper():<8} "
                   f"{str(r.get('siem', siem)):<7} {hits:>6}  {risk_of(hits)}")
    click.echo('-' * 78)
    click.echo(f'{len(results)} IOC(s) hunted, {total} total SIEM hits')

    enrichment = []
    if enrich:
        click.echo('\nEnriching with threat intelligence...')
        enrichment = enrich_results(results)
        if not enrichment:
            click.echo('  No enrichment (no API keys in .env, or no IP/domain/hash IOCs).')
        for e in enrichment:
            click.echo(f"  {str(e.get('value', e.get('ioc', ''))):<45} {e.get('status', '')}")

    if report:
        method, ext = REPORT_FORMATS[report]
        content = getattr(ReportGenerator(), method)(results, enrichment)
        path = Path(output) if output else Path(
            f"threat_hunt_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}")
        path.write_text(content, encoding='utf-8')
        click.echo(f'\nReport saved: {path.resolve()}')


def load_iocs_from_file(path):
    """Accept a JSON list, a JSON object with an "iocs" list, or a text file with one IOC per line."""
    text = Path(path).read_text(encoding='utf-8-sig')
    if Path(path).suffix.lower() == '.json':
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get('iocs', [])
        if not isinstance(data, list):
            raise click.BadParameter('JSON must be a list of IOCs or {"iocs": [...]}')
        iocs = [str(i).strip() for i in data]
    else:
        iocs = [line.strip() for line in text.splitlines()]
    return [i for i in iocs if i and not i.startswith('#')]


siem_option = click.option('--siem', type=click.Choice(['splunk', 'elk']), default='splunk',
                           show_default=True, help='SIEM to search')
enrich_option = click.option('--enrich/--no-enrich', default=False, show_default=True,
                             help='Enrich results with VirusTotal / AbuseIPDB')
report_option = click.option('--report', type=click.Choice(list(REPORT_FORMATS)),
                             help='Also save a report in this format')
output_option = click.option('--output', '-o', type=click.Path(dir_okay=False),
                             help='Report file path (default: timestamped name)')


@click.group()
def main():
    """threat-hunter: Automated threat hunting platform"""


@main.command()
@click.option('--ioc', 'iocs', required=True, multiple=True,
              help='IOC to hunt (IP, domain, URL, email, hash). Repeat for several.')
@siem_option
@enrich_option
@report_option
@output_option
def hunt(iocs, siem, enrich, report, output):
    """Hunt one or more IOCs given on the command line."""
    run_hunt(list(iocs), siem, enrich, report, output)


@main.command('hunt-file')
@click.option('--file', 'file_path', required=True, type=click.Path(exists=True, dir_okay=False),
              help='JSON list of IOCs, or a .txt file with one IOC per line')
@siem_option
@enrich_option
@report_option
@output_option
def hunt_file(file_path, siem, enrich, report, output):
    """Hunt every IOC in a file."""
    iocs = load_iocs_from_file(file_path)
    if not iocs:
        raise click.ClickException(f'No IOCs found in {file_path}')
    click.echo(f'Loaded {len(iocs)} IOC(s) from {file_path}')
    run_hunt(iocs, siem, enrich, report, output)


@main.command()
def test():
    """Test if threat-hunter is working"""
    click.echo('threat-hunter CLI is working!')


if __name__ == '__main__':
    main()