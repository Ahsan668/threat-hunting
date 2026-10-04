from typing import Dict, List
from datetime import datetime
import json

class ReportGenerator:
    """
    Generate incident reports from hunt results and enrichment data.
    Supports: JSON, HTML, plain text formats
    """
    
    def __init__(self):
        self.timestamp = datetime.utcnow().isoformat()
    
    def generate_json_report(self, hunts: List[Dict], enrichments: List[Dict]) -> str:
        """Generate JSON formatted report"""
        report = {
            "timestamp": self.timestamp,
            "hunt_results": hunts,
            "enrichment_data": enrichments,
            "summary": self._summarize(hunts, enrichments)
        }
        return json.dumps(report, indent=2)
    
    def generate_text_report(self, hunts: List[Dict], enrichments: List[Dict]) -> str:
        """Generate plain text formatted report"""
        lines = [
            "=" * 80,
            "THREAT HUNTING INCIDENT REPORT",
            f"Generated: {self.timestamp}",
            "=" * 80,
            "",
            "HUNT RESULTS:",
            "-" * 80,
        ]
        
        for hunt in hunts:
            lines.append(f"IOC: {hunt.get('ioc', 'N/A')}")
            lines.append(f"  Type: {hunt.get('ioc_type', 'N/A')}")
            lines.append(f"  SIEM: {hunt.get('siem', 'N/A')}")
            lines.append(f"  Hits: {hunt.get('hits', 0)}")
            lines.append("")
        
        lines.extend([
            "",
            "ENRICHMENT DATA:",
            "-" * 80,
        ])
        
        for enrichment in enrichments:
            lines.append(f"IOC: {enrichment.get('value', 'N/A')}")
            lines.append(f"  Engine: {enrichment.get('engine', 'N/A')}")
            lines.append(f"  Status: {enrichment.get('status', 'N/A')}")
            if enrichment.get('status') == 'found':
                for key, val in enrichment.items():
                    if key not in ['value', 'engine', 'status']:
                        lines.append(f"  {key}: {val}")
            lines.append("")
        
        summary = self._summarize(hunts, enrichments)
        lines.extend([
            "SUMMARY:",
            "-" * 80,
            f"Total IOCs hunted: {summary['total_iocs']}",
            f"Total hits: {summary['total_hits']}",
            f"Enriched IOCs: {summary['enriched_count']}",
            f"Malicious indicators: {summary['malicious_count']}",
            "=" * 80,
        ])
        
        return "\n".join(lines)
    
    def generate_html_report(self, hunts: List[Dict], enrichments: List[Dict]) -> str:
        """Generate HTML formatted report"""
        summary = self._summarize(hunts, enrichments)
        
        hunts_html = ""
        for hunt in hunts:
            hunts_html += f"""
            <tr>
                <td>{hunt.get('ioc', 'N/A')}</td>
                <td>{hunt.get('ioc_type', 'N/A')}</td>
                <td>{hunt.get('siem', 'N/A')}</td>
                <td>{hunt.get('hits', 0)}</td>
            </tr>
            """
        
        enrichments_html = ""
        for enrichment in enrichments:
            status_badge = f"<span style='background: {'red' if enrichment.get('status') == 'found' else 'green'}; color: white; padding: 5px; border-radius: 3px;'>{enrichment.get('status', 'N/A')}</span>"
            enrichments_html += f"""
            <tr>
                <td>{enrichment.get('value', 'N/A')}</td>
                <td>{enrichment.get('engine', 'N/A')}</td>
                <td>{status_badge}</td>
                <td>{enrichment.get('abuse_score', enrichment.get('malicious_count', 'N/A'))}</td>
            </tr>
            """
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Threat Hunting Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .container {{ background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                h1 {{ color: #333; border-bottom: 3px solid #d32f2f; padding-bottom: 10px; }}
                h2 {{ color: #d32f2f; margin-top: 20px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #d32f2f; color: white; }}
                tr:hover {{ background: #f5f5f5; }}
                .summary {{ background: #f0f0f0; padding: 15px; border-radius: 3px; margin: 15px 0; }}
                .timestamp {{ color: #888; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Threat Hunting Incident Report</h1>
                <p class="timestamp">Generated: {self.timestamp}</p>
                
                <div class="summary">
                    <strong>Summary:</strong><br>
                    Total IOCs hunted: {summary['total_iocs']}<br>
                    Total hits: {summary['total_hits']}<br>
                    Enriched IOCs: {summary['enriched_count']}<br>
                    Malicious indicators: {summary['malicious_count']}
                </div>
                
                <h2>Hunt Results</h2>
                <table>
                    <tr>
                        <th>IOC</th>
                        <th>Type</th>
                        <th>SIEM</th>
                        <th>Hits</th>
                    </tr>
                    {hunts_html}
                </table>
                
                <h2>Enrichment Data</h2>
                <table>
                    <tr>
                        <th>Value</th>
                        <th>Engine</th>
                        <th>Status</th>
                        <th>Risk Score</th>
                    </tr>
                    {enrichments_html}
                </table>
            </div>
        </body>
        </html>
        """
        return html
    
    def _summarize(self, hunts: List[Dict], enrichments: List[Dict]) -> Dict:
        """Generate summary statistics"""
        total_hits = sum(h.get('hits', 0) for h in hunts)
        malicious_count = sum(1 for e in enrichments if e.get('malicious_count', 0) > 0 or e.get('abuse_score', 0) > 50)
        
        return {
            "total_iocs": len(hunts),
            "total_hits": total_hits,
            "enriched_count": len(enrichments),
            "malicious_count": malicious_count,
        }