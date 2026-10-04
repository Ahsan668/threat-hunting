# Usage guide

## Configuration

Copy the example environment file and add your API keys:

```bash
cp .env.example .env
```

```
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

- VirusTotal: create a free account at virustotal.com and copy the key from your profile.
- AbuseIPDB: create a free account at abuseipdb.com and generate a key under API.

`.env` is listed in `.gitignore`, so keys stay out of the repository. Without keys, hunts still run and enrichment returns `no_api_key`.

SIEM connection settings live in `config.yaml` (see `config.example.yaml`). With demo mode on, no SIEM connection is needed.

## Web dashboard

Start the server from the project root:

```bash
python -m threat_hunter.web.app
```

Open http://127.0.0.1:5000.

1. Paste indicators into the IOC box, one per line. IPs, domains, URLs, emails, and MD5/SHA1/SHA256 hashes are detected automatically.
2. Choose the SIEM: Splunk or Elasticsearch.
3. Leave **Enrich with Threat Intelligence** checked to query VirusTotal and AbuseIPDB.
4. Click **Hunt IOCs**. A status line under the buttons shows progress, and any error message appears there too.
5. Click **Generate Report** and choose JSON, HTML, or Text to download the report for the hunt on screen.

### Reading the results

Risk is based on how many times an indicator appears in the SIEM:

| Risk | SIEM hits | Suggested action |
|---|---|---|
| High | more than 50 | Investigate now; likely active in the environment |
| Medium | 11 to 50 | Review the matching events and confirm context |
| Low | 10 or fewer | Note it; check whether the hits are benign |

Hit count alone doesn't prove compromise. A popular CDN domain can have thousands of benign hits, so read the enrichment table alongside it.

### Enrichment sources

| IOC type | Source |
|---|---|
| IPv4, IPv6 | AbuseIPDB |
| Domain, URL | VirusTotal |
| MD5, SHA1, SHA256 | VirusTotal |
| Email | Not enriched |

If an enrichment call fails or times out, that indicator shows `error` and the message is printed in the server console. The rest of the hunt still completes.

## Command line

```bash
python -m threat_hunter --help

# Hunt one indicator
python -m threat_hunter hunt --ioc 24.8.40.184

# Hunt several, on Elasticsearch, with enrichment
python -m threat_hunter hunt --ioc 24.8.40.184 --ioc polaris.fr --siem elk --enrich

# Hunt every indicator in a file and save an HTML report
python -m threat_hunter hunt-file --file examples/frothly_iocs.json --enrich --report html

# Check the installation
python -m threat_hunter test
```

| Option | Values | Default | Meaning |
|---|---|---|---|
| `--ioc` | any IOC | required for `hunt` | Indicator to hunt; repeat for several |
| `--file` | path | required for `hunt-file` | JSON list, JSON `{"iocs": [...]}`, or a `.txt` file with one IOC per line (`#` lines are skipped) |
| `--siem` | `splunk`, `elk` | `splunk` | SIEM to search |
| `--enrich` / `--no-enrich` | flag | off | Query VirusTotal and AbuseIPDB |
| `--report` | `json`, `html`, `text` | none | Also save a report |
| `--output`, `-o` | path | timestamped name | Where to save the report |

Example output:

```
IOC                                           TYPE     SIEM      HITS  RISK
------------------------------------------------------------------------------
192.168.247.129                               IPV4     splunk     487  HIGH
24.8.40.184                                   IPV4     splunk     342  HIGH
polaris.fr                                    DOMAIN   splunk     234  HIGH
attacker@frothly.com                          EMAIL    splunk      67  HIGH
------------------------------------------------------------------------------
4 IOC(s) hunted, 1130 total SIEM hits
```

After `pip install -e .`, the same commands are available as `threat-hunter ...`.

## API

The dashboard is a thin client over a JSON API, which can be called directly:

| Method | Endpoint | Body | Returns |
|---|---|---|---|
| POST | `/api/hunt` | `{"iocs": [...], "siem": "splunk", "enrich": true}` | `{"results": [...], "enrichment_data": [...]}` |
| POST | `/api/report` | `{"format": "json", "results": [...], "enrichment_data": [...]}` | Report file download |
| GET | `/api/health` | none | `{"status": "healthy"}` |

Example:

```bash
curl -X POST http://127.0.0.1:5000/api/hunt \
  -H "Content-Type: application/json" \
  -d '{"iocs": ["24.8.40.184"], "siem": "splunk", "enrich": false}'
```

## Troubleshooting

| Problem | Fix |
|---|---|
| Dashboard returns 404 | Run from the project root with `python -m threat_hunter.web.app` |
| Enrichment shows `no_api_key` | Check `.env` exists in the project root and restart the server |
| Clicking Hunt does nothing | Hard refresh with Ctrl+F5, then check the browser console (F12) |
| Test files fail with null bytes (Windows) | Antivirus is modifying files; add the project folder as an exclusion |