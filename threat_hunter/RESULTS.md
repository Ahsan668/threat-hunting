# Results: Frothly breach case study

This document connects Threat Hunter's demo to a real investigation: my analysis of the Frothly breach in the Splunk Boss of the SOC (BOTS) v3 dataset. The full investigation, including SPL queries and evidence, is in the [splunk-bots-investigation](https://github.com/Ahsan668/splunk-bots-investigation) repository.

## Background

BOTS v3 simulates a breach of Frothly, a fictional brewing company, by an adversary group called Taedonggang. On August 20, 2018, the attacker used an AWS EC2 instance (`mars.i-08e52f8b5a034012d`) to stage Frothly web code and Memcached data and send it to an external IP. In total, about 31.6 MB left the network over UDP.

### Timeline (UTC, August 20, 2018)

| Time | Phase | Evidence |
|---|---|---|
| 18:08:43 | Reconnaissance | osquery inventory checks for vulnerable Python packages |
| 18:50:53 | Infrastructure probing | Requests to the AWS instance metadata service (`169.254.169.254`) |
| 19:14:38 | Tool acquisition | TLS connection to python.org |
| 19:15:19 | Malware preparation | Several `s3-upload.py` processes started against the `frothlywebcode` bucket |
| 19:19:27 | Data staging | `scp` of `frothly_html_memcaced.tar.gz` |
| 19:26:54 | Exfiltration | `s3-upload.py` runs captured in bash history; two UDP transfers of about 15.8 MB each from `192.168.247.129` to `24.8.40.184` |

## Indicators found in the investigation

| Indicator | Type | Role in the breach |
|---|---|---|
| `192.168.247.129` | IPv4 (internal) | Source host of the exfiltration traffic |
| `24.8.40.184` | IPv4 (external) | Destination of the stolen data |
| `polaris.cr7wwvryvz4o.us-west-1.rds.amazonaws.com` | Domain | AWS RDS hostname queried 814 times during reconnaissance |
| `mars.i-08e52f8b5a034012d` | Host | Attacker-controlled EC2 instance |

## How this maps to the Threat Hunter demo

The demo hunt in the screenshots uses four indicators:

| Demo indicator | Source |
|---|---|
| `192.168.247.129` | Real indicator from the investigation |
| `24.8.40.184` | Real indicator from the investigation |
| `polaris.fr` | Sample domain, a stand-in for the real RDS hostname |
| `attacker@frothly.com` | Sample email, included to exercise email detection |

Hit counts in the demo come from demo mode, which returns simulated values so the project runs without a live SIEM. They are not results from searching the BOTS dataset.

## What Threat Hunter changes in this workflow

In the investigation, every indicator meant writing and running its own SPL query, then checking it by hand against threat intelligence sources and copying findings into notes. Threat Hunter takes the indicator list once, runs the search for each one, enriches the results, and writes the report, so the analyst's time goes to interpreting results instead of collecting them.

## Analyst recommendations for this incident

- Isolate the EC2 instance `mars.i-08e52f8b5a034012d` and preserve it for forensics
- Block `24.8.40.184` at the network perimeter and search for any other contact with it
- Rotate AWS credentials available to `ec2-user` and audit access to the `frothlywebcode` bucket
- Review access logs for the `polaris` RDS instance for signs of data access beyond DNS lookups
- Alert on large outbound UDP transfers from cloud hosts