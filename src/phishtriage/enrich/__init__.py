"""Threat-intel enrichment (week 3): look up IOCs in VirusTotal, AbuseIPDB, URLhaus and RDAP.

    models.py    Lookup (a question to one service) and LookupResult (its answer)
    plan.py      what to look up, where, in what order, and why anything is skipped
    cache.py     results kept on disk with an expiry, and the count of real API calls (step 7)
    base.py      rate limits, retries, timeouts, and one interface for every service (step 8)
    virustotal.py, abuseipdb.py, urlhaus.py, rdap.py   one client per service (steps 9-11)

Enrichment only adds facts to the report. Turning them into a verdict is week 4's job.
It runs only with --enrich: a plain "phishtriage analyze" never touches the network.
"""
