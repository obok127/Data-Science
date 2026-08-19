# URL Measurement Audit

A public-safe measurement reliability project combining browser/network collection with analytical validation and remediation prioritization.

## Repository layout

```text
url-measurement-audit/
├── README.md
├── requirements.txt
├── web_analytics_url_measurement_audit.ipynb
└── src/
    └── browser_measurement_collector.py
```

## Collector

The collector uses Playwright to inspect URLs and capture the first supported analytics page-view request. It demonstrates async browser automation, request interception, AppMeasurement/Web SDK parsing, first-page-view identification, soft-404 handling, consent-banner handling, concurrent processing, and checkpoint/resume.

### Example

```bash
python src/browser_measurement_collector.py \
  --input normalized_urls.csv \
  --output inspection_results.csv \
  --http-precheck
```

The input file must contain a `normalized_url` column.

## Notebook

`web_analytics_url_measurement_audit.ipynb` consumes generalized inspection outputs and shows how to distinguish healthy measurement from defects, separate dead URLs and uncertain captures, group related issues into remediation units, prioritize remediation using traffic impact, and validate transformations with explicit invariants.

## Public-data disclaimer

All names, domains, traffic counts, field names, and examples are synthetic or generalized. No production identifiers, company-specific domains, internal URLs, credentials, proprietary rules, or real business outputs are included.
