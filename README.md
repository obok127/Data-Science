# Web Analytics URL Measurement Audit

A vendor-neutral, public-safe measurement reliability project that turns noisy URL-level analytics data into prioritized remediation work.

## What it does

The notebook demonstrates an end-to-end analytical workflow:

- canonicalize URLs while removing tracking noise,
- preserve traffic volume during aggregation,
- join browser/network inspection outcomes,
- validate expected vs. observed measurement fields,
- distinguish tagging defects from broken URLs and uncertain captures,
- group related defects into remediation units,
- prioritize fixes by traffic impact,
- validate transformations with explicit invariants.

## Repository layout

```text
url-measurement-audit/
├── README.md
├── web_analytics_url_measurement_audit.ipynb
└── requirements.txt
```

## Run locally

```bash
pip install -r requirements.txt
jupyter notebook web_analytics_url_measurement_audit.ipynb
```

The notebook is self-contained and uses synthetic data only. It makes no external network calls.

## Portfolio positioning

This project is designed to demonstrate **measurement reliability, product analytics, data-quality engineering, and root-cause isolation** rather than a vendor-specific implementation.

A central principle is:

> A metric anomaly is not automatically a business anomaly. Validate the measurement before interpreting the behavior.

## Public-data disclaimer

All domains, URLs, traffic counts, field names, and inspection outcomes are synthetic or generalized. No production identifiers, customer data, internal URLs, credentials, proprietary capture scripts, or real output values are included.
