# Carbon Black Health CLI (Windows Native)

A Docker-free, Windows-native command line tool to run Carbon Black Cloud health checks.

## What it does now

- Authenticates to Carbon Black Cloud using API credentials.
- Discovers tenant information when possible.
- Runs core health checks:
  - tenant/org metadata
  - device inventory summary
  - alert summary (30 days)
  - policy and rule posture
  - watchlist coverage
  - policy drift from previous run baseline
  - policy settings posture
  - core prevention mode posture (monitor vs block)
  - alert workflow and closure aging
  - API and connector usage hygiene
  - permission rule audit
  - banned hash age review
  - endpoint state distribution
  - daily alert and threat score trends
  - dormant user login detection
  - sensor coverage quality (stale and unassigned)
  - alert quality (noise, repeats, unresolved aging)
  - policy efficacy by group (combined standard and core prevention posture)
- Writes outputs to JSON and CSV for easy sharing.
- Writes a PowerPoint executive summary from `summary.json` for stakeholder sharing.
- Writes a second technical PowerPoint deck from `summary.json` for engineering review.

## Requirements

- Windows 11 laptop with Python 3.10+ installed
- Network access to Carbon Black Cloud API endpoints

## Setup

1. Open PowerShell in this folder.
2. Install dependencies:

```powershell
pip install -r requirements.txt
```

## Configuration

Copy and edit [config.example.yaml](config.example.yaml), or create a JSON config file if YAML parsing is blocked by policy.

## API Key Setup

The API key used with this tool requires access to multiple Carbon Black Cloud endpoints. 

**Recommended approach:** Use the built-in **"View All"** role when assigning the API key. This ensures access to all required endpoints, including legacy platform endpoints not fully documented in the RBAC system.

**Alternative approach (custom access level):** If you require a more restrictive custom access level, ensure the following permissions are enabled with **READ** operations:
- `device` – for device inventory
- `org.alerts` – for alert data
- `org.policies` – for policy and rule details
- `org.audits` – for audit logs
- `org.watchlists` – for threat watchlists
- `org.reputations` – for reputation overrides
- `org.info` – for organization metadata (required for org details endpoint)

Note: The legacy `/appservices/v5/orgs/{id}/` endpoint used for organization metadata requires `org.info` permission in the custom access level, or the "View All" built-in role.

## Run

```powershell
python .\cbc_health.py run --config .\config.example.json
```

JSON config example:

```json
{
  "customer_name": "Example Customer",
  "api_id": "REPLACE_ME",
  "api_key": "REPLACE_ME",
  "products": null,
  "backend_url": null,
  "tenant_id": null,
  "tenant_key": null,
  "output_dir": "output",
  "verify_tls": true,
  "timeout_seconds": 30,
  "assessment_profile": "prod",
  "soc_analysts": null,
  "alerts_per_analyst_per_shift": 80,
  "alert_volume_avg_daily_threshold": 1000,
  "alert_volume_peak_daily_threshold": 1500
}
```

Product detection behavior:

- If `products` is omitted or `null`, the tool auto-detects products using product-specific endpoint probes plus org/policy signals.
- If `products` is provided, it is used as an explicit override and compared against auto-detection for mismatch warnings.
- Valid product names: `NGAV`, `EEDR`, `Live Query`, `XDR`, `Vulnerability Management`, `HBFW`, `Workloads`.

Alert-volume capacity tuning:

- `soc_analysts`: optional explicit SOC analyst count. If omitted/null, the tool estimates by active endpoint count.
- `alerts_per_analyst_per_shift`: assumed per-analyst throughput used in capacity ratio.
- `alert_volume_avg_daily_threshold`: absolute average daily alert pressure guardrail.
- `alert_volume_peak_daily_threshold`: absolute peak daily alert pressure guardrail.

Assessment profile options:

- `prod`: strict scoring for production tenants
- `lab`: reduced penalty for high-severity alert volume and lighter activity-ratio penalties

Optional dry run (no API calls):

```powershell
python .\cbc_health.py run --config .\config.example.json --dry-run
```

## Outputs

By default, outputs are written under:

- `./output/<tenant_key>/<timestamp>/summary.json`
- `./output/<tenant_key>/<timestamp>/devices.csv` (if device API call succeeds)
- `./output/<tenant_key>/<timestamp>/alerts.csv` (if alert API call succeeds)
- `./output/<tenant_key>/<timestamp>/policies.csv` (if policy API call succeeds)
- `./output/<tenant_key>/<timestamp>/policy_rules.csv` (if policy rules API calls succeed)
- `./output/<tenant_key>/<timestamp>/watchlists.csv` (if watchlist API call succeeds)
- `./output/<tenant_key>/<timestamp>/audit_logs.csv` (if audit log API call succeeds)
- `./output/<tenant_key>/<timestamp>/access_profiles.csv` (if access profiles API call succeeds)
- `./output/<tenant_key>/<timestamp>/grants.csv` (if grants API call succeeds)
- `./output/<tenant_key>/<timestamp>/reputation_overrides.csv` (if reputation overrides API call succeeds)
- `./output/<tenant_key>/<timestamp>/executive_summary.md` (human-readable one-page summary)
- `./output/<tenant_key>/<timestamp>/executive_summary_<orgDomain>.pptx` (PowerPoint deck generated from `summary.json`; orgDomain is sanitized for filename safety)
- `./output/<tenant_key>/<timestamp>/technical_deck_<orgDomain>.pptx` (technical PowerPoint deck generated from `summary.json`; orgDomain is sanitized for filename safety)

Drift baseline lookup is tenant-key scoped, so each run is compared against the most recent run for the same tenant key.

Additional summary sections in `summary.json`:

- `checks.watchlists`
- `checks.policy_drift`
- `products` (configured vs detected products, evidence, and probe results)
- `recommendations` (prioritized remediation)

## Notes

- No Docker, no WSL.
- Symantec checks are not included yet in this first version.
- Secrets should be managed by your enterprise policy. You can also pass credentials via command-line flags if needed.
