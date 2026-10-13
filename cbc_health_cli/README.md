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
  - policy tuning analysis (Broadcom Good/Better/Best maturity mapping)
- Writes outputs to JSON and CSV for easy sharing.
- Writes a PowerPoint executive summary from `summary.json` for stakeholder sharing.
- Writes a second technical PowerPoint deck from `summary.json` for engineering review.

## BYPASS Rule Priorities

The Detailed Breakdown slide classifies enabled or disabled policy rules whose normalized action is `BYPASS`, based on wildcard path values found in the rule's path-related fields and conditions:

- **P1 (Critical):** A candidate path starts and ends with `**`, indicating a broadly scoped path pattern.
- **P2 (High):** A candidate path starts with `**` or ends with `**`, but not both.

The slide reports the number of distinct policies containing at least one matching rule at each priority, not the number of matching rules. A policy can count as both P1 and P2 if it contains rules matching both patterns. These labels are this tool's prioritization heuristic, not Carbon Black Cloud rule severity labels.

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

**Required:** Use the built-in **"Super Admin"** role when creating the API key in Settings → API Access.

Several checks depend on the CBC Access v2 grants API (`GET /access/v2/orgs/{org}/grants/{principal}`) to resolve user roles and API connector access level types. This endpoint is only accessible to Super Admin credentials. The "View All" built-in role and all custom access levels return 403 for connector principal lookups (`psc:cnn:*`), even though they can read user principal grants. The relevant permission is not exposed as a configurable capability in the Access Levels UI, so there is no way to grant it to a restricted key.

If a non-Super Admin key is used, the tool will still run and produce output, but with these gaps (verified with a View All-style key):

- **Org details** (`GET /appservices/v5/orgs/{org_id}`) returns 403 and is recorded as an `org check failed` error. As a result:
  - The cover slide and deck filenames fall back to the backend hostname instead of the org domain.
  - EEDR-only detection (`ORG_DISABLE_DEFENSE_RULES`) cannot run, so policy and core prevention slides render charts instead of "not applicable" on EEDR-only tenants.
- **Users API** (`GET /appservices/v6/orgs/{org_key}/users`) returns 403. User and login data still comes from audit logs, but user roles show as `unknown`.
- **Connector grants** return 403, so API connector access level types show as `unknown`.
m
A 403 is not always caused by the access level. Other causes include the key type (SIEM and Live Response keys), MSSP parent/child org keys, authorized-IP restrictions on the key, and a corporate proxy or WAF. HTTP errors include the server's `error_code` and message in brackets (for example `[TOKEN_INVALID: Session Token is in blacklist]`). Errors are printed at the end of the run; 401/403 warnings are printed under `Access warnings`; full text for both is in `summary.json`. A `non-JSON body` detail means something other than the Carbon Black API answered, such as a proxy, WAF, or gateway error page. Confirm by repeating the call from a network without the proxy.

If the key is rejected outright (401/403 on the initial device search), the run stops with exit code 3 and writes no output.

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
