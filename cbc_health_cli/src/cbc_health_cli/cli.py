from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import perf_counter
from typing import Any

from cbc_health_cli.checks import (
    health_score,
    prioritized_recommendations,
    summarize_alert_quality,
    summarize_alert_workflow,
    summarize_alerts,
    summarize_api_connector_use,
    summarize_banned_hashes,
    summarize_core_prevention_settings,
    summarize_daily_alert_trends,
    summarize_devices,
    summarize_endpoint_status,
    summarize_permissions_rule_audit,
    summarize_policy_efficacy,
    summarize_policy_drift,
    summarize_policy_settings,
    summarize_policy_posture,
    summarize_sensor_coverage_quality,
    summarize_user_logins_with_users,
    summarize_watchlists,
)
from cbc_health_cli.client import CBCClient
from cbc_health_cli.config import load_app_config
from cbc_health_cli.reporting import (
    create_run_dir,
    find_latest_run_dir,
    read_records_csv,
    write_executive_markdown,
    write_executive_pptx,
    write_technical_pptx,
    write_records_csv,
    write_summary,
)


class _RunStatusBar:
    def __init__(self, total_steps: int) -> None:
        self.total_steps = max(total_steps, 1)
        self.current_step = 0

    def _render(self, message: str) -> None:
        width = 28
        ratio = self.current_step / self.total_steps
        filled = int(width * ratio)
        bar = "#" * filled + "-" * (width - filled)
        print(f"[{bar}] {self.current_step}/{self.total_steps} {message}", flush=True)

    def start(self, message: str) -> None:
        self._render(message)

    def advance(self, message: str) -> None:
        self.current_step = min(self.current_step + 1, self.total_steps)
        self._render(message)

    def note(self, message: str) -> None:
        self._render(message)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cbc-health", description="Carbon Black health checks (Windows-native CLI)")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run health checks")
    run.add_argument("--config", type=Path, help="Path to YAML/JSON config file")
    run.add_argument("--customer-name")
    run.add_argument("--api-id")
    run.add_argument("--api-key")
    run.add_argument("--backend-url")
    run.add_argument("--tenant-id")
    run.add_argument("--tenant-key")
    run.add_argument("--output-dir")
    run.add_argument("--timeout-seconds", type=int)
    run.add_argument("--verify-tls", action=argparse.BooleanOptionalAction, default=None)
    run.add_argument("--assessment-profile", choices=["prod", "lab"])
    run.add_argument("--dry-run", action="store_true", help="Validate config only")

    return parser


def _overrides_from_args(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "customer_name": args.customer_name,
        "api_id": args.api_id,
        "api_key": args.api_key,
        "backend_url": args.backend_url,
        "tenant_id": args.tenant_id,
        "tenant_key": args.tenant_key,
        "output_dir": args.output_dir,
        "timeout_seconds": args.timeout_seconds,
        "verify_tls": args.verify_tls,
        "assessment_profile": args.assessment_profile,
    }


def _format_elapsed_time(elapsed_seconds: float) -> str:
    total_seconds = max(int(elapsed_seconds), 0)
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def _extract_timestamp_map(org_info: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(org_info, dict):
        return {}
    change_timestamps = org_info.get("changeTimestamps", {})
    if not isinstance(change_timestamps, dict):
        return {}
    timestamp_map = change_timestamps.get("timestampMap", {})
    if not isinstance(timestamp_map, dict):
        return {}
    return timestamp_map


def _any_xdr_rule_config(data_collection_configs: list[dict[str, Any]]) -> bool:
    for cfg in data_collection_configs:
        if not isinstance(cfg, dict):
            continue
        name = str(cfg.get("name", "")).strip().lower()
        if name == "xdr" or "xdr" in name:
            return True
    return False


def _has_workloads_policy_signal(policies: list[dict[str, Any]]) -> bool:
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        if policy.get("auto_deregister_inactive_vm_workloads_interval_ms") is not None:
            return True
    return False


# Maps the suffix of a ``psc:feature:<name>`` entitlement feature ID to the
# internal product name used throughout the codebase.  Only the products we
# actively report on are included; unrecognised feature IDs are ignored.
_ENTITLEMENT_FEATURE_MAP: dict[str, str] = {
    "defense": "NGAV",
    "threathunter": "EEDR",
    "hbfw": "HBFW",
    "livequery": "Live Query",
    "xdr": "XDR",
    "vulnerability": "Vulnerability Management",
    "vulnerabilityendpoint": "Vulnerability Management for Endpoints",
    "workloadinv": "Workloads",
}


def _products_from_entitlements(entitlements: dict[str, Any]) -> list[str] | None:
    """Extract enabled product names from an entitlements response dict.

    Returns an ordered list of product names, or None if the response does not
    contain a recognisable ``features`` list (so callers can fall back to
    heuristics).
    """
    features = entitlements.get("features")
    if not isinstance(features, list):
        return None
    products: list[str] = []
    for item in features:
        if not isinstance(item, dict):
            continue
        feature_id = str(item.get("feature_id", ""))
        # feature_id format: "psc:feature:<name>"
        suffix = feature_id.split(":")[-1].lower()
        product = _ENTITLEMENT_FEATURE_MAP.get(suffix)
        if product and product not in products:
            products.append(product)
    return products


def _detect_products(
    *,
    configured_products: list[str] | None,
    org_info: dict[str, Any],
    policies: list[dict[str, Any]],
    data_collection_configs: list[dict[str, Any]],
    entitlements: dict[str, Any] | None,
) -> dict[str, Any]:
    detected_products: list[str] = []
    not_enabled_products: list[str] = []
    evidence: dict[str, list[str]] = {}
    negative_evidence: dict[str, list[str]] = {}

    def add(product: str, reason: str) -> None:
        if product not in detected_products:
            detected_products.append(product)
        evidence.setdefault(product, []).append(reason)

    def add_negative(product: str, reason: str) -> None:
        if product not in not_enabled_products:
            not_enabled_products.append(product)
        negative_evidence.setdefault(product, []).append(reason)

    entitlement_products = _products_from_entitlements(entitlements or {})

    if entitlement_products is not None:
        # Primary path: entitlements API returned a usable feature list.
        all_reportable = list(_ENTITLEMENT_FEATURE_MAP.values())
        for product in entitlement_products:
            add(product, "entitlements API: feature enabled")
        for product in all_reportable:
            if product not in entitlement_products:
                add_negative(product, "entitlements API: feature not present")
    else:
        # Fallback path: entitlements call failed; use org-info heuristics.
        timestamp_map = _extract_timestamp_map(org_info)
        ngav_disabled_signal = "ORG_DISABLE_DEFENSE_RULES" in timestamp_map
        if ngav_disabled_signal:
            add_negative("NGAV", "org.changeTimestamps.timestampMap contains ORG_DISABLE_DEFENSE_RULES")
        elif str(org_info.get("storageProfile", "")).strip().upper() == "NGAV":
            add("NGAV", "org.storageProfile is NGAV")
        if "ORG_THREATHUNTER_RULES" in timestamp_map:
            add("EEDR", "org.changeTimestamps.timestampMap contains ORG_THREATHUNTER_RULES")
        if _any_xdr_rule_config(data_collection_configs):
            add("XDR", "policy data_collection configs include an XDR rule")
        if _has_workloads_policy_signal(policies):
            add("Workloads", "policy payload contains workload auto-deregister settings")

    final_products = configured_products[:] if configured_products else detected_products[:]
    source = "config" if configured_products else "auto"

    return {
        "source": source,
        "configured": configured_products or [],
        "detected": detected_products,
        "not_enabled": sorted(not_enabled_products),
        "final": final_products,
        "evidence": evidence,
        "negative_evidence": negative_evidence,
        "entitlements": entitlements or {},
    }


def run_command(args: argparse.Namespace) -> int:
    config = load_app_config(args.config, _overrides_from_args(args))

    if args.dry_run:
        print("Configuration is valid.")
        print(json.dumps({
            "customer_name": config.customer_name,
            "backend_url": config.backend_url,
            "tenant_id": config.tenant_id,
            "tenant_key": config.tenant_key,
            "output_dir": str(config.output_dir),
            "verify_tls": config.verify_tls,
            "timeout_seconds": config.timeout_seconds,
            "assessment_profile": config.assessment_profile,
            "soc_analysts": config.soc_analysts,
            "alerts_per_analyst_per_shift": config.alerts_per_analyst_per_shift,
            "alert_volume_avg_daily_threshold": config.alert_volume_avg_daily_threshold,
            "alert_volume_peak_daily_threshold": config.alert_volume_peak_daily_threshold,
        }, indent=2))
        return 0

    run_start = perf_counter()

    status = _RunStatusBar(total_steps=30)
    status.start("Starting health check run")

    client = CBCClient(
        api_id=config.api_id,
        api_key=config.api_key,
        verify_tls=config.verify_tls,
        timeout_seconds=config.timeout_seconds,
    )
    status.advance("Starting tenant and backend resolution")

    tenant_id = config.tenant_id
    tenant_key = config.tenant_key
    backend_url = config.backend_url

    if not tenant_id or not tenant_key or not backend_url:
        discovered = client.discover_tenant(preferred_backend=backend_url)
        tenant_id = tenant_id or discovered.tenant_id
        tenant_key = tenant_key or discovered.tenant_key
        backend_url = backend_url or discovered.backend_url
    status.advance("Starting previous baseline load")

    previous_run_dir = find_latest_run_dir(config.output_dir, tenant_key)
    previous_policies: list[dict[str, Any]] = []
    if previous_run_dir:
        previous_policies = read_records_csv(previous_run_dir / "policies.csv")
    status.advance("Starting output directory preparation")

    run_dir = create_run_dir(config.output_dir, tenant_key)
    status.advance("Starting org check")

    summary: dict[str, Any] = {
        "customer_name": config.customer_name,
        "backend_url": backend_url,
        "tenant_id": tenant_id,
        "tenant_key": tenant_key,
        "checks": {},
        "errors": [],
        "warnings": [],
        "assessment_profile": config.assessment_profile,
        "alert_volume_model": {
            "soc_analysts": config.soc_analysts,
            "alerts_per_analyst_per_shift": config.alerts_per_analyst_per_shift,
            "avg_daily_threshold": config.alert_volume_avg_daily_threshold,
            "peak_daily_threshold": config.alert_volume_peak_daily_threshold,
        },
    }

    devices: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    alerts_num_found: int = 0
    policies: list[dict[str, Any]] = []
    policies_with_details: list[dict[str, Any]] = []
    policy_rules: list[dict[str, Any]] = []
    core_prevention_rules: list[dict[str, Any]] = []
    watchlists: list[dict[str, Any]] = []
    audit_logs: list[dict[str, Any]] = []
    ngav_enabled = True

    users: list[dict[str, Any]] = []
    reputation_overrides: list[dict[str, Any]] = []
    data_collection_configs: list[dict[str, Any]] = []
    org_info: dict[str, Any] = {}
    org_entitlements: dict[str, Any] = {}

    try:
        org_details = client.get_org_details(backend_url, tenant_id)
        org_info = org_details.get("organization", {}) if isinstance(org_details, dict) else {}
        summary["checks"]["org"] = {
            "status": "ok",
            "organization": org_info,
        }
    except Exception as exc:
        summary["checks"]["org"] = {"status": "error"}
        summary["errors"].append(f"org check failed: {exc}")
    status.advance("Starting entitlements fetch")

    try:
        org_entitlements = client.get_org_entitlements(backend_url, tenant_key)
    except Exception as exc:
        summary["warnings"].append(f"entitlements API unavailable, falling back to heuristics: {exc}")
        org_entitlements = {}
    status.advance("Starting device check")

    try:
        devices = client.get_devices(backend_url, tenant_key)
        dsum = summarize_devices(devices)
        summary["checks"]["devices"] = {"status": "ok", "summary": dsum}
    except Exception as exc:
        summary["checks"]["devices"] = {"status": "error"}
        summary["errors"].append(f"device check failed: {exc}")
    status.advance("Starting alert check")

    try:
        alerts, alerts_num_found = client.get_alerts(backend_url, tenant_key)
        asum = summarize_alerts(alerts)
        asum["total_alerts_in_api"] = alerts_num_found
        asum["total_alerts_processed"] = len(alerts)
        summary["checks"]["alerts"] = {"status": "ok", "summary": asum}
    except Exception as exc:
        summary["checks"]["alerts"] = {"status": "error"}
        summary["errors"].append(f"alert check failed: {exc}")
    status.advance("Starting policy and rule collection")

    try:
        policies = client.get_policies(backend_url, tenant_key)
        # Resolve NGAV capability from explicit override, configured products, or entitlements.
        if config.ngav_enabled is not None:
            ngav_enabled = config.ngav_enabled
        else:
            entitlement_products = _products_from_entitlements(org_entitlements)
            if config.products:
                ngav_enabled = "NGAV" in config.products
            elif entitlement_products is not None:
                ngav_enabled = "NGAV" in entitlement_products
            else:
                # Fallback to org-info heuristics when entitlements are unavailable.
                timestamp_map = _extract_timestamp_map(org_info)
                if "ORG_DISABLE_DEFENSE_RULES" in timestamp_map:
                    ngav_enabled = False
                else:
                    ngav_enabled = str(org_info.get("storageProfile", "")).strip().upper() == "NGAV"

        total_policies = len(policies)
        for index, policy in enumerate(policies, start=1):
            policy_id = str(policy.get("id", policy.get("policy_id", ""))).strip()
            if not policy_id:
                continue
            policy_name = str(policy.get("name", "unknown"))
            status.note(f"Working policy {index}/{total_policies}: {policy_name}")
            
            # Fetch detailed policy configuration to get sensor settings
            policy_detail = {}
            try:
                policy_detail = client.get_policy_details(backend_url, tenant_key, policy_id)
            except Exception:
                pass
            
            # Merge detailed config into policy object
            enriched_policy = dict(policy)
            if policy_detail:
                enriched_policy.update(policy_detail)
            policies_with_details.append(enriched_policy)
            
            # Fetch and process rules
            try:
                rules = client.get_policy_rules(backend_url, tenant_key, policy_id)
            except Exception:
                continue
            for rule in rules:
                enriched_rule = dict(rule)
                enriched_rule["policy_id"] = policy_id
                enriched_rule["policy_name"] = policy.get("name", "")
                policy_rules.append(enriched_rule)

            if ngav_enabled:
                try:
                    cp_rules = client.get_core_prevention_rules(backend_url, tenant_key, policy_id)
                except Exception:
                    cp_rules = []
                for rule in cp_rules:
                    enriched_rule = dict(rule)
                    enriched_rule["policy_id"] = policy_id
                    enriched_rule["policy_name"] = policy.get("name", "")
                    core_prevention_rules.append(enriched_rule)

        # Update policies with enriched version for subsequent checks and CSV output
        policies = policies_with_details
        psum = summarize_policy_posture(policies, policy_rules, ngav_enabled=ngav_enabled)
        summary["checks"]["policy_posture"] = {"status": "ok", "summary": psum}
    except Exception as exc:
        summary["checks"]["policy_posture"] = {"status": "error"}
        summary["errors"].append(f"policy posture check failed: {exc}")
    status.advance("Starting data collection settings load")

    try:
        data_collection_configs = client.get_data_collection_configs(backend_url, tenant_key)
    except Exception as exc:
        summary["warnings"].append(f"data collection configs API unavailable: {exc}")
    status.advance("Starting watchlist check")

    timestamp_map: dict[str, Any] = _extract_timestamp_map(org_info)
    entitlement_products = _products_from_entitlements(org_entitlements)
    if entitlement_products is not None:
        watchlist_checks_enabled = "EEDR" in entitlement_products
    else:
        watchlist_checks_enabled = "ORG_THREATHUNTER_RULES" in timestamp_map

    if not watchlist_checks_enabled:
        summary["checks"]["watchlists"] = {
            "status": "not_applicable",
            "reason": "ORG_THREATHUNTER_RULES is not enabled for this org",
        }
        watchlists = []
    else:
        try:
            watchlists = client.get_watchlists(backend_url, tenant_key)
            wsum = summarize_watchlists(watchlists)
            summary["checks"]["watchlists"] = {"status": "ok", "summary": wsum}
        except Exception as exc:
            summary["checks"]["watchlists"] = {"status": "error"}
            summary["errors"].append(f"watchlist check failed: {exc}")
    status.advance("Starting policy drift check")

    try:
        dsum = summarize_policy_drift(policies, previous_policies)
        summary["checks"]["policy_drift"] = {"status": "ok", "summary": dsum}
    except Exception as exc:
        summary["checks"]["policy_drift"] = {"status": "error"}
        summary["errors"].append(f"policy drift check failed: {exc}")
    status.advance("Starting policy settings check")

    try:
        ps_settings = summarize_policy_settings(policies, data_collection_configs)
        summary["checks"]["policy_settings"] = {"status": "ok", "summary": ps_settings}
    except Exception as exc:
        summary["checks"]["policy_settings"] = {"status": "error"}
        summary["errors"].append(f"policy settings check failed: {exc}")
    status.advance("Starting product detection synthesis")

    product_detection = _detect_products(
        configured_products=config.products,
        org_info=org_info,
        policies=policies,
        data_collection_configs=data_collection_configs,
        entitlements=org_entitlements,
    )
    summary["products"] = product_detection

    detected_set = set(product_detection.get("detected", []))
    configured_set = set(config.products or [])
    if configured_set and detected_set and configured_set != detected_set:
        summary["warnings"].append(
            "Configured products differ from auto-detected products "
            f"(configured={sorted(configured_set)}, auto={sorted(detected_set)})."
        )
    status.advance("Starting core prevention settings check")

    if ngav_enabled:
        try:
            cps_source = core_prevention_rules if core_prevention_rules else policy_rules
            cps = summarize_core_prevention_settings(cps_source, policy_rules)
            summary["checks"]["core_prevention_settings"] = {"status": "ok", "summary": cps}
        except Exception as exc:
            summary["checks"]["core_prevention_settings"] = {"status": "error"}
            summary["errors"].append(f"core prevention settings check failed: {exc}")
    else:
        summary["checks"]["core_prevention_settings"] = {
            "status": "not_applicable",
            "reason": "NGAV disabled (EEDR-only tenant); core prevention controls are unavailable",
        }
    status.advance("Starting alert workflow check")

    try:
        aws = summarize_alert_workflow(alerts)
        summary["checks"]["alert_workflow"] = {"status": "ok", "summary": aws}
    except Exception as exc:
        summary["checks"]["alert_workflow"] = {"status": "error"}
        summary["errors"].append(f"alert workflow check failed: {exc}")
    status.advance("Starting audit log collection")

    try:
        audit_logs = client.get_audit_logs(backend_url, tenant_key, tenant_id=tenant_id)
    except Exception as exc:
        summary["warnings"].append(f"audit log API unavailable: {exc}")
    status.advance("Starting user list collection")

    try:
        users = client.get_users(backend_url, tenant_key)
    except Exception as exc:
        summary["warnings"].append(f"users API unavailable: {exc}")
    status.advance("Starting API connector usage check")

    try:
        connector_use = summarize_api_connector_use(audit_logs)
        summary["checks"]["api_connector_use"] = {"status": "ok", "summary": connector_use}
    except Exception as exc:
        summary["checks"]["api_connector_use"] = {"status": "error"}
        summary["errors"].append(f"api connector check failed: {exc}")
    status.advance("Starting permissions rule audit")

    try:
        pra = summarize_permissions_rule_audit(policy_rules)
        summary["checks"]["permissions_rule_audit"] = {"status": "ok", "summary": pra}
    except Exception as exc:
        summary["checks"]["permissions_rule_audit"] = {"status": "error"}
        summary["errors"].append(f"permission rule audit check failed: {exc}")
    status.advance("Starting banned hashes age check")

    try:
        reputation_overrides = client.get_reputation_overrides(backend_url, tenant_key, tenant_id)
        bh = summarize_banned_hashes(reputation_overrides)
        summary["checks"]["banned_hashes_age"] = {"status": "ok", "summary": bh}
    except Exception as exc:
        summary["checks"]["banned_hashes_age"] = {"status": "unavailable"}
        summary["warnings"].append(f"banned hashes check unavailable: {exc}")
    status.advance("Starting endpoint status check")

    try:
        eps = summarize_endpoint_status(devices)
        summary["checks"]["endpoint_status"] = {"status": "ok", "summary": eps}
    except Exception as exc:
        summary["checks"]["endpoint_status"] = {"status": "error"}
        summary["errors"].append(f"endpoint status check failed: {exc}")
    status.advance("Starting daily alerts trend check")

    try:
        dat = summarize_daily_alert_trends(alerts)
        summary["checks"]["daily_alerts_threat_scores"] = {"status": "ok", "summary": dat}
    except Exception as exc:
        summary["checks"]["daily_alerts_threat_scores"] = {"status": "error"}
        summary["errors"].append(f"daily alerts trend check failed: {exc}")
    status.advance("Starting user logins check")

    try:
        ul = summarize_user_logins_with_users(audit_logs, users)
        summary["checks"]["user_logins"] = {"status": "ok", "summary": ul}
    except Exception as exc:
        summary["checks"]["user_logins"] = {"status": "error"}
        summary["errors"].append(f"user logins check failed: {exc}")
    status.advance("Starting sensor coverage quality check")

    try:
        scq = summarize_sensor_coverage_quality(devices)
        summary["checks"]["sensor_coverage_quality"] = {"status": "ok", "summary": scq}
    except Exception as exc:
        summary["checks"]["sensor_coverage_quality"] = {"status": "error"}
        summary["errors"].append(f"sensor coverage quality check failed: {exc}")
    status.advance("Starting alert quality check")

    try:
        aq = summarize_alert_quality(alerts, num_found=alerts_num_found)
        summary["checks"]["alert_quality"] = {"status": "ok", "summary": aq}
    except Exception as exc:
        summary["checks"]["alert_quality"] = {"status": "error"}
        summary["errors"].append(f"alert quality check failed: {exc}")
    status.advance("Starting policy efficacy check")

    try:
        pe = summarize_policy_efficacy(
            policies,
            policy_rules,
            core_prevention_rules if ngav_enabled else None,
            alerts,
        )
        summary["checks"]["policy_efficacy"] = {"status": "ok", "summary": pe}
    except Exception as exc:
        summary["checks"]["policy_efficacy"] = {"status": "error"}
        summary["errors"].append(f"policy efficacy check failed: {exc}")
    status.advance("Starting health score calculation")

    if summary["checks"].get("devices", {}).get("status") == "ok" and summary["checks"].get("alerts", {}).get("status") == "ok":
        dsum = summary["checks"]["devices"]["summary"]
        asum = summary["checks"]["alerts"]["summary"]
        psum = None
        wsum = None
        if summary["checks"].get("policy_posture", {}).get("status") == "ok":
            psum = summary["checks"]["policy_posture"]["summary"]
        if summary["checks"].get("watchlists", {}).get("status") == "ok":
            wsum = summary["checks"]["watchlists"]["summary"]
        summary["health"] = health_score(
            dsum,
            asum,
            psum,
            wsum,
            assessment_profile=config.assessment_profile,
        )
    status.advance("Starting recommendation generation")

    summary["recommendations"] = prioritized_recommendations(summary)
    status.advance("Starting report write")

    write_records_csv(run_dir, "devices.csv", devices)
    write_records_csv(run_dir, "alerts.csv", alerts)
    write_records_csv(run_dir, "policies.csv", policies)
    write_records_csv(run_dir, "policy_rules.csv", policy_rules)
    write_records_csv(run_dir, "watchlists.csv", watchlists)
    write_records_csv(run_dir, "audit_logs.csv", audit_logs)
    write_records_csv(run_dir, "users.csv", users)
    write_records_csv(run_dir, "reputation_overrides.csv", reputation_overrides)

    elapsed_seconds = perf_counter() - run_start
    elapsed_human = _format_elapsed_time(elapsed_seconds)
    summary["execution_time"] = {
        "seconds": round(elapsed_seconds, 3),
        "human_readable": elapsed_human,
    }

    write_summary(run_dir, summary)
    write_executive_markdown(run_dir, summary)
    write_executive_pptx(run_dir)
    write_technical_pptx(run_dir)
    status.advance("Run finished")

    print(f"Run complete. Output directory: {run_dir}")
    print(f"Execution time: {elapsed_human} ({elapsed_seconds:.3f} seconds)")
    if summary["errors"]:
        print("Completed with errors:")
        for err in summary["errors"]:
            print(f"- {err}")
        return 2
    return 0


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "run":
        return run_command(args)

    parser.print_help()
    return 1
