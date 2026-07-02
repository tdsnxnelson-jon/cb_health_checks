from __future__ import annotations

import ast
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any

import requests as _requests


BLOCK_ACTIONS = {"BLOCK", "DENY", "TERMINATE", "ISOLATE", "QUARANTINE"}
MONITOR_ACTIONS = {"ALLOW", "MONITOR", "REPORT", "ALERT", "LOG"}

REQUIRED_BLOCKING_CONTROLS: dict[str, dict[str, Any]] = {
    "known_malware": {
        "label": "Known malware",
        "tokens": ["known malware", "known_malware"],
    },
    "company_banned_list": {
        "label": "Application on company banned list",
        "tokens": ["company banned list", "company_banned", "banned list", "banned_list", "company_black_list"],
    },
    "unknown_application": {
        "label": "Unknown application/process",
        "tokens": ["unknown application", "unknown process", "resolving", "unknown_application"],
    },
    "adware_pup": {
        "label": "Adware/PUP",
        "tokens": ["adware", "pup", "potentially unwanted"],
    },
    "suspected_malware": {
        "label": "Suspected malware",
        "tokens": ["suspected malware", "suspected_malware", "suspect_malware"],
    },
    "not_listed_application": {
        "label": "Not listed application (adaptive whitelist)",
        "tokens": ["not listed", "adaptive_white_list", "adaptive whitelist", "not_listed"],
    },
}


def _to_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _to_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"true", "1", "yes", "enabled", "on"}:
            return True
        if v in {"false", "0", "no", "disabled", "off"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return None


def _pick_value(record: dict[str, Any], keys: list[str], default: Any = None) -> Any:
    for key in keys:
        if key in record and record.get(key) not in (None, ""):
            return record.get(key)
    return default


def _normalize_action(rule: dict[str, Any]) -> str:
    raw = _pick_value(rule, ["action", "operation", "rule_action", "policy_action"], None)
    op_raw = _pick_value(rule, ["operation", "op", "type"], "")

    # Core prevention rule configs often store mode in parameters instead of top-level action.
    if raw in (None, ""):
        params = rule.get("parameters")
        if isinstance(params, dict):
            raw = _pick_value(
                params,
                [
                    "WindowsAssignmentMode",
                    "LinuxAssignmentMode",
                    "MacAssignmentMode",
                    "assignment_mode",
                    "mode",
                ],
                "unknown",
            )

    action = str(raw).upper().strip()
    if action in {"REPORT", "DETECT", "MONITOR_ONLY", "ALERT_ONLY"}:
        return "MONITOR"
    if action in {"PREVENT", "ENFORCE", "BLOCK_AND_REPORT"}:
        return "BLOCK"
    # Some permission rules use action=IGNORE with operation=BYPASS_ALL.
    if "BYPASS" in str(op_raw).upper() or "BYPASS" in action:
        return "BYPASS"
    return action


def _extract_rule_text(rule: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ["name", "rule_name", "ruleName", "title", "description", "id", "type", "key", "config_name"]:
        value = rule.get(key)
        if value not in (None, ""):
            parts.append(str(value))

    params = rule.get("parameters")
    if isinstance(params, dict):
        for value in params.values():
            if value not in (None, ""):
                parts.append(str(value))

    return " ".join(parts).lower()


def _match_required_blocking_control(rule: dict[str, Any]) -> str | None:
    application = rule.get("application")
    if isinstance(application, dict):
        app_value = str(application.get("value", "")).strip().upper()
        if app_value == "KNOWN_MALWARE":
            return "known_malware"
        if app_value in {"COMPANY_BLACK_LIST", "COMPANY_BANNED_LIST"}:
            return "company_banned_list"
        if app_value == "RESOLVING":
            return "unknown_application"
        if app_value == "PUP":
            return "adware_pup"
        if app_value in {"SUSPECT_MALWARE", "SUSPECTED_MALWARE"}:
            return "suspected_malware"
        if app_value == "ADAPTIVE_WHITE_LIST":
            return "not_listed_application"

    haystack = _extract_rule_text(rule)
    if not haystack:
        return None

    for control_id, metadata in REQUIRED_BLOCKING_CONTROLS.items():
        tokens = metadata.get("tokens", [])
        if any(token in haystack for token in tokens):
            return control_id
    return None


def _normalize_status(device: dict[str, Any]) -> str:
    raw = _pick_value(device, ["status", "sensor_state", "state", "device_status"], "unknown")
    status = str(raw).strip().upper()

    if _to_bool(device.get("quarantined")) is True or "QUAR" in status:
        return "QUARANTINE"
    if _to_bool(device.get("bypass")) is True or "BYPASS" in status:
        return "BYPASS"
    if status == "REGISTERED":
        return "ACTIVE"
    if "INACTIVE" in status:
        return "INACTIVE"
    if "DEREG" in status:
        return "DEREGISTERED"
    if "ACTIVE" in status:
        return "ACTIVE"
    if status in {"UNKNOWN", ""}:
        return "UNKNOWN"
    return status


def _exclude_deregistered_devices(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [device for device in devices if _normalize_status(device) != "DEREGISTERED"]


def summarize_devices(devices: list[dict[str, Any]]) -> dict[str, Any]:
    counted_devices = _exclude_deregistered_devices(devices)
    total = len(counted_devices)
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    active_7d = 0
    os_counter: Counter[str] = Counter()

    for d in counted_devices:
        last_contact = _to_dt(_pick_value(d, ["last_contact_time", "last_contact", "last_seen_time"]))
        if last_contact and last_contact >= cutoff:
            active_7d += 1
        os_name = _pick_value(d, ["os", "os_version", "os_name"], "unknown")
        os_counter[str(os_name)] += 1

    active_ratio = (active_7d / total) if total else 0.0
    return {
        "total_devices": total,
        "active_last_7d": active_7d,
        "active_ratio_last_7d": round(active_ratio, 4),
        "os_breakdown": dict(os_counter.most_common(10)),
    }


def summarize_alerts(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(alerts)
    severity_counter: Counter[str] = Counter()
    type_counter: Counter[str] = Counter()

    for a in alerts:
        sev = str(_pick_value(a, ["severity", "threat_score", "impact_score"], "unknown"))
        atype = str(_pick_value(a, ["type", "category", "alert_type"], "unknown"))
        severity_counter[sev] += 1
        type_counter[atype] += 1

    high_sev = sum(count for key, count in severity_counter.items() if key.isdigit() and int(key) >= 7)
    return {
        "total_alerts_30d": total,
        "high_severity_alerts": high_sev,
        "severity_breakdown": dict(severity_counter),
        "type_breakdown": dict(type_counter.most_common(10)),
    }


def summarize_policy_posture(
    policies: list[dict[str, Any]],
    rules: list[dict[str, Any]],
    ngav_enabled: bool = True,
) -> dict[str, Any]:
    total_policies = len(policies)
    enabled_policies = 0
    inactive_policies = 0
    policy_type_counter: Counter[str] = Counter()

    for policy in policies:
        enabled_raw = _pick_value(policy, ["is_enabled", "enabled", "isEnabled"], True)
        if _to_bool(enabled_raw) is not False:
            enabled_policies += 1
        else:
            inactive_policies += 1
        ptype = str(_pick_value(policy, ["policy_type", "platform", "name"], "unknown"))
        policy_type_counter[ptype] += 1

    total_rules = len(rules)
    enabled_rules = 0
    blocking_rules = 0
    action_counter: Counter[str] = Counter()

    for rule in rules:
        enabled_raw = _pick_value(rule, ["is_enabled", "enabled", "isEnabled"], True)
        if _to_bool(enabled_raw) is not False:
            enabled_rules += 1

        action = _normalize_action(rule)
        action_counter[action] += 1
        # Standard policy rules with TERMINATE/DENY are NGAV reputation enforcement
        # rules. For EDR-only customers the sensor does not honour these actions, so
        # they must not be counted as blocking controls.
        if ngav_enabled and action in BLOCK_ACTIONS:
            blocking_rules += 1

    enabled_policy_ratio = (enabled_policies / total_policies) if total_policies else 0.0
    enabled_rule_ratio = (enabled_rules / total_rules) if total_rules else 0.0
    blocking_rule_ratio = (blocking_rules / total_rules) if total_rules else 0.0

    return {
        "total_policies": total_policies,
        "enabled_policies": enabled_policies,
        "inactive_policies": inactive_policies,
        "enabled_policy_ratio": round(enabled_policy_ratio, 4),
        "total_rules": total_rules,
        "enabled_rules": enabled_rules,
        "enabled_rule_ratio": round(enabled_rule_ratio, 4),
        "blocking_rules": blocking_rules,
        "blocking_rule_ratio": round(blocking_rule_ratio, 4),
        "ngav_enabled": ngav_enabled,
        "policy_type_breakdown": dict(policy_type_counter),
        "rule_action_breakdown": dict(action_counter.most_common(10)),
    }


def _watchlist_report_count(watchlist: dict[str, Any]) -> int | None:
    raw = _pick_value(watchlist, ["report_ids", "reportIds", "report_count", "reportCount"], None)
    if raw in (None, ""):
        return None
    if isinstance(raw, (int, float)):
        return max(int(raw), 0)
    if isinstance(raw, list):
        return len([item for item in raw if item not in (None, "")])
    if isinstance(raw, str):
        try:
            parsed = ast.literal_eval(raw)
        except Exception:
            return None
        if isinstance(parsed, list):
            return len([item for item in parsed if item not in (None, "")])
        if isinstance(parsed, (set, tuple)):
            return len([item for item in parsed if item not in (None, "")])
        if isinstance(parsed, dict):
            return len(parsed)
        if isinstance(parsed, (int, float)):
            return max(int(parsed), 0)
    return None


def summarize_watchlists(watchlists: list[dict[str, Any]]) -> dict[str, Any]:
    total_watchlists = len(watchlists)
    enabled_count = 0
    alerting_enabled_count = 0
    total_report_count = 0
    enabled_without_alerting_count = 0
    category_counter: Counter[str] = Counter()
    watchlist_details: list[dict[str, Any]] = []

    for wl in watchlists:
        enabled_raw = _pick_value(wl, ["enabled", "is_enabled", "isEnabled"], True)
        enabled = _to_bool(enabled_raw)
        if enabled is not False:
            enabled_count += 1

        report_count = _watchlist_report_count(wl)
        if report_count is not None:
            alerting_enabled = report_count > 0
        else:
            alerting_raw = _pick_value(
                wl,
                ["alerting_enabled", "alerts_enabled", "alertsEnabled", "report_only", "reportOnly"],
                None,
            )
            alerting_enabled = _to_bool(alerting_raw)
            if alerting_enabled is None:
                alerting_enabled = False

        if alerting_enabled:
            alerting_enabled_count += 1
        if (enabled is not False) and not alerting_enabled:
            enabled_without_alerting_count += 1

        if report_count is not None:
            total_report_count += report_count

        category = str(_pick_value(wl, ["category", "name"], "uncategorized"))
        category_counter[category] += 1

        watchlist_details.append(
            {
                "id": str(_pick_value(wl, ["id", "watchlist_id", "watchlistId"], "")).strip(),
                "name": str(_pick_value(wl, ["name", "title"], "unknown")).strip() or "unknown",
                "enabled": enabled if enabled is not None else True,
                "alerting_enabled": alerting_enabled,
                "report_count": report_count,
                "category": category,
            }
        )

    enabled_ratio = (enabled_count / total_watchlists) if total_watchlists else 0.0
    alerting_ratio = (alerting_enabled_count / total_watchlists) if total_watchlists else 0.0
    avg_reports = (total_report_count / total_watchlists) if total_watchlists else 0.0
    return {
        "total_watchlists": total_watchlists,
        "enabled_watchlists": enabled_count,
        "enabled_watchlist_ratio": round(enabled_ratio, 4),
        "alerting_enabled_watchlists": alerting_enabled_count,
        "alerting_enabled_watchlist_ratio": round(alerting_ratio, 4),
        "enabled_without_alerting_watchlists": enabled_without_alerting_count,
        "total_watchlist_reports": total_report_count,
        "average_report_count": round(avg_reports, 4),
        "report_only_watchlists": alerting_enabled_count,
        "category_breakdown": dict(category_counter.most_common(10)),
        "watchlist_details": watchlist_details,
    }


def extract_watchlists_from_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    dedup: dict[str, dict[str, Any]] = {}

    for alert in alerts:
        raw = alert.get("watchlists")
        parsed: list[dict[str, Any]] = []

        if isinstance(raw, list):
            parsed = [i for i in raw if isinstance(i, dict)]
        elif isinstance(raw, str) and raw.strip():
            try:
                candidate = ast.literal_eval(raw)
                if isinstance(candidate, list):
                    parsed = [i for i in candidate if isinstance(i, dict)]
            except Exception:
                parsed = []

        for item in parsed:
            wl_id = str(item.get("id", "")).strip()
            wl_name = str(item.get("name", "")).strip() or "unknown"
            key = wl_id or wl_name
            if not key:
                continue
            dedup[key] = {
                "id": wl_id,
                "name": wl_name,
                "enabled": True,
                "alerting_enabled": True,
                "report_count": None,
                "source": "alerts_fallback",
            }

    return list(dedup.values())


def summarize_policy_drift(current_policies: list[dict[str, Any]], previous_policies: list[dict[str, Any]]) -> dict[str, Any]:
    """Track meaningful policy settings drift: configuration and rule changes within existing policies."""

    def _coerce_structure(value: Any) -> Any:
        # Previous baselines are read from CSV and complex fields are serialized strings.
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return None

            lowered = raw.lower()
            if lowered in {"true", "false"}:
                return lowered == "true"

            if lowered in {"none", "null"}:
                return None

            if raw.isdigit() or (raw.startswith("-") and raw[1:].isdigit()):
                try:
                    return int(raw)
                except Exception:
                    pass

            if raw.startswith("{") or raw.startswith("["):
                try:
                    return ast.literal_eval(raw)
                except Exception:
                    return raw
            return raw
        return value

    def _canonicalize(value: Any) -> Any:
        value = _coerce_structure(value)
        if isinstance(value, dict):
            return {str(k): _canonicalize(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_canonicalize(v) for v in value]
        return value

    def _policy_profile(policy: dict[str, Any]) -> dict[str, Any]:
        # Compare stable, high-signal config fields and normalize CSV/API type differences.
        return _canonicalize({
            "name": policy.get("name"),
            "description": policy.get("description"),
            "enabled": _pick_value(policy, ["is_enabled", "enabled", "isEnabled"], True),
            "priority_level": policy.get("priority_level"),
            "position": policy.get("position"),
            "auto_delete_known_bad_hashes_delay": policy.get("auto_delete_known_bad_hashes_delay"),
            "auto_deregister_inactive_vdi_interval_ms": policy.get("auto_deregister_inactive_vdi_interval_ms"),
            "auto_deregister_inactive_vm_workloads_interval_ms": policy.get("auto_deregister_inactive_vm_workloads_interval_ms"),
            "av_settings": _coerce_structure(policy.get("av_settings")),
            "sensor_settings": _coerce_structure(policy.get("sensor_settings")),
            "sensor_configs": _coerce_structure(policy.get("sensor_configs")),
            "rule_configs": _coerce_structure(policy.get("rule_configs")),
        })

    def _policy_fingerprint(profile: dict[str, Any]) -> str:
        return json.dumps(profile, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    def _flatten(prefix: str, value: Any, out: dict[str, Any]) -> None:
        if isinstance(value, dict):
            for key in sorted(value.keys()):
                next_prefix = f"{prefix}.{key}" if prefix else str(key)
                _flatten(next_prefix, value[key], out)
            return
        if isinstance(value, list):
            for idx, item in enumerate(value):
                next_prefix = f"{prefix}[{idx}]"
                _flatten(next_prefix, item, out)
            return
        out[prefix] = value

    current_profiles = {
        str(_pick_value(p, ["id", "policy_id"], "")): _policy_profile(p)
        for p in current_policies
        if str(_pick_value(p, ["id", "policy_id"], "")).strip()
    }
    prev_profiles = {
        str(_pick_value(p, ["id", "policy_id"], "")): _policy_profile(p)
        for p in previous_policies
        if str(_pick_value(p, ["id", "policy_id"], "")).strip()
    }

    current_map = {pid: _policy_fingerprint(profile) for pid, profile in current_profiles.items()}
    prev_map = {pid: _policy_fingerprint(profile) for pid, profile in prev_profiles.items()}

    current_ids = set(current_map.keys())
    prev_ids = set(prev_map.keys())

    changed = sorted([pid for pid in current_ids.intersection(prev_ids) if current_map[pid] != prev_map[pid]])
    id_to_name = {
        str(_pick_value(p, ["id", "policy_id"], "")): str(p.get("name", "unknown"))
        for p in current_policies
        if str(_pick_value(p, ["id", "policy_id"], "")).strip()
    }
    changed_by_name = [id_to_name.get(pid, "unknown") for pid in changed]

    changed_details: list[dict[str, Any]] = []
    for pid in changed:
        prev_profile = prev_profiles.get(pid, {})
        current_profile = current_profiles.get(pid, {})

        prev_flat: dict[str, Any] = {}
        current_flat: dict[str, Any] = {}
        _flatten("", prev_profile, prev_flat)
        _flatten("", current_profile, current_flat)

        changed_paths = sorted(set(prev_flat.keys()).union(current_flat.keys()))
        field_changes: list[dict[str, Any]] = []
        for path in changed_paths:
            before = prev_flat.get(path)
            after = current_flat.get(path)
            if before != after:
                field_changes.append(
                    {
                        "field": path,
                        "before": before,
                        "after": after,
                    }
                )

        max_changes = 25
        changed_details.append(
            {
                "policy_id": pid,
                "policy_name": id_to_name.get(pid, "unknown"),
                "change_count": len(field_changes),
                "changes": field_changes[:max_changes],
                "truncated_changes": max(0, len(field_changes) - max_changes),
            }
        )

    return {
        "baseline_count": len(prev_ids),
        "current_count": len(current_ids),
        "changed_policy_ids": changed,
        "changed_policy_names": changed_by_name,
        "changed_policy_details": changed_details,
        "changed_count": len(changed),
        "drift_detected": bool(changed),
    }


def summarize_policy_settings(policies: list[dict[str, Any]], data_collection_configs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Audit policy configuration settings across all policies.

    Tracks per-policy sensor settings that control protection behavior.
    Settings come from two sources:
    1. Policy Service API sensor_settings field (list of name/value pairs) - per-policy settings
    2. Policy detail rule_configs entries for data collection controls like auth events and XDR

    Tenant-wide data_collection configs are retained only as supplemental metadata.
    """
    def _coerce_structure(value: Any) -> Any:
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return None

            lowered = raw.lower()
            if lowered in {"true", "false"}:
                return lowered == "true"

            if lowered in {"none", "null"}:
                return None

            if raw.isdigit() or (raw.startswith("-") and raw[1:].isdigit()):
                try:
                    return int(raw)
                except Exception:
                    pass

            if raw.startswith("{") or raw.startswith("["):
                try:
                    return ast.literal_eval(raw)
                except Exception:
                    return raw
            return raw
        return value

    def _normalize_rule_name(value: Any) -> str:
        return str(_coerce_structure(value) or "").strip().lower()

    # Map user-friendly names to uppercase setting names from the API (sensor_settings)
    setting_mapping = {
        "submit_unknown_binaries": ["UBS_OPT_IN"],
        "live_response_enabled": ["CB_LIVE_RESPONSE"],
        "delay_execute_for_cloud_scan": ["DELAY_EXECUTE"],
        "scan_execution_on_network_drive": ["SCAN_EXECUTE_ON_NETWORK_DRIVE"],
        "scan_network_drive": ["SCAN_NETWORK_DRIVE"],
        "uninstall_code_enabled": ["UNINSTALL_CODE"],
        "auth_event_collection": [],
        "xdr_network_data_collection": [],
        "windows_security_center": ["SECURITY_CENTER_OPT"],
    }

    rule_config_mapping = {
        "auth_event_collection": ("Authentication Events", "enable_auth_events"),
        "xdr_network_data_collection": ("XDR", "enable_network_data_collection"),
    }

    setting_rule_mapping: dict[str, tuple[str, str]] = {
        "submit_unknown_binaries": ("submit_unknown_binaries_enabled", "true"),
        "live_response_enabled": ("live_response_disabled", "false"),
        "delay_execute_for_cloud_scan": ("delay_execute_for_cloud_scan_disabled", "false"),
        "scan_execution_on_network_drive": ("scan_execution_on_network_drive_disabled", "false"),
        "scan_network_drive": ("scan_network_drive_enabled", "true"),
        "uninstall_code_enabled": ("uninstall_code_disabled", "false"),
        "auth_event_collection": ("auth_event_collection_disabled", "false"),
        "xdr_network_data_collection": ("xdr_network_data_collection_disabled", "false"),
        "windows_security_center": ("windows_security_center_disabled", "false"),
    }

    # Parse data collection configs to get tenant-wide settings.
    # These are not policy-scoped values and should never be counted once per policy.
    tenant_data_collection: dict[str, dict[str, Any]] = {
        "auth_event_collection": {"value": None, "source": "data_collection_configs_fallback"},
        "xdr_network_data_collection": {"value": None, "source": "data_collection_configs_fallback"},
    }

    if data_collection_configs:
        for rule in data_collection_configs:
            rule = _coerce_structure(rule)
            if not isinstance(rule, dict):
                continue

            name = rule.get("name", "")
            params = _coerce_structure(rule.get("parameters", {}))
            if not isinstance(params, dict):
                continue

            normalized_name = _normalize_rule_name(name)
            if "authentication events" in normalized_name:
                for key in ["enable_auth_events", "auth_event_collection"]:
                    if key in params:
                        tenant_data_collection["auth_event_collection"]["value"] = _to_bool(params.get(key))
                        break
            elif normalized_name == "xdr" or "xdr" in normalized_name or "network data collection" in normalized_name:
                for key in ["enable_network_data_collection", "network_data_collection", "xdr_network_data_collection"]:
                    if key in params:
                        tenant_data_collection["xdr_network_data_collection"]["value"] = _to_bool(params.get(key))
                        break

    per_setting: dict[str, dict[str, int]] = {}
    for _, (output_key, _) in setting_rule_mapping.items():
        per_setting[output_key] = {"true": 0, "false": 0, "unknown": 0}

    policy_details: list[dict[str, Any]] = []
    policies_with_sensor_settings = 0

    for policy in policies:
        policy_id = str(_pick_value(policy, ["id", "policy_id"], "unknown"))
        policy_name = str(policy.get("name", "unknown"))
        
        # Parse sensor_settings list into dict for easier lookup
        sensor_settings_list = policy.get("sensor_settings", [])
        sensor_settings_dict: dict[str, Any] = {}
        
        if isinstance(sensor_settings_list, list):
            policies_with_sensor_settings += 1
            for item in sensor_settings_list:
                if isinstance(item, dict):
                    name = item.get("name", "")
                    value = item.get("value", "")
                    sensor_settings_dict[name] = value

        rule_configs_list = _coerce_structure(policy.get("rule_configs", []))
        if not isinstance(rule_configs_list, list):
            rule_configs_list = _coerce_structure(policy.get("data_collection_configs", []))
        rule_config_flags: dict[str, bool | None] = {
            "auth_event_collection": None,
            "xdr_network_data_collection": None,
        }
        if isinstance(rule_configs_list, list):
            for item in rule_configs_list:
                item = _coerce_structure(item)
                if not isinstance(item, dict):
                    continue
                rule_name = str(item.get("name", ""))
                params = _coerce_structure(item.get("parameters", {}))
                if not isinstance(params, dict):
                    continue
                normalized_rule_name = _normalize_rule_name(rule_name)
                for setting_name, (expected_name, param_name) in rule_config_mapping.items():
                    if (
                        normalized_rule_name == expected_name.lower()
                        or expected_name.lower() in normalized_rule_name
                    ) and param_name in params:
                        rule_config_flags[setting_name] = _to_bool(params.get(param_name))

        settings_found = {}
        for setting_name, api_names in setting_mapping.items():
            raw = None

            if setting_name in rule_config_mapping:
                parsed = rule_config_flags.get(setting_name)
                if parsed is None:
                    parsed = tenant_data_collection.get(setting_name, {}).get("value")
            else:
                # Standard sensor_settings lookup
                for api_name in api_names:
                    if api_name in sensor_settings_dict:
                        raw = sensor_settings_dict[api_name]
                        break
                parsed = _to_bool(raw)

            output_key, monitored_state = setting_rule_mapping[setting_name]
            if parsed is None:
                per_setting[output_key]["unknown"] += 1
                continue

            if monitored_state == "true":
                monitored_value = bool(parsed)
            else:
                monitored_value = not bool(parsed)

            if monitored_value:
                per_setting[output_key]["true"] += 1
            else:
                per_setting[output_key]["false"] += 1

            settings_found[output_key] = monitored_value

        policy_details.append(
            {
                "policy_id": policy_id,
                "policy_name": policy_name,
                "settings_found": settings_found,
            }
        )

    settings_with_unknowns = sorted([name for name, counts in per_setting.items() if counts["unknown"] > 0])
    settings_of_concern: dict[str, int] = {}
    for _, (output_key, _) in setting_rule_mapping.items():
        counts = per_setting.get(output_key, {"true": 0})
        settings_of_concern[output_key] = int(counts.get("true", 0))

    return {
        "total_policies": len(policies),
        "policies_with_sensor_settings": policies_with_sensor_settings,
        "settings": per_setting,
        "settings_of_concern": settings_of_concern,
        "tenant_data_collection": tenant_data_collection,
        "settings_with_unknowns": settings_with_unknowns,
        "policy_details_sample": policy_details[:10],
    }


def summarize_core_prevention_settings(
    core_prevention_rules: list[dict[str, Any]],
    policy_rules_for_required_controls: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    by_category: dict[str, dict[str, int]] = defaultdict(lambda: {"monitor": 0, "block": 0, "unknown": 0})
    by_policy: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "policy_name": "unknown",
            "monitor": 0,
            "block": 0,
            "unknown": 0,
            "categories": set(),
            "required_controls": {},
        }
    )

    for rule in core_prevention_rules:
        category = str(_pick_value(rule, ["category", "type", "name"], "uncategorized"))
        policy_id = str(_pick_value(rule, ["policy_id", "policyId"], "unknown"))
        policy_name = str(_pick_value(rule, ["policy_name", "policyName"], "unknown"))
        action = _normalize_action(rule)

        policy_bucket = by_policy[policy_id]
        if policy_name:
            policy_bucket["policy_name"] = policy_name
        policy_bucket["categories"].add(category)

        if action in BLOCK_ACTIONS:
            by_category[category]["block"] += 1
            policy_bucket["block"] += 1
        elif action in MONITOR_ACTIONS:
            by_category[category]["monitor"] += 1
            policy_bucket["monitor"] += 1
        else:
            by_category[category]["unknown"] += 1
            policy_bucket["unknown"] += 1

    required_control_rules = policy_rules_for_required_controls if policy_rules_for_required_controls is not None else core_prevention_rules
    for rule in required_control_rules:
        matched_control = _match_required_blocking_control(rule)
        if not matched_control:
            continue

        policy_id = str(_pick_value(rule, ["policy_id", "policyId"], "unknown"))
        policy_name = str(_pick_value(rule, ["policy_name", "policyName"], "unknown"))
        policy_bucket = by_policy[policy_id]
        if policy_name:
            policy_bucket["policy_name"] = policy_name

        action = _normalize_action(rule)
        if action in BLOCK_ACTIONS:
            policy_bucket["required_controls"][matched_control] = "block"
        elif action in MONITOR_ACTIONS:
            if policy_bucket["required_controls"].get(matched_control) != "block":
                policy_bucket["required_controls"][matched_control] = "monitor"
        else:
            if matched_control not in policy_bucket["required_controls"]:
                policy_bucket["required_controls"][matched_control] = "unknown"

    alert_only_categories: list[str] = []
    for category, counts in by_category.items():
        if counts["monitor"] > 0 and counts["block"] == 0:
            alert_only_categories.append(category)

    alert_only_policies: list[dict[str, Any]] = []
    fully_alert_only_policies: list[dict[str, Any]] = []
    policies_with_missing_required_controls: list[dict[str, Any]] = []
    policies_with_enforcement_gaps: list[dict[str, Any]] = []
    policy_mode_breakdown: list[dict[str, Any]] = []
    for policy_id, counts in by_policy.items():
        total = counts["monitor"] + counts["block"] + counts["unknown"]
        required_controls = counts.get("required_controls", {})
        missing_required = [
            metadata["label"]
            for control_id, metadata in REQUIRED_BLOCKING_CONTROLS.items()
            if required_controls.get(control_id) != "block"
        ]
        row = {
            "policy_id": policy_id,
            "policy_name": counts["policy_name"],
            "monitor_rules": counts["monitor"],
            "block_rules": counts["block"],
            "unknown_rules": counts["unknown"],
            "monitor_ratio": round((counts["monitor"] / total), 4) if total else 0.0,
            "categories": sorted(counts["categories"]),
            "missing_required_controls": missing_required,
            "missing_required_controls_count": len(missing_required),
        }
        policy_mode_breakdown.append(row)
        if counts["monitor"] > 0:
            alert_only_policies.append(row)
        if counts["monitor"] > 0 and counts["block"] == 0:
            fully_alert_only_policies.append(row)
        if missing_required:
            policies_with_missing_required_controls.append(row)
        if counts["monitor"] > 0 or missing_required:
            policies_with_enforcement_gaps.append(row)

    policy_mode_breakdown.sort(
        key=lambda r: (r["missing_required_controls_count"], r["monitor_ratio"], r["monitor_rules"]),
        reverse=True,
    )
    alert_only_policies.sort(
        key=lambda r: (r["missing_required_controls_count"], r["monitor_rules"], r["policy_name"]),
        reverse=True,
    )
    fully_alert_only_policies.sort(
        key=lambda r: (r["missing_required_controls_count"], r["monitor_rules"], r["policy_name"]),
        reverse=True,
    )
    policies_with_missing_required_controls.sort(
        key=lambda r: (r["missing_required_controls_count"], r["policy_name"]),
        reverse=True,
    )
    policies_with_enforcement_gaps.sort(
        key=lambda r: (r["missing_required_controls_count"], r["monitor_rules"], r["policy_name"]),
        reverse=True,
    )

    return {
        "total_categories": len(by_category),
        "alert_only_categories": sorted(alert_only_categories),
        "total_policies": len(policy_mode_breakdown),
        "required_blocking_controls": [metadata["label"] for metadata in REQUIRED_BLOCKING_CONTROLS.values()],
        "alert_only_policies": alert_only_policies,
        "fully_alert_only_policies": fully_alert_only_policies,
        "policies_with_missing_required_controls": policies_with_missing_required_controls,
        "policies_with_enforcement_gaps": policies_with_enforcement_gaps,
        "policy_mode_breakdown": policy_mode_breakdown,
        "category_mode_breakdown": dict(by_category),
    }


def summarize_alert_workflow(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts: Counter[str] = Counter()
    closure_hours: list[float] = []
    open_age_hours: list[float] = []
    now = datetime.now(timezone.utc)

    for alert in alerts:
        # v7 API nests workflow info under the "workflow" key
        wf = alert.get("workflow") or {}
        status = str(wf.get("status") or _pick_value(alert, ["workflow_status", "status", "state"], "unknown")).lower()
        status_counts[status] += 1

        created = _to_dt(_pick_value(alert, ["backend_timestamp", "first_event_timestamp", "create_time", "first_event_time"]))
        # v7 closure time lives at workflow.change_timestamp
        closed = _to_dt(wf.get("change_timestamp") or _pick_value(alert, ["workflow_changed_timestamp", "closure_time", "last_update_time"]))

        if status in {"closed", "resolved", "dismissed"} and created and closed and closed >= created:
            closure_hours.append((closed - created).total_seconds() / 3600)
        elif status in {"open", "in_progress", "in progress", "new", "unknown"} and created:
            open_age_hours.append((now - created).total_seconds() / 3600)

    avg_close = round(sum(closure_hours) / len(closure_hours), 2) if closure_hours else None
    med_close = round(float(median(closure_hours)), 2) if closure_hours else None

    return {
        "status_counts": dict(status_counts),
        "closed_alerts": len(closure_hours),
        "avg_time_to_close_hours": avg_close,
        "median_time_to_close_hours": med_close,
        "open_alerts_over_72h": sum(1 for h in open_age_hours if h >= 72),
    }


def _build_enriched_ip_list(ip_counter: Counter[str], top_n: int = 10) -> list[dict[str, Any]]:
    top = ip_counter.most_common(top_n)
    ips = [ip for ip, _ in top if ip != "unknown"]
    info = _enrich_ips(ips)
    result = []
    for ip, count in top:
        entry: dict[str, Any] = {"ip": ip, "session_count": count}
        if ip in info:
            meta = info[ip]
            entry["hostname"] = meta.get("hostname")
            entry["org"] = meta.get("org")
            entry["country"] = meta.get("country")
        result.append(entry)
    return result


def _enrich_ips(ips: list[str]) -> dict[str, dict[str, str | None]]:
    """Enrich a list of IPs via ip-api.com batch (free, no key). Falls back silently."""
    result: dict[str, dict[str, str | None]] = {}
    if not ips:
        return result
    try:
        payload = [{"query": ip, "fields": "status,query,country,org,hostname"} for ip in ips]
        resp = _requests.post("http://ip-api.com/batch", json=payload, timeout=10)
        resp.raise_for_status()
        for entry in resp.json():
            q = entry.get("query", "")
            if entry.get("status") == "success":
                result[q] = {
                    "hostname": entry.get("hostname") or None,
                    "org": entry.get("org") or None,
                    "country": entry.get("country") or None,
                }
            else:
                result[q] = {"hostname": None, "org": None, "country": None}
    except Exception:  # noqa: BLE001
        for ip in ips:
            result.setdefault(ip, {"hostname": None, "org": None, "country": None})
    return result


def summarize_api_connector_use(
    audit_logs: list[dict[str, Any]],
) -> dict[str, Any]:
    connector_sessions: Counter[str] = Counter()
    ip_counter: Counter[str] = Counter()
    connector_events: list[dict[str, Any]] = []

    for event in audit_logs:
        description = str(event.get("description", ""))
        # Only count entries that represent connector authentication sessions
        if "Connector" not in description and "connector" not in description:
            continue

        connector_id = str(_pick_value(event, ["actor", "api_key_id", "access_key", "principal"], "unknown")).strip()
        connector_sessions[connector_id] += 1

        # Audit log v1 uses actor_ip, not ip_address/source_ip
        ip = str(_pick_value(event, ["actor_ip", "ip_address", "source_ip", "client_ip"], "unknown")).strip()
        if ip:
            ip_counter[ip] += 1

        connector_events.append({
            "connector_id": connector_id,
            "description": description,
            "actor_ip": ip,
            "create_time": event.get("create_time", ""),
        })

    dormant_entities: list[str] = []

    return {
        "total_audit_events": len(audit_logs),
        "connector_session_events": len(connector_events),
        "active_connectors": [
            {"connector_id": cid, "session_count": count}
            for cid, count in connector_sessions.most_common()
            if cid != "unknown"
        ],
        "active_connector_count": len([k for k in connector_sessions if k != "unknown"]),
        "unique_source_ips": len(ip_counter),
        "top_source_ips": _build_enriched_ip_list(ip_counter),
        "dormant_integrations": dormant_entities[:50],
        "dormant_integration_count": len(dormant_entities),
    }


def summarize_permissions_rule_audit(policy_rules: list[dict[str, Any]]) -> dict[str, Any]:
    broad_rules = 0
    disabled_rules = 0
    sample_broad_rules: list[dict[str, Any]] = []
    bypass_rules = 0
    bypass_path_pattern_rules = 0

    p1_by_policy: dict[str, dict[str, Any]] = {}
    p2_by_policy: dict[str, dict[str, Any]] = {}

    def _coerce_text_values(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            v = value.strip()
            if not v:
                return []
            # Some API payloads serialize selector objects as Python-literal strings.
            if v.startswith("{") or v.startswith("["):
                try:
                    parsed = ast.literal_eval(v)
                except Exception:
                    return [v]
                return _coerce_text_values(parsed)
            return [v]
        if isinstance(value, dict):
            out: list[str] = []
            for key in ["value", "path", "target", "process", "selector", "name"]:
                if key in value:
                    out.extend(_coerce_text_values(value.get(key)))
            return out
        if isinstance(value, list):
            out: list[str] = []
            for item in value:
                out.extend(_coerce_text_values(item))
            return out
        return [str(value)]

    def _candidate_paths(rule: dict[str, Any]) -> list[str]:
        candidates: list[str] = []
        for key in ["path", "process", "target", "selector", "application", "file", "expression"]:
            if key in rule:
                candidates.extend(_coerce_text_values(rule.get(key)))

        conditions = rule.get("conditions")
        candidates.extend(_coerce_text_values(conditions))

        # Keep order stable while deduplicating.
        deduped: list[str] = []
        seen: set[str] = set()
        for item in candidates:
            normalized = item.strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                deduped.append(normalized)
        return deduped

    for rule in policy_rules:
        enabled = _to_bool(_pick_value(rule, ["is_enabled", "enabled", "isEnabled"], True))
        if enabled is False:
            disabled_rules += 1

        values_to_scan = [
            str(_pick_value(rule, ["path", "process", "target", "selector"], "")),
            str(_pick_value(rule, ["name", "description"], "")),
        ]
        is_broad = any("*" in val or "any" in val.lower() for val in values_to_scan if val)
        if is_broad:
            broad_rules += 1
            if len(sample_broad_rules) < 20:
                sample_broad_rules.append(
                    {
                        "policy_id": str(_pick_value(rule, ["policy_id"], "")),
                        "rule_id": str(_pick_value(rule, ["id", "rule_id"], "")),
                        "name": str(_pick_value(rule, ["name", "description"], "")),
                        "action": _normalize_action(rule),
                    }
                )

        action = _normalize_action(rule)
        if action == "BYPASS":
            bypass_rules += 1

            matched_paths: list[str] = []
            has_p1 = False
            has_p2 = False

            for path in _candidate_paths(rule):
                leading = path.startswith("**")
                trailing = path.endswith("**")
                if not (leading or trailing):
                    continue

                bypass_path_pattern_rules += 1
                matched_paths.append(path)
                if leading and trailing:
                    has_p1 = True
                else:
                    has_p2 = True

            if has_p1 or has_p2:
                policy_id = str(_pick_value(rule, ["policy_id"], "unknown"))
                policy_name = str(_pick_value(rule, ["policy_name", "policy", "policy_display_name"], "unknown"))
                record = {
                    "policy_id": policy_id,
                    "policy_name": policy_name,
                    "rule_id": str(_pick_value(rule, ["id", "rule_id"], "")),
                    "sample_paths": matched_paths[:3],
                }

                if has_p1:
                    p1_by_policy.setdefault(policy_id, record)
                if has_p2:
                    p2_by_policy.setdefault(policy_id, record)

    return {
        "total_rules": len(policy_rules),
        "disabled_rules": disabled_rules,
        "broad_scope_rules": broad_rules,
        "sample_broad_scope_rules": sample_broad_rules,
        "bypass_rules": bypass_rules,
        "bypass_rules_with_leading_or_trailing_double_star": bypass_path_pattern_rules,
        "p1_policies": sorted(p1_by_policy.values(), key=lambda p: p.get("policy_name", "")),
        "p1_policy_count": len(p1_by_policy),
        "p2_policies": sorted(p2_by_policy.values(), key=lambda p: p.get("policy_name", "")),
        "p2_policy_count": len(p2_by_policy),
    }


def summarize_banned_hashes(reputation_overrides: list[dict[str, Any]]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    old_overrides: list[dict[str, Any]] = []
    banned_hash_overrides: list[dict[str, Any]] = []

    for item in reputation_overrides:
        override_list = str(_pick_value(item, ["override_list", "list_type"], "")).upper().strip()
        override_type = str(_pick_value(item, ["override_type", "type"], "")).upper().strip()
        hash_value = str(_pick_value(item, ["sha256_hash", "sha256", "md5", "hash"], "")).strip()

        is_blacklist = override_list in {"BLACK_LIST", "BLACKLIST", "DENY_LIST"}
        is_hash_override = override_type in {"SHA256", "MD5", "HASH"} and hash_value != ""
        if not (is_blacklist and is_hash_override):
            continue

        banned_hash_overrides.append(item)

        created = _to_dt(_pick_value(item, ["create_time", "created_at", "last_update_time"]))
        if not created:
            continue

        age_days = int((now - created).total_seconds() // 86400)
        if age_days >= 365:
            old_overrides.append(
                {
                    "hash": hash_value,
                    "age_days": age_days,
                    "reason": str(_pick_value(item, ["description", "comment"], "")),
                }
            )

    old_overrides.sort(key=lambda i: i["age_days"], reverse=True)
    return {
        "total_overrides": len(banned_hash_overrides),
        "older_than_365d": len(old_overrides),
        "sample_older_than_365d": old_overrides[:50],
    }


def summarize_endpoint_status(devices: list[dict[str, Any]]) -> dict[str, Any]:
    counted_devices = _exclude_deregistered_devices(devices)
    status_counts: Counter[str] = Counter()

    for device in counted_devices:
        status_counts[_normalize_status(device)] += 1

    non_active_total = sum(count for status, count in status_counts.items() if status != "ACTIVE")
    return {
        "status_counts": dict(status_counts),
        "non_active_total": non_active_total,
        "total_devices": len(counted_devices),
    }


def summarize_daily_alert_trends(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    daily_counts: Counter[str] = Counter()
    score_buckets: Counter[str] = Counter()

    for alert in alerts:
        ts = _to_dt(_pick_value(alert, ["backend_timestamp", "create_time", "first_event_time"]))
        if ts:
            daily_counts[ts.date().isoformat()] += 1

        sev_raw = _pick_value(alert, ["threat_score", "severity", "impact_score"], 0)
        try:
            sev = float(sev_raw)
        except Exception:
            sev = 0.0

        if sev >= 7:
            score_buckets["high(7-10)"] += 1
        elif sev >= 4:
            score_buckets["medium(4-6)"] += 1
        else:
            score_buckets["low(0-3)"] += 1

    ordered_daily = sorted(daily_counts.items(), key=lambda kv: kv[0])
    volumes = [count for _, count in ordered_daily]
    avg_daily = (sum(volumes) / len(volumes)) if volumes else 0.0

    spikes = [day for day, count in ordered_daily if avg_daily > 0 and count >= (avg_daily * 2.0)]
    dips = [day for day, count in ordered_daily if avg_daily > 0 and count <= (avg_daily * 0.5)]

    return {
        "daily_alert_counts": dict(ordered_daily),
        "avg_daily_alerts": round(avg_daily, 2),
        "spike_days": spikes,
        "dip_days": dips,
        "threat_score_distribution": dict(score_buckets),
    }


def summarize_user_logins(audit_logs: list[dict[str, Any]]) -> dict[str, Any]:
    return summarize_user_logins_with_users(audit_logs, [])


def summarize_user_logins_with_users(audit_logs: list[dict[str, Any]], users: list[dict[str, Any]]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    last_login_by_user: dict[str, datetime] = {}
    last_login_ip_by_user: dict[str, str] = {}
    login_count_by_user: Counter[str] = Counter()
    ips_by_user: dict[str, set[str]] = defaultdict(set)

    email_login_pattern = re.compile(r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\s+logged in successfully", re.IGNORECASE)

    for event in audit_logs:
        event_type = str(_pick_value(event, ["event_type", "type", "action"], "")).lower()
        description = str(_pick_value(event, ["description", "message", "details"], ""))
        description_lower = description.lower()
        is_login = any(token in event_type for token in ["login", "signin", "authenticate"]) or "logged in successfully" in description_lower
        if not is_login:
            continue

        user = str(_pick_value(event, ["username", "user", "actor", "principal"], "unknown"))
        match = email_login_pattern.search(description)
        if match:
            user = match.group(1)

        event_time = _to_dt(_pick_value(event, ["timestamp", "create_time", "event_time", "time"]))
        ip = str(_pick_value(event, ["actor_ip", "ip_address", "source_ip", "client_ip"], "unknown")).strip()
        if user == "unknown" or not event_time:
            continue

        login_count_by_user[user] += 1
        if ip and ip != "unknown":
            ips_by_user[user].add(ip)

        existing = last_login_by_user.get(user)
        if existing is None or event_time > existing:
            last_login_by_user[user] = event_time
            if ip and ip != "unknown":
                last_login_ip_by_user[user] = ip

    known_users: set[str] = set()
    for user in users:
        known_user = str(_pick_value(user, ["email", "username", "user_name", "login", "name"], "")).strip()
        if known_user:
            known_users.add(known_user)

    users_to_evaluate = known_users if known_users else set(last_login_by_user.keys())

    dormant_7 = []
    dormant_30 = []
    dormant_60 = []
    never_logged_in = []
    for user in users_to_evaluate:
        ts = last_login_by_user.get(user)
        if ts is None:
            never_logged_in.append(user)
            dormant_7.append(user)
            dormant_30.append(user)
            dormant_60.append(user)
            continue
        age_days = (now - ts).days
        if age_days >= 7:
            dormant_7.append(user)
        if age_days >= 30:
            dormant_30.append(user)
        if age_days >= 60:
            dormant_60.append(user)

    user_login_details = []
    for user in sorted(last_login_by_user.keys()):
        user_login_details.append(
            {
                "user": user,
                "last_login": last_login_by_user[user].isoformat(),
                "last_login_ip": last_login_ip_by_user.get(user, "unknown"),
                "login_count": int(login_count_by_user.get(user, 0)),
                "source_ips": sorted(ips_by_user.get(user, set())),
            }
        )

    return {
        "total_users": len(users_to_evaluate),
        "users_with_login_events": len(last_login_by_user),
        "users_without_login_events": sorted(never_logged_in),
        "users_without_login_events_count": len(never_logged_in),
        "user_login_details": user_login_details,
        "dormant_over_7d": sorted(dormant_7),
        "dormant_over_30d": sorted(dormant_30),
        "dormant_over_60d": sorted(dormant_60),
        "dormant_over_7d_count": len(dormant_7),
        "dormant_over_30d_count": len(dormant_30),
        "dormant_over_60d_count": len(dormant_60),
    }


def summarize_sensor_coverage_quality(devices: list[dict[str, Any]]) -> dict[str, Any]:
    counted_devices = _exclude_deregistered_devices(devices)
    now = datetime.now(timezone.utc)
    stale_sensors = 0
    version_counts: Counter[str] = Counter()
    stale_version_counts: Counter[str] = Counter()
    version_counts_by_os: dict[str, Counter[str]] = defaultdict(Counter)
    stale_version_counts_by_os: dict[str, Counter[str]] = defaultdict(Counter)

    for device in counted_devices:
        os_name = str(_pick_value(device, ["os", "os_name", "platform"], "unknown")).strip().upper() or "UNKNOWN"
        sensor_version = str(_pick_value(device, ["sensor_version", "agent_version", "version"], "unknown")).strip() or "unknown"
        version_counts[sensor_version] += 1
        version_counts_by_os[os_name][sensor_version] += 1

        last_contact = _to_dt(_pick_value(device, ["last_contact_time", "last_contact", "last_seen_time"]))
        if not last_contact or (now - last_contact) >= timedelta(days=7):
            stale_sensors += 1
            stale_version_counts[sensor_version] += 1
            stale_version_counts_by_os[os_name][sensor_version] += 1

    sensor_version_breakdown_by_os = {
        os_name: dict(version_counter.most_common())
        for os_name, version_counter in sorted(version_counts_by_os.items(), key=lambda item: item[0])
    }
    stale_sensor_version_breakdown_by_os = {
        os_name: dict(version_counter.most_common())
        for os_name, version_counter in sorted(stale_version_counts_by_os.items(), key=lambda item: item[0])
    }

    return {
        "total_devices": len(counted_devices),
        "stale_sensors_over_7d": stale_sensors,
        "sensor_version_breakdown": dict(version_counts.most_common()),
        "stale_sensor_version_breakdown": dict(stale_version_counts.most_common()),
        "sensor_version_breakdown_by_os": sensor_version_breakdown_by_os,
        "stale_sensor_version_breakdown_by_os": stale_sensor_version_breakdown_by_os,
    }


def summarize_alert_quality(alerts: list[dict[str, Any]], num_found: int = 0) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    noisy = 0
    low_severity_count = 0
    unresolved_aging: Counter[str] = Counter()
    repeated_counter: Counter[str] = Counter()
    disposition_counts: dict[str, int] = {
        "False Positive": 0,
        "True Positive": 0,
        "None": 0,
    }

    for alert in alerts:
        workflow = str(_pick_value(alert, ["workflow_status", "status", "state"], "unknown")).lower()
        determination = str(_pick_value(alert, ["determination", "reason", "closure_reason"], "")).lower()

        if not determination or determination in {"none", "unknown", "n/a", "na", "null"}:
            disposition_counts["None"] += 1
        elif any(token in determination for token in ["false", "benign", "duplicate"]):
            disposition_counts["False Positive"] += 1
        elif any(token in determination for token in ["true", "malicious", "threat"]):
            disposition_counts["True Positive"] += 1
        else:
            disposition_counts["None"] += 1

        if any(token in determination for token in ["benign", "false", "duplicate"]) or "duplicate" in workflow:
            noisy += 1

        sev_raw = _pick_value(alert, ["threat_score", "severity", "impact_score"], 0)
        try:
            sev = float(sev_raw)
        except Exception:
            sev = 0.0
        if sev < 5:
            low_severity_count += 1

        if workflow not in {"closed", "resolved", "dismissed"}:
            created = _to_dt(_pick_value(alert, ["backend_timestamp", "create_time", "first_event_time"]))
            if created:
                age_days = (now - created).days
                if age_days >= 30:
                    unresolved_aging["30+d"] += 1
                elif age_days >= 7:
                    unresolved_aging["7-29d"] += 1
                else:
                    unresolved_aging["0-6d"] += 1

        repeat_key = str(_pick_value(alert, ["threat_id", "rule_id", "ioc", "process_hash", "name"], "")).strip()
        if repeat_key:
            repeated_counter[repeat_key] += 1

    repeated_detections = sum(1 for _, count in repeated_counter.items() if count >= 3)
    total_alerts = len(alerts)
    low_severity_ratio = (low_severity_count / total_alerts) if total_alerts else 0.0

    # High-volume streams with mostly low-severity alerts create operational noise even
    # when explicit benign/false-positive determinations are sparse.
    weighted_noisy = noisy
    if total_alerts >= 1000 and low_severity_ratio >= 0.6:
        weighted_noisy = max(weighted_noisy, int(low_severity_count * 0.8))

    sample_noise_ratio = (weighted_noisy / total_alerts) if total_alerts else 0.0

    # When the collection cap was hit (num_found > sampled), the fraction of alerts that
    # were never reachable is itself a noise floor: if only 0.001% of all alerts could be
    # examined, the remaining 99.999% were never actioned and are operationally noise.
    cap_hit = num_found > total_alerts
    if cap_hit and num_found > 0:
        volume_noise_floor = 1.0 - (total_alerts / num_found)
        noise_ratio = max(sample_noise_ratio, volume_noise_floor)
    else:
        noise_ratio = sample_noise_ratio

    # 10k alerts/day is operationally unmanageable — score it as 100% noise.
    # Scale linearly so that daily volume is an independent noise floor regardless of
    # severity distribution or whether the collection cap was hit.
    # 180-day window is hardcoded to match the API query time_range.
    _ALERT_WINDOW_DAYS = 180
    _HIGH_VOLUME_DAILY_THRESHOLD = 10_000
    if num_found > 0:
        avg_daily_from_api = num_found / _ALERT_WINDOW_DAYS
        daily_volume_noise_floor = min(1.0, avg_daily_from_api / _HIGH_VOLUME_DAILY_THRESHOLD)
        noise_ratio = max(noise_ratio, daily_volume_noise_floor)

    return {
        "total_alerts": total_alerts,
        "total_alerts_in_api": num_found if num_found > 0 else total_alerts,
        "cap_hit": cap_hit,
        "noise_ratio": round(noise_ratio, 4),
        "sample_noise_ratio": round(sample_noise_ratio, 4),
        "low_severity_alerts_lt5": low_severity_count,
        "low_severity_ratio_lt5": round(low_severity_ratio, 4),
        "repeated_detection_keys_over_3": repeated_detections,
        "disposition_breakdown": disposition_counts,
        "unresolved_aging_buckets": dict(unresolved_aging),
    }


def summarize_policy_efficacy(
    policies: list[dict[str, Any]],
    policy_rules: list[dict[str, Any]],
    core_prevention_rules: list[dict[str, Any]] | None,
    alerts: list[dict[str, Any]],
) -> dict[str, Any]:
    efficacy_monitor_actions = MONITOR_ACTIONS - {"ALLOW"}

    policy_name_by_id = {
        str(_pick_value(policy, ["id", "policy_id"], "")): str(_pick_value(policy, ["name"], "unknown"))
        for policy in policies
    }

    by_policy: dict[str, dict[str, int]] = defaultdict(lambda: {"monitor": 0, "block": 0, "unknown": 0})
    for rule in policy_rules:
        pid = str(_pick_value(rule, ["policy_id", "policyId"], "unknown"))
        action = _normalize_action(rule)
        if action in BLOCK_ACTIONS:
            by_policy[pid]["block"] += 1
        elif action in efficacy_monitor_actions:
            by_policy[pid]["monitor"] += 1
        else:
            by_policy[pid]["unknown"] += 1

    for rule in core_prevention_rules or []:
        pid = str(_pick_value(rule, ["policy_id", "policyId"], "unknown"))
        action = _normalize_action(rule)
        if action in BLOCK_ACTIONS:
            by_policy[pid]["block"] += 1
        elif action == "MONITOR":
            by_policy[pid]["monitor"] += 1
        else:
            by_policy[pid]["unknown"] += 1

    alert_volume_by_policy: Counter[str] = Counter()
    for alert in alerts:
        pid = str(_pick_value(alert, ["policy_id", "policyId", "policy_applied"], ""))
        if pid:
            alert_volume_by_policy[pid] += 1

    monitor_heavy: list[dict[str, Any]] = []
    efficacy_rows: list[dict[str, Any]] = []

    for pid, counts in by_policy.items():
        total = counts["monitor"] + counts["block"] + counts["unknown"]
        monitor_ratio = (counts["monitor"] / total) if total else 0.0
        row = {
            "policy_id": pid,
            "policy_name": policy_name_by_id.get(pid, "unknown"),
            "monitor_rules": counts["monitor"],
            "block_rules": counts["block"],
            "unknown_rules": counts["unknown"],
            "monitor_ratio": round(monitor_ratio, 4),
            "alerts_30d": int(alert_volume_by_policy.get(pid, 0)),
        }
        efficacy_rows.append(row)
        if counts["monitor"] > 0 and counts["block"] == 0:
            monitor_heavy.append(row)

    efficacy_rows.sort(key=lambda r: (r["monitor_ratio"], r["alerts_30d"]), reverse=True)

    return {
        "total_policy_groups": len(efficacy_rows),
        "monitor_heavy_policy_groups": monitor_heavy,
        "policy_group_breakdown": efficacy_rows,
    }


def health_score(
    device_summary: dict[str, Any],
    alert_summary: dict[str, Any],
    policy_summary: dict[str, Any] | None = None,
    watchlist_summary: dict[str, Any] | None = None,
    assessment_profile: str = "prod",
) -> dict[str, Any]:
    score = 100
    notes: list[str] = []

    is_lab = assessment_profile == "lab"

    active_ratio = float(device_summary.get("active_ratio_last_7d", 0.0))
    if active_ratio < 0.6:
        score -= 15 if is_lab else 35
        notes.append("Low sensor activity ratio in the last 7 days")
    elif active_ratio < 0.8:
        score -= 8 if is_lab else 20
        notes.append("Moderate sensor activity ratio in the last 7 days")

    high_sev = int(alert_summary.get("high_severity_alerts", 0))
    if not is_lab:
        if high_sev > 200:
            score -= 30
            notes.append("Very high count of severity 7+ alerts")
        elif high_sev > 50:
            score -= 15
            notes.append("Elevated count of severity 7+ alerts")
    else:
        notes.append("Lab profile active: high-severity alert volume penalties reduced")

    if policy_summary is not None:
        enabled_policy_ratio = float(policy_summary.get("enabled_policy_ratio", 0.0))
        if enabled_policy_ratio < 0.7:
            score -= 20
            notes.append("Large number of inactive policies")

        total_rules = int(policy_summary.get("total_rules", 0))
        if total_rules == 0:
            score -= 20
            notes.append("No policy rules were detected")
        elif policy_summary.get("ngav_enabled", True):
            blocking_ratio = float(policy_summary.get("blocking_rule_ratio", 0.0))
            if blocking_ratio < 0.1:
                score -= 15
                notes.append("Low proportion of blocking enforcement rules")

    if watchlist_summary is not None:
        wl_count = int(watchlist_summary.get("total_watchlists", 0))
        wl_enabled_ratio = float(watchlist_summary.get("enabled_watchlist_ratio", 0.0))
        if wl_count == 0:
            score -= 5 if is_lab else 15
            notes.append("No watchlists were detected")
        elif wl_enabled_ratio < 0.8:
            score -= 4 if is_lab else 10
            notes.append("Low proportion of enabled watchlists")

    if score >= 85:
        status = "good"
    elif score >= 65:
        status = "watch"
    else:
        status = "at_risk"

    return {
        "score": max(score, 0),
        "status": status,
        "notes": notes,
        "assessment_profile": assessment_profile,
    }


def prioritized_recommendations(summary: dict[str, Any]) -> list[dict[str, str]]:
    recs: list[dict[str, str]] = []
    checks = summary.get("checks", {})
    profile = summary.get("assessment_profile", "prod")

    devices = checks.get("devices", {}).get("summary", {})
    alerts = checks.get("alerts", {}).get("summary", {})
    policy_posture = checks.get("policy_posture", {}).get("summary", {})
    watchlists = checks.get("watchlists", {}).get("summary", {})
    watchlists_check = checks.get("watchlists", {}) if isinstance(checks.get("watchlists", {}), dict) else {}
    drift = checks.get("policy_drift", {}).get("summary", {})
    alert_workflow = checks.get("alert_workflow", {}).get("summary", {})
    user_logins = checks.get("user_logins", {}).get("summary", {})
    daily_alerts = checks.get("daily_alerts_threat_scores", {}).get("summary", {})
    endpoint_status = checks.get("endpoint_status", {}).get("summary", {})
    sensor_coverage = checks.get("sensor_coverage_quality", {}).get("summary", {})
    alert_quality = checks.get("alert_quality", {}).get("summary", {})
    policy_efficacy = checks.get("policy_efficacy", {}).get("summary", {})
    alert_volume_model = summary.get("alert_volume_model", {})
    if not isinstance(alert_volume_model, dict):
        alert_volume_model = {}

    if float(devices.get("active_ratio_last_7d", 0.0)) < 0.6:
        recs.append(
            {
                "priority": "P1",
                "area": "Sensor Coverage",
                "recommendation": "Investigate inactive endpoints and restore sensor check-in coverage.",
                "evidence": f"active_ratio_last_7d={devices.get('active_ratio_last_7d', 'n/a')}",
            }
        )

    if profile == "prod" and int(alerts.get("high_severity_alerts", 0)) > 50:
        recs.append(
            {
                "priority": "P1",
                "area": "Alert Volume",
                "recommendation": "Triage and suppress noisy high-severity detections using tuning and watchlist hygiene.",
                "evidence": f"high_severity_alerts={alerts.get('high_severity_alerts', 'n/a')}",
            }
        )

    avg_daily_alerts = float(daily_alerts.get("avg_daily_alerts", 0.0))
    total_devices = int(devices.get("total_devices", 0))
    status_counts = endpoint_status.get("status_counts", {})
    active_endpoints = 0
    if isinstance(status_counts, dict):
        active_endpoints = int(status_counts.get("ACTIVE", 0)) + int(status_counts.get("BYPASS", 0))
    if active_endpoints <= 0:
        active_endpoints = total_devices

    daily_alert_counts = daily_alerts.get("daily_alert_counts", {})
    peak_daily_alerts = 0
    if isinstance(daily_alert_counts, dict) and daily_alert_counts:
        try:
            peak_daily_alerts = int(max(float(v) for v in daily_alert_counts.values()))
        except Exception:
            peak_daily_alerts = 0

    avg_alerts_per_endpoint_per_day = (avg_daily_alerts / active_endpoints) if active_endpoints > 0 else 0.0
    peak_alerts_per_endpoint_per_day = (peak_daily_alerts / active_endpoints) if active_endpoints > 0 else 0.0

    # Analyst-capacity model by tenant size (small teams ~5 analysts, large teams up to ~20)
    # unless explicitly overridden in config.
    configured_analysts = alert_volume_model.get("soc_analysts")
    if configured_analysts is not None:
        try:
            estimated_analysts = max(int(configured_analysts), 1)
        except Exception:
            estimated_analysts = 5
    else:
        if active_endpoints <= 10000:
            estimated_analysts = 5
        elif active_endpoints <= 50000:
            estimated_analysts = 8
        elif active_endpoints <= 100000:
            estimated_analysts = 12
        elif active_endpoints <= 200000:
            estimated_analysts = 16
        else:
            estimated_analysts = 20

    try:
        assumed_alerts_per_analyst_per_shift = max(int(alert_volume_model.get("alerts_per_analyst_per_shift", 80)), 1)
    except Exception:
        assumed_alerts_per_analyst_per_shift = 80

    try:
        avg_daily_threshold = max(int(alert_volume_model.get("avg_daily_threshold", 1000)), 1)
    except Exception:
        avg_daily_threshold = 1000
    try:
        peak_daily_threshold = max(int(alert_volume_model.get("peak_daily_threshold", 1500)), 1)
    except Exception:
        peak_daily_threshold = 1500

    estimated_team_capacity_per_day = estimated_analysts * assumed_alerts_per_analyst_per_shift
    capacity_ratio = (
        avg_daily_alerts / estimated_team_capacity_per_day if estimated_team_capacity_per_day > 0 else 0.0
    )

    # Alert volume should be judged by analyst handling capacity and active endpoint scale.
    # Keep an absolute guardrail as well: sustained 1k-1.5k/day is generally heavy for most teams.
    absolute_pressure = avg_daily_alerts >= avg_daily_threshold or peak_daily_alerts >= peak_daily_threshold
    analyst_pressure = capacity_ratio >= 1.0
    endpoint_pressure = avg_alerts_per_endpoint_per_day >= 0.02 or peak_alerts_per_endpoint_per_day >= 0.03

    if profile == "prod" and active_endpoints > 0 and (analyst_pressure or absolute_pressure or endpoint_pressure):
        p1_avg_threshold = int(max(avg_daily_threshold * 1.5, avg_daily_threshold + 500))
        p1_peak_threshold = int(max(peak_daily_threshold * 1.5, peak_daily_threshold + 750))
        priority = "P1" if (capacity_ratio >= 1.5 or avg_daily_alerts >= p1_avg_threshold or peak_daily_alerts >= p1_peak_threshold) else "P2"
        recs.append(
            {
                "priority": priority,
                "area": "Alert Volume",
                "recommendation": "Reduce excessive alert volume by tuning noisy detections, suppressing known-benign activity, and tightening watchlist scope.",
                "evidence": (
                    f"avg_alerts_per_endpoint_per_day={round(avg_alerts_per_endpoint_per_day, 4)}, "
                    f"peak_alerts_per_endpoint_per_day={round(peak_alerts_per_endpoint_per_day, 4)}, "
                    f"avg_daily_alerts={round(avg_daily_alerts, 2)}, "
                    f"peak_daily_alerts={peak_daily_alerts}, "
                    f"active_endpoints={active_endpoints}, "
                    f"estimated_analysts={estimated_analysts}, "
                    f"assumed_alerts_per_analyst_per_shift={assumed_alerts_per_analyst_per_shift}, "
                    f"avg_daily_threshold={avg_daily_threshold}, "
                    f"peak_daily_threshold={peak_daily_threshold}, "
                    f"estimated_team_capacity_per_day={estimated_team_capacity_per_day}, "
                    f"capacity_ratio={round(capacity_ratio, 2)}"
                ),
            }
        )

    low_severity_alerts = int(alert_quality.get("low_severity_alerts_lt5", 0))
    low_severity_ratio = float(alert_quality.get("low_severity_ratio_lt5", 0.0))
    total_alerts_quality = int(alert_quality.get("total_alerts", 0))
    if low_severity_ratio >= 0.6 and total_alerts_quality >= 1000:
        low_sev_priority = "P1" if (low_severity_ratio >= 0.8 and total_alerts_quality >= 5000) else "P2"
        recs.append(
            {
                "priority": low_sev_priority,
                "area": "Alert Quality",
                "recommendation": "Review and tune sub-5 severity alerts to reduce low-value noise and preserve analyst capacity for high-risk detections.",
                "evidence": (
                    f"low_severity_alerts_lt5={low_severity_alerts}, "
                    f"low_severity_ratio_lt5={round(low_severity_ratio, 4)}"
                ),
            }
        )

    if int(policy_posture.get("total_rules", 0)) == 0:
        recs.append(
            {
                "priority": "P1",
                "area": "Policy Enforcement",
                "recommendation": "Define and deploy policy rules for enforcement baseline.",
                "evidence": "total_rules=0",
            }
        )
    elif policy_posture.get("ngav_enabled", True) and float(policy_posture.get("blocking_rule_ratio", 0.0)) < 0.1:
        recs.append(
            {
                "priority": "P2",
                "area": "Policy Enforcement",
                "recommendation": "Increase proportion of deny/terminate style controls where appropriate.",
                "evidence": f"blocking_rule_ratio={policy_posture.get('blocking_rule_ratio', 'n/a')}",
            }
        )

    if watchlists_check.get("status") == "ok" and int(watchlists.get("total_watchlists", 0)) == 0:
        recs.append(
            {
                "priority": "P2",
                "area": "Watchlists",
                "recommendation": "Add at least baseline watchlists for critical detections and ATT&CK mappings.",
                "evidence": "total_watchlists=0",
            }
        )

    if bool(drift.get("drift_detected", False)):
        recs.append(
            {
                "priority": "P3",
                "area": "Governance",
                "recommendation": "Review policy configuration changes and validate whether all modifications were planned and approved.",
                "evidence": (
                    f"changed_count={drift.get('changed_count', 0)}, "
                    f"changed_policies={', '.join(drift.get('changed_policy_names', [])[:3])}"
                ),
            }
        )

    if int(alert_workflow.get("open_alerts_over_72h", 0)) > 0:
        recs.append(
            {
                "priority": "P2",
                "area": "Alert Workflow",
                "recommendation": "Reduce backlog of aged open alerts by tightening triage SLA and ownership.",
                "evidence": f"open_alerts_over_72h={alert_workflow.get('open_alerts_over_72h', 0)}",
            }
        )

    dormant_60d_count = int(user_logins.get("dormant_over_60d_count", 0))
    dormant_30d_count = int(user_logins.get("dormant_over_30d_count", 0))
    if dormant_60d_count > 0:
        users = user_logins.get("dormant_over_60d", [])
        names = users[:5] if isinstance(users, list) else []
        names_str = ", ".join(names) + (" ..." if isinstance(users, list) and len(users) > 5 else "")
        recs.append(
            {
                "priority": "P1",
                "area": "User Logins",
                "recommendation": "Investigate users dormant for 60+ days and remove or disable unnecessary access.",
                "evidence": f"dormant_over_60d_count={dormant_60d_count}, users={names_str}",
            }
        )
    elif dormant_30d_count > 0:
        users = user_logins.get("dormant_over_30d", [])
        names = users[:5] if isinstance(users, list) else []
        names_str = ", ".join(names) + (" ..." if isinstance(users, list) and len(users) > 5 else "")
        recs.append(
            {
                "priority": "P2",
                "area": "User Logins",
                "recommendation": "Review users dormant for 30+ days and validate if access is still required.",
                "evidence": f"dormant_over_30d_count={dormant_30d_count}, users={names_str}",
            }
        )

    if float(alert_quality.get("noise_ratio", 0.0)) > 0.4:
        recs.append(
            {
                "priority": "P2",
                "area": "Alert Quality",
                "recommendation": "Tune noisy detections and deduplicate repeated low-value alerts.",
                "evidence": f"noise_ratio={alert_quality.get('noise_ratio', 'n/a')}",
            }
        )

    monitor_heavy = policy_efficacy.get("monitor_heavy_policy_groups", [])
    if isinstance(monitor_heavy, list) and monitor_heavy:
        recs.append(
            {
                "priority": "P2",
                "area": "Policy Efficacy",
                "recommendation": "Move monitor-heavy policy groups toward blocking where risk allows.",
                "evidence": f"monitor_heavy_policy_groups={len(monitor_heavy)}",
            }
        )

    if policy_posture.get("ngav_enabled", True):
        core_prevention = checks.get("core_prevention_settings", {}).get("summary", {})
        alert_only = core_prevention.get("alert_only_policies", [])
        missing_required = core_prevention.get("policies_with_missing_required_controls", [])
        enforcement_gaps = core_prevention.get("policies_with_enforcement_gaps", [])
        if (
            isinstance(alert_only, list)
            and isinstance(missing_required, list)
            and isinstance(enforcement_gaps, list)
            and (alert_only or missing_required or enforcement_gaps)
        ):
            total_policies = int(core_prevention.get("total_policies", 0))
            alert_only_count = len(alert_only)
            missing_required_count = len(missing_required)
            combined_gap_count = len(enforcement_gaps)
            fully_alert_only_count = len(core_prevention.get("fully_alert_only_policies", []))
            names = [p.get("policy_name", p.get("policy_id", "?")) for p in enforcement_gaps[:5]]
            names_str = ", ".join(names) + (" ..." if combined_gap_count > 5 else "")
            # P1 when there is any fully alert-only policy, or when combined core-prevention
            # enforcement gaps impact at least a third of policies.
            priority = "P1" if (fully_alert_only_count > 0 or (total_policies > 0 and combined_gap_count / total_policies >= 0.33)) else "P2"
            recs.append(
                {
                    "priority": priority,
                    "area": "Core Prevention",
                    "recommendation": (
                        "Review core prevention and blocking/isolation posture: one or more policies have "
                        "alert-only (REPORT) behavior and/or are missing required blocking controls. "
                        "Enable blocking (PREVENT) and close missing-control gaps where the environment allows."
                    ),
                    "evidence": (
                        f"policies_with_gaps={combined_gap_count}, "
                        f"alert_only_policies={alert_only_count}, "
                        f"missing_required_controls={missing_required_count}, "
                        f"fully_alert_only={fully_alert_only_count}, "
                        f"policies={names_str}"
                    ),
                }
            )

    permissions_audit = checks.get("permissions_rule_audit", {}).get("summary", {})
    p1_policies = permissions_audit.get("p1_policies", [])
    p2_policies = permissions_audit.get("p2_policies", [])
    if isinstance(p1_policies, list) and p1_policies:
        names = [p.get("policy_name", p.get("policy_id", "?")) for p in p1_policies[:5]]
        names_str = ", ".join(names) + (" ..." if len(p1_policies) > 5 else "")
        recs.append(
            {
                "priority": "P1",
                "area": "Permissions Rule Audit",
                "recommendation": (
                    "Review BYPASS permission rules with path values that begin and end with '**'. "
                    "These create highly permissive scopes and should be narrowed immediately."
                ),
                "evidence": f"p1_policies={len(p1_policies)}, policies={names_str}",
            }
        )
    elif isinstance(p2_policies, list) and p2_policies:
        names = [p.get("policy_name", p.get("policy_id", "?")) for p in p2_policies[:5]]
        names_str = ", ".join(names) + (" ..." if len(p2_policies) > 5 else "")
        recs.append(
            {
                "priority": "P2",
                "area": "Permissions Rule Audit",
                "recommendation": (
                    "Review BYPASS permission rules with leading or trailing '**' in path values. "
                    "Constrain these selectors to least-privilege path scope."
                ),
                "evidence": f"p2_policies={len(p2_policies)}, policies={names_str}",
            }
        )

    if not recs:
        recs.append(
            {
                "priority": "P4",
                "area": "General",
                "recommendation": "No critical gaps detected; continue periodic review and trend monitoring.",
                "evidence": "all checks within configured thresholds",
            }
        )

    return recs
