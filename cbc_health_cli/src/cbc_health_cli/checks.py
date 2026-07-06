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

MINIMUM_BEHAVIOR_REQUIREMENTS: tuple[dict[str, Any], ...] = (
    {
        "id": "ransomware_like_behavior",
        "label": "Performs ransomware-like behavior",
        "operation_ids": ["RANSOM"],
        "tokens": [
            "performs ransomware-like behavior",
            "ransomware-like behavior",
            "ransomware like behavior",
            "ransomware",
        ],
    },
    {
        "id": "scrapes_memory",
        "label": "Scrapes memory of another process",
        "operation_ids": ["MEMORY_SCRAPE"],
        "tokens": [
            "scrapes memory of another process",
            "scrape memory of another process",
            "scrapes memory",
            "scrape memory",
        ],
    },
    {
        "id": "injects_code_or_modifies_memory",
        "label": "Injects code or modifies memory of another process",
        "operation_ids": ["CODE_INJECTION"],
        "tokens": [
            "injects code or modifies memory of another process",
            "injects code",
            "modifies memory of another process",
            "modify memory of another process",
        ],
    },
    {
        "id": "executes_code_from_memory",
        "label": "Executes code from memory",
        "operation_ids": ["EXECUTE_CODE_FROM_MEMORY", "EXECUTES_CODE_FROM_MEMORY", "MEMORY_EXECUTION"],
        "tokens": [
            "executes code from memory",
            "execute code from memory",
            "memory execution",
        ],
    },
    {
        "id": "communicates_over_network",
        "label": "Communicates over the network",
        "operation_ids": ["NETWORK", "NETWORK_COMMUNICATION", "COMMUNICATES_OVER_NETWORK"],
        "tokens": [
            "communicates over the network",
            "communicate over the network",
            "network communication",
        ],
    },
    {
        "id": "invokes_untrusted_process",
        "label": "Invokes an untrusted process",
        "operation_ids": ["INVOKES_UNTRUSTED_PROCESS", "UNTRUSTED_PROCESS", "UNTRUSTED_CHILD_PROCESS"],
        "tokens": [
            "invokes an untrusted process",
            "invoke an untrusted process",
            "untrusted process",
        ],
    },
)

GOOD_MINIMUM_BEHAVIOR_REQUIREMENTS_BY_CONTROL: dict[str, tuple[str, ...]] = {
    "unknown_application": ("ransomware_like_behavior", "scrapes_memory"),
    "not_listed_application": ("ransomware_like_behavior", "scrapes_memory"),
}

BETTER_MINIMUM_BEHAVIOR_REQUIREMENTS_BY_CONTROL: dict[str, tuple[str, ...]] = {
    "unknown_application": ("executes_code_from_memory", "communicates_over_network"),
    "not_listed_application": ("invokes_untrusted_process", "executes_code_from_memory"),
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


def _matched_minimum_behavior_ids(rule: dict[str, Any]) -> set[str]:
    matched: set[str] = set()
    operation_ids = _extract_rule_operation_ids(rule)
    for requirement in MINIMUM_BEHAVIOR_REQUIREMENTS:
        requirement_id = str(requirement.get("id", "")).strip()
        if not requirement_id:
            continue

        configured_operations = {
            str(item).strip().upper()
            for item in requirement.get("operation_ids", [])
            if str(item).strip()
        }
        if configured_operations and operation_ids.intersection(configured_operations):
            matched.add(requirement_id)
            continue

        haystack = _extract_rule_text(rule)
        tokens = requirement.get("tokens", [])
        if haystack and any(token in haystack for token in tokens):
            matched.add(str(requirement.get("id", "")).strip())
    return {item for item in matched if item}


def _extract_rule_operation_ids(rule: dict[str, Any]) -> set[str]:
    operation_ids: set[str] = set()

    def _collect(value: Any) -> None:
        if value in (None, ""):
            return
        if isinstance(value, str):
            normalized = value.strip().upper()
            if normalized:
                operation_ids.add(normalized)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                _collect(item)
            return
        if isinstance(value, dict):
            for key, nested_value in value.items():
                normalized_key = str(key).strip().lower()
                if normalized_key in {
                    "operation",
                    "operations",
                    "op",
                    "ops",
                    "attempted_operation",
                    "attempted_operations",
                    "operation_attempt",
                    "operation_attempts",
                }:
                    _collect(nested_value)

    _collect(rule.get("operation"))
    _collect(rule.get("operations"))
    _collect(rule.get("op"))
    params = rule.get("parameters")
    if isinstance(params, dict):
        _collect(params)

    return operation_ids


def _raw_device_status(device: dict[str, Any]) -> str:
    raw = _pick_value(device, ["status", "sensor_state", "state", "device_status"], "unknown")
    status = str(raw).strip().upper()

    if _to_bool(device.get("quarantined")) is True or "QUAR" in status:
        return "QUARANTINE"
    if "BYPASS_ON" in status:
        return "BYPASS_ON"
    if _to_bool(device.get("bypass")) is True or "BYPASS" in status:
        return "BYPASS"
    if status == "SENSOR_OUTOFDATE" or ("SENSOR" in status and "OUTOFDATE" in status):
        return "SENSOR_OUTOFDATE"
    return status


def _normalize_status(device: dict[str, Any]) -> str:
    status = _raw_device_status(device)

    if status == "REGISTERED":
        return "ACTIVE"
    if status == "LIVE":
        return "ACTIVE"
    if "INACTIVE" in status:
        return "INACTIVE"
    if "DEREG" in status:
        return "DEREGISTERED"
    if "ACTIVE" in status:
        return "ACTIVE"
    if status == "ALL":
        return "ALL"
    if status in {"UNKNOWN", ""}:
        return "UNKNOWN"
    return status


COUNTED_DEVICE_STATUSES = {
    "REGISTERED",
    "ACTIVE",
    "INACTIVE",
    "ALL",
    "BYPASS_ON",
    "BYPASS",
    "QUARANTINE",
    "SENSOR_OUTOFDATE",
    "LIVE",
}

ACTIVE_ENDPOINT_STATUSES = {"ACTIVE", "LIVE", "BYPASS", "BYPASS_ON"}


def _filter_counted_devices(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [device for device in devices if _raw_device_status(device) in COUNTED_DEVICE_STATUSES]


def summarize_devices(devices: list[dict[str, Any]]) -> dict[str, Any]:
    counted_devices = _filter_counted_devices(devices)
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


def _coerce_list(value: Any) -> list[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    if isinstance(value, dict):
        return [value]
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return []
        if raw[0] in "[({":
            try:
                parsed = ast.literal_eval(raw)
            except Exception:
                parsed = None
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, (tuple, set)):
                return list(parsed)
            if isinstance(parsed, dict):
                return [parsed]
        if any(separator in raw for separator in (";", "|")):
            return [part.strip() for part in re.split(r"[;|]", raw) if part.strip()]
        return [raw]
    return [value]


def _normalize_process_name(value: Any) -> str:
    raw = str(value).strip().strip('"')
    if not raw:
        return ""
    normalized = raw.replace("\\", "/").rstrip("/")
    candidate = normalized.rsplit("/", 1)[-1].strip()
    return candidate or raw


def _normalize_reputation_name(value: Any) -> str:
    raw = str(value).strip()
    if not raw:
        return ""
    normalized = raw.replace("_", " ").strip()
    if normalized.lower() in {"unknown", "n/a", "not applied"}:
        return ""
    return normalized.title()


_ATTACK_TECHNIQUE_ID_LABELS: dict[str, str] = {
    "T1204": "User Execution",
    "T1204.002": "User Execution: Malicious File",
    "T1055": "Process Injection",
    "T1055.013": "Process Injection: Process Doppelganging",
    "T1496": "Resource Hijacking",
}


def _normalize_attack_technique_name(value: Any) -> str:
    raw = str(value).strip()
    if not raw:
        return ""

    token = raw.upper()
    if token.startswith("MITRE_"):
        token = token[len("MITRE_"):]

    attack_id_match = re.search(r"T\d{4}(?:\.\d{3})?", token)
    attack_id = attack_id_match.group(0) if attack_id_match else ""

    label = ""
    if attack_id:
        label = _ATTACK_TECHNIQUE_ID_LABELS.get(attack_id, "")
        if not label:
            suffix = token.split(attack_id, 1)[1].strip("_")
            if suffix:
                label = suffix.replace("_", " ").title()
        if not label:
            label = f"Technique {attack_id}"
    else:
        label = token.replace("_", " ").title()

    return label


def _extract_alert_attack_techniques(alert: dict[str, Any]) -> list[str]:
    techniques: list[str] = []

    for key in ["attack_technique", "attack_techniques", "mitre_attack_technique", "technique"]:
        for item in _coerce_list(alert.get(key)):
            label = str(item).strip() if not isinstance(item, dict) else str(
                _pick_value(item, ["attack_technique", "technique", "name", "id"], "")
            ).strip()
            if label:
                normalized = _normalize_attack_technique_name(label)
                if normalized:
                    techniques.append(normalized)

    for item in _coerce_list(alert.get("ttps")):
        if isinstance(item, dict):
            label = str(_pick_value(item, ["attack_technique", "technique", "name", "id", "ttp"], "")).strip()
        else:
            label = str(item).strip()
        if label:
            normalized = _normalize_attack_technique_name(label)
            if normalized:
                techniques.append(normalized)

    unique_techniques: list[str] = []
    seen: set[str] = set()
    for technique in techniques:
        key = technique.casefold()
        if key in seen:
            continue
        seen.add(key)
        unique_techniques.append(technique)
    return unique_techniques


def _extract_alert_process_name(alert: dict[str, Any]) -> str:
    for key in ["process_name", "blocked_name", "childproc_name", "parent_name", "threat_name", "report_name"]:
        label = _normalize_process_name(alert.get(key))
        if label:
            return label
    return ""


def _extract_alert_reputation(alert: dict[str, Any]) -> str:
    for key in [
        "process_effective_reputation",
        "process_reputation",
        "blocked_effective_reputation",
        "childproc_effective_reputation",
        "parent_effective_reputation",
        "parent_reputation",
    ]:
        label = _normalize_reputation_name(alert.get(key))
        if label:
            return label
    return ""


def summarize_alerts(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(alerts)
    severity_counter: Counter[str] = Counter()
    type_counter: Counter[str] = Counter()
    attack_technique_counter: Counter[str] = Counter()
    process_counter: Counter[str] = Counter()
    reputation_counter: Counter[str] = Counter()

    for a in alerts:
        sev = str(_pick_value(a, ["severity", "threat_score", "impact_score"], "unknown"))
        atype = str(_pick_value(a, ["type", "category", "alert_type"], "unknown"))
        severity_counter[sev] += 1
        type_counter[atype] += 1

        for technique in _extract_alert_attack_techniques(a):
            attack_technique_counter[technique] += 1

        process_name = _extract_alert_process_name(a)
        if process_name:
            process_counter[process_name] += 1

        reputation_name = _extract_alert_reputation(a)
        if reputation_name:
            reputation_counter[reputation_name] += 1

    high_sev = sum(count for key, count in severity_counter.items() if key.isdigit() and int(key) >= 7)
    return {
        "total_alerts_30d": total,
        "high_severity_alerts": high_sev,
        "severity_breakdown": dict(severity_counter),
        "type_breakdown": dict(type_counter.most_common(10)),
        "attack_technique_breakdown": dict(attack_technique_counter.most_common(10)),
        "process_breakdown": dict(process_counter.most_common(10)),
        "reputation_breakdown": dict(reputation_counter.most_common(10)),
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
    path_based_policy_rules = 0
    action_counter: Counter[str] = Counter()

    for rule in rules:
        enabled_raw = _pick_value(rule, ["is_enabled", "enabled", "isEnabled"], True)
        if _to_bool(enabled_raw) is not False:
            enabled_rules += 1

        application = rule.get("application")
        app_type = ""
        if isinstance(application, dict):
            app_type = str(_pick_value(application, ["type", "application_type", "app_type"], "")).strip().upper()
        if not app_type:
            app_type = str(_pick_value(rule, ["application_type", "app_type", "rule_application_type"], "")).strip().upper()
        if app_type == "NAME_PATH":
            path_based_policy_rules += 1

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
        "path_based_policy_rules": path_based_policy_rules,
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


def _alert_watchlist_items(alert: dict[str, Any]) -> list[dict[str, Any]]:
    raw = alert.get("watchlists")
    parsed: list[dict[str, Any]] = []
    if isinstance(raw, list):
        parsed = [item for item in raw if isinstance(item, dict)]
    elif isinstance(raw, str) and raw.strip():
        try:
            candidate = ast.literal_eval(raw)
        except Exception:
            candidate = None
        if isinstance(candidate, list):
            parsed = [item for item in candidate if isinstance(item, dict)]
    return parsed


def summarize_watchlist_effectiveness(
    watchlist_summary: dict[str, Any],
    alerts: list[dict[str, Any]],
) -> dict[str, Any]:
    total_alerts = len(alerts)
    watchlist_alerts = 0
    watchlist_high_severity_alerts = 0
    watchlist_low_severity_alerts = 0
    watchlist_alert_counts: Counter[str] = Counter()

    for alert in alerts:
        alert_type = str(_pick_value(alert, ["type", "category", "alert_type"], "")).strip().upper()
        wl_items = _alert_watchlist_items(alert)
        is_watchlist_alert = alert_type == "WATCHLIST" or bool(wl_items)
        if not is_watchlist_alert:
            continue

        watchlist_alerts += 1

        sev_raw = _pick_value(alert, ["threat_score", "severity", "impact_score"], 0)
        try:
            sev = float(sev_raw)
        except Exception:
            sev = 0.0
        if sev >= 7:
            watchlist_high_severity_alerts += 1
        if sev < 5:
            watchlist_low_severity_alerts += 1

        if wl_items:
            for item in wl_items:
                wl_id = str(item.get("id", "")).strip()
                wl_name = str(item.get("name", "")).strip()
                key = wl_id or wl_name or "unknown_watchlist"
                watchlist_alert_counts[key] += 1
        else:
            watchlist_alert_counts["unattributed_watchlist_alerts"] += 1

    watchlist_alert_ratio = (watchlist_alerts / total_alerts) if total_alerts > 0 else 0.0
    watchlist_high_ratio = (watchlist_high_severity_alerts / watchlist_alerts) if watchlist_alerts > 0 else 0.0
    watchlist_low_ratio = (watchlist_low_severity_alerts / watchlist_alerts) if watchlist_alerts > 0 else 0.0
    top_watchlist_share = 0.0
    if watchlist_alerts > 0 and watchlist_alert_counts:
        top_watchlist_share = max(watchlist_alert_counts.values()) / watchlist_alerts

    total_watchlists = int(watchlist_summary.get("total_watchlists", 0)) if isinstance(watchlist_summary, dict) else 0
    enabled_watchlists = int(watchlist_summary.get("enabled_watchlists", 0)) if isinstance(watchlist_summary, dict) else 0
    enabled_without_alerting = int(watchlist_summary.get("enabled_without_alerting_watchlists", 0)) if isinstance(watchlist_summary, dict) else 0
    alerting_enabled_watchlists = int(watchlist_summary.get("alerting_enabled_watchlists", 0)) if isinstance(watchlist_summary, dict) else 0

    posture_score = 100.0
    posture_findings: list[str] = []
    if total_watchlists <= 0:
        posture_score = 0.0
        posture_findings.append("No watchlists configured")
    else:
        disabled_watchlists = max(total_watchlists - enabled_watchlists, 0)
        disabled_ratio = (disabled_watchlists / total_watchlists) if total_watchlists > 0 else 0.0
        if disabled_ratio > 0:
            posture_score -= min(25.0, 25.0 * disabled_ratio)

        if enabled_watchlists > 0:
            enabled_without_alerting_ratio = enabled_without_alerting / enabled_watchlists
            if enabled_without_alerting_ratio > 0:
                posture_score -= min(45.0, 45.0 * enabled_without_alerting_ratio)
                posture_findings.append("Many enabled watchlists are not configured to alert")

            alerting_coverage_ratio = alerting_enabled_watchlists / enabled_watchlists
            if alerting_coverage_ratio < 0.6:
                posture_score -= min(30.0, 30.0 * ((0.6 - alerting_coverage_ratio) / 0.6))
                posture_findings.append("Alerting coverage across enabled watchlists is low")
        else:
            posture_score -= 70.0
            posture_findings.append("No enabled watchlists")
    posture_score = max(min(posture_score, 100.0), 0.0)

    signal_score = 100.0
    signal_findings: list[str] = []
    if total_alerts <= 0:
        signal_score = 100.0
    elif watchlist_alerts <= 0:
        signal_score = 45.0 if total_alerts >= 200 else 70.0
        signal_findings.append("No watchlist alerts observed in current alert set")
    else:
        if watchlist_alerts >= 100 and watchlist_low_ratio >= 0.75:
            signal_score -= 35.0
            signal_findings.append("Watchlist alert stream is dominated by sub-5 severity alerts")
        elif watchlist_alerts >= 100 and watchlist_low_ratio >= 0.6:
            signal_score -= 20.0
            signal_findings.append("Watchlist alert stream has elevated sub-5 severity volume")

        if watchlist_alerts >= 100 and watchlist_high_ratio < 0.1:
            signal_score -= 20.0
            signal_findings.append("Very low share of high-severity watchlist alerts")
        elif watchlist_alerts >= 100 and watchlist_high_ratio < 0.2:
            signal_score -= 10.0

        if watchlist_alert_ratio > 0.9:
            signal_score -= 15.0
            signal_findings.append("Most alerts are watchlist-driven; likely over-triggering")
        elif total_alerts >= 500 and watchlist_alert_ratio < 0.02:
            signal_score -= 10.0
            signal_findings.append("Very low watchlist contribution relative to total alert volume")

        if top_watchlist_share > 0.6:
            signal_score -= min(20.0, 20.0 * ((top_watchlist_share - 0.6) / 0.4))
            signal_findings.append("Watchlist alert volume is highly concentrated in a single watchlist")
    signal_score = max(min(signal_score, 100.0), 0.0)

    effectiveness_score = int(round((posture_score * 0.4) + (signal_score * 0.6)))

    return {
        "score_0_100": effectiveness_score,
        "posture_score_0_100": int(round(posture_score)),
        "signal_score_0_100": int(round(signal_score)),
        "metrics": {
            "total_alerts": total_alerts,
            "watchlist_alerts": watchlist_alerts,
            "watchlist_alert_ratio": round(watchlist_alert_ratio, 4),
            "watchlist_high_severity_alerts": watchlist_high_severity_alerts,
            "watchlist_high_severity_ratio": round(watchlist_high_ratio, 4),
            "watchlist_low_severity_alerts_lt5": watchlist_low_severity_alerts,
            "watchlist_low_severity_ratio_lt5": round(watchlist_low_ratio, 4),
            "top_watchlist_share": round(top_watchlist_share, 4),
            "total_watchlists": total_watchlists,
            "enabled_watchlists": enabled_watchlists,
            "alerting_enabled_watchlists": alerting_enabled_watchlists,
            "enabled_without_alerting_watchlists": enabled_without_alerting,
        },
        "findings": list(dict.fromkeys(posture_findings + signal_findings))[:6],
        "top_watchlist_alert_counts": dict(watchlist_alert_counts.most_common(10)),
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
            "minimum_behavior_controls": defaultdict(set),
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
            if (
                matched_control in GOOD_MINIMUM_BEHAVIOR_REQUIREMENTS_BY_CONTROL
                or matched_control in BETTER_MINIMUM_BEHAVIOR_REQUIREMENTS_BY_CONTROL
            ):
                matched_behaviors = _matched_minimum_behavior_ids(rule)
                if matched_behaviors:
                    behavior_bucket = policy_bucket["minimum_behavior_controls"].setdefault(matched_control, set())
                    behavior_bucket.update(matched_behaviors)
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
        minimum_behavior_controls = counts.get("minimum_behavior_controls", {})
        requirement_label_by_id = {
            str(requirement.get("id", "")).strip(): str(requirement.get("label", "")).strip()
            for requirement in MINIMUM_BEHAVIOR_REQUIREMENTS
            if str(requirement.get("id", "")).strip()
        }

        missing_good_minimum_behavior_controls: list[str] = []
        for control_id, requirement_ids in GOOD_MINIMUM_BEHAVIOR_REQUIREMENTS_BY_CONTROL.items():
            present_behavior_ids = set(minimum_behavior_controls.get(control_id, set()))
            control_label = REQUIRED_BLOCKING_CONTROLS.get(control_id, {}).get("label", control_id)
            for requirement_id in requirement_ids:
                if requirement_id in present_behavior_ids:
                    continue
                requirement_label = requirement_label_by_id.get(requirement_id, requirement_id)
                missing_good_minimum_behavior_controls.append(f"{control_label}: {requirement_label}")

        missing_better_minimum_behavior_controls: list[str] = []
        for control_id, requirement_ids in BETTER_MINIMUM_BEHAVIOR_REQUIREMENTS_BY_CONTROL.items():
            present_behavior_ids = set(minimum_behavior_controls.get(control_id, set()))
            control_label = REQUIRED_BLOCKING_CONTROLS.get(control_id, {}).get("label", control_id)
            for requirement_id in requirement_ids:
                if requirement_id in present_behavior_ids:
                    continue
                requirement_label = requirement_label_by_id.get(requirement_id, requirement_id)
                missing_better_minimum_behavior_controls.append(f"{control_label}: {requirement_label}")

        # Keep legacy field name for downstream compatibility; this now maps to GOOD requirements.
        missing_minimum_behavior_controls = missing_good_minimum_behavior_controls
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
            "missing_minimum_behavior_controls": missing_minimum_behavior_controls,
            "missing_minimum_behavior_controls_count": len(missing_minimum_behavior_controls),
            "missing_good_minimum_behavior_controls": missing_good_minimum_behavior_controls,
            "missing_good_minimum_behavior_controls_count": len(missing_good_minimum_behavior_controls),
            "missing_better_minimum_behavior_controls": missing_better_minimum_behavior_controls,
            "missing_better_minimum_behavior_controls_count": len(missing_better_minimum_behavior_controls),
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
        key=lambda r: (
            r["missing_required_controls_count"],
            r.get("missing_minimum_behavior_controls_count", 0),
            r["monitor_ratio"],
            r["monitor_rules"],
        ),
        reverse=True,
    )
    alert_only_policies.sort(
        key=lambda r: (
            r["missing_required_controls_count"],
            r.get("missing_minimum_behavior_controls_count", 0),
            r["monitor_rules"],
            r["policy_name"],
        ),
        reverse=True,
    )
    fully_alert_only_policies.sort(
        key=lambda r: (
            r["missing_required_controls_count"],
            r.get("missing_minimum_behavior_controls_count", 0),
            r["monitor_rules"],
            r["policy_name"],
        ),
        reverse=True,
    )
    policies_with_missing_required_controls.sort(
        key=lambda r: (
            r["missing_required_controls_count"],
            r.get("missing_minimum_behavior_controls_count", 0),
            r["policy_name"],
        ),
        reverse=True,
    )
    policies_with_enforcement_gaps.sort(
        key=lambda r: (
            r["missing_required_controls_count"],
            r.get("missing_minimum_behavior_controls_count", 0),
            r["monitor_rules"],
            r["policy_name"],
        ),
        reverse=True,
    )

    return {
        "total_categories": len(by_category),
        "alert_only_categories": sorted(alert_only_categories),
        "total_policies": len(policy_mode_breakdown),
        "required_blocking_controls": [metadata["label"] for metadata in REQUIRED_BLOCKING_CONTROLS.values()],
        "minimum_behavior_requirements": [
            requirement["label"] for requirement in MINIMUM_BEHAVIOR_REQUIREMENTS
        ],
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
    api_access_keys: list[dict[str, Any]] | None = None,
    connector_activity: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    api_access_keys = api_access_keys or []
    connector_activity = connector_activity or {}

    api_access_type_by_id: dict[str, str] = {}
    for key in api_access_keys:
        if not isinstance(key, dict):
            continue
        api_id = str(_pick_value(key, ["api_id", "apiId", "id", "key_id", "connector_id"], "")).strip()
        if not api_id:
            continue
        access_level_type = str(
            _pick_value(
                key,
                [
                    "access_level_type",
                    "accessLevelType",
                    "access_level_name",
                    "accessLevelName",
                    "access_level",
                    "accessLevel",
                    "role",
                ],
                "unknown",
            )
        ).strip() or "unknown"
        api_access_type_by_id[api_id] = access_level_type

    connector_sessions: Counter[str] = Counter()
    access_type_counter: Counter[str] = Counter()
    connector_access_type_counter: dict[str, Counter[str]] = defaultdict(Counter)
    ip_counter: Counter[str] = Counter()
    connector_ips: dict[str, set[str]] = defaultdict(set)
    connector_events: list[dict[str, Any]] = []

    for event in audit_logs:
        description = str(event.get("description", ""))
        # Only count entries that represent connector authentication sessions
        if "Connector" not in description and "connector" not in description:
            continue

        connector_id = str(_pick_value(event, ["actor", "api_key_id", "access_key", "principal"], "unknown")).strip()
        connector_sessions[connector_id] += 1
        access_level_type = api_access_type_by_id.get(connector_id, "")
        if not access_level_type:
            access_level_type = "unknown"
        access_type_counter[access_level_type] += 1
        connector_access_type_counter[connector_id][access_level_type] += 1

        # Audit log v1 uses actor_ip, not ip_address/source_ip
        ip = str(_pick_value(event, ["actor_ip", "ip_address", "source_ip", "client_ip"], "unknown")).strip()
        if ip:
            ip_counter[ip] += 1
            connector_ips[connector_id].add(ip)

        connector_events.append({
            "connector_id": connector_id,
            "api_access_level_type": access_level_type,
            "description": description,
            "actor_ip": ip,
            "create_time": event.get("create_time", ""),
        })

    connector_session_events = len(connector_events)

    # When targeted connector activity is provided, trust those connector-specific
    # counts over bulk audit parsing (which can be capped/truncated).
    if connector_activity:
        connector_sessions = Counter()
        access_type_counter = Counter()
        connector_access_type_counter = defaultdict(Counter)
        ip_counter = Counter()
        connector_ips = defaultdict(set)
        connector_session_events = 0

        for connector_id, metrics in connector_activity.items():
            if not isinstance(metrics, dict):
                continue
            session_count = int(metrics.get("session_count", 0) or 0)
            if session_count <= 0:
                continue

            connector_sessions[connector_id] = session_count
            connector_session_events += session_count

            access_level_type = api_access_type_by_id.get(connector_id, "") or "unknown"
            access_type_counter[access_level_type] += session_count
            connector_access_type_counter[connector_id][access_level_type] += session_count

            ips_raw = metrics.get("ip_addresses", [])
            if isinstance(ips_raw, list):
                for value in ips_raw:
                    ip = str(value).strip()
                    if ip:
                        connector_ips[connector_id].add(ip)

            ip_counts_raw = metrics.get("ip_counts", {})
            if isinstance(ip_counts_raw, dict) and ip_counts_raw:
                for raw_ip, raw_count in ip_counts_raw.items():
                    ip = str(raw_ip).strip()
                    if not ip:
                        continue
                    ip_counter[ip] += int(raw_count or 0)
            else:
                for ip in connector_ips.get(connector_id, set()):
                    ip_counter[ip] += 1

    dormant_entities: list[str] = []

    return {
        "total_audit_events": len(audit_logs),
        "connector_session_events": connector_session_events,
        "active_connectors": [
            {
                "connector_id": cid,
                "api_access_level_type": (
                    connector_access_type_counter[cid].most_common(1)[0][0]
                    if connector_access_type_counter.get(cid)
                    else "unknown"
                ),
                "session_count": count,
                "ip_addresses": ", ".join(sorted(connector_ips.get(cid, set()))),
            }
            for cid, count in connector_sessions.most_common()
            if cid != "unknown"
        ],
        "active_connector_count": len([k for k in connector_sessions if k != "unknown"]),
        "api_access_level_type_breakdown": dict(access_type_counter.most_common()),
        "unique_source_ips": len(ip_counter),
        "top_source_ips": _build_enriched_ip_list(ip_counter),
        "dormant_integrations": dormant_entities[:50],
        "dormant_integration_count": len(dormant_entities),
    }


def summarize_live_query_audit_remediation(
    live_query_activity: dict[str, Any] | None,
    audit_logs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Summarize Live Query activity from API data with audit-log fallback."""

    known_recommended = {
        "active sensor policies",
        "installed windows patches",
        "failed rdp logon - security event log",
    }

    def _normalize_query_name(name: str) -> str:
        normalized = (name or "").strip().lower()
        normalized = re.sub(r"\s*\(updated\)\s*$", "", normalized)
        normalized = re.sub(r"\s+", " ", normalized)
        return normalized

    def _empty_payload(source: str) -> dict[str, Any]:
        return {
            "data_source": source,
            "total_live_query_events": 0,
            "total_query_runs": 0,
            "total_query_creates": 0,
            "recommended_query_runs": 0,
            "custom_query_runs": 0,
            "avg_endpoints_per_query": None,
            "queried_os_breakdown": {},
            "users_query_creates": [],
            "top_queries": [],
            "daily_event_counts": {},
            "known_recommended_names": sorted(known_recommended),
        }

    def _first_text(record: dict[str, Any], keys: list[str], default: str = "") -> str:
        for key in keys:
            value = record.get(key)
            if value is None:
                continue
            text = str(value).strip()
            if text:
                return text
        return default

    def _first_int(record: dict[str, Any], keys: list[str]) -> int | None:
        for key in keys:
            value = record.get(key)
            if value in (None, ""):
                continue
            try:
                return int(float(value))
            except Exception:
                continue
        return None

    def _safe_int(value: Any) -> int:
        try:
            return int(float(value))
        except Exception:
            return 0

    def _is_true(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        text = str(value or "").strip().lower()
        return text in {"true", "1", "yes", "enabled"}

    def _device_filter_oses(record: dict[str, Any]) -> list[str]:
        all_oses = ["Windows", "macOS", "Linux"]
        device_filter = record.get("device_filter")
        if not isinstance(device_filter, dict):
            return all_oses

        os_value = device_filter.get("os")
        if os_value in (None, "", "null", "None"):
            return all_oses

        raw_values: list[str] = []
        if isinstance(os_value, list):
            raw_values = [str(v).strip() for v in os_value if str(v).strip()]
        else:
            raw_values = [str(os_value).strip()] if str(os_value).strip() else []

        if not raw_values:
            return all_oses

        mapped: list[str] = []
        for raw in raw_values:
            normalized = raw.lower()
            if "win" in normalized:
                mapped.append("Windows")
            elif "mac" in normalized or "osx" in normalized:
                mapped.append("macOS")
            elif "lin" in normalized:
                mapped.append("Linux")
            else:
                mapped.append(raw)

        # Preserve order, remove duplicates.
        deduped: list[str] = []
        seen: set[str] = set()
        for os_name in mapped:
            if os_name not in seen:
                seen.add(os_name)
                deduped.append(os_name)
        return deduped

    def _is_recommended_from_run(run: dict[str, Any]) -> bool:
        rqid = _first_text(run, ["recommended_query_id", "recommendedQueryId"], "")
        return rqid not in ("", "null", "None")

    def _summarize_from_api(lq: dict[str, Any]) -> dict[str, Any]:
        runs_raw = lq.get("runs", []) if isinstance(lq, dict) else []
        templates = lq.get("templates", []) if isinstance(lq, dict) else []
        runs = [run for run in runs_raw if isinstance(run, dict)]

        if not runs:
            return _empty_payload("api")

        template_by_id: dict[str, dict[str, Any]] = {}
        template_name_by_id: dict[str, str] = {}
        template_os_by_id: dict[str, list[str]] = {}
        users_query_runs: Counter[str] = Counter()

        for template in templates:
            if not isinstance(template, dict):
                continue
            tid = _first_text(template, ["id", "template_id", "templateId", "query_id", "queryId"]) or ""
            tname = _first_text(template, ["name", "query_name", "queryName", "title"], "Unknown")

            if tid:
                template_by_id[tid] = template
                template_name_by_id[tid] = tname
                template_os_by_id[tid] = _device_filter_oses(template)

        query_run_counts: Counter[str] = Counter()
        query_os: dict[str, set[str]] = defaultdict(set)
        os_counter: Counter[str] = Counter()
        endpoints_seen: list[int] = []
        daily_event_counts: Counter[str] = Counter()
        query_type_by_name: dict[str, str] = {}

        total_query_runs = 0
        total_query_creates = 0

        for run in runs:
            if not isinstance(run, dict):
                continue
            total_query_runs += 1

            run_template_id = _first_text(run, ["template_id", "templateId", "query_id", "queryId", "scheduled_query_id", "scheduledQueryId"], "")
            query_name = _first_text(run, ["name", "query_name", "queryName", "template_name", "templateName", "scheduled_query_name", "scheduledQueryName", "title"], "")
            if not query_name and run_template_id:
                query_name = template_name_by_id.get(run_template_id, "Unknown")
            if not query_name:
                query_name = "Unknown"

            query_type = "Recommended" if _is_recommended_from_run(run) else "Custom"

            query_type_by_name[query_name] = query_type
            query_run_counts[query_name] += 1

            creator = _first_text(run, ["created_by", "creator", "actor", "username", "user", "principal"], "")
            if creator:
                users_query_runs[creator] += 1

            endpoint_count = _first_int(
                run,
                [
                    "device_count",
                    "target_count",
                    "endpoint_count",
                    "num_devices",
                    "total_devices",
                    "results_count",
                    "success_count",
                ],
            )
            if endpoint_count is not None:
                endpoints_seen.append(endpoint_count)

            run_oses = _device_filter_oses(run)
            if (not run_oses or run_oses == ["Windows", "macOS", "Linux"]) and run_template_id:
                run_oses = template_os_by_id.get(run_template_id, run_oses)


            for os_name in run_oses:
                query_os[query_name].add(os_name)
                os_counter[os_name] += 1

            run_time = _to_dt(_first_text(run, ["create_time", "created_at", "timestamp", "run_time", "start_time"], ""))
            if run_time:
                daily_event_counts[run_time.date().isoformat()] += 1

        recommended_query_runs = 0
        custom_query_runs = 0
        top_queries: list[dict[str, Any]] = []
        for query_name, run_count in query_run_counts.most_common(15):
            query_type = query_type_by_name.get(query_name, "Custom")
            if query_type == "Recommended":
                recommended_query_runs += run_count
            else:
                custom_query_runs += run_count

            top_queries.append(
                {
                    "query_name": query_name,
                    "run_count": run_count,
                    "query_type": query_type,
                    "os": ", ".join(sorted(query_os.get(query_name, set()))) or "Unknown",
                }
            )

        avg_endpoints_per_query: float | None
        if endpoints_seen:
            avg_endpoints_per_query = round(sum(endpoints_seen) / len(endpoints_seen), 2)
        else:
            avg_endpoints_per_query = None

        users_rows = [
            {"user": user, "run_count": count, "create_count": count}
            for user, count in users_query_runs.most_common(15)
        ]

        return {
            "data_source": "api",
            "total_live_query_events": int(total_query_runs),
            "total_query_runs": total_query_runs,
            "total_query_creates": total_query_creates,
            "total_unique_queries_run": int(len(query_run_counts)),
            "recommended_query_runs": recommended_query_runs,
            "custom_query_runs": custom_query_runs,
            "avg_endpoints_per_query": avg_endpoints_per_query,
            "queried_os_breakdown": dict(os_counter),
            "users_query_creates": users_rows,
            "top_queries": top_queries,
            "daily_event_counts": dict(sorted(daily_event_counts.items(), key=lambda kv: kv[0])),
            "known_recommended_names": sorted(known_recommended),
        }

    def _summarize_from_audit(logs: list[dict[str, Any]]) -> dict[str, Any]:
        live_events = [event for event in logs if isinstance(event, dict) and _event_is_live_query(event)]
        if not live_events:
            return _empty_payload("audit")

        users_query_creates: Counter[str] = Counter()
        query_run_counts: Counter[str] = Counter()
        query_os: dict[str, set[str]] = defaultdict(set)
        daily_event_counts: Counter[str] = Counter()
        os_counter: Counter[str] = Counter()
        endpoints_seen: list[int] = []

        total_query_runs = 0
        total_query_creates = 0

        for event in live_events:
            desc = str(_pick_value(event, ["description", "message", "details"], ""))
            action = _parse_action(desc)
            query_name = _parse_query_name(desc)
            actor = str(_pick_value(event, ["actor", "username", "user", "principal"], "unknown")).strip() or "unknown"

            event_time = _to_dt(_pick_value(event, ["timestamp", "create_time", "event_time", "time"]))
            if event_time:
                daily_event_counts[event_time.date().isoformat()] += 1

            if action == "created":
                total_query_creates += 1
                users_query_creates[actor] += 1

            if action == "run":
                total_query_runs += 1
                query_run_counts[query_name] += 1

                for os_name in _parse_os(desc, query_name):
                    query_os[query_name].add(os_name)
                    os_counter[os_name] += 1

                endpoint_count = _parse_endpoints_count(desc)
                if endpoint_count is not None:
                    endpoints_seen.append(endpoint_count)

        recommended_query_runs = 0
        custom_query_runs = 0
        top_queries: list[dict[str, Any]] = []
        for query_name, run_count in query_run_counts.most_common(15):
            normalized = _normalize_query_name(query_name)
            is_recommended = normalized in known_recommended
            if is_recommended:
                recommended_query_runs += run_count
                query_type = "Recommended"
            else:
                custom_query_runs += run_count
                query_type = "Custom"
            top_queries.append(
                {
                    "query_name": query_name,
                    "run_count": run_count,
                    "query_type": query_type,
                    "os": ", ".join(sorted(query_os.get(query_name, set()))) or "Unknown",
                }
            )

        avg_endpoints_per_query: float | None
        if endpoints_seen:
            avg_endpoints_per_query = round(sum(endpoints_seen) / len(endpoints_seen), 2)
        else:
            avg_endpoints_per_query = None

        users_rows = [
            {"user": user, "create_count": count}
            for user, count in users_query_creates.most_common(15)
        ]

        return {
            "data_source": "audit",
            "total_live_query_events": len(live_events),
            "total_query_runs": total_query_runs,
            "total_query_creates": total_query_creates,
            "recommended_query_runs": recommended_query_runs,
            "custom_query_runs": custom_query_runs,
            "avg_endpoints_per_query": avg_endpoints_per_query,
            "queried_os_breakdown": dict(os_counter),
            "users_query_creates": users_rows,
            "top_queries": top_queries,
            "daily_event_counts": dict(sorted(daily_event_counts.items(), key=lambda kv: kv[0])),
            "known_recommended_names": sorted(known_recommended),
        }

    def _event_is_live_query(event: dict[str, Any]) -> bool:
        desc = str(_pick_value(event, ["description", "message", "details"], "")).lower()
        request_url = str(_pick_value(event, ["request_url", "requestUrl", "request_uri", "requestURI"], "")).lower()
        if "ran query:" in desc:
            return True
        if " query " in desc and ("schedule" in desc or "created" in desc or "deleted" in desc or "stopped" in desc):
            return True
        if "livequery" in request_url or "/runs/" in request_url or "/templates/" in request_url:
            return True
        return False

    def _parse_query_name(desc: str) -> str:
        match = re.search(r"Ran query:\s*(.+)", desc, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        match = re.search(r"Query\s+(.+?)\s+(?:schedule\s+)?(?:created|deleted|stopped)", desc, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        match = re.search(r"(?:Created query|Query created):\s*(.+)", desc, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return "Unknown"

    def _parse_action(desc: str) -> str:
        d = desc.lower()
        if "ran query:" in d:
            return "run"
        if "schedule" in d and "created" in d:
            return "schedule_created"
        if "schedule" in d and "deleted" in d:
            return "schedule_deleted"
        if "schedule" in d and "stopped" in d:
            return "schedule_stopped"
        if "query" in d and "created" in d:
            return "created"
        return "other"

    def _parse_os(desc: str, query_name: str) -> list[str]:
        text = f"{desc} {query_name}".lower()
        os_hits: list[str] = []
        if "windows" in text or " win " in text:
            os_hits.append("Windows")
        if "linux" in text:
            os_hits.append("Linux")
        if "mac" in text or "osx" in text:
            os_hits.append("macOS")
        return os_hits

    def _parse_endpoints_count(desc: str) -> int | None:
        match = re.search(r"(\d+)\s*(?:endpoints|endpoint|devices|device)", desc, re.IGNORECASE)
        if not match:
            return None
        try:
            return int(match.group(1))
        except Exception:
            return None

    api_summary = _summarize_from_api(live_query_activity or {})
    if _safe_int(api_summary.get("total_query_runs", 0)) > 0:
        return api_summary

    audit_summary = _summarize_from_audit(audit_logs)
    if _safe_int(audit_summary.get("total_live_query_events", 0)) > 0:
        return audit_summary

    return _empty_payload("none")


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
    counted_devices = _filter_counted_devices(devices)
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
    return summarize_user_logins_with_users(audit_logs, [], [])


def _normalize_role_name(role_value: str) -> str:
    raw = str(role_value or "").strip()
    if not raw:
        return "unknown"

    if raw.lower() == "deprecated":
        return "unknown"

    token = raw.split(":")[-1]
    token = token.replace("_ROLE", "")

    known = {
        "BETA_SUPER_ADMIN": "Super Admin",
        "BETA_LEVEL_1_ANALYST": "Level 1 Analyst",
        "BETA_LEVEL_2_ANALYST": "Level 2 Analyst",
        "BETA_LEVEL_3_ANALYST": "Level 3 Analyst",
        "SUPER_ADMIN": "Super Admin",
        "LEVEL_1_ANALYST": "Level 1 Analyst",
        "LEVEL_2_ANALYST": "Level 2 Analyst",
        "LEVEL_3_ANALYST": "Level 3 Analyst",
        "MANAGE_ANALYST_1": "Level 1 Analyst",
        "MANAGE_ANALYST_2": "Level 2 Analyst",
        "MANAGE_ANALYST_3": "Level 3 Analyst",
        "LEVEL_1_ANALYST_WITH_MANAGE_USERS": "Level 1 Analyst",
        "LEVEL_2_ANALYST_WITH_MANAGE_USERS": "Level 2 Analyst",
        "LEVEL_3_ANALYST_WITH_MANAGE_USERS": "Level 3 Analyst",
    }
    if token in known:
        return known[token]

    if "SUPER" in token and "ADMIN" in token:
        return "Super Admin"

    readable = token.replace("_", " ").strip()
    return readable.title() if readable else "unknown"


def _roles_from_grant(grant: dict[str, Any]) -> list[str]:
    roles: list[str] = []
    direct_roles = grant.get("roles")
    if isinstance(direct_roles, list):
        roles.extend(str(item) for item in direct_roles if str(item).strip())

    profiles = grant.get("profiles")
    if isinstance(profiles, list):
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            profile_roles = profile.get("roles")
            if isinstance(profile_roles, list):
                roles.extend(str(item) for item in profile_roles if str(item).strip())

    deduped = list(dict.fromkeys(roles))
    return deduped


def summarize_user_logins_with_users(
    audit_logs: list[dict[str, Any]],
    users: list[dict[str, Any]],
    user_grants: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    user_grants = user_grants or []
    now = datetime.now(timezone.utc)
    last_login_by_user: dict[str, datetime] = {}
    last_login_ip_by_user: dict[str, str] = {}
    login_count_by_user: Counter[str] = Counter()
    ips_by_user: dict[str, set[str]] = defaultdict(set)

    def _normalize_user_identifier(value: Any) -> str:
        return str(value or "").strip().lower()

    email_login_pattern = re.compile(r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\s+logged in successfully", re.IGNORECASE)

    for event in audit_logs:
        event_type = str(_pick_value(event, ["event_type", "type", "action"], "")).lower()
        description = str(_pick_value(event, ["description", "message", "details"], ""))
        description_lower = description.lower()
        is_login = any(token in event_type for token in ["login", "signin", "authenticate"]) or "logged in successfully" in description_lower
        if not is_login:
            continue

        user = _normalize_user_identifier(_pick_value(event, ["username", "user", "actor", "principal"], "unknown"))
        match = email_login_pattern.search(description)
        if match:
            user = _normalize_user_identifier(match.group(1))

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
    user_role_by_identifier: dict[str, str] = {}

    def _set_role(identifier: str, role: str) -> None:
        key = _normalize_user_identifier(identifier)
        if not key:
            return
        existing = user_role_by_identifier.get(key)
        if existing in (None, "", "unknown") and role:
            user_role_by_identifier[key] = role

    # Prefer grants for role assignment because role placement differs by tenant
    # (grant.roles vs grant.profiles[].roles).
    for grant in user_grants:
        if not isinstance(grant, dict):
            continue
        grant_roles = _roles_from_grant(grant)
        if not grant_roles:
            continue
        normalized_roles = [_normalize_role_name(role) for role in grant_roles]
        # Keep first role; CBC grants are commonly single-role per principal.
        role_name = normalized_roles[0] if normalized_roles else "unknown"

        principal_name = _normalize_user_identifier(
            _pick_value(grant, ["principal_name", "principalName", "email", "username"], "")
        )
        if principal_name:
            _set_role(principal_name, role_name)

        principal = str(grant.get("principal", "")).strip()
        if principal.startswith("psc:user:"):
            principal_id = _normalize_user_identifier(principal.split(":")[-1])
            if principal_id:
                _set_role(principal_id, role_name)

    for user in users:
        role = str(_pick_value(user, ["role", "user_role", "access_role"], "unknown")).strip() or "unknown"
        normalized_user_role = _normalize_role_name(role)
        canonical_user = _normalize_user_identifier(
            _pick_value(user, ["login_name", "email", "username", "user_name", "login", "name"], "")
        )
        if canonical_user:
            known_users.add(canonical_user)

        for key in ["login_name", "email", "username", "user_name", "login", "name", "login_id", "contact_id"]:
            identifier = _normalize_user_identifier(_pick_value(user, [key], ""))
            if not identifier:
                continue
            _set_role(identifier, normalized_user_role)

        login_id = _normalize_user_identifier(_pick_value(user, ["login_id"], ""))
        if canonical_user and login_id:
            # Login events sometimes resolve to numeric login IDs.
            _set_role(canonical_user, user_role_by_identifier.get(login_id, normalized_user_role))

    def _user_role(user_name: str) -> str:
        normalized_user = _normalize_user_identifier(user_name)
        direct = user_role_by_identifier.get(normalized_user)
        if direct not in (None, ""):
            return str(direct)
        return "unknown"

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
                "role": _user_role(user),
                "last_login": last_login_by_user[user].isoformat(),
                "last_login_ip": last_login_ip_by_user.get(user, "unknown"),
                "login_count": int(login_count_by_user.get(user, 0)),
                "source_ips": sorted(ips_by_user.get(user, set())),
            }
        )

    dormant_7_sorted = sorted(dormant_7)
    dormant_30_sorted = sorted(dormant_30)
    dormant_60_sorted = sorted(dormant_60)
    never_logged_in_sorted = sorted(never_logged_in)

    return {
        "total_users": len(users_to_evaluate),
        "users_with_login_events": len(last_login_by_user),
        "users_without_login_events": never_logged_in_sorted,
        "users_without_login_events_details": [
            {"user": user, "role": _user_role(user)} for user in never_logged_in_sorted
        ],
        "users_without_login_events_count": len(never_logged_in),
        "user_login_details": user_login_details,
        "dormant_over_7d": dormant_7_sorted,
        "dormant_over_30d": dormant_30_sorted,
        "dormant_over_60d": dormant_60_sorted,
        "dormant_over_7d_details": [{"user": user, "role": _user_role(user)} for user in dormant_7_sorted],
        "dormant_over_30d_details": [{"user": user, "role": _user_role(user)} for user in dormant_30_sorted],
        "dormant_over_60d_details": [{"user": user, "role": _user_role(user)} for user in dormant_60_sorted],
        "dormant_over_7d_count": len(dormant_7),
        "dormant_over_30d_count": len(dormant_30),
        "dormant_over_60d_count": len(dormant_60),
    }


def summarize_sensor_coverage_quality(devices: list[dict[str, Any]]) -> dict[str, Any]:
    counted_devices = _filter_counted_devices(devices)
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


def summarize_policy_tuning_analysis(
    summary: dict[str, Any],
    policies: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Map current policy posture to Broadcom's Endpoint Standard Good/Better/Best framework."""
    checks = summary.get("checks", {}) if isinstance(summary, dict) else {}
    if not isinstance(checks, dict):
        checks = {}

    policy_posture = checks.get("policy_posture", {}).get("summary", {})
    core_prevention = checks.get("core_prevention_settings", {}).get("summary", {})
    policy_efficacy = checks.get("policy_efficacy", {}).get("summary", {})
    permissions_audit = checks.get("permissions_rule_audit", {}).get("summary", {})
    policy_drift = checks.get("policy_drift", {}).get("summary", {})

    def _to_int(value: Any) -> int:
        try:
            return int(float(value))
        except Exception:
            return 0

    def _policy_id(record: dict[str, Any]) -> str:
        return str(_pick_value(record, ["policy_id", "policyId", "id"], "")).strip()

    def _policy_assigned_endpoints(policy: dict[str, Any]) -> int:
        candidates = [
            _pick_value(policy, ["total_num_devices", "num_devices", "totalNumDevices", "numDevices"], 0),
            _pick_value(policy, ["device_count", "assigned_devices", "assigned_endpoints"], 0),
        ]
        return max(_to_int(value) for value in candidates)

    assigned_policy_ids: set[str] = set()
    if isinstance(policies, list):
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            pid = _policy_id(policy)
            if not pid:
                continue
            if _policy_assigned_endpoints(policy) > 0:
                assigned_policy_ids.add(pid)

    use_assigned_scope = bool(assigned_policy_ids)

    def _count_scoped(records: Any) -> int:
        if not isinstance(records, list):
            return 0
        if not use_assigned_scope:
            return len(records)
        count = 0
        for record in records:
            if isinstance(record, dict) and _policy_id(record) in assigned_policy_ids:
                count += 1
        return count

    ngav_enabled = bool(policy_posture.get("ngav_enabled", True))
    if not ngav_enabled:
        return {
            "framework": "Broadcom Endpoint Standard Good-Better-Best",
            "reference_url": "https://techdocs.broadcom.com/us/en/carbon-black/cloud/cloud-best-practices/index/cbc-tile-bp-tuning-es-policy.html",
            "framework_applicable": False,
            "current_tier": "not_applicable",
            "score_0_100": 0,
            "review_cadence": "quarterly_or_biannual",
            "reason": "NGAV is not enabled for this tenant, so Endpoint Standard policy tuning tiers do not apply.",
            "metrics": {
                "total_policies": int(policy_posture.get("total_policies", 0)),
                "ngav_enabled": False,
            },
            "gates": {
                "good": {"pass": False, "reason": "not_applicable"},
                "better": {"pass": False, "reason": "not_applicable"},
                "best": {"pass": False, "reason": "not_applicable"},
            },
            "top_gaps": [],
            "next_actions": [],
        }

    total_policies_all = int(core_prevention.get("total_policies", policy_posture.get("total_policies", 0)))
    total_policies_scored = len(assigned_policy_ids) if use_assigned_scope else total_policies_all

    policy_group_breakdown = policy_efficacy.get("policy_group_breakdown", [])
    total_rules_scored = 0
    if isinstance(policy_group_breakdown, list) and policy_group_breakdown:
        for row in policy_group_breakdown:
            if not isinstance(row, dict):
                continue
            if use_assigned_scope and _policy_id(row) not in assigned_policy_ids:
                continue
            total_rules_scored += _to_int(row.get("monitor_rules", 0))
            total_rules_scored += _to_int(row.get("block_rules", 0))
            total_rules_scored += _to_int(row.get("unknown_rules", 0))
    if total_rules_scored <= 0:
        total_rules_scored = int(policy_posture.get("total_rules", 0))

    fully_alert_only_count_all = len(core_prevention.get("fully_alert_only_policies", []) or [])
    missing_required_count_all = len(core_prevention.get("policies_with_missing_required_controls", []) or [])
    enforcement_gap_count_all = len(core_prevention.get("policies_with_enforcement_gaps", []) or [])
    policy_mode_breakdown_all = core_prevention.get("policy_mode_breakdown", []) or []
    missing_minimum_behavior_all_rows = [
        row
        for row in policy_mode_breakdown_all
        if isinstance(row, dict) and _to_int(row.get("missing_minimum_behavior_controls_count", 0)) > 0
    ]
    missing_better_minimum_behavior_all_rows = [
        row
        for row in policy_mode_breakdown_all
        if isinstance(row, dict) and _to_int(row.get("missing_better_minimum_behavior_controls_count", 0)) > 0
    ]
    missing_minimum_behavior_count_all = len(missing_minimum_behavior_all_rows)
    missing_better_minimum_behavior_count_all = len(missing_better_minimum_behavior_all_rows)
    monitor_heavy_count_all = len(policy_efficacy.get("monitor_heavy_policy_groups", []) or [])
    p1_bypass_count_all = len(permissions_audit.get("p1_policies", []) or [])
    p2_bypass_count_all = len(permissions_audit.get("p2_policies", []) or [])
    drift_detected_all = bool(policy_drift.get("drift_detected", False))

    fully_alert_only_count = _count_scoped(core_prevention.get("fully_alert_only_policies", []))
    missing_required_count = _count_scoped(core_prevention.get("policies_with_missing_required_controls", []))
    enforcement_gap_count = _count_scoped(core_prevention.get("policies_with_enforcement_gaps", []))
    missing_minimum_behavior_count = _count_scoped(missing_minimum_behavior_all_rows)
    missing_better_minimum_behavior_count = _count_scoped(missing_better_minimum_behavior_all_rows)
    monitor_heavy_count = _count_scoped(policy_efficacy.get("monitor_heavy_policy_groups", []))
    p1_bypass_count = _count_scoped(permissions_audit.get("p1_policies", []))
    p2_bypass_count = _count_scoped(permissions_audit.get("p2_policies", []))

    drift_details = policy_drift.get("changed_policy_details", [])
    if use_assigned_scope and isinstance(drift_details, list):
        drift_detected = any(isinstance(item, dict) and _policy_id(item) in assigned_policy_ids for item in drift_details)
    else:
        drift_detected = drift_detected_all

    good_pass = (
        total_rules_scored > 0
        and fully_alert_only_count == 0
        and missing_required_count == 0
        and missing_minimum_behavior_count == 0
    )

    monitor_heavy_ratio = (monitor_heavy_count / total_policies_scored) if total_policies_scored > 0 else 0.0
    better_pass = (
        good_pass
        and missing_better_minimum_behavior_count == 0
        and p1_bypass_count == 0
        and monitor_heavy_ratio <= 0.2
    )

    path_based_policy_rules = _to_int(policy_posture.get("path_based_policy_rules", 0))
    best_pass = (
        better_pass
        and p2_bypass_count == 0
        and monitor_heavy_count == 0
        and not drift_detected
        and path_based_policy_rules >= 5
    )

    if best_pass:
        current_tier = "best"
    elif better_pass:
        current_tier = "better"
    elif good_pass:
        current_tier = "good"
    else:
        current_tier = "weak"

    # Normalize penalties by assigned-policy scope so the score degrades
    # proportionally instead of collapsing to zero in medium-size tenants.
    policy_scope = max(total_policies_scored, 1)
    score = 100.0
    score -= min(25.0, 25.0 * (fully_alert_only_count / policy_scope))
    score -= min(25.0, 25.0 * (missing_required_count / policy_scope))
    score -= min(20.0, 20.0 * (missing_minimum_behavior_count / policy_scope))
    score -= min(10.0, 10.0 * (missing_better_minimum_behavior_count / policy_scope))
    score -= min(12.0, 12.0 * (p1_bypass_count / policy_scope))
    score -= min(8.0, 8.0 * (p2_bypass_count / policy_scope))
    if path_based_policy_rules < 5:
        score -= min(8.0, 8.0 * ((5 - path_based_policy_rules) / 5.0))
    if monitor_heavy_ratio > 0.2:
        score -= min(12.0, 12.0 * ((monitor_heavy_ratio - 0.2) / 0.8))
    if drift_detected:
        score -= 5.0
    score = max(min(score, 100.0), 0.0)
    score = int(round(score))

    top_gaps: list[str] = []
    next_actions: list[str] = []

    if fully_alert_only_count_all > 0:
        top_gaps.append(f"{fully_alert_only_count_all} policies are fully alert-only (monitor without block rules) across all policies")
        next_actions.append("Use Test Rule first, then move alert-only controls to DENY/TERMINATE where business impact is acceptable")
    if missing_required_count_all > 0:
        top_gaps.append(f"{missing_required_count_all} policies are missing one or more required block controls across all policies")
        next_actions.append("Use Test Rule and close required control gaps for known malware, suspected malware, adware/PUP, unknown, and not listed app controls")
    if missing_minimum_behavior_count_all > 0:
        top_gaps.append(
            f"{missing_minimum_behavior_count_all} policies are missing GOOD minimum behavior controls for Unknown or Not Listed app categories"
        )
        next_actions.append(
            "For GOOD baseline, run Test Rule then enforce DENY/TERMINATE for Performs ransomware-like behavior and Scrapes memory of another process on Unknown and Not listed categories"
        )
    if missing_better_minimum_behavior_count_all > 0:
        top_gaps.append(
            f"{missing_better_minimum_behavior_count_all} policies are missing BETTER minimum behavior controls for Unknown or Not Listed app categories"
        )
        next_actions.append(
            "For BETTER baseline, run Test Rule then enforce DENY/TERMINATE for Unknown: Executes code from memory and Communicates over the network; Not listed: Invokes an untrusted process and Executes code from memory"
        )
    monitor_heavy_ratio_all = (monitor_heavy_count_all / total_policies_all) if total_policies_all > 0 else 0.0
    if monitor_heavy_ratio_all > 0.2:
        top_gaps.append(f"{monitor_heavy_count_all} policy groups remain monitor-heavy across all policies")
        next_actions.append("Harden monitor-heavy groups in stages using device-group pilots before broad rollout")
    if p1_bypass_count_all > 0:
        top_gaps.append(f"{p1_bypass_count_all} policies contain highly permissive BYPASS wildcard path rules across all policies")
        next_actions.append("Narrow broad BYPASS path scopes to least privilege and replace with explicit allow patterns")
    if p2_bypass_count_all > 0 and p1_bypass_count_all == 0:
        top_gaps.append(f"{p2_bypass_count_all} policies contain risky BYPASS wildcard path rules across all policies")
    if path_based_policy_rules < 5:
        top_gaps.append(
            f"Only {path_based_policy_rules} path-based policy rules detected; BEST minimum requires at least 5 NAME_PATH rules"
        )
        next_actions.append("Add at least five policy path-based rules (application.type = NAME_PATH) to satisfy BEST minimum criteria")
    if drift_detected_all:
        top_gaps.append("Policy drift detected since last run (all policies scope)")
        next_actions.append("Add a formal quarterly or bi-annual policy tuning review and change-approval validation")

    if not next_actions:
        next_actions.append("Maintain quarterly or bi-annual policy tuning reviews and continue using Test Rule before production enforcement changes")

    def _missing_required_control_actions(missing_controls: list[str]) -> list[str]:
        if not missing_controls:
            return [
                "Use Test Rule on a pilot group and enable missing required controls with DENY/TERMINATE after validation"
            ]

        actions: list[str] = []
        for control in missing_controls:
            label = str(control).strip().lower()
            if not label:
                continue

            if "known malware" in label:
                actions.append(
                    "Known malware: run Test Rule for 'Runs or is running', then set action to DENY (or TERMINATE per org standard)"
                )
            elif "company banned list" in label:
                actions.append(
                    "Application on company banned list: run Test Rule for 'Runs or is running', then set action to DENY (or TERMINATE per org standard)"
                )
            elif "unknown" in label:
                actions.append(
                    "Unknown application/process: run Test Rule, then ensure DENY/TERMINATE at minimum for Performs ransomware-like behavior and Scrapes memory of another process"
                )
            elif "not listed" in label or "adaptive" in label:
                actions.append(
                    "Not listed application: run Test Rule, then ensure DENY/TERMINATE at minimum for Performs ransomware-like behavior and Scrapes memory of another process"
                )
            elif "adware" in label or "pup" in label:
                actions.append(
                    "Adware/PUP: run Test Rule for 'Runs or is running', then set action to DENY (or TERMINATE per org standard)"
                )
            elif "suspected malware" in label:
                actions.append(
                    "Suspected malware: run Test Rule for 'Runs or is running', then set action to DENY (or TERMINATE per org standard)"
                )
            else:
                actions.append(
                    f"{control}: run Test Rule first, then enforce targeted operation attempts with DENY/TERMINATE after validation"
                )
        return actions

    policy_name_by_id: dict[str, str] = {}
    assigned_endpoints_by_id: dict[str, int] = {}
    if isinstance(policies, list):
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            pid = _policy_id(policy)
            if not pid:
                continue
            policy_name_by_id[pid] = str(_pick_value(policy, ["name", "policy_name"], "unknown"))
            assigned_endpoints_by_id[pid] = _policy_assigned_endpoints(policy)

    mode_by_policy_id: dict[str, dict[str, Any]] = {}
    for row in core_prevention.get("policy_mode_breakdown", []) or []:
        if not isinstance(row, dict):
            continue
        pid = _policy_id(row)
        if not pid:
            continue
        mode_by_policy_id[pid] = row

    efficacy_by_policy_id: dict[str, dict[str, Any]] = {}
    for row in policy_efficacy.get("policy_group_breakdown", []) or []:
        if not isinstance(row, dict):
            continue
        pid = _policy_id(row)
        if not pid:
            continue
        efficacy_by_policy_id[pid] = row

    p1_policy_ids = {
        _policy_id(item)
        for item in (permissions_audit.get("p1_policies", []) or [])
        if isinstance(item, dict) and _policy_id(item)
    }
    p2_policy_ids = {
        _policy_id(item)
        for item in (permissions_audit.get("p2_policies", []) or [])
        if isinstance(item, dict) and _policy_id(item)
    }
    drifted_policy_ids = {
        _policy_id(item)
        for item in (policy_drift.get("changed_policy_details", []) or [])
        if isinstance(item, dict) and _policy_id(item)
    }

    all_policy_ids: set[str] = set(policy_name_by_id.keys())
    all_policy_ids.update(mode_by_policy_id.keys())
    all_policy_ids.update(efficacy_by_policy_id.keys())
    all_policy_ids.update(p1_policy_ids)
    all_policy_ids.update(p2_policy_ids)
    all_policy_ids.update(drifted_policy_ids)

    def _next_level_plan(pid: str) -> dict[str, Any]:
        mode_row = mode_by_policy_id.get(pid, {})
        efficacy_row = efficacy_by_policy_id.get(pid, {})

        monitor_rules = _to_int(mode_row.get("monitor_rules", efficacy_row.get("monitor_rules", 0)))
        block_rules = _to_int(mode_row.get("block_rules", efficacy_row.get("block_rules", 0)))
        unknown_rules = _to_int(mode_row.get("unknown_rules", efficacy_row.get("unknown_rules", 0)))
        total_rules = monitor_rules + block_rules + unknown_rules
        missing_required_controls_count = _to_int(mode_row.get("missing_required_controls_count", 0))
        missing_required_controls = mode_row.get("missing_required_controls", [])
        if not isinstance(missing_required_controls, list):
            missing_required_controls = []
        missing_minimum_behavior_controls_count = _to_int(mode_row.get("missing_minimum_behavior_controls_count", 0))
        missing_minimum_behavior_controls = mode_row.get("missing_minimum_behavior_controls", [])
        if not isinstance(missing_minimum_behavior_controls, list):
            missing_minimum_behavior_controls = []
        missing_better_minimum_behavior_controls_count = _to_int(
            mode_row.get("missing_better_minimum_behavior_controls_count", 0)
        )
        missing_better_minimum_behavior_controls = mode_row.get("missing_better_minimum_behavior_controls", [])
        if not isinstance(missing_better_minimum_behavior_controls, list):
            missing_better_minimum_behavior_controls = []
        monitor_ratio_policy = float(efficacy_row.get("monitor_ratio", mode_row.get("monitor_ratio", 0.0)) or 0.0)
        has_p1 = pid in p1_policy_ids
        has_p2 = pid in p2_policy_ids
        is_drifted = pid in drifted_policy_ids
        fully_alert_only = monitor_rules > 0 and block_rules == 0

        good_gate = (
            total_rules > 0
            and (not fully_alert_only)
            and missing_required_controls_count == 0
            and missing_minimum_behavior_controls_count == 0
        )
        better_gate = (
            good_gate
            and missing_better_minimum_behavior_controls_count == 0
            and (not has_p1)
            and monitor_ratio_policy <= 0.2
        )
        best_gate = (
            better_gate
            and (not has_p2)
            and monitor_rules == 0
            and (not is_drifted)
            and path_based_policy_rules >= 5
        )

        if best_gate:
            tier = "best"
            next_target = "maintain"
            actions = ["Maintain current posture; continue quarterly/bi-annual review and Test Rule validation before major changes"]
        elif better_gate:
            tier = "better"
            next_target = "best"
            actions: list[str] = []
            if has_p2:
                actions.append(
                    "Review P2 BYPASS rules and narrow scope to specific binaries, extensions, and explicit least-privilege paths"
                )
            if monitor_rules > 0:
                actions.append("Use Test Rule to validate residual monitor-only rules, then convert validated high-risk behavior to DENY/TERMINATE")
            if is_drifted:
                actions.append("Review and approve drifted policy changes before promotion to BEST")
            if path_based_policy_rules < 5:
                actions.append("Add at least five path-based policy rules (application.type = NAME_PATH) to satisfy BEST minimum criteria")
            if not actions:
                actions.append("Sustain BETTER controls and tighten residual monitor behavior to reach BEST")
        elif good_gate:
            tier = "good"
            next_target = "better"
            actions = []
            if has_p1:
                actions.append(
                    "Review P1 BYPASS rules and narrow scope to specific binaries, extensions, and explicit least-privilege paths"
                )
            if monitor_ratio_policy > 0.2:
                actions.append("Use Test Rule to reduce monitor-heavy behavior and move validated high-risk operations to DENY/TERMINATE until monitor ratio is <= 20%")
            if missing_better_minimum_behavior_controls_count > 0:
                actions.extend(
                    [
                        "Unknown application/process: run Test Rule, then set DENY/TERMINATE for Executes code from memory and Communicates over the network",
                        "Not listed application: run Test Rule, then set DENY/TERMINATE for Invokes an untrusted process and Executes code from memory",
                    ]
                )
            if not actions:
                actions.append("Continue progressive hardening with staged test groups to reach BETTER")
        else:
            tier = "weak"
            next_target = "good"
            actions = []
            if total_rules <= 0:
                actions.append("Define baseline prevention rules for this policy")
            if fully_alert_only:
                actions.append("Run Test Rule on current monitor-only behaviors, then convert validated high-risk operations to DENY/TERMINATE")
            if missing_required_controls_count > 0:
                actions.extend(_missing_required_control_actions(missing_required_controls))
            if missing_minimum_behavior_controls_count > 0:
                actions.append(
                    "For Unknown application/process and Not listed application, run Test Rule and set DENY/TERMINATE at minimum for: Performs ransomware-like behavior; Scrapes memory of another process"
                )
            if missing_better_minimum_behavior_controls_count > 0:
                actions.append(
                    "For BETTER readiness, run Test Rule then enforce Unknown: Executes code from memory + Communicates over the network; Not listed: Invokes an untrusted process + Executes code from memory"
                )
            if has_p1:
                actions.append(
                    "Review critical P1 BYPASS wildcard rules and narrow scope to specific binaries, extensions, and explicit paths"
                )
            if not actions:
                actions.append("Close GOOD-gate gaps using staged Test Rule rollout and least-privilege tuning")

        return {
            "policy_id": pid,
            "policy_name": policy_name_by_id.get(pid, mode_row.get("policy_name", efficacy_row.get("policy_name", "unknown"))),
            "assigned_endpoints": int(assigned_endpoints_by_id.get(pid, 0)),
            "current_tier": tier,
            "next_target": next_target,
            "actions": actions,
            "action_count": len(actions),
            "needs_attention": tier != "best",
        }

    policy_maturity_all = [_next_level_plan(pid) for pid in all_policy_ids]
    tier_rank = {"weak": 0, "good": 1, "better": 2, "best": 3}
    policy_maturity_all.sort(
        key=lambda row: (
            tier_rank.get(str(row.get("current_tier", "best")), 3),
            -int(row.get("assigned_endpoints", 0)),
            str(row.get("policy_name", "")).lower(),
        )
    )
    policy_maturity_attention = [row for row in policy_maturity_all if bool(row.get("needs_attention", False))]

    return {
        "framework": "Broadcom Endpoint Standard Good-Better-Best",
        "reference_url": "https://techdocs.broadcom.com/us/en/carbon-black/cloud/cloud-best-practices/index/cbc-tile-bp-tuning-es-policy.html",
        "framework_applicable": True,
        "current_tier": current_tier,
        "score_0_100": score,
        "review_cadence": "quarterly_or_biannual",
        "tier_score_scope": "assigned_policies_only",
        "metrics": {
            "total_policies": total_policies_scored,
            "total_policies_scored": total_policies_scored,
            "total_policies_all": total_policies_all,
            "assigned_policy_count": len(assigned_policy_ids),
            "total_rules": total_rules_scored,
            "total_rules_scored": total_rules_scored,
            "fully_alert_only_policies": fully_alert_only_count,
            "fully_alert_only_policies_all": fully_alert_only_count_all,
            "policies_with_missing_required_controls": missing_required_count,
            "policies_with_missing_required_controls_all": missing_required_count_all,
            "policies_with_enforcement_gaps": enforcement_gap_count,
            "policies_with_enforcement_gaps_all": enforcement_gap_count_all,
            "monitor_heavy_policy_groups": monitor_heavy_count,
            "monitor_heavy_ratio": round(monitor_heavy_ratio, 4),
            "monitor_heavy_policy_groups_all": monitor_heavy_count_all,
            "monitor_heavy_ratio_all": round(monitor_heavy_ratio_all, 4),
            "policies_missing_minimum_behavior_controls": missing_minimum_behavior_count,
            "policies_missing_minimum_behavior_controls_all": missing_minimum_behavior_count_all,
            "policies_missing_better_minimum_behavior_controls": missing_better_minimum_behavior_count,
            "policies_missing_better_minimum_behavior_controls_all": missing_better_minimum_behavior_count_all,
            "permissions_audit_p1_policies": p1_bypass_count,
            "permissions_audit_p2_policies": p2_bypass_count,
            "permissions_audit_p1_policies_all": p1_bypass_count_all,
            "permissions_audit_p2_policies_all": p2_bypass_count_all,
            "policy_drift_detected": drift_detected,
            "policy_drift_detected_all": drift_detected_all,
            "path_based_policy_rules": path_based_policy_rules,
        },
        "gates": {
            "good": {
                "pass": good_pass,
                "criteria": "No fully alert-only policies, no missing required blocking controls, and no missing GOOD minimum behavior controls",
            },
            "better": {
                "pass": better_pass,
                "criteria": "Good gate plus no missing BETTER minimum behavior controls, no P1 BYPASS wildcard issues, and <=20% monitor-heavy policy groups",
            },
            "best": {
                "pass": best_pass,
                "criteria": "Better gate plus at least 5 NAME_PATH rules, no P2 BYPASS wildcard issues, no monitor-heavy groups, and no unreviewed drift",
            },
        },
        "top_gaps": top_gaps[:6],
        "next_actions": next_actions[:6],
        "policy_maturity_action_plan": policy_maturity_attention,
        "policy_maturity_action_plan_all": policy_maturity_all,
        "policy_maturity_attention_count": len(policy_maturity_attention),
    }


def health_score(
    device_summary: dict[str, Any],
    alert_summary: dict[str, Any],
    policy_summary: dict[str, Any] | None = None,
    watchlist_summary: dict[str, Any] | None = None,
    policy_tuning_summary: dict[str, Any] | None = None,
    watchlist_effectiveness_summary: dict[str, Any] | None = None,
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

    total_alerts = int(alert_summary.get("total_alerts_30d", 0))
    severity_breakdown = alert_summary.get("severity_breakdown", {})
    low_severity_alerts = 0
    if isinstance(severity_breakdown, dict):
        for sev_key, count in severity_breakdown.items():
            try:
                sev = int(str(sev_key).strip())
                sev_count = int(float(count))
            except Exception:
                continue
            if sev < 5 and sev_count > 0:
                low_severity_alerts += sev_count

    # Penalize noisy low-value alert composition only when alert volume is material.
    low_severity_ratio = (low_severity_alerts / total_alerts) if total_alerts > 0 else 0.0
    if total_alerts >= 200:
        if low_severity_ratio >= 0.75:
            score -= 6 if is_lab else 12
            notes.append("Disproportionately high share of sub-5 severity alerts")
        elif low_severity_ratio >= 0.6:
            score -= 3 if is_lab else 6
            notes.append("Elevated share of sub-5 severity alerts")

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

    base_score = max(score, 0)

    # Blend operational health with policy maturity and watchlist effectiveness.
    # The base operational score remains dominant, while policy/watchlist quality
    # materially affects the final health result when available.
    policy_maturity_score: int | None = None
    watchlist_effectiveness_score: int | None = None
    policy_maturity_weight = 0.0
    watchlist_effectiveness_weight = 0.0
    base_weight = 1.0

    if isinstance(policy_tuning_summary, dict):
        framework_applicable = bool(policy_tuning_summary.get("framework_applicable", False))
        maturity_raw = policy_tuning_summary.get("score_0_100")
        try:
            maturity_value = int(float(maturity_raw))
        except Exception:
            maturity_value = None

        if framework_applicable and maturity_value is not None:
            policy_maturity_score = max(min(maturity_value, 100), 0)
            policy_maturity_weight = 0.25

    if isinstance(watchlist_effectiveness_summary, dict):
        effectiveness_raw = watchlist_effectiveness_summary.get("score_0_100")
        try:
            effectiveness_value = int(float(effectiveness_raw))
        except Exception:
            effectiveness_value = None
        if effectiveness_value is not None:
            watchlist_effectiveness_score = max(min(effectiveness_value, 100), 0)
            watchlist_effectiveness_weight = 0.20

    if policy_maturity_weight > 0.0 or watchlist_effectiveness_weight > 0.0:
        base_weight = 1.0 - policy_maturity_weight - watchlist_effectiveness_weight
        composite_score = base_score * base_weight
        if policy_maturity_score is not None and policy_maturity_weight > 0.0:
            composite_score += policy_maturity_score * policy_maturity_weight
        if watchlist_effectiveness_score is not None and watchlist_effectiveness_weight > 0.0:
            composite_score += watchlist_effectiveness_score * watchlist_effectiveness_weight
        score = int(round(composite_score))

        component_notes = [f"{int(round(base_weight * 100))}% operational health ({base_score}/100)"]
        if policy_maturity_score is not None and policy_maturity_weight > 0.0:
            component_notes.append(f"{int(round(policy_maturity_weight * 100))}% policy maturity ({policy_maturity_score}/100)")
        if watchlist_effectiveness_score is not None and watchlist_effectiveness_weight > 0.0:
            component_notes.append(
                f"{int(round(watchlist_effectiveness_weight * 100))}% watchlist effectiveness ({watchlist_effectiveness_score}/100)"
            )
        notes.append("Composite scoring applied: " + " + ".join(component_notes))
    else:
        score = base_score

    if score >= 85:
        status = "good"
    elif score >= 65:
        status = "watch"
    else:
        status = "at_risk"

    return {
        "score": score,
        "status": status,
        "notes": notes,
        "assessment_profile": assessment_profile,
        "base_score": base_score,
        "policy_maturity_score": policy_maturity_score,
        "watchlist_effectiveness_score": watchlist_effectiveness_score,
        "base_weight": round(base_weight, 4),
        "policy_maturity_weight": policy_maturity_weight,
        "watchlist_effectiveness_weight": watchlist_effectiveness_weight,
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
    policy_tuning = checks.get("policy_tuning_analysis", {}).get("summary", {})
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
        active_endpoints = sum(int(status_counts.get(status, 0)) for status in ACTIVE_ENDPOINT_STATUSES)
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
        user_details = user_logins.get("dormant_over_60d_details", [])
        if isinstance(user_details, list) and user_details:
            sample_details = user_details[:5]
            names = [
                f"{str(item.get('user', 'unknown'))} ({str(item.get('role', 'unknown'))})"
                for item in sample_details
                if isinstance(item, dict)
            ]
            names_str = ", ".join(names) + (" ..." if len(user_details) > 5 else "")
        else:
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
        user_details = user_logins.get("dormant_over_30d_details", [])
        if isinstance(user_details, list) and user_details:
            sample_details = user_details[:5]
            names = [
                f"{str(item.get('user', 'unknown'))} ({str(item.get('role', 'unknown'))})"
                for item in sample_details
                if isinstance(item, dict)
            ]
            names_str = ", ".join(names) + (" ..." if len(user_details) > 5 else "")
        else:
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
                        "Use Test Rule first, then enforce validated high-risk behavior with DENY/TERMINATE and close missing-control gaps where the environment allows."
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

    if isinstance(policy_tuning, dict) and policy_tuning.get("framework_applicable", False):
        tier = str(policy_tuning.get("current_tier", "weak"))
        if tier != "best":
            top_gaps = policy_tuning.get("top_gaps", [])
            gap_hint = "; ".join([str(item) for item in top_gaps[:2]]) if isinstance(top_gaps, list) else ""
            tier_priority = {
                "weak": "P1",
                "good": "P1",
                "better": "P3",
            }.get(tier, "P3")
            recs.append(
                {
                    "priority": tier_priority,
                    "area": "Policy Tuning",
                    "recommendation": (
                        "Advance Endpoint Standard policy maturity using the Good/Better/Best framework "
                        "with staged testing and least-privilege hardening."
                    ),
                    "evidence": (
                        f"current_tier={tier}, score_0_100={policy_tuning.get('score_0_100', 'n/a')}"
                        + (f", gaps={gap_hint}" if gap_hint else "")
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
