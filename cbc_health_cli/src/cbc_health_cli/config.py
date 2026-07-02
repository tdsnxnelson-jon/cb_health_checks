from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cbc_health_cli.models import AppConfig

try:
    import yaml  # type: ignore
except Exception:
    yaml = None


def _read_config_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(raw)
    else:
        if yaml is None:
            raise ValueError(
                "YAML config requested but PyYAML is not installed. Use JSON config or install PyYAML."
            )
        data = yaml.safe_load(raw)

    if not isinstance(data, dict):
        raise ValueError("Config must be a JSON/YAML object")
    return data


def load_app_config(config_path: Path | None, overrides: dict[str, Any]) -> AppConfig:
    file_data: dict[str, Any] = {}
    if config_path:
        file_data = _read_config_file(config_path)

    merged: dict[str, Any] = {**file_data}
    for key, value in overrides.items():
        if value is not None:
            merged[key] = value

    missing = [k for k in ("customer_name", "api_id", "api_key") if not merged.get(k)]
    if missing:
        raise ValueError(f"Missing required fields: {', '.join(missing)}")

    # Validate and normalize products when explicitly provided.
    VALID_PRODUCTS = {"NGAV", "EEDR", "Live Query", "XDR", "Vulnerability Management", "HBFW", "Workloads"}
    products: list[str] | None = None
    products_raw = merged.get("products")
    if products_raw is not None:
        if not isinstance(products_raw, list):
            raise ValueError("products must be a list")
        if not products_raw:
            # Treat an empty list like omitted/null to keep auto-detection behavior.
            products_raw = None
        else:
            products = []
            for p in products_raw:
                p_str = str(p).strip()
                if p_str not in VALID_PRODUCTS:
                    raise ValueError(f"Invalid product: '{p_str}'. Valid products are: {', '.join(sorted(VALID_PRODUCTS))}")
                if p_str not in products:
                    products.append(p_str)

    output_dir = Path(str(merged.get("output_dir", "output")))
    verify_tls = bool(merged.get("verify_tls", True))
    timeout_seconds = int(merged.get("timeout_seconds", 30))
    assessment_profile = str(merged.get("assessment_profile", "prod")).strip().lower()
    if assessment_profile not in {"prod", "lab"}:
        raise ValueError("assessment_profile must be either 'prod' or 'lab'")
    # None = auto-detect from org data at runtime; True/False = explicit override
    ngav_enabled_raw = merged.get("ngav_enabled")
    ngav_enabled: bool | None = bool(ngav_enabled_raw) if ngav_enabled_raw is not None else None

    soc_analysts_raw = merged.get("soc_analysts")
    soc_analysts: int | None = int(soc_analysts_raw) if soc_analysts_raw is not None else None
    alerts_per_analyst_per_shift = int(merged.get("alerts_per_analyst_per_shift", 80))
    alert_volume_avg_daily_threshold = int(merged.get("alert_volume_avg_daily_threshold", 1000))
    alert_volume_peak_daily_threshold = int(merged.get("alert_volume_peak_daily_threshold", 1500))

    if soc_analysts is not None and soc_analysts <= 0:
        raise ValueError("soc_analysts must be > 0 when provided")
    if alerts_per_analyst_per_shift <= 0:
        raise ValueError("alerts_per_analyst_per_shift must be > 0")
    if alert_volume_avg_daily_threshold <= 0:
        raise ValueError("alert_volume_avg_daily_threshold must be > 0")
    if alert_volume_peak_daily_threshold <= 0:
        raise ValueError("alert_volume_peak_daily_threshold must be > 0")

    return AppConfig(
        customer_name=str(merged["customer_name"]),
        api_id=str(merged["api_id"]),
        api_key=str(merged["api_key"]),
        backend_url=merged.get("backend_url"),
        tenant_id=merged.get("tenant_id"),
        tenant_key=merged.get("tenant_key"),
        output_dir=output_dir,
        verify_tls=verify_tls,
        timeout_seconds=timeout_seconds,
        assessment_profile=assessment_profile,
        products=products,
        ngav_enabled=ngav_enabled,
        soc_analysts=soc_analysts,
        alerts_per_analyst_per_shift=alerts_per_analyst_per_shift,
        alert_volume_avg_daily_threshold=alert_volume_avg_daily_threshold,
        alert_volume_peak_daily_threshold=alert_volume_peak_daily_threshold,
    )
