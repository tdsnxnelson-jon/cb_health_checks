from dataclasses import dataclass
from pathlib import Path


DEFAULT_BACKENDS = [
    "https://dashboard.confer.net",
    "https://defense.conferdeploy.net",
    "https://defense-prod05.conferdeploy.net",
    "https://defense-eu.conferdeploy.net",
    "https://defense-prodsyd.conferdeploy.net",
    "https://defense-eap01.conferdeploy.net",
]


@dataclass
class AppConfig:
    customer_name: str
    api_id: str
    api_key: str
    backend_url: str | None
    tenant_id: str | None
    tenant_key: str | None
    output_dir: Path
    verify_tls: bool
    timeout_seconds: int
    assessment_profile: str
    # Optional explicit product override. If omitted, products are auto-detected at runtime.
    products: list[str] | None = None
    # None = auto-detect from org data; True/False = explicit override
    ngav_enabled: bool | None = None
    # Optional SOC capacity overrides used in alert volume recommendation logic.
    soc_analysts: int | None = None
    alerts_per_analyst_per_shift: int = 80
    alert_volume_avg_daily_threshold: int = 1000
    alert_volume_peak_daily_threshold: int = 1500
