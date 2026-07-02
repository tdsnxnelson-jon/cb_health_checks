from __future__ import annotations

import warnings
from dataclasses import dataclass
from typing import Any

import requests
from urllib3.exceptions import InsecureRequestWarning

from cbc_health_cli.models import DEFAULT_BACKENDS


@dataclass
class TenantInfo:
    backend_url: str
    tenant_id: str
    tenant_key: str


class CBCClient:
    def __init__(self, api_id: str, api_key: str, verify_tls: bool = True, timeout_seconds: int = 30):
        self.api_id = api_id
        self.api_key = api_key
        self.verify_tls = verify_tls
        self.timeout_seconds = timeout_seconds
        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-Auth-Token": f"{api_key}/{api_id}",
                "accept": "application/json",
                "Content-Type": "application/json",
            }
        )

    def _get(self, url: str) -> requests.Response:
        response = self._request("GET", url)
        response.raise_for_status()
        return response

    def _post(self, url: str, payload: dict[str, Any]) -> requests.Response:
        response = self._request("POST", url, json=payload)
        response.raise_for_status()
        return response

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        if self.verify_tls:
            return self.session.request(method, url, verify=True, timeout=self.timeout_seconds, **kwargs)

        # Scope warning suppression to insecure requests only.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InsecureRequestWarning)
            return self.session.request(method, url, verify=False, timeout=self.timeout_seconds, **kwargs)

    @staticmethod
    def _extract_list_payload(data: Any) -> list[dict[str, Any]]:
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            for key in (
                "results",
                "entries",
                "items",
                "data",
                "logs",
                "entitlements",
                "products",
                "watchlists",
                "policies",
                "users",
                "overrides",
                "reputations",
            ):
                value = data.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
        return []

    def discover_tenant(self, preferred_backend: str | None = None) -> TenantInfo:
        backends = [preferred_backend] if preferred_backend else DEFAULT_BACKENDS
        last_error: Exception | None = None

        for backend in backends:
            try:
                orgs_url = f"{backend}/appservices/v5/orgs/"
                orgs_data = self._get(orgs_url).json()
                org = orgs_data["organizations"][0]["id"]
                org_url = f"{backend}/appservices/v5/orgs/{org}/"
                org_data = self._get(org_url).json()
                org_key = org_data["organization"]["orgKey"]
                return TenantInfo(backend_url=backend, tenant_id=org, tenant_key=org_key)
            except Exception as exc:
                last_error = exc

        if last_error:
            raise RuntimeError(f"Unable to discover tenant/backend: {last_error}") from last_error
        raise RuntimeError("Unable to discover tenant/backend")

    def get_org_details(self, backend_url: str, tenant_id: str) -> dict[str, Any]:
        url = f"{backend_url}/appservices/v5/orgs/{tenant_id}/"
        return self._get(url).json()

    def get_devices(self, backend_url: str, tenant_key: str, rows: int = 5000) -> list[dict[str, Any]]:
        """Fetch all devices with automatic pagination."""
        url = f"{backend_url}/appservices/v6/orgs/{tenant_key}/devices/_search"
        all_results: list[dict[str, Any]] = []
        page_size = 5000
        start = 0
        max_iterations = 100  # Safety limit: 500k devices max
        iteration = 0

        while iteration < max_iterations:
            payload = {
                "criteria": {},
                "rows": page_size,
                "start": start,
                "sort": [{"field": "last_contact_time", "order": "DESC"}],
            }
            try:
                data = self._post(url, payload).json()
                results = data.get("results", [])
                if not results:
                    break
                all_results.extend(results)
                if len(results) < page_size:
                    break
                start += page_size
                iteration += 1
            except Exception:
                break

        return all_results

    def get_alerts(self, backend_url: str, tenant_key: str, rows: int = 2000) -> tuple[list[dict[str, Any]], int]:
        """Fetch all alerts with automatic pagination. Returns (results, num_found_in_api)."""
        url = f"{backend_url}/api/alerts/v7/orgs/{tenant_key}/alerts/_search"
        all_results: list[dict[str, Any]] = []
        page_size = 2000
        start = 1
        max_iterations = 100  # Safety limit: 200k alerts max
        iteration = 0
        num_found: int = 0

        while iteration < max_iterations:
            payload = {
                "query": "",
                "time_range": {"range": "-180d"},
                "criteria": {
                    "minimum_severity": 1,
                },
                "start": start,
                "rows": page_size,
                "sort": [{"field": "backend_timestamp", "order": "DESC"}],
            }
            try:
                data = self._post(url, payload).json()
                results = data.get("results", [])
                if iteration == 0:
                    num_found = int(data.get("num_found", 0))
                if not results:
                    break
                all_results.extend(results)
                if len(results) < page_size:
                    break
                start += page_size
                iteration += 1
            except Exception:
                break

        return all_results, num_found

    def get_policies(self, backend_url: str, tenant_key: str) -> list[dict[str, Any]]:
        endpoints = [
            f"{backend_url}/policyservice/v1/orgs/{tenant_key}/policies",
            f"{backend_url}/policyservice/v1/orgs/{tenant_key}/policies/summary",
        ]
        last_error: Exception | None = None

        for url in endpoints:
            try:
                data = self._get(url).json()
                if isinstance(data, list):
                    return data
                if isinstance(data, dict):
                    if isinstance(data.get("policies"), list):
                        return data["policies"]
                    if isinstance(data.get("results"), list):
                        return data["results"]
                return []
            except Exception as exc:
                last_error = exc

        if last_error:
            raise RuntimeError(f"Unable to fetch policies: {last_error}") from last_error
        return []

    def get_policy_details(self, backend_url: str, tenant_key: str, policy_id: str) -> dict[str, Any]:
        """Fetch full policy configuration including settings."""
        endpoints = [
            f"{backend_url}/policyservice/v1/orgs/{tenant_key}/policies/{policy_id}",
        ]

        last_error: Exception | None = None
        for url in endpoints:
            try:
                data = self._get(url).json()
                if isinstance(data, dict):
                    return data
            except Exception as exc:
                last_error = exc

        if last_error:
            raise RuntimeError(f"Unable to fetch policy details for {policy_id}: {last_error}") from last_error
        return {}

    def get_data_collection_configs(self, backend_url: str, tenant_key: str) -> list[dict[str, Any]]:
        """Fetch data collection rule configurations (auth events, XDR, etc.)."""
        endpoints = [
            f"{backend_url}/policyservice/v1/orgs/{tenant_key}/rule_configs/data_collection",
        ]

        last_error: Exception | None = None
        for url in endpoints:
            try:
                data = self._get(url).json()
                if isinstance(data, dict) and isinstance(data.get("results"), list):
                    return data["results"]
                if isinstance(data, list):
                    return data
            except Exception as exc:
                last_error = exc

        if last_error:
            raise RuntimeError(f"Unable to fetch data collection configs: {last_error}") from last_error
        return []

    def get_policy_rules(self, backend_url: str, tenant_key: str, policy_id: str) -> list[dict[str, Any]]:
        endpoints = [
            f"{backend_url}/policyservice/v1/orgs/{tenant_key}/policies/{policy_id}/rules",
            f"{backend_url}/policyservice/v1/orgs/{tenant_key}/policies/{policy_id}",
        ]
        last_error: Exception | None = None

        for url in endpoints:
            try:
                data = self._get(url).json()
                if isinstance(data, list):
                    return data
                if isinstance(data, dict):
                    if isinstance(data.get("rules"), list):
                        return data["rules"]
                    if isinstance(data.get("results"), list):
                        return data["results"]
                return []
            except Exception as exc:
                last_error = exc

        if last_error:
            raise RuntimeError(f"Unable to fetch policy rules for {policy_id}: {last_error}") from last_error
        return []

    def get_core_prevention_rules(self, backend_url: str, tenant_key: str, policy_id: str) -> list[dict[str, Any]]:
        url = f"{backend_url}/policyservice/v1/orgs/{tenant_key}/policies/{policy_id}/rule_configs/core_prevention"
        try:
            data = self._get(url).json()
            return self._extract_list_payload(data)
        except Exception as exc:
            raise RuntimeError(
                f"Unable to fetch core prevention rules for {policy_id}: {exc}"
            ) from exc

    def get_watchlists(self, backend_url: str, tenant_key: str) -> list[dict[str, Any]]:
        endpoints = [
            f"{backend_url}/threathunter/watchlistmgr/v3/orgs/{tenant_key}/watchlists",
            f"{backend_url}/threathunter/watchlistsvc/v1/orgs/{tenant_key}/watchlists",
            f"{backend_url}/api/watchlist/v1/orgs/{tenant_key}/watchlists",
        ]
        last_error: Exception | None = None

        for url in endpoints:
            try:
                response = self._get(url)
                data = response.json()
                if isinstance(data, list):
                    return data
                if isinstance(data, dict):
                    if isinstance(data.get("results"), list):
                        return data["results"]
                    if isinstance(data.get("watchlists"), list):
                        return data["watchlists"]
                    if isinstance(data.get("data"), list):
                        return data["data"]
                return []
            except Exception as exc:
                last_error = exc

        if last_error:
            raise RuntimeError(f"Unable to fetch watchlists: {last_error}") from last_error
        return []

    def get_audit_logs(
        self,
        backend_url: str,
        tenant_key: str,
        rows: int = 2000,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch audit logs up to the requested row cap with pagination."""
        normalized_backend = backend_url.rstrip("/")
        org = tenant_key
        target_rows = max(1, rows)

        modern_paths = [
            "/audit_log/v1/orgs/{org}/logs/_search",
            "/auditlog/v1/orgs/{org}/logs/_search",
            "/api/audit_log/v1/orgs/{org}/logs/_search",
        ]
        legacy_paths = [
            "/appservices/v5/orgs/{org}/auditlog/find",
            "/appservices/v6/orgs/{org}/auditlog/find",
        ]

        last_error: Exception | None = None
        last_attempt: str | None = None
        attempt_failures: list[str] = []
        # Modern audit APIs are org-key based.
        for path in modern_paths:
            url = f"{normalized_backend}{path.format(org=org)}"
            for method in ("POST", "GET"):
                try:
                    last_attempt = f"{method} {url}"
                    all_results: list[dict[str, Any]] = []
                    page_size = max(1, min(target_rows, 1000))
                    start = 0
                    max_iterations = 25
                    iteration = 0

                    while iteration < max_iterations and len(all_results) < target_rows:
                        request_rows = min(page_size, target_rows - len(all_results))
                        payload = {
                            "criteria": {},
                            "time_range": {"range": "-30d"},
                            "start": start,
                            "rows": request_rows,
                            "sort": [{"field": "timestamp", "order": "DESC"}],
                        }
                        if method == "POST":
                            response = self._post(url, payload)
                        else:
                            response = self._request("GET", url, params=payload)
                            response.raise_for_status()
                        response_text = (response.text or "").strip()
                        if not response_text:
                            break
                        try:
                            data = response.json()
                        except ValueError as exc:
                            content_type = response.headers.get("Content-Type", "unknown")
                            raise RuntimeError(
                                f"Non-JSON response (status={response.status_code}, content_type={content_type})"
                            ) from exc
                        results = self._extract_list_payload(data)
                        if not results:
                            break
                        all_results.extend(results)
                        if len(results) < request_rows:
                            break
                        start += len(results)
                        iteration += 1

                    if all_results:
                        return all_results[:target_rows]
                    last_error = RuntimeError(f"Audit log endpoint returned zero entries: {method} {url}")
                except Exception as exc:
                    if all_results:
                        return all_results[:target_rows]
                    last_error = exc
                    attempt_failures.append(f"{method} {url} -> {exc}")

        # Legacy appservices audit routes generally expect numeric org id.
        legacy_org_tokens: list[str] = []
        if tenant_id:
            legacy_org_tokens.append(str(tenant_id))
        if tenant_key not in legacy_org_tokens:
            legacy_org_tokens.append(tenant_key)

        for legacy_org in legacy_org_tokens:
            for path in legacy_paths:
                url = f"{normalized_backend}{path.format(org=legacy_org)}"
                for method in ("POST",):
                    try:
                        last_attempt = f"{method} {url}"
                        all_results = []
                        page_size = max(1, min(target_rows, 1000))
                        from_row = 1
                        max_iterations = 25
                        iteration = 0

                        while iteration < max_iterations and len(all_results) < target_rows:
                            request_rows = min(page_size, target_rows - len(all_results))
                            payload = {
                                "version": "1",
                                "fromRow": from_row,
                                "maxRows": request_rows,
                                "searchWindow": "ALL",
                                "sortDefinition": {"fieldName": "TIME", "sortOrder": "DESC"},
                                "criteria": {"FLAGGED_ENTRIES": ["false"], "VERBOSE_ENTRIES": ["false"]},
                                "orgId": legacy_org,
                            }
                            if method == "POST":
                                response = self._post(url, payload)
                            response_text = (response.text or "").strip()
                            if not response_text:
                                break
                            try:
                                data = response.json()
                            except ValueError as exc:
                                content_type = response.headers.get("Content-Type", "unknown")
                                raise RuntimeError(
                                    f"Non-JSON response (status={response.status_code}, content_type={content_type})"
                                ) from exc
                            results = self._extract_list_payload(data)
                            if not results:
                                break
                            all_results.extend(results)
                            if len(results) < request_rows:
                                break
                            from_row += len(results)
                            iteration += 1

                        if all_results:
                            return all_results[:target_rows]
                        last_error = RuntimeError(f"Audit log endpoint returned zero entries: {method} {url}")
                    except Exception as exc:
                        if all_results:
                            return all_results[:target_rows]
                        last_error = exc
                        attempt_failures.append(f"{method} {url} -> {exc}")

        if last_error:
            attempt_context = f" (last attempt: {last_attempt})" if last_attempt else ""
            attempts_context = ""
            if attempt_failures:
                attempts_context = f" (attempts: {' | '.join(attempt_failures[:8])})"
            raise RuntimeError(f"Unable to fetch audit logs: {last_error}{attempt_context}{attempts_context}") from last_error
        return []



    def get_reputation_overrides(
        self, backend_url: str, tenant_key: str, tenant_id: str | None = None
    ) -> list[dict[str, Any]]:
        org_tokens: list[str] = [tenant_key]
        if tenant_id and tenant_id not in org_tokens:
            org_tokens.append(tenant_id)

        requests_to_try: list[tuple[str, str, dict[str, Any] | None]] = []
        for org in org_tokens:
            requests_to_try.extend(
                [
                    (
                        "POST",
                        f"{backend_url}/appservices/v6/orgs/{org}/reputations/overrides/_search",
                        {"criteria": {}, "start": 0, "rows": 1000},
                    ),
                    ("GET", f"{backend_url}/appservices/v6/orgs/{org}/reputations/overrides", None),
                    ("GET", f"{backend_url}/threathunter/feedmgr/v2/orgs/{org}/reports/reputation/overrides", None),
                    ("GET", f"{backend_url}/policyservice/v1/orgs/{org}/reputation/overrides", None),
                ]
            )

        last_error: Exception | None = None
        for method, url, payload in requests_to_try:
            try:
                if method == "POST":
                    data = self._post(url, payload or {}).json()
                else:
                    data = self._get(url).json()
                return self._extract_list_payload(data)
            except Exception as exc:
                last_error = exc

        if last_error:
            raise RuntimeError(f"Unable to fetch reputation overrides: {last_error}") from last_error
        return []

    def get_users(self, backend_url: str, tenant_key: str, rows: int = 10000) -> list[dict[str, Any]]:
        """Fetch all users with automatic pagination."""
        endpoints = [
            f"{backend_url}/appservices/v6/orgs/{tenant_key}/users",
        ]

        last_error: Exception | None = None
        for base_url in endpoints:
            try:
                all_results: list[dict[str, Any]] = []
                page_size = 5000
                start = 0
                max_iterations = 20  # Safety limit: 100k users max
                iteration = 0

                while iteration < max_iterations:
                    url = f"{base_url}?start={start}&rows={page_size}"
                    data = self._get(url).json()
                    results = self._extract_list_payload(data)
                    if not results:
                        break
                    all_results.extend(results)
                    if len(results) < page_size:
                        break
                    start += page_size
                    iteration += 1

                return all_results
            except Exception as exc:
                last_error = exc

        if last_error:
            raise RuntimeError(f"Unable to fetch users: {last_error}") from last_error
        return []

    def probe_product_endpoints(self, backend_url: str, tenant_key: str) -> dict[str, Any]:
        """Probe product endpoints and classify as enabled/not_enabled/unknown.

        Classification rules:
        - enabled: any probe returns HTTP 200
        - not_enabled: at least one probe returns HTTP 403 and no probe returns 200
        - unknown: all other outcomes
        """
        probes: dict[str, list[dict[str, Any]]] = {
            "NGAV": [
                {
                    "method": "GET",
                    "url": f"{backend_url}/appservices/v6/orgs/{tenant_key}/reputations/overrides",
                    "params": {"start": 0, "rows": 1},
                },
                {
                    "method": "GET",
                    "url": f"{backend_url}/policyservice/v1/orgs/{tenant_key}/reputation/overrides",
                    "params": {"start": 0, "rows": 1},
                },
            ],
            "EEDR": [
                {
                    "method": "GET",
                    "url": f"{backend_url}/threathunter/watchlistmgr/v3/orgs/{tenant_key}/watchlists",
                    "params": {"start": 0, "rows": 1},
                },
                {
                    "method": "GET",
                    "url": f"{backend_url}/threathunter/watchlistsvc/v1/orgs/{tenant_key}/watchlists",
                    "params": {"start": 0, "rows": 1},
                },
            ],
            "Live Query": [
                {
                    "method": "GET",
                    "url": f"{backend_url}/appservices/v6/orgs/{tenant_key}/livequery/sessions",
                    "params": {"start": 0, "rows": 1},
                },
                {
                    "method": "GET",
                    "url": f"{backend_url}/appservices/v6/orgs/{tenant_key}/livequery/scheduled_queries",
                    "params": {"start": 0, "rows": 1},
                },
            ],
            "Vulnerability Management": [
                {
                    "method": "GET",
                    "url": f"{backend_url}/appservices/v6/orgs/{tenant_key}/vulnerability/summary",
                    "params": None,
                },
                {
                    "method": "GET",
                    "url": f"{backend_url}/vulnerability/assessment/api/v1/orgs/{tenant_key}/summary",
                    "params": None,
                },
            ],
            "HBFW": [
                {
                    "method": "GET",
                    "url": f"{backend_url}/policyservice/v1/orgs/{tenant_key}/rule_configs/firewall",
                    "params": None,
                },
                {
                    "method": "GET",
                    "url": f"{backend_url}/policyservice/v1/orgs/{tenant_key}/firewall/rules",
                    "params": None,
                },
            ],
            "Workloads": [
                {
                    "method": "GET",
                    "url": f"{backend_url}/appservices/v6/orgs/{tenant_key}/workloads",
                    "params": {"start": 0, "rows": 1},
                },
                {
                    "method": "GET",
                    "url": f"{backend_url}/appservices/v6/orgs/{tenant_key}/inventory/workloads",
                    "params": {"start": 0, "rows": 1},
                },
            ],
        }

        product_results: dict[str, Any] = {}
        detected_products: list[str] = []

        for product, probe_list in probes.items():
            attempts: list[dict[str, Any]] = []
            product_detected = False
            saw_403 = False
            saw_400 = False
            for probe in probe_list:
                method = str(probe["method"])
                url = str(probe["url"])
                params = probe.get("params")
                status: int | None = None
                error: str | None = None
                try:
                    if method == "GET":
                        response = self._request("GET", url, params=params)
                    else:
                        response = self._request(method, url)
                    status = int(response.status_code)
                except Exception as exc:
                    error = str(exc)

                attempts.append(
                    {
                        "method": method,
                        "url": url,
                        "status_code": status,
                        "error": error,
                    }
                )

                if status == 200:
                    product_detected = True
                if status == 400:
                    saw_400 = True
                if status == 403:
                    saw_403 = True

            if product_detected:
                classification = "enabled"
            elif product == "HBFW" and saw_400 and not saw_403:
                # Super-admin heuristic: HBFW endpoint responded but rejected the request shape.
                # Treat as enabled unless license gating returns 403.
                classification = "enabled_via_400"
                product_detected = True
            elif saw_403:
                classification = "not_enabled"
            else:
                classification = "unknown"

            product_results[product] = {
                "detected": product_detected,
                "classification": classification,
                "probes": attempts,
            }
            if product_detected:
                detected_products.append(product)

        return {
            "detected_products": detected_products,
            "products": product_results,
        }
