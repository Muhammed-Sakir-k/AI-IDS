import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

_geo_cache = {}
_geo_failures = {}


def get_geo(ip):
    # Skip private/local IPs
    private_prefixes = (
        "192.168.", "10.", "172.16.", "172.17.",
        "172.18.", "172.19.", "172.20.", "172.21.",
        "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "127.", "0.", "::1"
    )
    if any(ip.startswith(p) for p in private_prefixes):
        return None

    if ip in _geo_cache:
        return _geo_cache[ip]
    if time.monotonic() - _geo_failures.get(ip, 0) < 30:
        return None

    try:
        response = requests.get(
            f"https://ipwho.is/{ip}",
            timeout=3
        )

        # Rate-limited or empty body — don't call .json() on it
        if response.status_code != 200 or not response.text.strip():
            print(f"[GEO] Empty/bad response for {ip} (status {response.status_code})")
            _geo_failures[ip] = time.monotonic()
            return None

        data = response.json()

        if data.get("success", True):
            connection = data.get("connection") or {}
            result = {
                "ip":      ip,
                "country": data.get("country", "Unknown"),
                "city":    data.get("city", "Unknown"),
                "isp":     connection.get("isp", "Unknown"),
                "lat":     data.get("latitude", 0),
                "lon":     data.get("longitude", 0),
                "flag":    data.get("country_code", "").lower()
            }
            _geo_cache[ip] = result
            _geo_failures.pop(ip, None)
            return result
        else:
            # e.g. status == "fail" (invalid IP, reserved range, etc.)
            _geo_failures[ip] = time.monotonic()
            return None

    except (requests.exceptions.RequestException, ValueError) as e:
        print(f"[GEO] Lookup failed for {ip}: {e}")
        _geo_failures[ip] = time.monotonic()
        return None


def get_geo_bulk(ip_list, limit=20):
    """Resolve a bounded set of IPs without blocking the dashboard per IP.

    Geo data is supplementary, so a slow external API must never hold up the
    entire dashboard. Results and failures remain cached by ``get_geo``.
    """
    unique_ips = list(dict.fromkeys(str(ip) for ip in ip_list if ip))[:limit]
    if not unique_ips:
        return []

    results = []
    with ThreadPoolExecutor(max_workers=min(8, len(unique_ips))) as executor:
        futures = {executor.submit(get_geo, ip): ip for ip in unique_ips}
        for future in as_completed(futures):
            try:
                geo = future.result()
                if geo:
                    results.append(geo)
            except Exception as exc:
                print(f"[GEO] Lookup failed for {futures[future]}: {exc}")
    return results
