from __future__ import annotations

import ipaddress
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from .scanner import NetworkScanner


def group_ips_by_subnet(ips: list[str], prefixlen: int) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = defaultdict(list)
    for ip in ips:
        try:
            interface = ipaddress.ip_interface(f"{ip}/{prefixlen}")
            network = interface.network
            buckets[str(network)].append(ip)
        except ValueError:
            buckets[ip].append(ip)
    return dict(buckets)


def batch_nmap_scan(
    scanner: NetworkScanner,
    ips: list[str],
    profile: str,
    speed: str,
    *,
    prefixlen: int = 24,
    parallel_workers: int = 4,
) -> dict[str, tuple[bool, list[int]]]:
    """Scan many hosts using per-subnet nmap invocations with limited parallelism."""
    if not ips:
        return {}

    buckets = group_ips_by_subnet(ips, prefixlen)
    results: dict[str, tuple[bool, list[int]]] = {}

    def scan_bucket(cidr: str, bucket_ips: list[str]) -> dict[str, tuple[bool, list[int]]]:
        bucket_results: dict[str, tuple[bool, list[int]]] = {}
        if len(bucket_ips) == 1 and "/" not in cidr:
            ip = bucket_ips[0]
            bucket_results[ip] = scanner._scan_host(ip, profile, speed)
            return bucket_results
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            scan_target = str(network)
        except ValueError:
            for ip in bucket_ips:
                bucket_results[ip] = scanner._scan_host(ip, profile, speed)
            return bucket_results
        bucket_results.update(scanner._scan_network(scan_target, profile, speed, expected_ips=set(bucket_ips)))
        return bucket_results

    workers = max(1, min(parallel_workers, len(buckets)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(scan_bucket, cidr, bucket_ips): cidr
            for cidr, bucket_ips in buckets.items()
        }
        for future in as_completed(futures):
            results.update(future.result())
    return results


def parallel_ping_dns(
    items: list[tuple[str, Callable[[], None]]],
    *,
    parallel_workers: int = 4,
) -> None:
    if not items:
        return
    workers = max(1, min(parallel_workers, len(items)))

    def run_item(item: tuple[str, Callable[[], None]]) -> str:
        _ip, worker = item
        worker()
        return _ip

    with ThreadPoolExecutor(max_workers=workers) as executor:
        list(executor.map(lambda item: run_item(item), items))
