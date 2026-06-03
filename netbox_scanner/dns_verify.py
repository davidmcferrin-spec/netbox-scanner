from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field


@dataclass(slots=True)
class DNSLookupResult:
    ip: str
    ptr_hostname: str | None
    forward_has_a_or_cname: bool = False
    forward_addresses: list[str] = field(default_factory=list)
    reason: str = ""


def _build_resolver(resolver=None, nameservers: list[str] | None = None, timeout: float = 2.0):
    if resolver is not None:
        return resolver
    try:
        import dns.resolver
    except ImportError as exc:  # pragma: no cover - depends on optional dependency
        raise RuntimeError("dnspython is required for DNS verification.") from exc

    built = dns.resolver.Resolver()
    if nameservers:
        built.nameservers = nameservers
    built.timeout = timeout
    built.lifetime = timeout
    return built


def _resolve_addresses(resolver, hostname: str, record_type: str) -> list[str]:
    try:
        answers = resolver.resolve(hostname, record_type)
    except Exception:
        return []
    if record_type == "CNAME":
        return [str(answer).rstrip(".") for answer in answers]
    return [str(ipaddress.ip_address(str(answer))) for answer in answers]


def lookup_dns(
    ip: str,
    resolver=None,
    nameservers: list[str] | None = None,
    timeout: float = 2.0,
) -> DNSLookupResult:
    resolver = _build_resolver(resolver=resolver, nameservers=nameservers, timeout=timeout)
    try:
        normalized_ip = ipaddress.ip_address(ip)
    except ValueError:
        return DNSLookupResult(ip=ip, ptr_hostname=None, reason="invalid_ip")

    ip_str = str(normalized_ip)
    try:
        ptr_query = normalized_ip.reverse_pointer
        ptr_answers = resolver.resolve(ptr_query, "PTR")
        ptr_hostname = str(next(iter(ptr_answers))).rstrip(".")
    except Exception:
        return DNSLookupResult(ip=ip_str, ptr_hostname=None, reason="ptr_missing")

    record_type = "AAAA" if normalized_ip.version == 6 else "A"
    forward_addresses = _resolve_addresses(resolver, ptr_hostname, record_type)
    cname_targets = _resolve_addresses(resolver, ptr_hostname, "CNAME")
    forward_has_a_or_cname = bool(forward_addresses or cname_targets)
    all_addresses = sorted(set(forward_addresses + cname_targets))

    if forward_has_a_or_cname:
        return DNSLookupResult(
            ip=ip_str,
            ptr_hostname=ptr_hostname,
            forward_has_a_or_cname=True,
            forward_addresses=all_addresses,
            reason="lookup_ok",
        )

    return DNSLookupResult(
        ip=ip_str,
        ptr_hostname=ptr_hostname,
        forward_has_a_or_cname=False,
        forward_addresses=[],
        reason="forward_missing",
    )
