from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass(slots=True)
class DNSVerificationResult:
    ip: str
    hostname: str | None
    verified: bool
    dns_mismatch: bool
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


def verify_dns(
    ip: str,
    resolver=None,
    nameservers: list[str] | None = None,
    timeout: float = 2.0,
) -> DNSVerificationResult:
    resolver = _build_resolver(resolver=resolver, nameservers=nameservers, timeout=timeout)
    try:
        normalized_ip = ipaddress.ip_address(ip)
    except ValueError:
        return DNSVerificationResult(ip=ip, hostname=None, verified=False, dns_mismatch=True, reason="invalid_ip")

    try:
        ptr_query = normalized_ip.reverse_pointer
        ptr_answers = resolver.resolve(ptr_query, "PTR")
        hostname = str(next(iter(ptr_answers))).rstrip(".")
    except Exception:
        return DNSVerificationResult(
            ip=str(normalized_ip),
            hostname=None,
            verified=False,
            dns_mismatch=True,
            reason="reverse_lookup_failed",
        )

    record_type = "AAAA" if normalized_ip.version == 6 else "A"
    try:
        forward_answers = resolver.resolve(hostname, record_type)
    except Exception:
        return DNSVerificationResult(
            ip=str(normalized_ip),
            hostname=hostname,
            verified=False,
            dns_mismatch=True,
            reason="forward_lookup_failed",
        )

    resolved = {str(ipaddress.ip_address(str(answer))) for answer in forward_answers}
    if str(normalized_ip) in resolved:
        return DNSVerificationResult(
            ip=str(normalized_ip),
            hostname=hostname,
            verified=True,
            dns_mismatch=False,
            reason="verified",
        )

    return DNSVerificationResult(
        ip=str(normalized_ip),
        hostname=hostname,
        verified=False,
        dns_mismatch=True,
        reason="forward_mismatch",
    )
