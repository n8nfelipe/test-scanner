"""Passive, bounded web security checks for targets the operator is authorized to test."""

from __future__ import annotations

import datetime as dt
import http.client
import ipaddress
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from email.message import Message
from typing import Optional
from urllib.parse import urljoin, urlparse, urlunparse


MAX_BODY_BYTES = 512 * 1024
MAX_REDIRECTS = 3
TIMEOUT_SECONDS = 8
USER_AGENT = "SafeSurfaceScanner/1.0 (authorized passive assessment)"


class ScanError(ValueError):
    """An expected input or target validation error."""


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    evidence: str
    recommendation: str
    confidence: str = "high"


@dataclass
class ResponseData:
    url: str
    status: int
    reason: str
    headers: Message
    body: bytes
    elapsed_ms: int
    peer_ip: str
    tls: Optional[dict] = None


@dataclass
class ScanContext:
    target: str
    findings: list[Finding] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    requests: int = 0

    def add(self, **kwargs: str) -> None:
        self.findings.append(Finding(**kwargs))


def _validate_url(value: str) -> tuple[str, str, int, str]:
    value = value.strip()
    if len(value) > 2048:
        raise ScanError("A URL deve ter no máximo 2048 caracteres")
    if not value:
        raise ScanError("Informe uma URL")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise ScanError("Apenas URLs http:// e https:// são aceitas")
    if parsed.username or parsed.password:
        raise ScanError("URLs com usuário e senha embutidos não são aceitas")
    if not parsed.hostname:
        raise ScanError("A URL precisa conter um hostname")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ScanError("Porta inválida") from exc
    if not 1 <= port <= 65535:
        raise ScanError("Porta inválida")
    path = parsed.path or "/"
    normalized = urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, ""))
    return normalized, parsed.hostname, port, parsed.scheme


def _resolve_public(hostname: str, port: int) -> list[str]:
    normalized_hostname = hostname.casefold().rstrip(".")
    is_localhost_name = normalized_hostname == "localhost"
    try:
        is_loopback_literal = ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        is_loopback_literal = False

    try:
        literal = ipaddress.ip_address(hostname)
        addresses = [str(literal)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ScanError(f"Não foi possível resolver o hostname: {exc}") from exc
        addresses = list(dict.fromkeys(info[4][0] for info in infos))

    if not addresses:
        raise ScanError("O hostname não possui endereço resolvível")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if is_localhost_name or is_loopback_literal:
            if not ip.is_loopback:
                raise ScanError("O hostname local precisa resolver para um endereço de loopback")
            continue
        # is_global excludes loopback, RFC1918, link-local, multicast, reserved,
        # documentation ranges and other non-public destinations.
        if not ip.is_global:
            raise ScanError("Por segurança, o scanner só aceita destinos públicos")
    return addresses


def _host_header(hostname: str, port: int, scheme: str) -> str:
    host = f"[{hostname}]" if ":" in hostname else hostname
    default = 443 if scheme == "https" else 80
    return host if port == default else f"{host}:{port}"


def _read_response(sock: socket.socket) -> tuple[int, str, Message, bytes]:
    response = http.client.HTTPResponse(sock)
    response.begin()
    body = response.read(MAX_BODY_BYTES + 1)
    return response.status, response.reason, response.headers, body[:MAX_BODY_BYTES]


def _request(url: str) -> ResponseData:
    normalized, hostname, port, scheme = _validate_url(url)
    addresses = _resolve_public(hostname, port)
    last_error: Optional[Exception] = None
    for address in addresses:
        raw: Optional[socket.socket] = None
        sock: Optional[socket.socket] = None
        started = time.monotonic()
        tls_info = None
        try:
            raw = socket.create_connection((address, port), timeout=TIMEOUT_SECONDS)
            sock = raw
            if scheme == "https":
                context = ssl.create_default_context()
                sock = context.wrap_socket(raw, server_hostname=hostname)
                cert = sock.getpeercert()
                tls_info = {
                    "version": sock.version() or "unknown",
                    "cipher": (sock.cipher() or ("unknown",))[0],
                    "subject": cert.get("subject", ()),
                    "issuer": cert.get("issuer", ()),
                }
            path = urlparse(normalized).path or "/"
            if urlparse(normalized).query:
                path += "?" + urlparse(normalized).query
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {_host_header(hostname, port, scheme)}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                "Accept: text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8\r\n"
                "Accept-Encoding: identity\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii", "ignore")
            sock.sendall(request)
            status, reason, headers, body = _read_response(sock)
            return ResponseData(
                url=normalized,
                status=status,
                reason=reason,
                headers=headers,
                body=body,
                elapsed_ms=round((time.monotonic() - started) * 1000),
                peer_ip=address,
                tls=tls_info,
            )
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            if sock is not None:
                sock.close()
            elif raw is not None:
                raw.close()
    raise ScanError(f"Não foi possível conectar ao destino: {last_error}")


def _fetch_with_redirects(url: str, ctx: ScanContext, same_host_only: bool = True) -> Optional[ResponseData]:
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        try:
            response = _request(current)
            ctx.requests += 1
        except ScanError as exc:
            ctx.errors.append(f"{current}: {exc}")
            return None
        if response.status not in {301, 302, 303, 307, 308}:
            return response
        location = response.headers.get("Location")
        if not location:
            return response
        next_url = urljoin(response.url, location)
        try:
            _, current_host, _, _ = _validate_url(response.url)
            _, next_host, _, _ = _validate_url(next_url)
        except ScanError as exc:
            ctx.errors.append(f"Redirecionamento inválido: {exc}")
            return response
        if same_host_only and current_host.lower().rstrip(".") != next_host.lower().rstrip("."):
            ctx.observations.append(f"Redirecionamento externo bloqueado: {next_url}")
            return response
        current = next_url
    ctx.errors.append("Limite de redirecionamentos atingido")
    return None


def _header(response: ResponseData, name: str) -> str:
    return response.headers.get(name, "").strip()


def _is_html(response: ResponseData) -> bool:
    content_type = _header(response, "Content-Type").lower()
    return "text/html" in content_type or response.body.lstrip().lower().startswith((b"<!doctype html", b"<html"))


def _scan_headers(response: ResponseData, ctx: ScanContext) -> None:
    headers = {key.lower(): value.strip() for key, value in response.headers.items()}
    https = response.url.startswith("https://")

    required = [
        ("content-security-policy", "CSP ausente", "MÉDIA", "Adicionar uma Content-Security-Policy adequada ao contexto da aplicação."),
        ("x-content-type-options", "Proteção contra MIME sniffing ausente", "BAIXA", "Enviar X-Content-Type-Options: nosniff."),
        ("referrer-policy", "Referrer-Policy ausente", "BAIXA", "Definir uma política explícita, como strict-origin-when-cross-origin."),
        ("permissions-policy", "Permissions-Policy ausente", "BAIXA", "Restringir APIs do navegador que a aplicação não utiliza."),
    ]
    for header_name, title, severity, recommendation in required:
        if header_name not in headers:
            ctx.add(
                id=f"missing-{header_name}",
                title=title,
                severity=severity,
                category="Headers de segurança",
                evidence=f"{header_name} não foi enviado em {response.status} {response.reason}.",
                recommendation=recommendation,
            )

    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
        ctx.add(
            id="clickjacking-protection-missing",
            title="Proteção contra clickjacking ausente",
            severity="MÉDIA",
            category="Headers de segurança",
            evidence="X-Frame-Options e CSP frame-ancestors não foram observados.",
            recommendation="Usar frame-ancestors na CSP ou X-Frame-Options quando compatível.",
        )
    if https and "strict-transport-security" not in headers:
        ctx.add(
            id="missing-hsts",
            title="HSTS ausente",
            severity="MÉDIA",
            category="TLS e transporte",
            evidence="A resposta HTTPS não envia Strict-Transport-Security.",
            recommendation="Após confirmar que todo o site funciona em HTTPS, habilitar HSTS com uma duração adequada.",
        )

    cors = headers.get("access-control-allow-origin", "")
    credentials = headers.get("access-control-allow-credentials", "").lower()
    if cors == "*" and credentials == "true":
        ctx.add(
            id="cors-wildcard-credentials",
            title="CORS permite qualquer origem com credenciais",
            severity="ALTA",
            category="Configuração de acesso",
            evidence="Access-Control-Allow-Origin: * combinado com Allow-Credentials: true.",
            recommendation="Permitir somente origens confiáveis e evitar curingas em respostas autenticadas.",
        )
    elif cors == "*":
        ctx.add(
            id="cors-wildcard",
            title="CORS permite qualquer origem",
            severity="BAIXA",
            category="Configuração de acesso",
            evidence="Access-Control-Allow-Origin: *.",
            recommendation="Restringir as origens se a API expõe dados ou operações sensíveis.",
            confidence="média",
        )

    for name in ("server", "x-powered-by"):
        if headers.get(name):
            ctx.add(
                id=f"technology-disclosure-{name}",
                title="Divulgação de tecnologia na resposta",
                severity="INFORMATIVA",
                category="Divulgação de informação",
                evidence=f"{name}: {headers[name]}.",
                recommendation="Remover ou generalizar banners quando isso não prejudicar a operação.",
            )


def _scan_cookies(response: ResponseData, ctx: ScanContext) -> None:
    cookies = response.headers.get_all("Set-Cookie", [])
    if not cookies:
        return
    https = response.url.startswith("https://")
    for raw in cookies:
        name = raw.split("=", 1)[0].strip() or "(sem nome)"
        lower = raw.lower()
        missing = []
        if https and "secure" not in lower:
            missing.append("Secure")
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if "samesite" not in lower:
            missing.append("SameSite")
        if missing:
            ctx.add(
                id=f"cookie-flags-{re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-') or 'cookie'}",
                title="Cookie sem atributos de proteção",
                severity="MÉDIA" if "HttpOnly" in missing or (https and "Secure" in missing) else "BAIXA",
                category="Cookies e sessão",
                evidence=f"Cookie {name} não informa: {', '.join(missing)}.",
                recommendation="Aplicar Secure em HTTPS, HttpOnly para tokens não acessados pelo JavaScript e SameSite conforme o fluxo.",
            )


def _scan_content(response: ResponseData, ctx: ScanContext) -> None:
    if not _is_html(response):
        return
    text = response.body.decode("utf-8", "replace")
    if response.url.startswith("http://") and re.search(r"<input\b[^>]*\btype\s*=\s*[\"']?password", text, re.I):
        ctx.add(
            id="password-form-over-http",
            title="Formulário de senha servido por HTTP",
            severity="ALTA",
            category="TLS e transporte",
            evidence="Foi encontrado um input type=password em uma página HTTP.",
            recommendation="Servir a página e o envio do formulário exclusivamente por HTTPS.",
        )
    if response.url.startswith("https://"):
        mixed = re.findall(r"(?:src|href)\s*=\s*[\"'](http://[^\"']+)", text, re.I)
        if mixed:
            ctx.add(
                id="mixed-content",
                title="Possível conteúdo misto",
                severity="MÉDIA",
                category="TLS e transporte",
                evidence=f"Encontradas {len(mixed)} referência(s) HTTP em uma página HTTPS.",
                recommendation="Trocar recursos para HTTPS ou usar URLs relativas/seguras.",
                confidence="média",
            )


def _scan_supporting_files(base_url: str, ctx: ScanContext) -> None:
    for path, label in (("/robots.txt", "robots.txt"), ("/.well-known/security.txt", "security.txt")):
        url = urljoin(base_url, path)
        response = _fetch_with_redirects(url, ctx)
        if response and 200 <= response.status < 300:
            ctx.observations.append(f"{label} encontrado ({response.status}, {len(response.body)} bytes)")


def scan_url(target: str) -> dict:
    normalized, hostname, port, scheme = _validate_url(target)
    # Validate before any network I/O, and keep all later requests same-origin.
    _resolve_public(hostname, port)
    started = time.monotonic()
    ctx = ScanContext(target=normalized)
    response = _fetch_with_redirects(normalized, ctx)
    if response is None:
        raise ScanError("Não foi possível obter uma resposta do destino")

    _scan_headers(response, ctx)
    _scan_cookies(response, ctx)
    _scan_content(response, ctx)
    ctx.observations.append(f"Resposta principal: {response.status} {response.reason} em {response.elapsed_ms} ms")
    ctx.observations.append(f"IP conectado: {response.peer_ip}")
    if response.tls:
        ctx.observations.append(f"TLS: {response.tls['version']} / {response.tls['cipher']}")

    if scheme == "https":
        _scan_supporting_files(normalized, ctx)
        if port == 443:
            http_response = _fetch_with_redirects(f"http://{hostname}/", ctx)
            if http_response and http_response.status in {200, 204}:
                ctx.add(
                    id="http-available",
                    title="HTTP permanece acessível sem redirecionar",
                    severity="MÉDIA",
                    category="TLS e transporte",
                    evidence=f"http://{hostname}/ respondeu {http_response.status} sem redirecionamento para HTTPS.",
                    recommendation="Redirecionar HTTP para HTTPS e manter conteúdo sensível somente no canal seguro.",
                )

    severity_order = {"CRÍTICA": 0, "ALTA": 1, "MÉDIA": 2, "BAIXA": 3, "INFORMATIVA": 4}
    ctx.findings.sort(key=lambda item: severity_order.get(item.severity, 9))
    counts = {severity: sum(f.severity == severity for f in ctx.findings) for severity in severity_order}
    return {
        "target": normalized,
        "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "duration_ms": round((time.monotonic() - started) * 1000),
        "requests": ctx.requests,
        "response": {"status": response.status, "content_type": _header(response, "Content-Type") or "não informado"},
        "summary": {"total": len(ctx.findings), "counts": counts},
        "findings": [finding.__dict__ for finding in ctx.findings],
        "observations": ctx.observations,
        "errors": ctx.errors,
        "scope": "Somente verificações passivas, limitadas e same-origin; nenhum exploit, brute force ou payload destrutivo foi executado.",
    }
