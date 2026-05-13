#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
import tempfile
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import socket
import re
import pdfplumber
import requests
from bs4 import BeautifulSoup
from tabulate import tabulate


def red(text: str) -> str:
    return f"\033[91m{text}\033[0m"


def orange(text: str) -> str:
    return f"\033[93m{text}\033[0m"


def script_dir() -> Path:
    return Path(__file__).resolve().parent


def default_bsi_pdf_path() -> Path:
    return Path.home() / ".cipherscout" / "BSI-TR-02102-2.pdf"


def wrap_text(text: str, width: int = 60) -> str:
    if not text:
        return ""

    wrapped_lines: list[str] = []

    for line in text.splitlines():
        wrapped_lines.extend(
            textwrap.wrap(
                line,
                width=width,
                break_long_words=False,
                break_on_hyphens=False,
            )
            or [""]
        )

    return "\n".join(wrapped_lines)


def clean_cell(value: str | None) -> str:
    return " ".join(value.split()) if value else ""


def parse_iso_datetime(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

def export_markdown_report(
    output_path: Path,
    target: str,
    certificate_info: dict[str, str],
    tls_versions: list[str],
    cipher_rows: list[list[str]],
    security_rows: list[list[str]],
) -> None:
    lines: list[str] = []

    lines.append("# CipherScout Report")
    lines.append("")

    lines.append(f"- Target: `{target}`")
    lines.append("")

    if certificate_info:
        lines.append("## Certificate Information")
        lines.append("")

        cert_rows = [
            [key, strip_ansi(value)]
            for key, value in certificate_info.items()
        ]

        lines.append(
            markdown_table(
                ["Field", "Value"],
                cert_rows,
            )
        )
        lines.append("")

    if tls_versions:
        lines.append("## Supported TLS Versions")
        lines.append("")

        version_rows = [
            [strip_ansi(version)]
            for version in tls_versions
        ]

        lines.append(
            markdown_table(
                ["Version"],
                version_rows,
            )
        )
        lines.append("")

    if cipher_rows:
        lines.append("## Accepted Cipher Suites")
        lines.append("")

        lines.append(
            markdown_table(
                [
                    "Cipher Suite",
                    "BSI secure until",
                    "ciphersuite.info status",
                    "Weakness",
                ],
                cipher_rows,
            )
        )
        lines.append("")

    if security_rows:
        lines.append("## Additional Security Checks")
        lines.append("")

        lines.append(
            markdown_table(
                ["Check", "Value"],
                security_rows,
            )
        )
        lines.append("")

    output_path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

def validate_target(target: str) -> None:
    if ":" in target:
        host, port_str = target.rsplit(":", 1)

        try:
            port = int(port_str)
        except ValueError as exc:
            raise RuntimeError(
                f"Invalid port in target: {target}"
            ) from exc
    else:
        host = target
        port = 443

    try:
        with socket.create_connection(
            (host, port),
            timeout=5,
        ):
            pass

    except OSError as exc:
        raise RuntimeError(
            f"Target unreachable: {host}:{port}"
        ) from exc

def update_bsi_pdf(destination: Path | None = None) -> Path:
    destination = destination or default_bsi_pdf_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp_destination = destination.with_suffix(destination.suffix + ".tmp")

    try:
        response = requests.get(
            "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102-2.pdf?__blob=publicationFile",
            timeout=30,
            headers={"Accept": "application/pdf"},
            stream=True,
        )
        response.raise_for_status()

        content_type = response.headers.get("Content-Type", "")
        if "pdf" not in content_type.lower():
            raise RuntimeError(
                f"Unexpected content type from BSI download: {content_type or 'unknown'}"
            )

        with tmp_destination.open("wb") as file:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    file.write(chunk)

        if tmp_destination.stat().st_size == 0:
            raise RuntimeError("Downloaded BSI PDF is empty")

        tmp_destination.replace(destination)
        return destination

    except Exception:
        tmp_destination.unlink(missing_ok=True)
        raise


def load_bsi_cipher_table(pdf_path: Path) -> dict[str, dict[str, str | int]]:
    if not pdf_path.is_file():
        raise FileNotFoundError(
            f"PDF file not found: {pdf_path}. Run with --update-bsi first."
        )

    lookup: dict[str, dict[str, str | int]] = {}

    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page_number, page in enumerate(pdf.pages, start=1):
                for table in page.extract_tables() or []:
                    for row in table:
                        cleaned_row = [clean_cell(cell) for cell in row]

                        if len(cleaned_row) < 4:
                            continue

                        cipher_suite = cleaned_row[0]
                        if not cipher_suite.startswith("TLS_"):
                            continue

                        lookup[cipher_suite] = {
                            "iana_no": cleaned_row[1],
                            "specification": cleaned_row[2],
                            "use_up_to": cleaned_row[3],
                            "page": page_number,
                        }

    except Exception as exc:
        raise RuntimeError(f"Failed to read BSI PDF: {exc}") from exc

    return lookup


def run_sslyze(target: str) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        json_path = Path(tmp.name)

    cmd = [
        "sslyze",
        "--quiet",
        "--json_out",
        str(json_path),
        target,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )

        with json_path.open("r", encoding="utf-8") as file:
            return json.load(file)

    except json.JSONDecodeError as exc:
        raise RuntimeError(f"SSLyze produced invalid JSON: {exc}") from exc

    finally:
        json_path.unlink(missing_ok=True)

def get_first_server_scan(sslyze_data: dict[str, Any]) -> dict[str, Any]:
    servers = sslyze_data.get("server_scan_results", [])
    return servers[0] if servers else {}


def get_scan_result(sslyze_data: dict[str, Any]) -> dict[str, Any]:
    return get_first_server_scan(sslyze_data).get("scan_result", {})


def format_sans(cert: dict[str, Any]) -> str:
    san = cert.get("subject_alternative_name", {})

    if not isinstance(san, dict):
        return "unknown"

    dns_names = san.get("dns_names", []) or []
    ip_addresses = san.get("ip_addresses", []) or []

    values = [str(name) for name in dns_names]
    values.extend(str(ip) for ip in ip_addresses)

    return ", ".join(values) if values else "none"


def format_certificate_valid_until(cert: dict[str, Any]) -> str:
    valid_until = str(cert.get("not_valid_after", "unknown"))
    parsed = parse_iso_datetime(valid_until)

    if parsed and parsed < datetime.now(timezone.utc):
        return orange(valid_until)

    return valid_until


def format_signature_algorithm(cert: dict[str, Any]) -> str:
    signature_hash = cert.get("signature_hash_algorithm", {})
    algorithm = str(signature_hash.get("name", "unknown"))

    if algorithm.lower() in {"sha", "sha1"}:
        return orange(algorithm)

    return algorithm

def format_ocsp_stapling(deployment: dict[str, Any]) -> str:
    ocsp_response = deployment.get("ocsp_response")

    if ocsp_response is None:
        return red("not supported")

    return "supported"

def extract_certificate_information(sslyze_data: dict[str, Any]) -> dict[str, str]:
    certificate_info = (
        get_scan_result(sslyze_data)
        .get("certificate_info", {})
        .get("result", {})
    )

    deployments = certificate_info.get("certificate_deployments", [])
    if not deployments:
        return {}

    deployment = deployments[0]

    chain = deployment.get("received_certificate_chain", [])
    if not chain:
        return {}

    cert = chain[0]
    public_key = cert.get("public_key", {})

    public_key_algorithm = str(public_key.get("algorithm", "unknown"))

    rows = {
        "Certificate valid until": format_certificate_valid_until(cert),
        "Public Key Algorithm": public_key_algorithm,
        "Key Size": str(public_key.get("key_size", "unknown")),
        "Signature Algorithm": format_signature_algorithm(cert),
        "Subject Alternative Names": format_sans(cert),
        "OCSP Stapling": format_ocsp_stapling(deployment),
    }

    if public_key_algorithm == "RSAPublicKey":
        rows["Exponent"] = str(public_key.get("rsa_e", "unknown"))

    elif public_key_algorithm == "ECPublicKey":
        rows["Curve"] = str(public_key.get("ec_curve_name", "unknown"))

    return rows

def extract_supported_tls_versions(sslyze_data: dict[str, Any]) -> list[str]:
    scan_result = get_scan_result(sslyze_data)

    version_mapping = {
        "ssl_2_0_cipher_suites": "SSL 2.0",
        "ssl_3_0_cipher_suites": "SSL 3.0",
        "tls_1_0_cipher_suites": "TLS 1.0",
        "tls_1_1_cipher_suites": "TLS 1.1",
        "tls_1_2_cipher_suites": "TLS 1.2",
        "tls_1_3_cipher_suites": "TLS 1.3",
    }

    versions: list[str] = []

    for scan_name, display_name in version_mapping.items():
        accepted = (
            scan_result
            .get(scan_name, {})
            .get("result", {})
            .get("accepted_cipher_suites", [])
        )

        if not accepted:
            continue

        if display_name == "TLS 1.0":
            versions.append(red(display_name))
        elif display_name == "TLS 1.1":
            versions.append(orange(display_name))
        else:
            versions.append(display_name)

    return versions


def format_check_result(result: Any) -> str:
    if result is None:
        return ""

    if not isinstance(result, dict):
        return str(result)

    values: list[str] = []

    for value in result.values():
        if isinstance(value, list):
            if value and isinstance(value[0], dict) and "name" in value[0]:
                values.append(", ".join(str(item.get("name")) for item in value))
            else:
                values.append(str(value))
        else:
            values.append(str(value))

    return "\n".join(values)


def color_check_value(scan_name: str, value: str) -> str:
    normalized = value.strip().lower()

    if scan_name == "tls_compression" and normalized == "true":
        return orange(value)

    if scan_name == "openssl_ccs_injection" and normalized == "true":
        return red(value)

    if scan_name == "tls_fallback_scsv" and normalized == "false":
        return red(value)

    if scan_name == "heartbleed" and normalized == "true":
        return red(value)

    if scan_name == "robot":
        if normalized == "unknown_inconsistent_results":
            return orange(value)

        if normalized in {
            "vulnerable_weak_oracle",
            "vulnerable_strong_oracle",
        }:
            return red(value)

    if scan_name == "tls_extended_master_secret" and normalized == "false":
        return orange(value)

    return value


def curve_names(curves: Any) -> str:
    if not isinstance(curves, list):
        return "none"

    names = [
        str(curve.get("name"))
        for curve in curves
        if isinstance(curve, dict) and curve.get("name")
    ]

    return ", ".join(names) if names else "none"


def extract_security_checks(sslyze_data: dict[str, Any]) -> list[list[str]]:
    scan_result = get_scan_result(sslyze_data)

    checks = {
        "tls_compression": "DEFLATE Compression",
        "openssl_ccs_injection": "OpenSSL CCS Injection",
        "tls_fallback_scsv": "TLS Fallback SCSV",
        "heartbleed": "OpenSSL Heartbleed",
        "robot": "ROBOT Attack",
        "session_renegotiation": "Session Renegotiation",
        "elliptic_curves": "Elliptic Curve Key Exchange",
        "tls_extended_master_secret": "TLS Extended Master Secret Extension",
    }

    rows: list[list[str]] = []

    for scan_name, display_name in checks.items():
        scan_data = scan_result.get(scan_name)

        if not isinstance(scan_data, dict):
            continue

        result = scan_data.get("result") or {}
        error_reason = scan_data.get("error_reason")

        if error_reason:
            rows.append([display_name, str(error_reason)])
            continue

        if scan_name == "session_renegotiation":
            rows.append(["Session Renegotiation", ""])
            rows.append([
                "  ├─ Supports secure renegotiation",
                str(result.get("supports_secure_renegotiation", "unknown")),
            ])

            dos_value = str(
                result.get("is_vulnerable_to_client_renegotiation_dos", "unknown")
            )
            if dos_value.lower() == "true":
                dos_value = orange(dos_value)

            rows.append([
                "  └─ Vulnerable to renegotiation DoS",
                dos_value,
            ])
            continue

        if scan_name == "elliptic_curves":
            rows.append(["Elliptic Curve Key Exchange", ""])
            rows.append([
                "  ├─ Supports ECDH key exchange",
                str(result.get("supports_ecdh_key_exchange", "unknown")),
            ])
            rows.append([
                "  ├─ Supported curves",
                wrap_text(curve_names(result.get("supported_curves")), 80),
            ])
            rows.append([
                "  └─ Rejected curves",
                wrap_text(curve_names(result.get("rejected_curves")), 80),
            ])
            continue

        formatted = format_check_result(result)
        colored = color_check_value(scan_name, formatted)

        rows.append([
            display_name,
            wrap_text(colored, 80),
        ])

    return rows


def extract_accepted_cipher_suites(sslyze_data: dict[str, Any]) -> set[str]:
    accepted: set[str] = set()

    for server in sslyze_data.get("server_scan_results", []):
        scan_result = server.get("scan_result", {})

        for scan_name, scan_data in scan_result.items():
            if not scan_name.endswith("_cipher_suites"):
                continue

            result = scan_data.get("result")
            if not result:
                continue

            for entry in result.get("accepted_cipher_suites", []):
                cipher_suite = entry.get("cipher_suite", {})
                name = cipher_suite.get("name")

                if isinstance(name, str) and name.startswith("TLS_"):
                    accepted.add(name)

    return accepted


def lookup_ciphersuite_warnings(cipher_suite: str) -> str:
    url = f"https://ciphersuite.info/cs/{cipher_suite}/"

    try:
        response = requests.get(
            url,
            timeout=10,
            headers={"Accept": "text/html"},
        )
        response.raise_for_status()

    except requests.Timeout:
        return "warning lookup timeout"

    except requests.RequestException:
        return "warning lookup failed"

    soup = BeautifulSoup(response.text, "html.parser")
    warnings: list[str] = []

    for class_name in ("alert-warning", "alert-danger"):
        for alert in soup.select(f".{class_name}"):
            warning_text = " ".join(alert.get_text(" ", strip=True).split())

            if warning_text:
                warnings.append(warning_text)

    return "\n".join(warnings)


def lookup_ciphersuite_security(cipher_suite: str) -> dict[str, str]:
    url = f"https://ciphersuite.info/api/cs/{cipher_suite}/"

    try:
        response = requests.get(
            url,
            timeout=10,
            headers={"Accept": "application/json"},
        )

        if response.status_code == 404:
            return {"security": "not found", "warning": ""}

        response.raise_for_status()
        data = response.json()

    except requests.Timeout:
        return {"security": "lookup timeout", "warning": ""}

    except requests.RequestException:
        return {"security": "lookup failed", "warning": ""}

    except json.JSONDecodeError:
        return {"security": "invalid API response", "warning": ""}

    cipher_data = data.get(cipher_suite)
    if not isinstance(cipher_data, dict):
        return {"security": "unknown", "warning": ""}

    security = str(cipher_data.get("security", "unknown"))
    warning = ""

    if security in {"weak", "insecure"}:
        warning = lookup_ciphersuite_warnings(cipher_suite)

    return {
        "security": security,
        "warning": warning,
    }


def color_cipher_row(row: list[str], security: str) -> list[str]:
    normalized = security.strip().lower()

    if normalized == "insecure":
        return [red(cell) for cell in row]

    if normalized == "weak":
        return [orange(cell) for cell in row]

    return row


def build_table_rows(
    cipher_suites: set[str],
    bsi_lookup: dict[str, dict[str, str | int]],
) -> list[list[str]]:
    rows: list[list[str]] = []

    for cipher_suite in sorted(cipher_suites):
        bsi_entry = bsi_lookup.get(cipher_suite)
        cipher_info = lookup_ciphersuite_security(cipher_suite)

        row = [
            cipher_suite,
            str(bsi_entry["use_up_to"]) if bsi_entry else "not listed",
            cipher_info["security"],
            wrap_text(cipher_info["warning"]),
        ]

        rows.append(color_cipher_row(row, cipher_info["security"]))

    return rows


def parse_cipher_suites(value: str) -> set[str]:
    cipher_suites = {
        cipher_suite.strip()
        for cipher_suite in value.split(",")
        if cipher_suite.strip()
    }

    invalid = [
        cipher_suite
        for cipher_suite in cipher_suites
        if not cipher_suite.startswith("TLS_")
    ]

    if invalid:
        raise ValueError(
            "Invalid cipher suite name(s): " + ", ".join(sorted(invalid))
        )

    return cipher_suites


def print_certificate_information(info: dict[str, str]) -> None:
    print("\nCertificate Information")

    if not info:
        print("No certificate information found.")
        return

    print(tabulate(info.items(), headers=["Field", "Value"], tablefmt="grid"))


def print_supported_tls_versions(versions: list[str]) -> None:
    print("\nSupported TLS Versions")

    if not versions:
        print("No supported TLS versions found.")
        return

    print(tabulate([[version] for version in versions], headers=["Version"], tablefmt="grid"))


def print_cipher_table(rows: list[list[str]]) -> None:
    print("\nAccepted Cipher Suites")

    if not rows:
        print("No accepted cipher suites found.")
        return

    print(
        tabulate(
            rows,
            headers=[
                "Cipher Suite",
                "BSI secure until",
                "ciphersuite.info status",
                "Weakness",
            ],
            tablefmt="grid",
        )
    )

def strip_ansi(text: str) -> str:
    ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
    return ansi_escape.sub("", text)


def markdown_table(
    headers: list[str],
    rows: list[list[str]],
) -> str:
    cleaned_rows = [
        [strip_ansi(str(cell)) for cell in row]
        for row in rows
    ]

    return tabulate(
        cleaned_rows,
        headers=headers,
        tablefmt="github",
    )

def print_security_checks(rows: list[list[str]]) -> None:
    print("\nAdditional Security Checks")

    if not rows:
        print("No security check results found.")
        return

    print(tabulate(rows, headers=["Check", "Value"], tablefmt="grid"))


ASCII_ART = r"""
   ▄████▄   ██▓ ██▓███   ██░ ██ ▓█████  ██▀███
  ▒██▀ ▀█  ▓██▒▓██░  ██▒▓██░ ██▒▓█   ▀ ▓██ ▒ ██▒
  ▒▓█    ▄ ▒██▒▓██░ ██▓▒▒██▀▀██░▒███   ▓██ ░▄█ ▒
  ▒▓▓▄ ▄██▒░██░▒██▄█▓▒ ▒░▓█ ░██ ▒▓█  ▄ ▒██▀▀█▄
  ▒ ▓███▀ ░░██░▒██▒ ░  ░░▓█▒░██▓░▒████▒░██▓ ▒██▒
  ░ ░▒ ▒  ░░▓  ▒▓▒░ ░  ░ ▒ ░░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░
    ░  ▒    ▒ ░░▒ ░      ▒ ░▒░ ░ ░ ░  ░  ░▒ ░ ▒░
  ░         ▒ ░░░        ░  ░░ ░   ░     ░░   ░
  ░ ░       ░            ░  ░  ░   ░  ░   ░
  ░

                CipherScout :: TLS Cipher Suite Auditor
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            ASCII_ART
            + "\nRun SSLyze against a target, extract accepted cipher suites,\n"
            "compare them with the BSI TLS PDF, and query ciphersuite.info."
        ),
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Target host, e.g. example.com:443",
    )

    parser.add_argument(
        "--cipher-suites",
        help=(
            "Comma-separated TLS cipher suites to evaluate instead of scanning a target, "
            "e.g. TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384"
        ),
    )

    parser.add_argument(
        "--export-md",
        type=Path,
        help="Export the report as Markdown",
    )

    parser.add_argument(
        "pdf",
        nargs="?",
        type=Path,
        default=default_bsi_pdf_path(),
        help=f"Path to the BSI TLS PDF. Defaults to ./BSI-TR-02102-2.pdf",
    )

    parser.add_argument(
        "--update-bsi",
        action="store_true",
        help="Download the latest BSI TLS PDF into the script directory and exit.",
    )

    return parser.parse_args()

def main() -> int:
    args = parse_args()

    certificate_info: dict[str, str] = {}
    tls_versions: list[str] = []
    security_rows: list[list[str]] = []
    sslyze_data: dict[str, Any] | None = None

    try:
        if args.update_bsi:
            pdf_path = update_bsi_pdf()
            print(f"Updated BSI TLS PDF: {pdf_path}")
            return 0

        if not args.target and not args.cipher_suites:
            print(
                "Error: either target or --cipher-suites is required unless --update-bsi is used",
                file=sys.stderr,
            )
            return 2

        if args.target and args.cipher_suites:
            print(
                "Error: use either target scanning or --cipher-suites, not both",
                file=sys.stderr,
            )
            return 2

        bsi_lookup = load_bsi_cipher_table(args.pdf)

        if args.cipher_suites:
            cipher_suites = parse_cipher_suites(args.cipher_suites)
        else:
            validate_target(args.target)

            sslyze_data = run_sslyze(args.target)
            cipher_suites = extract_accepted_cipher_suites(sslyze_data)

            certificate_info = extract_certificate_information(sslyze_data)
            tls_versions = extract_supported_tls_versions(sslyze_data)

            print_certificate_information(certificate_info)
            print_supported_tls_versions(tls_versions)

        cipher_rows = build_table_rows(cipher_suites, bsi_lookup)
        print_cipher_table(cipher_rows)

        if sslyze_data:
            security_rows = extract_security_checks(sslyze_data)
            print_security_checks(security_rows)

        if args.export_md:
            export_markdown_report(
                output_path=args.export_md,
                target=args.target or "manual cipher input",
                certificate_info=certificate_info,
                tls_versions=tls_versions,
                cipher_rows=cipher_rows,
                security_rows=security_rows,
            )

            print(f"\nMarkdown report exported to: {args.export_md}")

        return 0

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())