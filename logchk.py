from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, TextIO
from urllib.parse import parse_qs, urlparse


DEFAULT_BOT_PATTERNS = [
    r"bot",
    r"spider",
    r"crawler",
    r"crawl",
    r"slurp",
    r"scan",
    r"curl",
    r"wget",
    r"python-requests",
    r"python-urllib",
    r"go-http-client",
    r"libwww-perl",
    r"httpclient",
    r"axios",
    r"postmanruntime",
    r"insomnia",
    r"zgrab",
    r"nmap",
    r"nikto",
    r"sqlmap",
    r"semrushbot",
    r"ahrefsbot",
    r"mj12bot",
    r"dotbot",
    r"gptbot",
    r"chatgpt-user",
    r"perplexitybot",
    r"cohere-ai",
]

LOG_PATTERN = re.compile(
    r'^(?P<remote>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<body_bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)


@dataclass
class RequestInfo:
    method: str
    path: str
    protocol: str
    query_params: dict[str, list[str]]


@dataclass
class LogEntry:
    raw_line: str
    parsed: bool
    remote_ip: str | None = None
    status: str | None = None
    user_agent: str | None = None
    request: RequestInfo | None = None
    filtered_reason: str | None = None


@dataclass
class IpStats:
    successful: int = 0
    unsuccessful: int = 0


@dataclass
class Summary:
    total_lines: int = 0
    parsed_lines: int = 0
    unparsed_lines: int = 0
    kept_lines: int = 0
    filtered_bots: int = 0
    filtered_non_200: int = 0
    filtered_high_unsuccessful_ips: int = 0


def parse_request(request: str) -> RequestInfo | None:
    parts = request.split(" ")
    if len(parts) < 3:
        return None

    method, target, protocol = parts[0], parts[1], parts[2]
    parsed_target = urlparse(target)
    path = parsed_target.path or target
    query_params = parse_qs(parsed_target.query)
    return RequestInfo(method=method, path=path, protocol=protocol, query_params=query_params)


def parse_log_line(line: str) -> LogEntry:
    match = LOG_PATTERN.match(line.rstrip("\n"))
    if not match:
        return LogEntry(raw_line=line, parsed=False)

    request = parse_request(match.group("request"))
    return LogEntry(
        raw_line=line,
        parsed=True,
        remote_ip=match.group("remote"),
        status=match.group("status"),
        user_agent=match.group("user_agent"),
        request=request,
    )


def build_bot_regex(custom_patterns: list[str]) -> re.Pattern[str]:
    patterns = DEFAULT_BOT_PATTERNS + custom_patterns
    return re.compile("|".join(f"(?:{pattern})" for pattern in patterns), re.IGNORECASE)


def tally_ip_stats(entries: Iterable[LogEntry]) -> dict[str, IpStats]:
    ip_stats: dict[str, IpStats] = {}
    for entry in entries:
        if not entry.parsed or not entry.remote_ip or not entry.status:
            continue

        if entry.remote_ip not in ip_stats:
            ip_stats[entry.remote_ip] = IpStats()

        if entry.status == "200":
            ip_stats[entry.remote_ip].successful += 1
        else:
            ip_stats[entry.remote_ip].unsuccessful += 1

    return ip_stats


def apply_filters(
    entries: list[LogEntry],
    bot_regex: re.Pattern[str],
    ip_stats: dict[str, IpStats],
    unsuccessful_threshold: int,
) -> tuple[list[LogEntry], list[LogEntry], Summary]:
    summary = Summary(total_lines=len(entries))
    kept: list[LogEntry] = []
    filtered: list[LogEntry] = []

    # Pass 1: filter bots/scanners by user-agent.
    stage_1: list[LogEntry] = []
    for entry in entries:
        if not entry.parsed:
            summary.unparsed_lines += 1
            kept.append(entry)
            continue

        summary.parsed_lines += 1
        if entry.user_agent and bot_regex.search(entry.user_agent):
            entry.filtered_reason = "bot_user_agent"
            summary.filtered_bots += 1
            filtered.append(entry)
            continue

        stage_1.append(entry)

    # Pass 2: filter non-200 statuses.
    stage_2: list[LogEntry] = []
    for entry in stage_1:
        if entry.status != "200":
            entry.filtered_reason = "non_200_status"
            summary.filtered_non_200 += 1
            filtered.append(entry)
            continue

        stage_2.append(entry)

    # Pass 3: filter IPs with more than threshold unsuccessful entries.
    for entry in stage_2:
        remote_ip = entry.remote_ip
        if not remote_ip:
            kept.append(entry)
            continue

        unsuccessful = ip_stats.get(remote_ip, IpStats()).unsuccessful
        if unsuccessful > unsuccessful_threshold:
            entry.filtered_reason = "ip_unsuccessful_threshold"
            summary.filtered_high_unsuccessful_ips += 1
            filtered.append(entry)
            continue

        kept.append(entry)

    summary.kept_lines = len(kept)
    return kept, filtered, summary


def open_input(path: str) -> TextIO:
    if path == "-":
        return sys.stdin
    return Path(path).open("r", encoding="utf-8", errors="replace")


def open_output(path: str | None) -> TextIO:
    if not path:
        return sys.stdout
    return Path(path).open("w", encoding="utf-8", newline="")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Filter nginx access logs with a multi-pass pipeline.")
    parser.add_argument("input", help="Input access log path, or '-' for stdin")
    parser.add_argument("-o", "--output", help="Path for cleaned output. Defaults to stdout")
    parser.add_argument("--filtered-output", help="Optional path to write filtered-out lines")
    parser.add_argument(
        "--bot-pattern",
        action="append",
        default=[],
        help="Additional case-insensitive regex pattern for bot/scanner user-agents. Repeatable.",
    )
    parser.add_argument(
        "--unsuccessful-threshold",
        type=int,
        default=2,
        help="Filter IPs with more than this number of unsuccessful requests. Defaults to 2.",
    )
    parser.add_argument("--summary", action="store_true", help="Print summary and IP tallies to stderr")
    return parser


def print_summary(summary: Summary, ip_stats: dict[str, IpStats]) -> None:
    print(f"Total lines: {summary.total_lines}", file=sys.stderr)
    print(f"Parsed lines: {summary.parsed_lines}", file=sys.stderr)
    print(f"Unparsed lines kept: {summary.unparsed_lines}", file=sys.stderr)
    print(f"Kept lines: {summary.kept_lines}", file=sys.stderr)
    print(f"Filtered bots/scanners: {summary.filtered_bots}", file=sys.stderr)
    print(f"Filtered non-200 statuses: {summary.filtered_non_200}", file=sys.stderr)
    print(
        f"Filtered by IP unsuccessful threshold: {summary.filtered_high_unsuccessful_ips}",
        file=sys.stderr,
    )

    print("IP tallies:", file=sys.stderr)
    for remote_ip in sorted(ip_stats):
        counts = ip_stats[remote_ip]
        print(
            f"{remote_ip} successful={counts.successful} unsuccessful={counts.unsuccessful}",
            file=sys.stderr,
        )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.unsuccessful_threshold < 0:
        parser.error("--unsuccessful-threshold must be >= 0")

    input_handle = open_input(args.input)
    output_handle = open_output(args.output)
    filtered_handle = open_output(args.filtered_output) if args.filtered_output else None

    close_input = input_handle is not sys.stdin
    close_output = output_handle is not sys.stdout
    close_filtered = filtered_handle not in (None, sys.stdout)

    try:
        entries = [parse_log_line(line) for line in input_handle]
        ip_stats = tally_ip_stats(entries)
        bot_regex = build_bot_regex(args.bot_pattern)
        kept, filtered, summary = apply_filters(
            entries,
            bot_regex,
            ip_stats,
            args.unsuccessful_threshold,
        )

        for entry in kept:
            output_handle.write(entry.raw_line)

        if filtered_handle:
            for entry in filtered:
                filtered_handle.write(entry.raw_line)
    finally:
        if close_input:
            input_handle.close()
        if close_output:
            output_handle.close()
        if close_filtered and filtered_handle:
            filtered_handle.close()

    if args.summary:
        print_summary(summary, ip_stats)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
