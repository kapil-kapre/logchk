from __future__ import annotations

import argparse
from collections import defaultdict
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, TextIO


DEFAULT_BOT_PATTERNS = [
    r"bot",
    r"spider",
    r"crawler",
    r"crawl",
    r"slurp",
    r"googlebot",
    r"bingbot",
    r"duckduckbot",
    r"baiduspider",
    r"yandexbot",
    r"facebot",
    r"applebot",
    r"semrushbot",
    r"ahrefsbot",
    r"mj12bot",
    r"dotbot",
    r"petalbot",
    r"bytespider",
    r"gptbot",
    r"chatgpt-user",
    r"perplexitybot",
    r"cohere-ai",
    r"amazonbot",
    r"ccbot",
    r"seekport",
    r"seznambot",
    r"ia_archiver",
    r"go-http-client/1\.1",
    r"scan",
    r"traffic",
    r"WPCheck",
    r"WPCrawl",
    r"Censys",
    r"inspect",
    r"check",
    r"python-requests",
    r"zgrab",
    r"odin",
    r"openai",
    r"chatgpt",
    r"gemini",
    r"amazon",
    r"microsoft",
    r"meta",
    r"google",
    r"facebook"
]

LOG_PATTERN = re.compile(
    r'^(?P<remote>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<body_bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)


@dataclass
class Stats:
    total_lines: int = 0
    kept_lines: int = 0
    filtered_bots: int = 0
    filtered_non_200: int = 0
    filtered_non_get: int = 0
    filtered_blocked_ip: int = 0
    filtered_low_success_ips: int = 0
    filtered_missing_required_css: int = 0
    unparsed_lines: int = 0
    blocked_ips: set[str] = field(default_factory=set)


def build_bot_regex(custom_patterns: list[str]) -> re.Pattern[str]:
    patterns = DEFAULT_BOT_PATTERNS + custom_patterns
    return re.compile("|".join(f"(?:{pattern})" for pattern in patterns), re.IGNORECASE)


def is_bot_user_agent(user_agent: str, bot_regex: re.Pattern[str]) -> bool:
    return bool(bot_regex.search(user_agent))


def get_request_method(request: str) -> str | None:
    parts = request.split(" ", 1)
    if not parts or not parts[0]:
        return None
    return parts[0].upper()


def get_request_path(request: str) -> str | None:
    parts = request.split(" ")
    if len(parts) < 2:
        return None
    return parts[1]


def has_required_css(path: str | None) -> bool:
    if not path:
        return False

    normalized_path = path.split("?", 1)[0].split("#", 1)[0].lower()
    basename = normalized_path.rsplit("/", 1)[-1]
    return basename in {"site.css", "style.css"}


def should_keep_line(line: str, bot_regex: re.Pattern[str], stats: Stats) -> bool:
    stats.total_lines += 1

    match = LOG_PATTERN.match(line.rstrip("\n"))
    if not match:
        stats.unparsed_lines += 1
        return True

    remote_ip = match.group("remote")
    status = match.group("status")
    request = match.group("request")
    user_agent = match.group("user_agent")
    method = get_request_method(request)

    if remote_ip in stats.blocked_ips:
        stats.filtered_blocked_ip += 1
        return False

    if method != "GET":
        stats.filtered_non_get += 1
        stats.blocked_ips.add(remote_ip)
        return False

    if status != "200":
        stats.filtered_non_200 += 1
        stats.blocked_ips.add(remote_ip)
        return False

    if is_bot_user_agent(user_agent, bot_regex):
        stats.filtered_bots += 1
        stats.blocked_ips.add(remote_ip)
        return False

    return True


def iter_clean_lines(
    lines: Iterable[str],
    bot_regex: re.Pattern[str],
    stats: Stats,
    min_successful_requests: int,
) -> Iterable[str]:
    pending_lines: list[tuple[str, str | None]] = []
    successful_by_ip: dict[str, int] = defaultdict(int)
    css_success_by_ip: dict[str, bool] = defaultdict(bool)

    for line in lines:
        if should_keep_line(line, bot_regex, stats):
            match = LOG_PATTERN.match(line.rstrip("\n"))
            if not match:
                pending_lines.append((line, None))
                continue

            remote_ip = match.group("remote")
            request = match.group("request")
            pending_lines.append((line, remote_ip))
            successful_by_ip[remote_ip] += 1
            if has_required_css(get_request_path(request)):
                css_success_by_ip[remote_ip] = True

    for line, remote_ip in pending_lines:
        if remote_ip is None:
            stats.kept_lines += 1
            yield line
            continue

        if successful_by_ip[remote_ip] >= min_successful_requests and css_success_by_ip[remote_ip]:
            stats.kept_lines += 1
            yield line
            continue

        if successful_by_ip[remote_ip] < min_successful_requests:
            stats.filtered_low_success_ips += 1
            continue

        stats.filtered_missing_required_css += 1


def open_input(path: str) -> TextIO:
    if path == "-":
        return sys.stdin
    return Path(path).open("r", encoding="utf-8", errors="replace")


def open_output(path: str | None) -> TextIO:
    if not path:
        return sys.stdout
    return Path(path).open("w", encoding="utf-8", newline="")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Clean an nginx access log by keeping only GET requests with 200 responses, excluding bots, "
            "and requiring a minimum number of successful requests per IP."
        )
    )
    parser.add_argument("input", help="Input access log path, or '-' for stdin")
    parser.add_argument("-o", "--output", help="Output path. Defaults to stdout")
    parser.add_argument(
        "--bot-pattern",
        action="append",
        default=[],
        help="Additional case-insensitive regex pattern used to identify bots. Can be repeated.",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print processing stats to stderr when complete.",
    )
    parser.add_argument(
        "--min-successful-requests",
        type=int,
        default=3,
        help="Minimum successful requests an IP must have to be kept. Defaults to 3.",
    )
    return parser


def print_summary(stats: Stats) -> None:
    print(f"Total lines: {stats.total_lines}", file=sys.stderr)
    print(f"Kept lines: {stats.kept_lines}", file=sys.stderr)
    print(f"Filtered bots: {stats.filtered_bots}", file=sys.stderr)
    print(f"Filtered non-200 responses: {stats.filtered_non_200}", file=sys.stderr)
    print(f"Filtered non-GET requests: {stats.filtered_non_get}", file=sys.stderr)
    print(f"Filtered requests from blocked IPs: {stats.filtered_blocked_ip}", file=sys.stderr)
    print(f"Filtered by minimum successful requests/IP: {stats.filtered_low_success_ips}", file=sys.stderr)
    print(
        f"Filtered by missing site.css/style.css success: {stats.filtered_missing_required_css}",
        file=sys.stderr,
    )
    print(f"Blocked IP count: {len(stats.blocked_ips)}", file=sys.stderr)
    print(f"Unparsed lines kept: {stats.unparsed_lines}", file=sys.stderr)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.min_successful_requests < 1:
        parser.error("--min-successful-requests must be >= 1")

    bot_regex = build_bot_regex(args.bot_pattern)
    stats = Stats()

    input_handle = open_input(args.input)
    output_handle = open_output(args.output)

    close_input = input_handle is not sys.stdin
    close_output = output_handle is not sys.stdout

    try:
        for line in iter_clean_lines(input_handle, bot_regex, stats, args.min_successful_requests):
            output_handle.write(line)
    finally:
        if close_input:
            input_handle.close()
        if close_output:
            output_handle.close()

    if args.summary:
        print_summary(stats)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())