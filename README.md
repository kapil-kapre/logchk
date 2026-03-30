# logchk

logchk is a command-line tool to clean nginx access logs and keep only likely real-user traffic.

## What It Does

The tool processes nginx combined access log lines and keeps only requests that satisfy all rules.

A request is removed if any of the following is true:
- User-Agent matches a known bot/scanner pattern (or a custom pattern).
- HTTP method is not GET.
- HTTP status is not 200.
- The request comes from an IP that was previously filtered earlier in the same run.

After this first pass, an IP must also satisfy both:
- It has at least N successful requests (default: 3).
- It has at least one successful request to site.css or style.css.

If an IP fails either condition above, all of that IP's successful requests are removed from output.

## Requirements

- Python 3.9+

No third-party packages are required.

## Usage

Run against a file and print cleaned log lines to stdout:

```bash
python logchk.py access.log
```

Write output to a file:

```bash
python logchk.py access.log --output clean.log
```

Read from stdin:

```bash
type access.log | python logchk.py -
```

Show processing summary on stderr:

```bash
python logchk.py access.log --summary
```

Set minimum successful requests required per IP (default is 3):

```bash
python logchk.py access.log --min-successful-requests 3
```

Add custom bot/scanner patterns (repeatable):

```bash
python logchk.py access.log --bot-pattern customcrawler --bot-pattern monitorbot
```

## Filter Order

Rules are applied in this order:
1. Parse line.
2. Drop if source IP is already blocked.
3. Drop if method is not GET.
4. Drop if status is not 200.
5. Drop if User-Agent matches bot/scanner patterns.
6. Second pass: keep only IPs meeting minimum successful request count.
7. Second pass: keep only IPs with successful site.css or style.css request.

## Summary Fields

When --summary is enabled, logchk prints:
- Total lines
- Kept lines
- Filtered bots
- Filtered non-200 responses
- Filtered non-GET requests
- Filtered requests from blocked IPs
- Filtered by minimum successful requests/IP
- Filtered by missing site.css/style.css success
- Blocked IP count
- Unparsed lines kept

## Notes

- Parser targets standard nginx combined access log format.
- Unparsed lines are preserved.
- IP blocking is per run (per file/stream processing execution).
