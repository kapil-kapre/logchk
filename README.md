# logchk

logchk filters nginx access logs using a multi-pass pipeline to remove bots/scanners and non-user traffic.

## Filtering Plan Implemented

The tool parses each line into a structure containing:
- source IP
- request fields (method/path/protocol/query params)
- status
- user-agent

Then it applies these passes in order:
1. filter out bots/scanners by user-agent
2. filter out entries whose status is not `200`
3. filter out remaining entries whose IP has more than `2` unsuccessful requests or fewer than a configured minimum successful count
4. filter out entries whose referer does not contain `kapre.in`

`unsuccessful` means parsed entries from that IP with status not equal to `200`.

If a line cannot be parsed as nginx combined format, it is kept.

## Requirements

- Python 3.9+

No third-party packages are required.

## Usage

Write cleaned log to stdout:

```bash
python logchk.py access.log
```

Write cleaned log to a file:

```bash
python logchk.py access.log --output clean.log
```

Write filtered-out entries to another file:

```bash
python logchk.py access.log --output clean.log --filtered-output filtered.log
```

Read from stdin:

```bash
type access.log | python logchk.py -
```

Show summary and per-IP tallies:

```bash
python logchk.py access.log --summary
```

Add custom bot patterns (repeatable):

```bash
python logchk.py access.log --bot-pattern customcrawler --bot-pattern monitorbot
```

Adjust IP unsuccessful threshold (default is 2):

```bash
python logchk.py access.log --unsuccessful-threshold 2
```

Set minimum successful count required per IP (default is 0):

```bash
python logchk.py access.log --successful-threshold 3
```

Override the required referer substring for pass 4:

```bash
python logchk.py access.log --required-referer-substring kapre.in
```

## Summary Fields

With `--summary`, logchk prints:
- total and parsed/unparsed line counts
- kept line count
- filtered counts per pass
- per-IP successful/unsuccessful tallies
