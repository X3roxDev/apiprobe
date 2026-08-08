# APIProbe

A compact HTTP/API testing CLI for quick endpoint checks, scripted smoke tests, and response inspection.

## Why This Exists

APIProbe is designed as a small, practical command-line project that can be read, modified, and run without a heavy setup step. It keeps the implementation in `main.py` so the repository stays easy to browse on GitHub.

## Highlights

- Supports GET, POST, PUT, PATCH, and DELETE requests.
- Accepts custom headers, query parameters, request bodies, and timeouts.
- Displays status, response headers, response timing, and optionally saves response bodies.
- Uses Python's standard TLS verification by default.
- Works as a single-file tool with no third-party dependencies.

## Requirements

- Python 3.11 or newer
- Windows or Linux where the underlying operating-system feature is available
- No third-party Python packages

## Quick Start

```bash
python main.py --help
```

Run commands from inside the `apiprobe` folder.

## Command Examples

```bash
python main.py request GET https://example.com
```

```bash
python main.py request GET https://api.example.com/users --header Accept=application/json
```

```bash
python main.py request POST https://api.example.com/items --body '{"name":"demo"}' --json response.json
```

## Output

Most commands print a readable terminal report. Commands with `--json` or `--csv` write structured files that can be used by scripts, automation, or later review.


## Safety Notes

Use APIProbe for authorized APIs and test environments. It does not disable certificate checks by default.