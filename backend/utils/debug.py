import json
import sys
from datetime import datetime, timezone
import traceback

DEBUG_MODE = True

# All diagnostics go to stderr. stdout is reserved for protocol traffic
# (the MCP stdio transport reads JSON-RPC from the server's stdout), so
# anything printed there corrupts the stream.


def _ts():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def debug_log(label, data):
    if not DEBUG_MODE:
        return
    print(f"\n[{_ts()}] [DEBUG] {label}:", file=sys.stderr)
    print(data, file=sys.stderr)


def debug_pretty(label, data):
    if not DEBUG_MODE:
        return
    print(f"\n[{_ts()}] [DEBUG] {label}:", file=sys.stderr)
    try:
        print(json.dumps(data, indent=4), file=sys.stderr)
    except Exception:
        print(data, file=sys.stderr)


def debug_error(label, error):
    if not DEBUG_MODE:
        return
    print(f"\n[{_ts()}] [ERROR] {label}: {str(error)}", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)


def debug_stage(stage_name):
    if not DEBUG_MODE:
        return
    print(f"\n[{_ts()}] ======== {stage_name.upper()} ========", file=sys.stderr)


def debug_len(label, data):
    if not DEBUG_MODE:
        return
    if data is None:
        length = 0
    else:
        try:
            length = len(data)
        except Exception:
            length = "N/A"

    print(f"\n[{_ts()}] [DEBUG] {label} COUNT: {length}", file=sys.stderr)