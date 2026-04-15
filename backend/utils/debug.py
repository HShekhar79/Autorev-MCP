import json
from datetime import datetime, timezone
import traceback

DEBUG_MODE = True


def _ts():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def debug_log(label, data):
    if not DEBUG_MODE:
        return
    print(f"\n[{_ts()}] [DEBUG] {label}:")
    print(data)


def debug_pretty(label, data):
    if not DEBUG_MODE:
        return
    print(f"\n[{_ts()}] [DEBUG] {label}:")
    try:
        print(json.dumps(data, indent=4))
    except Exception:
        print(data)


def debug_error(label, error):
    if not DEBUG_MODE:
        return
    print(f"\n[{_ts()}] [ERROR] {label}: {str(error)}")
    traceback.print_exc()


def debug_stage(stage_name):
    if not DEBUG_MODE:
        return
    print(f"\n[{_ts()}] ======== {stage_name.upper()} ========")


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

    print(f"\n[{_ts()}] [DEBUG] {label} COUNT: {length}")