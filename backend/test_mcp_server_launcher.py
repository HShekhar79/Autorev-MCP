import os
import runpy
import sys

log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "mcp_server_stderr.log",
)

log = open(log_path, "a", encoding="utf-8", buffering=1)
sys.stderr = log

runpy.run_path(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_server.py"),
    run_name="__main__",
)
