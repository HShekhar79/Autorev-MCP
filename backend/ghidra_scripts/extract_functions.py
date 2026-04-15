# extract_functions.py
# Ghidra headless post-analysis script.
#
# Enumerates all functions in the current program and writes structured JSON
# to <output_dir>/extract_functions_output.json
#
# JSON output schema:
# [
#   {
#     "name":    "<function name>",
#     "address": "<hex entry point>",
#     "size":    <byte count as int>
#   },
#   ...
# ]
#
# Usage (analyzeHeadless postScript args):
#   -postScript extract_functions.py --output-dir /path/to/output/dir
#
# Ghidra scripting API ref:
#   https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html

import json
import os
import sys

# ---------------------------------------------------------------------------
# Resolve output directory from script arguments
# ---------------------------------------------------------------------------
args = getScriptArgs()  # noqa: F821  (Ghidra injects getScriptArgs globally)

output_dir = None
for i, arg in enumerate(args):
    if arg == "--output-dir" and i + 1 < len(args):
        output_dir = args[i + 1]
        break

if not output_dir:
    output_dir = os.path.join(os.environ.get("TMPDIR", "/tmp"), "ghidra_output")

try:
    os.makedirs(output_dir, exist_ok=True)
except Exception as e:
    print("[GHIDRA][extract_functions] Cannot create output dir: %s" % e)
    # Do not raise — let the script exit cleanly so the engine records a WARN

# ---------------------------------------------------------------------------
# Extract functions via Ghidra API
# ---------------------------------------------------------------------------
results = []

try:
    program      = currentProgram   # noqa: F821
    func_manager = program.getFunctionManager()
    functions    = func_manager.getFunctions(True)  # True = forward iteration

    for func in functions:
        try:
            entry_addr = func.getEntryPoint()
            body       = func.getBody()
            size       = int(body.getNumAddresses()) if body else 0
            name       = str(func.getName())
            address    = str(entry_addr)

            results.append({
                "name":    name,
                "address": address,
                "size":    size,
            })
        except Exception as inner_exc:
            # Skip single broken function — don't abort the whole scan
            print("[GHIDRA][extract_functions] WARN skipping func: %s" % inner_exc)
            continue

except Exception as exc:
    print("[GHIDRA][extract_functions] ERROR enumerating functions: %s" % exc)

# ---------------------------------------------------------------------------
# Write output
# ---------------------------------------------------------------------------
out_path = os.path.join(output_dir, "extract_functions_output.json")

try:
    with open(out_path, "w") as fh:
        json.dump(results, fh)
    print("[GHIDRA][extract_functions] Wrote %d functions → %s" % (len(results), out_path))
except Exception as exc:
    print("[GHIDRA][extract_functions] ERROR writing output: %s" % exc)
