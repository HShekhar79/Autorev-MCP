# extract_strings.py
# Ghidra headless post-analysis script.
#
# Enumerates all defined strings in the program's data and writes them to
# <output_dir>/extract_strings_output.json
#
# JSON output schema:
# [
#   {
#     "value":   "<string content>",
#     "address": "<hex address>",
#     "length":  <byte length as int>
#   },
#   ...
# ]
#
# Usage (analyzeHeadless postScript args):
#   -postScript extract_strings.py --output-dir /path/to/output/dir

import json
import os

# ---------------------------------------------------------------------------
# Resolve output directory from script arguments
# ---------------------------------------------------------------------------
args = getScriptArgs()  # noqa: F821

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
    print("[GHIDRA][extract_strings] Cannot create output dir: %s" % e)

# ---------------------------------------------------------------------------
# Extract strings via Ghidra API
# ---------------------------------------------------------------------------
MAX_STRINGS = 5000   # safety cap — matches engine-side MAX_STRINGS
MIN_LEN     = 4      # ignore trivially short strings

results = []

try:
    program  = currentProgram   # noqa: F821
    listing  = program.getListing()
    data_itr = listing.getDefinedData(True)   # forward iteration over all defined data

    for data in data_itr:
        if len(results) >= MAX_STRINGS:
            break

        data_type = data.getDataType()
        dt_name   = str(data_type.getName()).lower()

        # Accept all variants of string types Ghidra defines
        if "string" not in dt_name and "unicode" not in dt_name:
            continue

        try:
            value = data.getValue()
            if value is None:
                continue

            s = str(value).strip()

            if len(s) < MIN_LEN:
                continue

            results.append({
                "value":   s,
                "address": str(data.getAddress()),
                "length":  len(s),
            })
        except Exception as inner_exc:
            print("[GHIDRA][extract_strings] WARN skipping item: %s" % inner_exc)
            continue

except Exception as exc:
    print("[GHIDRA][extract_strings] ERROR: %s" % exc)

# ---------------------------------------------------------------------------
# Write output
# ---------------------------------------------------------------------------
out_path = os.path.join(output_dir, "extract_strings_output.json")

try:
    with open(out_path, "w") as fh:
        json.dump(results, fh)
    print("[GHIDRA][extract_strings] Wrote %d strings → %s" % (len(results), out_path))
except Exception as exc:
    print("[GHIDRA][extract_strings] ERROR writing output: %s" % exc)
