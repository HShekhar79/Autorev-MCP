# extract_calls.py
# Ghidra headless post-analysis script.
#
# Enumerates all CALL instructions across all defined functions and collects
# the resolved callee name (import, thunk, internal function).  Writes
# deduplicated results to <output_dir>/extract_calls_output.json
#
# JSON output schema:
# [
#   {
#     "caller":  "<caller function name>",
#     "callee":  "<called function / import name>",
#     "address": "<hex address of call site>"
#   },
#   ...
# ]
#
# Usage (analyzeHeadless postScript args):
#   -postScript extract_calls.py --output-dir /path/to/output/dir

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
    print("[GHIDRA][extract_calls] Cannot create output dir: %s" % e)

# ---------------------------------------------------------------------------
# Extract call sites via Ghidra API
# ---------------------------------------------------------------------------
from ghidra.program.model.symbol import FlowType  # noqa: E402  (Ghidra jython import)

results = []
seen_pairs = set()   # (caller_name, callee_name) — avoid duplicate rows

try:
    program      = currentProgram   # noqa: F821
    func_manager = program.getFunctionManager()
    ref_manager  = program.getReferenceManager()
    symbol_table = program.getSymbolTable()
    listing      = program.getListing()

    for func in func_manager.getFunctions(True):
        caller_name = str(func.getName())
        body        = func.getBody()

        if body is None:
            continue

        addr_set = body.getAddresses(True)
        for addr in addr_set:
            instr = listing.getInstructionAt(addr)
            if instr is None:
                continue

            flow = instr.getFlowType()
            if not (flow.isCall() or flow == FlowType.UNCONDITIONAL_CALL):
                continue

            # Resolve callee: first try the instruction's flow addresses
            flows = instr.getFlows()
            callee_name = None

            if flows and len(flows) > 0:
                target_addr = flows[0]
                target_func = func_manager.getFunctionAt(target_addr)
                if target_func:
                    callee_name = str(target_func.getName())
                else:
                    # May be a thunk to an import
                    syms = symbol_table.getSymbols(target_addr)
                    for sym in syms:
                        callee_name = str(sym.getName())
                        break

            if not callee_name:
                # Fall back: check references FROM this instruction
                refs = ref_manager.getReferencesFrom(addr)
                for ref in refs:
                    if ref.getReferenceType().isCall():
                        target_func = func_manager.getFunctionAt(ref.getToAddress())
                        if target_func:
                            callee_name = str(target_func.getName())
                            break

            if callee_name:
                pair = (caller_name, callee_name)
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    results.append({
                        "caller":  caller_name,
                        "callee":  callee_name,
                        "address": str(addr),
                    })

except Exception as exc:
    print("[GHIDRA][extract_calls] ERROR: %s" % exc)

# ---------------------------------------------------------------------------
# Write output
# ---------------------------------------------------------------------------
out_path = os.path.join(output_dir, "extract_calls_output.json")

try:
    with open(out_path, "w") as fh:
        json.dump(results, fh)
    print("[GHIDRA][extract_calls] Wrote %d call entries → %s" % (len(results), out_path))
except Exception as exc:
    print("[GHIDRA][extract_calls] ERROR writing output: %s" % exc)
