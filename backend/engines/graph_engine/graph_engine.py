import r2pipe
import re
from utils.debug import debug_log


def normalize_call(call):

    if not call:
        return ""

    call = call.replace("sym.imp.", "")
    call = call.replace("sym.", "")
    call = call.replace("reloc.", "")
    call = call.replace("[", "").replace("]", "")

    call = call.split(" ")[0]
    call = re.sub(r"[AW]$", "", call)

    return call.strip()


def extract_call_graph(binary_path):

    r2 = r2pipe.open(binary_path)

    graph = []
    edges = set()

    try:
        r2.cmd("aaa")

        functions = r2.cmdj("aflj") or []

        for func in functions:

            fname = func.get("name")
            if not fname:
                continue

            try:
                disasm = r2.cmdj(f"pdfj @ {fname}")

                if not disasm or "ops" not in disasm:
                    continue

                for op in disasm["ops"]:

                    if "call" not in op.get("type", ""):
                        continue

                    disasm_text = op.get("disasm", "")
                    if not disasm_text:
                        continue

                    parts = disasm_text.split()
                    if len(parts) < 2:
                        continue

                    target = normalize_call(parts[-1])

                    if not target:
                        continue

                    edge = (fname, target)

                    if edge not in edges:
                        edges.add(edge)
                        graph.append({
                            "from": fname,
                            "to": target
                        })

            except Exception as e:
                debug_log("GRAPH FUNCTION ERROR", str(e))
                continue

    finally:
        r2.quit()

    return graph