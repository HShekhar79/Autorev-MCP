import r2pipe
import os
from utils.debug import debug_log


class RadareExtractor:

    def __init__(self, binary_path):
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        self.binary_path = binary_path
        self.r2 = None

    def open(self):
        try:
            self.r2 = r2pipe.open(self.binary_path, flags=["-2"])
            self.r2.cmd("e anal.timeout=180")
            self.r2.cmd("aaa")
        except Exception as e:
            raise RuntimeError(f"Radare2 analysis failed: {e}")

    def close(self):
        try:
            if self.r2:
                self.r2.quit()
        except Exception:
            pass

    def get_functions(self):
        funcs = self.r2.cmdj("aflj")
        return funcs or []

    def get_imports(self):
        imports = self.r2.cmdj("iij")
        return [imp.get("name") for imp in imports or [] if imp.get("name")]

    def get_strings(self):
        strings = self.r2.cmdj("izj")
        return [s.get("string") for s in strings or [] if s.get("string")]

    def extract_calls_from_function(self, func_name):

        calls = []

        disasm = self.r2.cmdj(f"pdfj @ {func_name}")

        if not disasm or "ops" not in disasm:
            return calls

        for op in disasm["ops"]:

            if op.get("type") != "call":
                continue

            disasm_text = op.get("disasm", "")

            if not disasm_text:
                continue

            parts = disasm_text.split()

            if len(parts) < 2:
                continue

            raw_call = parts[-1]

            raw_call = raw_call.replace("sym.imp.", "")
            raw_call = raw_call.replace("sym.", "")
            raw_call = raw_call.replace("reloc.", "")
            raw_call = raw_call.replace("[", "").replace("]", "")

            raw_call = raw_call.strip()

            if raw_call:
                calls.append(raw_call)

        return list(set(calls))


# ----------------------------------
# WRAPPER FUNCTIONS
# ----------------------------------

def extract_functions(binary_path):

    extractor = RadareExtractor(binary_path)

    try:
        extractor.open()
        return extractor.get_functions()
    except Exception as e:
        debug_log("EXTRACT FUNCTIONS ERROR", str(e))
        return []
    finally:
        extractor.close()


def extract_imports(binary_path):

    extractor = RadareExtractor(binary_path)

    try:
        extractor.open()
        return extractor.get_imports()
    except Exception as e:
        debug_log("EXTRACT IMPORTS ERROR", str(e))
        return []
    finally:
        extractor.close()


def extract_strings(binary_path):

    extractor = RadareExtractor(binary_path)

    try:
        extractor.open()
        return extractor.get_strings()
    except Exception as e:
        debug_log("EXTRACT STRINGS ERROR", str(e))
        return []
    finally:
        extractor.close()


def extract_file_info(binary_path):

    extractor = RadareExtractor(binary_path)

    try:
        extractor.open()
        return extractor.r2.cmdj("ij") or {}
    except Exception as e:
        debug_log("EXTRACT FILE INFO ERROR", str(e))
        return {}
    finally:
        extractor.close()


def extract_sections(binary_path):

    extractor = RadareExtractor(binary_path)

    try:
        extractor.open()
        return extractor.r2.cmdj("iSj") or []
    except Exception as e:
        debug_log("EXTRACT SECTIONS ERROR", str(e))
        return []
    finally:
        extractor.close()