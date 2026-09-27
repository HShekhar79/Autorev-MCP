import r2pipe
from pprint import pprint

file_path = "storage\\uploads\\1224ac91_test_mitre.exe"
r2 = r2pipe.open(file_path, flags=["-2"])
r2.cmd("aaa")

# Let's try getting all calls
# 'agcj' gives Call graph in JSON format
cg = r2.cmdj("agcj")

calls = set()
if cg:
    for node in cg:
        if "imports" in node:
            for imp in node["imports"]:
                calls.add(imp)

        # "out" contains references to other functions/imports
        # Actually in agcj, it's just a graph of blocks
        # Let's check aflj instead
        pass

funcs = r2.cmdj("aflj")
if funcs:
    print(f"Functions found: {len(funcs)}")

    for f in funcs:
        offset = f.get("offset")

        if offset is None:
            continue

        xrefs = r2.cmdj(f"axtj {offset}")
        # Or faster: just check imports usage
        pass

print("Radare2 PE test completed successfully.")
r2.quit()

# A simpler way : 'axj' or 'afoj'
r2.quit()
