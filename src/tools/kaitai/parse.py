"""Parses files with a Kaitai Struct parser compiled to Python.

argv: <directory holding the compiled module> <module name> <class name> <request.json>
request: {"files": [str]}
answer (stdout, one JSON line): {"files": [{"path": str, "ok": bool, "consumed": int, "size": int, "error"?: str}]}

A file passes when the parser reads it without error and, with `_read` eager, every field is read. `consumed` is
how far the top-level stream got: less than `size` means trailing bytes the format does not describe. The parser
only reads the file (Kaitai's generated Python performs no I/O beyond its stream).
"""

import importlib
import json
import sys


def main():
    directory, module, cls, request = sys.argv[1:5]
    sys.path.insert(0, directory)
    parser = getattr(importlib.import_module(module), cls)
    out = []
    for path in json.load(open(request))["files"]:
        with open(path, "rb") as f:
            size = len(f.read())
        try:
            parsed = parser.from_file(path)
            out.append({"path": path, "ok": True, "consumed": parsed._io.pos(), "size": size})
            parsed._io.close()
        except Exception as error:  # any parse failure is a result, not a crash
            out.append({"path": path, "ok": False, "consumed": 0, "size": size, "error": f"{type(error).__name__}: {error}"[:300]})
    print(json.dumps({"files": out}))


if __name__ == "__main__":
    main()
