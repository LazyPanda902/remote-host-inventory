from __future__ import annotations
import argparse
import json
from pathlib import Path
from .core import check_inventory

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Audit a local SSH server inventory without connecting to hosts.")
    parser.add_argument("inventory", help="Local JSON list or object with an assets list")
    args = parser.parse_args(argv)
    data = json.loads(Path(args.inventory).read_text(encoding="utf-8"))
    items = data.get("assets") if isinstance(data, dict) else data
    result = check_inventory(items)
    print(json.dumps(result, indent=2))
    return 1 if any(x["severity"] == "high" for x in result["issues"]) else 0

if __name__ == "__main__":
    raise SystemExit(main())
