from pathlib import Path
import sys

if __package__ in {None, ""}:
    project_root = Path(__file__).resolve().parent.parent
    root_str = str(project_root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)

try:
    from .cli import main
except ImportError:
    from reconhive.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
