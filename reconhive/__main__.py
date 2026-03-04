try:
    from .cli import main
except ImportError:
    from reconhive.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
