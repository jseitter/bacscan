"""Entry point for `python -m bacscan` and the macOS app bundle.

No arguments -> GUI. Any arguments -> command line (e.g. `bacscan.app/Contents/MacOS/bacscan scan`).
"""
import sys


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("-psn_")]  # old Finder process-serial arg
    if not args:
        from bacscan.gui.app import main as gui_main
        return gui_main()
    from bacscan.cli.main import main as cli_main
    return cli_main(args)


if __name__ == "__main__":
    sys.exit(main())
