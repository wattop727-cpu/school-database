"""
main.py
-------
Entry point for the Email Header Analyzer.
Run with:
    python main.py          → launches the GUI
    python main.py --cli    → launches the CLI
    python main.py file.eml → analyses a file via CLI
"""

import sys


def main():
    """
    Determine whether to launch the GUI or CLI based on command-line arguments.
    Uses conditional statements.
    """
    # Conditional: if --cli flag is passed, use CLI; otherwise launch GUI
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        # Remove the --cli flag before passing to cli module
        sys.argv.pop(1)
        from cli import run_cli
        run_cli()
    elif len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
        # A file path was passed — use CLI to analyse it
        from cli import run_cli
        run_cli()
    else:
        # Default: launch the GUI
        from gui import launch_gui
        launch_gui()


if __name__ == "__main__":
    main()
