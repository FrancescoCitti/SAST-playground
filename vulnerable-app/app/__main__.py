"""Entry point: ``python -m app``."""

from . import create_app

app = create_app()

if __name__ == "__main__":
    # VULN #5: Debug flag left enabled.
    # Expected tool(s): Semgrep (the custom `custom-flask-debug-enabled` rule;
    # also flagged by p/security-audit). Running Flask with debug=True exposes
    # the Werkzeug interactive debugger, which allows arbitrary code execution
    # on any unhandled exception. Production must run with debug=False.
    app.run(host="0.0.0.0", port=5000, debug=True)
