"""HTTP handlers wiring user input to dangerous sinks."""

import os
import pickle
import base64

from flask import Blueprint, request, jsonify

from . import db

bp = Blueprint("app", __name__)


@bp.route("/users")
def users():
    # Forwards an attacker-controlled query parameter into the SQL layer
    # (see VULN #1 in db.py).
    username = request.args.get("name", "")
    return jsonify(db.find_user(username))


@bp.route("/ping")
def ping():
    """Ping a host.

    VULN #2: OS command injection.
    Expected tool(s): Semgrep (p/security-audit / p/owasp-top-ten), CodeQL
    (taint from ``request.args`` into ``os.system``).

    ``host`` flows unsanitised into a shell command, so ``8.8.8.8; rm -rf /``
    runs arbitrary commands. The safe form passes an argument list to
    ``subprocess.run([...], shell=False)``.
    """
    host = request.args.get("host", "127.0.0.1")
    os.system("ping -c 1 " + host)
    return jsonify({"pinged": host})


@bp.route("/load", methods=["POST"])
def load():
    """Rehydrate a session blob.

    VULN #3: Insecure deserialization.
    Expected tool(s): Semgrep (the custom `custom-insecure-deserialization`
    rule), CodeQL (untrusted data to ``pickle.loads``).

    ``pickle.loads`` on attacker-supplied bytes yields remote code execution
    via ``__reduce__``. Use a safe format such as JSON for untrusted input.
    """
    blob = base64.b64decode(request.get_data())
    session = pickle.loads(blob)
    return jsonify({"keys": list(session.keys())})
