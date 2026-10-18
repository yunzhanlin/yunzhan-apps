#!/usr/bin/env python3
"""Create the first administrator and save its one-time credentials for root."""

import json
import os
import pathlib
import secrets
import sqlite3
import string
import urllib.request


DB = pathlib.Path("/var/lib/panel/panel.db")
TOKEN = pathlib.Path("/var/lib/panel/bootstrap-token")
OUTPUT = pathlib.Path("/etc/panel/first-login.json")
BASE = "http://127.0.0.1:19100"


def main():
    with sqlite3.connect(DB) as db:
        users = db.execute("SELECT count(*) FROM users").fetchone()[0]
        entry = db.execute("SELECT http_entry FROM panel_access WHERE id=1").fetchone()[0]
    if users:
        return
    if len(entry) != 10 or not entry.isalnum():
        raise RuntimeError("installer did not generate a valid panel entry")
    token = TOKEN.read_text(encoding="ascii").strip()
    if OUTPUT.exists():
        credentials = json.loads(OUTPUT.read_text(encoding="utf-8"))
        if credentials.get("entry") != entry:
            raise RuntimeError("stored first-login entry does not match panel state")
    else:
        alphabet = string.ascii_letters + string.digits
        credentials = {
            "username": "admin",
            "password": "".join(secrets.choice(alphabet) for _ in range(28)),
            "entry": entry,
        }
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(OUTPUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(credentials, out, ensure_ascii=False)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
    request = urllib.request.Request(
        BASE + "/api/bootstrap",
        data=json.dumps({"username": credentials["username"], "password": credentials["password"], "token": token}).encode("utf-8"),
        headers={"Content-Type": "application/json", "Origin": BASE},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status != 201:
            raise RuntimeError("administrator initialization failed")
    print("First-login credentials saved in /etc/panel/first-login.json (root only)")


if __name__ == "__main__":
    main()
