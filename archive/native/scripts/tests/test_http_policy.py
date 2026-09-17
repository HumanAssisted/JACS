from __future__ import annotations

import http.server
import importlib
import importlib.util
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_script(name: str):
    path = ROOT / "scripts" / name
    module_name = name.removesuffix(".py").replace("-", "_")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NoRedirectPolicyTests(unittest.TestCase):
    def test_default_opener_does_not_contact_redirect_target(self) -> None:
        policy = importlib.import_module("scripts.http_policy")
        hits: list[str] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
                hits.append(self.path)
                if self.path == "/start":
                    self.send_response(302)
                    self.send_header("Location", "/target")
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"unexpected")

            def log_message(self, *_args: object) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            request = urllib.request.Request(f"http://127.0.0.1:{port}/start")
            with self.assertRaises(urllib.error.HTTPError) as raised:
                policy.open_no_redirect(request, timeout=2)
            self.assertEqual(raised.exception.code, 302)
            raised.exception.close()
            self.assertEqual(hits, ["/start"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_registry_clients_share_the_no_redirect_default(self) -> None:
        policy = importlib.import_module("scripts.http_policy")
        clients = (
            ("homebrew_release.py", "fetch_bytes", "opener"),
            ("verify_pypi_release_attestations.py", "fetch_metadata", "open_url"),
            ("crates_release_gate.py", "probe_exact_version", "open_url"),
            ("check-release-matrix.py", "get_json", "open_url"),
            ("release_retry.py", "probe_retry_surfaces", "open_url"),
        )
        for script, function, parameter in clients:
            with self.subTest(script=script):
                module = load_script(script)
                default = getattr(module, function).__kwdefaults__[parameter]
                self.assertIs(default, policy.open_no_redirect)


if __name__ == "__main__":
    unittest.main()
