import contextlib
import unittest
import urllib.error

from scripts.check_npm_bootstrap import PACKAGE_URL, require_absent


class NpmBootstrapTests(unittest.TestCase):
    def test_existing_package_cannot_use_bootstrap(self):
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            require_absent(open_url=lambda request, timeout: contextlib.nullcontext())

    def test_only_authoritative_not_found_allows_bootstrap(self):
        def absent(request, *, timeout):
            self.assertEqual(request.full_url, PACKAGE_URL)
            self.assertEqual(timeout, 20)
            raise urllib.error.HTTPError(PACKAGE_URL, 404, "not found", {}, None)

        require_absent(open_url=absent)

    def test_registry_errors_do_not_authorize_bootstrap(self):
        errors = [urllib.error.HTTPError(PACKAGE_URL, code, "error", {}, None)
                  for code in (301, 401, 403, 429, 500)]
        errors += [urllib.error.URLError("offline"), TimeoutError()]
        for error in errors:
            def fail(request, *, timeout):
                raise error

            with self.subTest(error=error), self.assertRaisesRegex(RuntimeError, "check failed"):
                require_absent(open_url=fail)
