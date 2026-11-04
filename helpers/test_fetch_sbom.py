#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for fetch_sbom.py (asynchronous GitHub SBOM API, issue #42)."""

import json
import logging
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from fetch_sbom import (
    API_VERSION,
    SbomFetchError,
    fetch_sbom,
    main,
)

logging.disable(logging.CRITICAL)

REPO = "octo-org/octo-repo"
API = "https://api.github.com"
GENERATE_URL = f"{API}/repos/{REPO}/dependency-graph/sbom/generate-report"
SBOM_URL = f"{API}/repos/{REPO}/dependency-graph/sbom/fetch-report/1234-uuid"
DOWNLOAD_URL = "https://storage.example.com/sbom.json?sig=abc"
SPDX = {
    "spdxVersion": "SPDX-2.3",
    "SPDXID": "SPDXRef-DOCUMENT",
    "packages": [{"name": "a"}, {"name": "b"}],
    "relationships": [{"relationshipType": "DEPENDS_ON"}],
}


def _response(status, body=None, headers=None):
    response = MagicMock()
    response.status_code = status
    response.headers = headers or {}
    response.text = json.dumps(body) if body is not None else ""
    if body is None:
        response.json.side_effect = ValueError("no json")
    else:
        response.json.return_value = body
    return response


class FakeSession:
    """Returns queued responses per URL and records every call."""

    def __init__(self, responses):
        self.responses = {url: list(items) for url, items in responses.items()}
        self.calls = []

    def get(self, url, headers=None, **kwargs):
        self.calls.append({"url": url, "headers": headers or {}, **kwargs})
        return self.responses[url].pop(0)


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def _run(session, timeout=300):
    clock = FakeClock()
    result = fetch_sbom(REPO, "secret-token", api_url=API, timeout_seconds=timeout,
                        session=session, sleep=clock.sleep, clock=clock.time)
    return result, clock


class TestFetchSbom(unittest.TestCase):

    def test_ready_immediately(self):
        session = FakeSession({
            GENERATE_URL: [_response(201, {"sbom_url": SBOM_URL})],
            SBOM_URL: [_response(302, headers={"Location": DOWNLOAD_URL})],
            DOWNLOAD_URL: [_response(200, SPDX)],
        })
        result, clock = _run(session)
        self.assertEqual(result, SPDX)
        self.assertEqual(clock.sleeps, [])

    def test_sends_api_version_and_token_to_github(self):
        session = FakeSession({
            GENERATE_URL: [_response(201, {"sbom_url": SBOM_URL})],
            SBOM_URL: [_response(302, headers={"Location": DOWNLOAD_URL})],
            DOWNLOAD_URL: [_response(200, SPDX)],
        })
        _run(session)
        for call in session.calls[:2]:
            self.assertEqual(call["headers"]["X-GitHub-Api-Version"], API_VERSION)
            self.assertEqual(call["headers"]["Authorization"], "Bearer secret-token")
        self.assertFalse(session.calls[1]["allow_redirects"])

    def test_download_does_not_leak_token(self):
        session = FakeSession({
            GENERATE_URL: [_response(201, {"sbom_url": SBOM_URL})],
            SBOM_URL: [_response(302, headers={"Location": DOWNLOAD_URL})],
            DOWNLOAD_URL: [_response(200, SPDX)],
        })
        _run(session)
        download_call = session.calls[2]
        self.assertEqual(download_call["url"], DOWNLOAD_URL)
        self.assertNotIn("Authorization", download_call["headers"])

    def test_polls_while_processing(self):
        session = FakeSession({
            GENERATE_URL: [_response(201, {"sbom_url": SBOM_URL})],
            SBOM_URL: [_response(202), _response(202), _response(202),
                       _response(302, headers={"Location": DOWNLOAD_URL})],
            DOWNLOAD_URL: [_response(200, SPDX)],
        })
        result, clock = _run(session)
        self.assertEqual(result, SPDX)
        self.assertEqual(clock.sleeps, [2, 4, 8])

    def test_poll_interval_is_capped(self):
        session = FakeSession({
            GENERATE_URL: [_response(201, {"sbom_url": SBOM_URL})],
            SBOM_URL: [_response(202)] * 6 + [_response(302, headers={"Location": DOWNLOAD_URL})],
            DOWNLOAD_URL: [_response(200, SPDX)],
        })
        _, clock = _run(session)
        self.assertEqual(max(clock.sleeps), 15)

    def test_respects_retry_after(self):
        session = FakeSession({
            GENERATE_URL: [_response(201, {"sbom_url": SBOM_URL})],
            SBOM_URL: [_response(202, headers={"Retry-After": "5"}),
                       _response(302, headers={"Location": DOWNLOAD_URL})],
            DOWNLOAD_URL: [_response(200, SPDX)],
        })
        _, clock = _run(session)
        self.assertEqual(clock.sleeps, [5.0])

    def test_timeout(self):
        session = FakeSession({
            GENERATE_URL: [_response(201, {"sbom_url": SBOM_URL})],
            SBOM_URL: [_response(202)] * 100,
        })
        with self.assertRaisesRegex(SbomFetchError, "Timed out"):
            _run(session, timeout=20)

    def test_generate_not_found(self):
        session = FakeSession({GENERATE_URL: [_response(404, {"message": "Not Found"})]})
        with self.assertRaisesRegex(SbomFetchError, "Dependency Graph is enabled"):
            _run(session)

    def test_generate_forbidden(self):
        session = FakeSession({GENERATE_URL: [_response(403, {"message": "Forbidden"})]})
        with self.assertRaisesRegex(SbomFetchError, "403"):
            _run(session)

    def test_fetch_report_not_found(self):
        session = FakeSession({
            GENERATE_URL: [_response(201, {"sbom_url": SBOM_URL})],
            SBOM_URL: [_response(404, {"message": "Not Found"})],
        })
        with self.assertRaisesRegex(SbomFetchError, "404"):
            _run(session)

    def test_missing_sbom_url(self):
        session = FakeSession({GENERATE_URL: [_response(201, {})]})
        with self.assertRaisesRegex(SbomFetchError, "sbom_url"):
            _run(session)

    def test_unwraps_legacy_sbom_wrapper(self):
        session = FakeSession({
            GENERATE_URL: [_response(201, {"sbom_url": SBOM_URL})],
            SBOM_URL: [_response(302, headers={"Location": DOWNLOAD_URL})],
            DOWNLOAD_URL: [_response(200, {"sbom": SPDX})],
        })
        result, _ = _run(session)
        self.assertEqual(result, SPDX)

    def test_rejects_non_sbom_document(self):
        session = FakeSession({
            GENERATE_URL: [_response(201, {"sbom_url": SBOM_URL})],
            SBOM_URL: [_response(302, headers={"Location": DOWNLOAD_URL})],
            DOWNLOAD_URL: [_response(200, {"message": "something else"})],
        })
        with self.assertRaisesRegex(SbomFetchError, "packages"):
            _run(session)

    def test_strips_trailing_slash_from_api_url(self):
        session = FakeSession({
            GENERATE_URL: [_response(201, {"sbom_url": SBOM_URL})],
            SBOM_URL: [_response(302, headers={"Location": DOWNLOAD_URL})],
            DOWNLOAD_URL: [_response(200, SPDX)],
        })
        clock = FakeClock()
        fetch_sbom(REPO, "t", api_url=API + "/", session=session, sleep=clock.sleep, clock=clock.time)
        self.assertEqual(session.calls[0]["url"], GENERATE_URL)


class TestMain(unittest.TestCase):

    def test_writes_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = os.path.join(tmp, "sbom.json")
            with patch("fetch_sbom.fetch_sbom", return_value=SPDX) as mocked, \
                    patch.dict(os.environ, {"GITHUB_TOKEN": "tok", "GITHUB_API_URL": "https://ghe.example.com/api/v3"}):
                exit_code = main([REPO, output])
            self.assertEqual(exit_code, 0)
            with open(output) as f:
                self.assertEqual(json.load(f), SPDX)
            mocked.assert_called_once_with(REPO, "tok", api_url="https://ghe.example.com/api/v3",
                                           timeout_seconds=300)

    def test_returns_error_code_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = os.path.join(tmp, "sbom.json")
            with patch("fetch_sbom.fetch_sbom", side_effect=SbomFetchError("boom")):
                exit_code = main([REPO, output])
            self.assertEqual(exit_code, 1)
            self.assertFalse(os.path.exists(output))


if __name__ == "__main__":
    unittest.main()
