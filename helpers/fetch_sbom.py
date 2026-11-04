#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""Fetch the SPDX SBOM of a repository via GitHub's asynchronous SBOM API.

Flow (see https://docs.github.com/en/rest/dependency-graph/sboms):
  1. GET /repos/{owner}/{repo}/dependency-graph/sbom/generate-report -> 201 {"sbom_url": ...}
  2. GET {sbom_url} -> 202 while processing, 302 redirect to a temporary download URL when ready
  3. GET {download_url} -> SPDX JSON
"""

import argparse
import json
import logging
import os
import sys
import time

import requests

API_VERSION = "2026-03-10"
DEFAULT_API_URL = "https://api.github.com"
DEFAULT_TIMEOUT_SECONDS = 300
MAX_POLL_INTERVAL_SECONDS = 15
REQUEST_TIMEOUT_SECONDS = 60


class SbomFetchError(Exception):
    """Raised when the SBOM cannot be retrieved."""


def _api_headers(token):
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _access_error(status_code, repository, response):
    try:
        message = response.json().get("message", "")
    except ValueError:
        message = response.text
    return SbomFetchError(
        f"GitHub API returned {status_code} for '{repository}' ({message}). "
        "Make sure the Dependency Graph is enabled for this repository and the token "
        "has read access to its contents (permissions: contents: read)."
    )


def request_report(session, api_url, repository, token):
    """Trigger SBOM generation and return the polling URL."""
    url = f"{api_url}/repos/{repository}/dependency-graph/sbom/generate-report"
    response = session.get(url, headers=_api_headers(token), timeout=REQUEST_TIMEOUT_SECONDS)
    if response.status_code in (403, 404):
        raise _access_error(response.status_code, repository, response)
    if response.status_code not in (200, 201):
        raise SbomFetchError(
            f"Unexpected status {response.status_code} when requesting SBOM generation: {response.text}"
        )
    sbom_url = response.json().get("sbom_url")
    if not sbom_url:
        raise SbomFetchError(f"SBOM generation response did not contain 'sbom_url': {response.text}")
    return sbom_url


def _poll_interval(response, attempt):
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        try:
            return min(max(float(retry_after), 1.0), MAX_POLL_INTERVAL_SECONDS)
        except ValueError:
            pass
    return min(2 ** attempt, MAX_POLL_INTERVAL_SECONDS)


def wait_for_download_url(session, sbom_url, repository, token, timeout_seconds,
                          sleep=time.sleep, clock=time.monotonic):
    """Poll the report URL until GitHub redirects to the finished SBOM."""
    deadline = clock() + timeout_seconds
    attempt = 1
    while True:
        response = session.get(sbom_url, headers=_api_headers(token),
                               allow_redirects=False, timeout=REQUEST_TIMEOUT_SECONDS)
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location")
            if not location:
                raise SbomFetchError("SBOM report redirect did not contain a Location header.")
            return location
        if response.status_code in (403, 404):
            raise _access_error(response.status_code, repository, response)
        if response.status_code not in (201, 202):
            raise SbomFetchError(
                f"Unexpected status {response.status_code} while polling SBOM report: {response.text}"
            )

        delay = _poll_interval(response, attempt)
        if clock() + delay > deadline:
            raise SbomFetchError(
                f"Timed out after {timeout_seconds}s waiting for GitHub to generate the SBOM."
            )
        logging.info("SBOM is still being generated, retrying in %ss...", delay)
        sleep(delay)
        attempt += 1


def download_sbom(session, download_url):
    """Download the SBOM from the temporary URL (without GitHub credentials)."""
    response = session.get(download_url, timeout=REQUEST_TIMEOUT_SECONDS)
    if response.status_code != 200:
        raise SbomFetchError(f"Failed to download SBOM (status {response.status_code}).")
    try:
        data = response.json()
    except ValueError as exc:
        raise SbomFetchError(f"Downloaded SBOM is not valid JSON: {exc}") from exc
    # The deprecated synchronous endpoint wrapped the document in {"sbom": {...}}.
    if isinstance(data, dict) and isinstance(data.get("sbom"), dict):
        data = data["sbom"]
    if not isinstance(data, dict) or "packages" not in data:
        raise SbomFetchError("Downloaded document does not look like an SPDX SBOM (no 'packages').")
    return data


def fetch_sbom(repository, token, api_url=DEFAULT_API_URL, timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
               session=None, sleep=time.sleep, clock=time.monotonic):
    session = session or requests.Session()
    api_url = api_url.rstrip("/")
    sbom_url = request_report(session, api_url, repository, token)
    logging.info("SBOM generation requested: %s", sbom_url)
    download_url = wait_for_download_url(session, sbom_url, repository, token, timeout_seconds,
                                         sleep=sleep, clock=clock)
    return download_sbom(session, download_url)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fetch a repository SBOM via GitHub's asynchronous SBOM API.")
    parser.add_argument("repository", help="Repository in the form owner/repo.")
    parser.add_argument("output", help="Path of the SPDX JSON file to write.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS,
                        help=f"Maximum seconds to wait for SBOM generation (default: {DEFAULT_TIMEOUT_SECONDS}).")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(levelname)s: %(message)s")

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    api_url = os.environ.get("GITHUB_API_URL") or DEFAULT_API_URL

    try:
        sbom = fetch_sbom(args.repository, token, api_url=api_url, timeout_seconds=args.timeout)
    except (SbomFetchError, requests.RequestException) as exc:
        print(f"Error: Failed to fetch SBOM: {exc}", file=sys.stderr)
        return 1

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2)

    print("SBOM file successfully downloaded.")
    print("--- SBOM Entry Count ---")
    print(f"packages: {len(sbom.get('packages', []))}")
    print(f"relationships: {len(sbom.get('relationships', []))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
