#!/usr/bin/env python3
"""
Prisma Cloud — Fetch All Repositories (v2 API) & Export to CSV
===============================================================
Compatible with Python 3.7+

Features:
  - Authenticates using Access Key ID + Secret Key
  - Fetches ALL repositories from /bridgecrew/api/v2/repositories
  - Handles pagination (page=0 based)
  - Writes to CSV immediately (crash-safe)
  - Retries all network calls with exponential backoff
  - Re-authenticates every 5 minutes automatically

Requirements:
    pip3 install requests

Usage:
    python3 prisma_repositories_export.py
"""

import requests
import csv
import time
import sys
import getpass
import os
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────
API_URL        = "https://api.ind.prismacloud.io"
PAGE_SIZE      = 100             # Max page size for v2 API
TOKEN_REFRESH  = 300             # Re-authenticate every 5 minutes
SLEEP_PAGES    = 0.3             # Delay between pagination calls
MAX_RETRIES    = 5               # Max retries on network errors
RETRY_BACKOFF  = [2, 5, 10, 20, 30]  # Seconds to wait between retries

OUTPUT_FILE    = "repositories_export.csv"

CSV_FIELDNAMES = [
    "id",
    "repository",
    "source",
    "owner",
    "full_repository_name",
    "default_branch",
    "scanned_branch",
    "is_public",
    "creation_date",
    "last_scan_date",
    "description",
    "integration_ids",
    "vcs_tokens",
    "connection_status",
    "connection_message",
]


# ─────────────────────────────────────────────────────────────
# RETRY HELPER
# ─────────────────────────────────────────────────────────────

def request_with_retry(method, url, label="request", **kwargs):
    """Make an HTTP request with automatic retry on network errors."""
    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.request(method, url, **kwargs)
            return resp
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.SSLError,
            requests.exceptions.ChunkedEncodingError,
        ) as e:
            wait = RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)]
            print("  [RETRY {}/{}] {} — {}: waiting {}s...".format(
                attempt + 1, MAX_RETRIES, label, type(e).__name__, wait))
            time.sleep(wait)
        except Exception as e:
            print("  [ERROR] Unexpected error for {}: {}".format(label, e))
            return None

    print("  [FAIL] All {} retries exhausted for: {}".format(MAX_RETRIES, label))
    return None


# ─────────────────────────────────────────────────────────────
# AUTHENTICATION
# ─────────────────────────────────────────────────────────────

class AuthManager:
    def __init__(self, access_key, secret_key):
        self.access_key     = access_key
        self.secret_key     = secret_key
        self.token          = None
        self.token_acquired = 0

    def authenticate(self):
        print("[AUTH] Authenticating with Prisma Cloud...")

        resp = request_with_retry(
            "POST",
            "{}/login".format(API_URL),
            label="login",
            json={"username": self.access_key, "password": self.secret_key},
            headers={"Content-Type": "application/json"},
            timeout=30
        )

        if resp is None:
            print("[ERROR] Authentication failed after all retries. Check your network.")
            sys.exit(1)

        if resp.status_code != 200:
            print("[ERROR] Authentication returned HTTP {}. Check your credentials.".format(
                resp.status_code))
            sys.exit(1)

        self.token = resp.json().get("token")
        if not self.token:
            print("[ERROR] No token in response.")
            sys.exit(1)

        self.token_acquired = time.time()
        print("[AUTH] Authenticated successfully at {}".format(
            datetime.now().strftime("%H:%M:%S")))

    def get_token(self):
        elapsed = time.time() - self.token_acquired
        if not self.token or elapsed >= TOKEN_REFRESH:
            print("[AUTH] Token is {}s old — re-authenticating...".format(int(elapsed)))
            self.authenticate()
        return self.token

    def headers(self):
        return {
            "Content-Type": "application/json",
            "x-redlock-auth": self.get_token()
        }


# ─────────────────────────────────────────────────────────────
# PARSE REPOSITORY ROW
# ─────────────────────────────────────────────────────────────

def parse_repo(repo):
    """Flatten a repository API response object into a CSV row dict."""
    validation = repo.get("validationDetails") or {}

    # Join list fields into pipe-separated strings for CSV readability
    integration_ids = "|".join(repo.get("integrationIds") or [])
    vcs_tokens      = "|".join(repo.get("vcsTokens") or [])

    return {
        "id":                   repo.get("id", ""),
        "repository":           repo.get("repository", ""),
        "source":               repo.get("source", ""),
        "owner":                repo.get("owner", ""),
        "full_repository_name": repo.get("fullRepositoryName", ""),
        "default_branch":       repo.get("defaultBranch", ""),
        "scanned_branch":       repo.get("scannedBranch", ""),
        "is_public":            repo.get("isPublic", False),
        "creation_date":        repo.get("creationDate", ""),
        "last_scan_date":       repo.get("lastScanDate", "") or "never",
        "description":          repo.get("description", "") or "",
        "integration_ids":      integration_ids,
        "vcs_tokens":           vcs_tokens,
        "connection_status":    validation.get("status", ""),
        "connection_message":   validation.get("message", ""),
    }


# ─────────────────────────────────────────────────────────────
# FETCH ALL REPOSITORIES
# ─────────────────────────────────────────────────────────────

def fetch_all_repositories(auth, csv_writer):
    """
    Fetch all repos from v2 API, writing each page to CSV immediately.
    Returns total count of repos fetched.
    """
    print("\n[REPOS] Fetching all repositories from v2 API...")

    page           = 0
    total_fetched  = 0
    last_first_id  = None

    while True:
        # Generate current Unix timestamp in milliseconds for the 'time' param
        current_time_ms = int(time.time() * 1000)

        print("  → Fetching page {} (offset {})...".format(
            page, page * PAGE_SIZE))

        resp = request_with_retry(
            "GET",
            "{}/bridgecrew/api/v2/repositories".format(API_URL),
            label="repos page={}".format(page),
            headers=auth.headers(),
            params={
                "filter":        "VCS",
                "page":          page,
                "pageSize":      PAGE_SIZE,
                "sortBy":        "creationDate",
                "sortDir":       "ASC",
                "includeStatus": "true",
                "time":          current_time_ms,
            },
            timeout=30
        )

        if resp is None:
            print("  [ERROR] Failed to fetch page {}. Stopping.".format(page))
            break

        if resp.status_code != 200:
            print("  [ERROR] HTTP {} on page {}. Stopping.".format(
                resp.status_code, page))
            break

        try:
            data = resp.json()
        except Exception as e:
            print("  [ERROR] Could not parse response on page {}: {}".format(page, e))
            break

        # Extract repositories array
        repos = data.get("repositories", [])
        count = len(repos)

        if count == 0:
            print("  → No more repositories at page {}. Done.".format(page))
            break

        # Duplicate page detection
        first_id = repos[0].get("id") if repos else None
        if first_id and first_id == last_first_id:
            print("  → Duplicate page detected. Stopping pagination.")
            break
        last_first_id = first_id

        # Parse and write each repo to CSV immediately
        for repo in repos:
            row = parse_repo(repo)
            csv_writer.writerow(row)

        # Flush to disk after each page
        csv_writer.f.flush()
        os.fsync(csv_writer.f.fileno())

        total_fetched += count
        print("  → Got {} repos on page {}. Total so far: {}".format(
            count, page, total_fetched))

        # Last page check
        if count < PAGE_SIZE:
            print("  → Last page reached ({} < {}). Done.".format(count, PAGE_SIZE))
            break

        page += 1
        time.sleep(SLEEP_PAGES)

    print("[REPOS] Total repositories fetched: {}".format(total_fetched))
    return total_fetched


# ─────────────────────────────────────────────────────────────
# CSV WRITER WRAPPER
# ─────────────────────────────────────────────────────────────

class RepoCsvWriter:
    """Simple wrapper to keep the file and DictWriter together."""
    def __init__(self, filepath):
        self.f      = open(filepath, "w", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(
            self.f, fieldnames=CSV_FIELDNAMES, extrasaction="ignore")
        self.writer.writeheader()
        self.f.flush()

    def writerow(self, row):
        self.writer.writerow(row)

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("   Prisma Cloud — Repositories Export Script (v2 API)")
    print("=" * 60)

    # Collect credentials
    print("\nEnter your Prisma Cloud credentials:")
    access_key = input("  Access Key ID : ").strip()
    secret_key = getpass.getpass("  Secret Key    : ").strip()

    if not access_key or not secret_key:
        print("[ERROR] Access Key ID and Secret Key cannot be empty.")
        sys.exit(1)

    # Authenticate
    auth = AuthManager(access_key, secret_key)
    auth.authenticate()

    # Open CSV for writing
    csv_writer = RepoCsvWriter(OUTPUT_FILE)

    total = 0

    try:
        total = fetch_all_repositories(auth, csv_writer)

    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Ctrl+C detected — saving progress...")

    finally:
        csv_writer.close()

    # Summary
    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print("  Total repositories exported : {}".format(total))
    print("  Output file                 : {}".format(OUTPUT_FILE))
    print("=" * 60)
    print("\n✅ Done!")


if __name__ == "__main__":
    main()
