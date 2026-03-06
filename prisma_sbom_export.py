#!/usr/bin/env python3
"""
Prisma Cloud — Fetch All Repositories & Export SBOM to CSV
===========================================================
Compatible with Python 3.7+

Features:
  - Writes data to CSV immediately after each repo (crash-safe)
  - Retries all network calls with exponential backoff
  - Re-authenticates every 5 minutes automatically
  - Generates a repository summary CSV with SBOM status and reasons

Requirements:
    pip3 install requests

Usage:
    python3 prisma_sbom_export.py
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
PAGE_SIZE      = 50
TOKEN_REFRESH  = 300             # Re-authenticate every 5 minutes
SLEEP_REPOS    = 0.5             # Delay between repo SBOM calls
SLEEP_PAGES    = 0.3             # Delay between pagination calls
MAX_RETRIES    = 5               # Max retries on network errors
RETRY_BACKOFF  = [2, 5, 10, 20, 30]  # Seconds to wait between retries

OUTPUT_OSS        = "sbom_oss_packages.csv"
OUTPUT_IAC        = "sbom_iac.csv"
OUTPUT_CONTAINERS = "sbom_container_images.csv"
OUTPUT_COMBINED   = "sbom_all_combined.csv"
OUTPUT_SUMMARY    = "sbom_repository_summary.csv"

SUMMARY_FIELDNAMES = [
    "repository_name",
    "source",
    "owner",
    "default_branch",
    "last_scan_date",
    "runs",
    "sbom_status",
    "oss_packages_count",
    "iac_count",
    "containers_count",
    "reason",
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
            print("    [RETRY {}/{}] {} — {}: waiting {}s...".format(
                attempt + 1, MAX_RETRIES, label, type(e).__name__, wait))
            time.sleep(wait)
        except Exception as e:
            print("    [ERROR] Unexpected error for {}: {}".format(label, e))
            return None

    print("    [FAIL] All {} retries exhausted for: {}".format(MAX_RETRIES, label))
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
# CSV WRITER — opens files once, appends rows immediately
# ─────────────────────────────────────────────────────────────

class CsvWriter:
    """
    Keeps CSV files open for the duration of the script.
    Writes and flushes each row immediately — crash-safe.
    """
    def __init__(self):
        self.files   = {}
        self.writers = {}
        self.counts  = {
            "oss": 0, "iac": 0, "containers": 0, "summary": 0
        }

    def _get_writer(self, key, filepath, fieldnames):
        if key not in self.writers:
            f      = open(filepath, "w", newline="", encoding="utf-8")
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            self.files[key]   = f
            self.writers[key] = writer
        return self.writers[key]

    def _flush(self, key):
        if key in self.files:
            self.files[key].flush()
            os.fsync(self.files[key].fileno())

    def write_sbom_rows(self, key, filepath, rows, repo_name):
        """Write SBOM data rows, prepending repository_name column."""
        if not rows:
            return 0
        enriched = []
        for row in rows:
            entry = {"repository_name": repo_name}
            entry.update(row)
            enriched.append(entry)

        fieldnames = list(enriched[0].keys())
        writer     = self._get_writer(key, filepath, fieldnames)
        writer.writerows(enriched)
        self._flush(key)
        self.counts[key] += len(enriched)
        return len(enriched)

    def write_summary_row(self, row):
        """Write one row to the repository summary CSV."""
        writer = self._get_writer("summary", OUTPUT_SUMMARY, SUMMARY_FIELDNAMES)
        writer.writerow(row)
        self._flush("summary")
        self.counts["summary"] += 1

    def close_all(self):
        for f in self.files.values():
            try:
                f.close()
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────
# FETCH ALL REPOSITORIES
# ─────────────────────────────────────────────────────────────

def fetch_all_repositories(auth):
    print("\n[REPOS] Fetching all repositories...")

    all_repos     = []
    offset        = 0
    last_first_id = None

    while True:
        print("  → Fetching repos at offset {}...".format(offset))

        resp = request_with_retry(
            "GET",
            "{}/code/api/v1/repositories".format(API_URL),
            label="repos offset={}".format(offset),
            headers=auth.headers(),
            params={"pageSize": PAGE_SIZE, "pageOffset": offset},
            timeout=30
        )

        if resp is None:
            print("  [ERROR] Failed to fetch repos at offset {}. Stopping.".format(offset))
            break

        if resp.status_code != 200:
            print("  [ERROR] HTTP {} at offset {}. Stopping.".format(
                resp.status_code, offset))
            break

        data = resp.json()

        if isinstance(data, list):
            page_repos = data
        elif isinstance(data, dict):
            page_repos = (
                data.get("data") or
                data.get("repositories") or
                data.get("results") or
                []
            )
        else:
            page_repos = []

        count = len(page_repos)

        if count == 0:
            print("  → No more repositories at offset {}. Done.".format(offset))
            break

        # Duplicate page detection
        first_id = page_repos[0].get("id") if page_repos else None
        if first_id and first_id == last_first_id:
            print("  → Duplicate page detected. Stopping pagination.")
            break
        last_first_id = first_id

        all_repos.extend(page_repos)
        print("  → Got {} repos at offset {}. Total so far: {}".format(
            count, offset, len(all_repos)))

        if count < PAGE_SIZE:
            print("  → Last page reached ({} < {}). Done.".format(count, PAGE_SIZE))
            break

        offset += PAGE_SIZE
        time.sleep(SLEEP_PAGES)

    print("[REPOS] Total repositories fetched: {}".format(len(all_repos)))
    return all_repos


# ─────────────────────────────────────────────────────────────
# DOWNLOAD CSV FROM PRESIGNED S3 URL
# ─────────────────────────────────────────────────────────────

def download_csv(s3_url, label=""):
    resp = request_with_retry(
        "GET", s3_url, label="S3 {}".format(label), timeout=60)

    if resp is None or resp.status_code != 200:
        return None

    content = resp.text
    if not content or "<html" in content.lower():
        return None

    lines = content.strip().splitlines()
    if len(lines) < 2:
        return None

    reader = csv.DictReader(lines)
    return list(reader)


# ─────────────────────────────────────────────────────────────
# BUILD SUMMARY ROW HELPER
# ─────────────────────────────────────────────────────────────

def build_summary_row(repo, sbom_status, oss_count, iac_count,
                      containers_count, reason):
    return {
        "repository_name":    repo.get("repository") or repo.get("name") or "unknown",
        "source":             repo.get("source", ""),
        "owner":              repo.get("owner", ""),
        "default_branch":     repo.get("defaultBranch", ""),
        "last_scan_date":     repo.get("lastScanDate") or "never",
        "runs":               repo.get("runs", 0),
        "sbom_status":        sbom_status,
        "oss_packages_count": oss_count,
        "iac_count":          iac_count,
        "containers_count":   containers_count,
        "reason":             reason,
    }


# ─────────────────────────────────────────────────────────────
# FETCH SBOM FOR A SINGLE REPOSITORY
# ─────────────────────────────────────────────────────────────

def fetch_sbom_for_repo(auth, repo):
    """
    Returns dict:
      oss, iac, containers : list of row dicts
      reason               : string reason if no SBOM
    """
    repo_id   = repo.get("id", "")
    repo_name = repo.get("repository") or repo.get("name") or "unknown"
    runs      = repo.get("runs", 0)
    result    = {"oss": [], "iac": [], "containers": [], "reason": ""}

    # Note: runs=0 is recorded in summary but we still attempt the API
    # because the runs field is unreliable and some repos have SBOM despite runs=0
    runs_context = " (runs=0)" if runs == 0 else ""

    if not repo_id:
        result["reason"] = "no_repo_id"
        print("    [SKIP] No ID for repo: {}".format(repo_name))
        return result

    resp = request_with_retry(
        "GET",
        "{}/bridgecrew/api/v1/bom/getBOMReport/{}".format(API_URL, repo_id),
        label="BOM {}".format(repo_name),
        headers=auth.headers(),
        params={"format": "csv", "material": "all"},
        timeout=30
    )

    if resp is None:
        result["reason"] = "api_error{}".format(runs_context)
        print("    [SKIP] Could not fetch SBOM for: {}".format(repo_name))
        return result

    if resp.status_code == 404:
        result["reason"] = "no_sbom_found{}".format(runs_context)
        print("    [SKIP] No SBOM found (404): {}".format(repo_name))
        return result

    if resp.status_code != 200:
        result["reason"] = "api_error_http_{}{}".format(resp.status_code, runs_context)
        print("    [SKIP] HTTP {} for SBOM: {}".format(resp.status_code, repo_name))
        return result

    try:
        data = resp.json()
    except Exception as e:
        result["reason"] = "invalid_response{}".format(runs_context)
        print("    [SKIP] Could not parse SBOM response for {}: {}".format(repo_name, e))
        return result

    bom_response = data.get("bomResponse", [])
    if not bom_response:
        result["reason"] = "empty_bom_response{}".format(runs_context)
        print("    [SKIP] Empty bomResponse for: {}".format(repo_name))
        return result

    any_data = False

    for item in bom_response:
        link = item.get("reportLink", "")
        if not link:
            continue

        if "oss_packages" in link:
            rows = download_csv(link, label="oss_packages")
            if rows:
                result["oss"] = rows
                any_data = True
                print("    ✓ OSS Packages    : {} rows".format(len(rows)))
            else:
                print("    ~ OSS Packages    : empty csv")

        elif "iac.csv" in link:
            rows = download_csv(link, label="iac")
            if rows:
                result["iac"] = rows
                any_data = True
                print("    ✓ IAC             : {} rows".format(len(rows)))
            else:
                print("    ~ IAC             : empty csv")

        elif "container" in link:
            rows = download_csv(link, label="containers")
            if rows:
                result["containers"] = rows
                any_data = True
                print("    ✓ Container Images: {} rows".format(len(rows)))
            else:
                print("    ~ Containers      : empty csv")

    if not any_data:
        result["reason"] = "empty_csv{}".format(runs_context)

    return result


# ─────────────────────────────────────────────────────────────
# COMBINE ALL CSVs INTO ONE MASTER FILE
# ─────────────────────────────────────────────────────────────

def combine_csv_files():
    print("\n[CSV] Combining SBOM files into: {}".format(OUTPUT_COMBINED))

    files = [
        (OUTPUT_OSS,        "oss_packages"),
        (OUTPUT_IAC,        "iac"),
        (OUTPUT_CONTAINERS, "container_images"),
    ]

    combined_rows = []
    fieldnames    = None

    for filepath, label in files:
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            continue
        with open(filepath, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows   = list(reader)
            if not rows:
                continue
            if fieldnames is None:
                fieldnames = ["sbom_type"] + list(rows[0].keys())
            for row in rows:
                entry = {"sbom_type": label}
                entry.update(row)
                combined_rows.append(entry)
        print("  → Merged: {} ({} rows)".format(filepath, len(rows)))

    if not combined_rows or not fieldnames:
        print("  [SKIP] No data to combine.")
        return

    with open(OUTPUT_COMBINED, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(combined_rows)

    print("  → Combined file: {} ({} total rows)".format(
        OUTPUT_COMBINED, len(combined_rows)))


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("   Prisma Cloud — SBOM Export Script")
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

    # Fetch all repos
    repos = fetch_all_repositories(auth)
    if not repos:
        print("[ERROR] No repositories found. Exiting.")
        sys.exit(0)

    # Initialise crash-safe CSV writer
    csv_writer = CsvWriter()

    repos_with_sbom = 0
    repos_skipped   = 0

    print("\n[SBOM] Fetching SBOM for {} repositories...".format(len(repos)))
    print("[INFO] Data is written to CSV immediately — safe to Ctrl+C.\n")

    try:
        for i, repo in enumerate(repos, start=1):
            repo_name = repo.get("repository") or repo.get("name") or "unknown"
            print("  [{}/{}] {}".format(i, len(repos), repo_name))

            sbom  = fetch_sbom_for_repo(auth, repo)
            found = False

            oss_count        = 0
            iac_count        = 0
            containers_count = 0

            if sbom["oss"]:
                oss_count = csv_writer.write_sbom_rows(
                    "oss", OUTPUT_OSS, sbom["oss"], repo_name)
                found = True

            if sbom["iac"]:
                iac_count = csv_writer.write_sbom_rows(
                    "iac", OUTPUT_IAC, sbom["iac"], repo_name)
                found = True

            if sbom["containers"]:
                containers_count = csv_writer.write_sbom_rows(
                    "containers", OUTPUT_CONTAINERS, sbom["containers"], repo_name)
                found = True

            # Write summary row immediately
            summary_row = build_summary_row(
                repo=repo,
                sbom_status="available" if found else "not_available",
                oss_count=oss_count,
                iac_count=iac_count,
                containers_count=containers_count,
                reason=sbom["reason"] if not found else ""
            )
            csv_writer.write_summary_row(summary_row)

            if found:
                repos_with_sbom += 1
            else:
                repos_skipped += 1

            time.sleep(SLEEP_REPOS)

    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Ctrl+C detected — saving progress...")

    finally:
        csv_writer.close_all()

    # Combine into master CSV
    combine_csv_files()

    # Summary
    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print("  Repos processed         : {}".format(repos_with_sbom + repos_skipped))
    print("  Repos with SBOM data    : {}".format(repos_with_sbom))
    print("  Repos skipped (no data) : {}".format(repos_skipped))
    print("  OSS rows written        : {}".format(csv_writer.counts["oss"]))
    print("  IAC rows written        : {}".format(csv_writer.counts["iac"]))
    print("  Container rows written  : {}".format(csv_writer.counts["containers"]))
    print("\n  Output files:")
    print("    OSS Packages       → {}".format(OUTPUT_OSS))
    print("    IAC                → {}".format(OUTPUT_IAC))
    print("    Containers         → {}".format(OUTPUT_CONTAINERS))
    print("    Combined all       → {}".format(OUTPUT_COMBINED))
    print("    Repository Summary → {}".format(OUTPUT_SUMMARY))
    print("=" * 60)
    print("\n✅ Done!")


if __name__ == "__main__":
    main()
