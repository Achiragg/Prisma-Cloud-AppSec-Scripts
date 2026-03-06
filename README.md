# prisma-cloud-appsec-scripts

> Python scripts to export **Repository data** and **SBOM (Software Bill of Materials)** from Prisma Cloud Application Security using the REST API.

---

> ⚠️ **Disclaimer:** This is an independent, community-built tool and is **not officially affiliated with, endorsed, or supported by Palo Alto Networks**. Use at your own risk. Palo Alto Networks and Prisma Cloud are trademarks of Palo Alto Networks, Inc.

---

## Overview

This repository contains two Python scripts that interact with the **Prisma Cloud Application Security (Bridgecrew) API** to extract repository and SBOM data at scale. Both scripts are designed to handle large environments (1,000+ repositories) with built-in pagination, automatic token refresh, crash-safe CSV writing, and retry logic for network failures.

| Script | Description |
|---|---|
| `prisma_repositories_export.py` | Fetches all connected VCS repositories and exports metadata to CSV |
| `prisma_sbom_export.py` | Fetches SBOM data (OSS packages, IaC, containers) for all repositories and exports to CSV |

---

## Features

- 🔐 **Secure credential input** — credentials entered at runtime, never hardcoded
- 🔄 **Automatic token refresh** — re-authenticates every 5 minutes (token expires at 10 min)
- 📄 **Crash-safe writes** — data is flushed to CSV after every repo, so no data is lost if the script is interrupted
- 🔁 **Retry logic** — all network calls retry up to 5 times with exponential backoff (2s → 5s → 10s → 20s → 30s)
- 📑 **Pagination handled** — fetches all pages automatically with duplicate page detection
- ✅ **Python 3.7+ compatible** — no modern type hint syntax

---

## Requirements

- Python 3.7 or higher
- `requests` library

Install dependencies:

```bash
pip3 install requests
```

---

## Authentication

Both scripts authenticate using a **Prisma Cloud Access Key ID and Secret Key**.

To generate one:
1. Log in to your Prisma Cloud console
2. Go to **Settings → Access Keys**
3. Click **Add Access Key**
4. Copy the **Access Key ID** and **Secret Key**

> ⚠️ The Secret Key is only shown once at creation time. Store it securely.

---

## Script 1 — Repository Export

### `prisma_repositories_export.py`

Fetches all VCS repositories connected to Prisma Cloud Application Security and exports them to a single CSV file.

**Uses:** `GET /bridgecrew/api/v2/repositories`

#### Usage

```bash
python3 prisma_repositories_export.py
```

You will be prompted to enter:
```
Enter your Prisma Cloud credentials:
  Access Key ID : <your-access-key-id>
  Secret Key    : <hidden>
```

#### Output

**`repositories_export.csv`** — one row per repository with the following columns:

| Column | Description |
|---|---|
| `id` | Repository UUID |
| `repository` | Repository name |
| `source` | VCS source (e.g. `gitlabEnterprise`, `github`) |
| `owner` | Repository owner / group |
| `full_repository_name` | `owner/repository` |
| `default_branch` | Default branch name |
| `scanned_branch` | Branch being scanned by Prisma |
| `is_public` | Whether the repo is public |
| `creation_date` | Date added to Prisma Cloud |
| `last_scan_date` | Last scan timestamp (`never` if not scanned) |
| `description` | Repository description |
| `integration_ids` | Pipe-separated integration UUIDs |
| `vcs_tokens` | Pipe-separated VCS token usernames |
| `connection_status` | `Connected`, `Limited permissions`, `Disconnected` |
| `connection_message` | Error detail if not connected |

#### Sample Output

```
id,repository,source,owner,full_repository_name,default_branch,...
955495f7-...,affiliate,gitlabEnterprise,test-group1,test-group1/affiliate,master,...
84c5aa82-...,web-app,gitlabEnterprise,test-group1,test-group1/web-app,master,...
```

---

## Script 2 — SBOM Export

### `prisma_sbom_export.py`

Fetches SBOM data for all repositories and exports to CSV. Generates separate files for OSS packages, IaC findings, and container images, plus a combined file and a repository-level summary.

**Uses:**
- `GET /code/api/v1/repositories` — to fetch all repos
- `GET /bridgecrew/api/v1/bom/getBOMReport/{repoId}` — to fetch SBOM per repo
- Presigned AWS S3 URLs — to download the actual CSV data

#### Usage

```bash
python3 prisma_sbom_export.py
```

You will be prompted to enter:
```
Enter your Prisma Cloud credentials:
  Access Key ID : <your-access-key-id>
  Secret Key    : <hidden>
```

#### Output Files

| File | Description |
|---|---|
| `sbom_oss_packages.csv` | Open source package data across all repos |
| `sbom_iac.csv` | Infrastructure-as-Code findings across all repos |
| `sbom_container_images.csv` | Container image data across all repos |
| `sbom_all_combined.csv` | All 3 files merged with a `sbom_type` column |
| `sbom_repository_summary.csv` | One row per repo with SBOM status and reason |

#### Repository Summary Columns

| Column | Description |
|---|---|
| `repository_name` | Repository name |
| `source` | VCS source |
| `owner` | Repository owner / group |
| `default_branch` | Default branch |
| `last_scan_date` | Last scan timestamp |
| `runs` | Number of scans run |
| `sbom_status` | `available` or `not_available` |
| `oss_packages_count` | Number of OSS package rows |
| `iac_count` | Number of IaC rows |
| `containers_count` | Number of container rows |
| `reason` | Reason if SBOM not available (see below) |

#### Reason Codes

| Reason | Meaning |
|---|---|
| `no_sbom_found (runs=0)` | API returned 404 — no SBOM data exists |
| `empty_bom_response (runs=0)` | API responded but returned no report links |
| `empty_csv (runs=0)` | S3 links returned but CSV files had no data rows |
| `api_error` | Network failure after all retries |
| `no_repo_id` | Repository had no ID in the API response |
| `invalid_response` | Could not parse the API response |

> **Note:** `(runs=0)` is appended to the reason when the repository's `runs` field is 0, indicating it may never have been scanned. The script still attempts the API call regardless, as the `runs` field is not always reliable.

---

## Configuration

Both scripts have a configuration block at the top you can adjust:

```python
API_URL        = "https://api.ind.prismacloud.io"  # Change to your region's API URL
PAGE_SIZE      = 50       # Number of repos per page
TOKEN_REFRESH  = 300      # Re-authenticate every 5 minutes
SLEEP_REPOS    = 0.5      # Delay between repo API calls (rate limiting)
SLEEP_PAGES    = 0.3      # Delay between pagination calls
MAX_RETRIES    = 5        # Max retries on network failures
```

### API URL by Region

| Region | API URL |
|---|---|
| US | `https://api.prismacloud.io` |
| US2 | `https://api2.prismacloud.io` |
| EU | `https://api.eu.prismacloud.io` |
| India | `https://api.ind.prismacloud.io` |
| Australia | `https://api.anz.prismacloud.io` |

---

## Security Notes

- ✅ No credentials are hardcoded in either script
- ✅ Secret Key input is hidden using `getpass` (not visible while typing)
- ✅ JWT tokens are never printed or logged
- ✅ Tokens are held in memory only and never written to disk
- ⚠️ The generated CSV files may contain sensitive data (repo names, email addresses, package versions). Do not commit them to version control.

Add this to your `.gitignore`:

```
*.csv
```

---

## API Stability Notice

Some endpoints used in these scripts (e.g. `/bridgecrew/api/v1/bom/getBOMReport`) are **not part of the official publicly versioned API** and may change or be deprecated by Palo Alto Networks at any time without prior notice. If a script stops working after a Prisma Cloud update, the API endpoint or response structure may have changed.

If you encounter issues, check the latest API documentation at [pan.dev](https://pan.dev/prisma-cloud/api/code/) and update the endpoint URLs and response parsing accordingly.

---

## Branding Notice

This repository is not affiliated with Palo Alto Networks. No Palo Alto Networks or Prisma Cloud logos, trademarks, or brand assets are used in this project. All product names and trademarks are the property of their respective owners.

---

## Interrupting the Script

Both scripts handle `Ctrl+C` gracefully. Since data is written to CSV after every repository, all progress up to the interruption point is saved. You will see:

```
[INTERRUPTED] Ctrl+C detected — saving progress...
```

---

## Tested Environment

- Python 3.9+
- macOS (zsh terminal)
- Prisma Cloud India region (`api.ind.prismacloud.io`)
- GitLab Enterprise VCS integration

---

## License

MIT License — free to use, modify, and distribute.

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
