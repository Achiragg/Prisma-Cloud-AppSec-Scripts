prisma-cloud-appsec-scripts

Python scripts to export Repository data and SBOM (Software Bill of Materials) from Prisma Cloud Application Security using the REST API.


Overview
This repository contains two Python scripts that interact with the Prisma Cloud Application Security (Bridgecrew) API to extract repository and SBOM data at scale. Both scripts are designed to handle large environments (1,000+ repositories) with built-in pagination, automatic token refresh, crash-safe CSV writing, and retry logic for network failures.
ScriptDescriptionprisma_repositories_export.pyFetches all connected VCS repositories and exports metadata to CSVprisma_sbom_export.pyFetches SBOM data (OSS packages, IaC, containers) for all repositories and exports to CSV

Features

🔐 Secure credential input — credentials entered at runtime, never hardcoded
🔄 Automatic token refresh — re-authenticates every 5 minutes (token expires at 10 min)
📄 Crash-safe writes — data is flushed to CSV after every repo, so no data is lost if the script is interrupted
🔁 Retry logic — all network calls retry up to 5 times with exponential backoff (2s → 5s → 10s → 20s → 30s)
📑 Pagination handled — fetches all pages automatically with duplicate page detection
✅ Python 3.7+ compatible — no modern type hint syntax


Requirements

Python 3.7 or higher
requests library

Install dependencies:
bashpip3 install requests

Authentication
Both scripts authenticate using a Prisma Cloud Access Key ID and Secret Key.
To generate one:

Log in to your Prisma Cloud console
Go to Settings → Access Keys
Click Add Access Key
Copy the Access Key ID and Secret Key


⚠️ The Secret Key is only shown once at creation time. Store it securely.


Script 1 — Repository Export
prisma_repositories_export.py
Fetches all VCS repositories connected to Prisma Cloud Application Security and exports them to a single CSV file.
Uses: GET /bridgecrew/api/v2/repositories
Usage
bashpython3 prisma_repositories_export.py
You will be prompted to enter:
Enter your Prisma Cloud credentials:
  Access Key ID : <your-access-key-id>
  Secret Key    : <hidden>
Output
repositories_export.csv — one row per repository with the following columns:
ColumnDescriptionidRepository UUIDrepositoryRepository namesourceVCS source (e.g. gitlabEnterprise, github)ownerRepository owner / groupfull_repository_nameowner/repositorydefault_branchDefault branch namescanned_branchBranch being scanned by Prismais_publicWhether the repo is publiccreation_dateDate added to Prisma Cloudlast_scan_dateLast scan timestamp (never if not scanned)descriptionRepository descriptionintegration_idsPipe-separated integration UUIDsvcs_tokensPipe-separated VCS token usernamesconnection_statusConnected, Limited permissions, Disconnectedconnection_messageError detail if not connected
Sample Output
id,repository,source,owner,full_repository_name,default_branch,...
955495f7-...,affiliate,gitlabEnterprise,test-group1,test-group1/affiliate,master,...
84c5aa82-...,web-app,gitlabEnterprise,test-group1,test-group1/web-app,master,...

Script 2 — SBOM Export
prisma_sbom_export.py
Fetches SBOM data for all repositories and exports to CSV. Generates separate files for OSS packages, IaC findings, and container images, plus a combined file and a repository-level summary.
Uses:

GET /code/api/v1/repositories — to fetch all repos
GET /bridgecrew/api/v1/bom/getBOMReport/{repoId} — to fetch SBOM per repo
Presigned AWS S3 URLs — to download the actual CSV data

Usage
bashpython3 prisma_sbom_export.py
You will be prompted to enter:
Enter your Prisma Cloud credentials:
  Access Key ID : <your-access-key-id>
  Secret Key    : <hidden>
Output Files
FileDescriptionsbom_oss_packages.csvOpen source package data across all repossbom_iac.csvInfrastructure-as-Code findings across all repossbom_container_images.csvContainer image data across all repossbom_all_combined.csvAll 3 files merged with a sbom_type columnsbom_repository_summary.csvOne row per repo with SBOM status and reason
Repository Summary Columns
ColumnDescriptionrepository_nameRepository namesourceVCS sourceownerRepository owner / groupdefault_branchDefault branchlast_scan_dateLast scan timestamprunsNumber of scans runsbom_statusavailable or not_availableoss_packages_countNumber of OSS package rowsiac_countNumber of IaC rowscontainers_countNumber of container rowsreasonReason if SBOM not available (see below)
Reason Codes
ReasonMeaningno_sbom_found (runs=0)API returned 404 — no SBOM data existsempty_bom_response (runs=0)API responded but returned no report linksempty_csv (runs=0)S3 links returned but CSV files had no data rowsapi_errorNetwork failure after all retriesno_repo_idRepository had no ID in the API responseinvalid_responseCould not parse the API response

Note: (runs=0) is appended to the reason when the repository's runs field is 0, indicating it may never have been scanned. The script still attempts the API call regardless, as the runs field is not always reliable.


Configuration
Both scripts have a configuration block at the top you can adjust:
pythonAPI_URL        = "https://api.ind.prismacloud.io"  # Change to your region's API URL
PAGE_SIZE      = 50       # Number of repos per page
TOKEN_REFRESH  = 300      # Re-authenticate every 5 minutes
SLEEP_REPOS    = 0.5      # Delay between repo API calls (rate limiting)
SLEEP_PAGES    = 0.3      # Delay between pagination calls
MAX_RETRIES    = 5        # Max retries on network failures
API URL by Region
RegionAPI URLUShttps://api.prismacloud.ioUS2https://api2.prismacloud.ioEUhttps://api.eu.prismacloud.ioIndiahttps://api.ind.prismacloud.ioAustraliahttps://api.anz.prismacloud.io

Security Notes

✅ No credentials are hardcoded in either script
✅ Secret Key input is hidden using getpass (not visible while typing)
✅ JWT tokens are never printed or logged
✅ Tokens are held in memory only and never written to disk
⚠️ The generated CSV files may contain sensitive data (repo names, email addresses, package versions). Do not commit them to version control.

Add this to your .gitignore:
*.csv

Interrupting the Script
Both scripts handle Ctrl+C gracefully. Since data is written to CSV after every repository, all progress up to the interruption point is saved. You will see:
[INTERRUPTED] Ctrl+C detected — saving progress...

Tested Environment

Python 3.9+
macOS (zsh terminal)
Prisma Cloud India region (api.ind.prismacloud.io)
GitLab Enterprise VCS integration


License
MIT License — free to use, modify, and distribute.

Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
