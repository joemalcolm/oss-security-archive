# oss-security-archive

A [public-inbox](https://public-inbox.org/) mirror of the [oss-security](https://www.openwall.com/lists/oss-security/) mailing list.

## Quick start

```bash
# Clone and build indexes
git clone https://github.com/joemalcolm/oss-security-archive.git
cd oss-security-archive
public-inbox-index inbox

# Search for a CVE
lei q -I inbox "CVE-2026-7168"

# Search by author
lei q -I inbox "f:daniel@haxx.se"

# Output as JSON
lei q -I inbox -f json "CVE-2026"
```

## Bootstrap

Run the bootstrap workflow from GitHub Actions, or locally:

```bash
sudo apt install public-inbox xapian-tools  # or brew install
./scripts/setup-inbox.sh inbox
./scripts/bootstrap.sh 2020 2026
public-inbox-index inbox
```

## How it works

A GitHub Action runs every 4 hours, fetches new posts from Openwall's mbox endpoint, and ingests them via `public-inbox-mda`. Indexes (Xapian full-text + SQLite metadata) are rebuilt locally by each consumer — they are not committed to git.

See [CLAUDE.md](CLAUDE.md) for detailed architecture and maintenance instructions.
