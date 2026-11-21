# Janus

**Two faces, one gate.** Janus scans the image behind every Docker container on a host with two independent vulnerability scanners, [Grype](https://github.com/anchore/grype) and [Trivy](https://github.com/aquasecurity/trivy). It merges what they find into one report and lets you browse it per image in the terminal, worst image first and highest CVSS score first.

It was written for **bender** (TrueNAS Community Edition 25.10, HP MicroServer Gen8), where about forty containers run from a single `docker-compose.yaml`. It is meant to be run by hand at regular intervals: scan once, then come back to the saved result as often as needed.

## Why "Janus"

Janus is the Roman god of doorways and gates, shown with two faces looking in opposite directions. The tool works the same way:

- **Two faces watching one gate.** Grype and Trivy examine each image separately. A finding both of them report is marked `G+T` and is the most reliable kind.
- **Guardian of thresholds.** Every container image is a doorway into the host. Janus shows what comes through each one, worst first.
- **Looking back and ahead.** Saved scans let you look back at earlier results. The "fixed in" column points ahead to the version that closes each flaw.

## What it does

Janus collects every container on the host, running or stopped, and finds the exact image each one runs. It refreshes both vulnerability databases once, then scans the images one at a time, with Grype and with Trivy. The two reports are merged: the same vulnerability in the same package and version counts once, even when the scanners spell the package name or version differently. The result is saved to disk and opened in an interactive browser.

The browser has two screens. The first lists every image with its CRITICAL, HIGH, MEDIUM, LOW and UNKNOWN counts on coloured backgrounds, sorted worst first. Pressing Enter on an image opens the second screen: that image's vulnerabilities, sorted from the highest CVSS score to the lowest, with the selected finding shown in full at the bottom.

## Requirements

- A Linux host running Docker, and root access (Janus talks to the Docker socket).
- Python 3.8 or newer. Only the standard library is used. The browser needs the `curses` module, which the Python on TrueNAS normally includes; without it, `--list` still works.
- Network access on the first run, to download the two scanner images and their vulnerability databases. Later runs only download database updates.
- About 2 GB of free memory while a scan is running, and a few gigabytes of disk space for the vulnerability databases in the Docker volume `janus-cache`.

## Installation on bender

Janus lives in its own git checkout under `configs/`, like `audiobook-foundry`:

```bash
git clone http://git.home.arpa:3030/<user>/janus.git /mnt/BIG/filme/configs/janus
```

Run it from there:

```bash
python3 /mnt/BIG/filme/configs/janus/janus.py
```

To update it later:

```bash
git -C /mnt/BIG/filme/configs/janus pull
```

Before the first run, check that the scanner versions at the top of `janus.py` (`GRYPE_IMAGE` and `TRIVY_IMAGE`) match the ones Dockhand uses under **Settings → General**, so both tools report the same results.

## Usage

The commands below are shortened to `janus.py`; on bender, run them as `python3 /mnt/BIG/filme/configs/janus/janus.py`.

| Command | What it does |
|---|---|
| `janus.py` | Scan every container, save the result, open the browser. |
| `janus.py --view` | Open the last saved scan without scanning. |
| `janus.py --view FILE` | Open an older saved scan. |
| `janus.py jellyfin postgres` | Scan only the named containers. |
| `janus.py --image REF` | Also scan an image no container uses yet, such as the suspended arr images. Repeatable. |
| `janus.py --min-severity high` | Hide everything below HIGH. |
| `janus.py --fixed-only` | Show only findings that a newer version fixes. |
| `janus.py --list` | Print one flat list, sorted by score, instead of opening the browser. |
| `janus.py --csv FILE` | Also write the findings to a CSV file. |
| `janus.py --scanner grype` | Use only one scanner (`grype` or `trivy`). |
| `janus.py --skip-db-update` | Scan with the cached databases as they are. |
| `janus.py --version` | Print the version. |

A full scan of about forty images takes tens of minutes on bender, because the images are scanned one at a time with capped resources. The result is saved before the browser opens, so a dropped SSH session loses nothing: reconnect and run `janus.py --view`.

When the output is not a terminal (redirected to a file, or run from cron), Janus prints the flat list without colours instead of opening the browser.

## The browser

The image list, with sample data:

```text
Janus - bender - scanned 2026-11-20 20:30 - anchore/grype:v0.115.0, aquasec/trivy:0.71.2
Up/Down PgUp/PgDn move   Enter open   f fixed only: off   q quit

  CONTAINER    IMAGE                          CRITICAL   HIGH       MEDIUM     LOW        UNKNOWN
> (all images) 7 images, 160 findings               29         38         28         28         37
  keepalived   osixia/keepalived:2.0.20             14         15          9          9         13
  hedgedoc     quay.io/hedgedoc/hedgedoc:la~         4          7          3          5          6
  postgres     ghcr.io/immich-app/postgres@~         4          6          5          4          6
  vaultwarden  vaultwarden/server:latest             4          4          7          5          5
 !nebula-sync  ghcr.io/lovelaze/nebula-sync~         0          0          0          0          0
  syncthing    syncthing/syncthing:latest            0          0          0          0          0
```

On screen, each count column has its own background colour: white on red for CRITICAL, black on orange for HIGH, black on yellow for MEDIUM, white on blue for LOW, and white on grey for UNKNOWN. A `!` before a name means a scanner failed on that image; the bottom line says which one and why. The first entry, `(all images)`, opens every finding of every image in one list. On a terminal narrower than about 85 columns the IMAGE column is hidden so the counts still fit.

One image's vulnerabilities, with sample data:

```text
hedgedoc   quay.io/hedgedoc/hedgedoc:latest
 CRITICAL 4   HIGH 7   MEDIUM 3   LOW 5   UNKNOWN 6   fixed only: off

SEVERITY      SCORE  ID              PACKAGE                           INSTALLED  FIXED IN  BY
 LOW          10.0   CVE-2026-91866  zlib1g                            1.0.8      -         G+T
 CRITICAL     9.6    CVE-2026-37446  org.apache.tomcat.embed:tomcat-~  1.0.12     -         G
 HIGH         9.5    CVE-2026-85449  openssl                           1.0.13     1.2.13    G

CVE-2026-91866  Example flaw number 8 in a library that lets a remote attacker do something bad.
zlib1g 1.0.8 -> -   found by Grype + Trivy   https://nvd.nist.gov/vuln/detail/CVE-2026-91866
Up/Down PgUp/PgDn Home/End move   f fixed only   Left/Esc/q back
```

The selected row is highlighted. The two lines at the bottom show it in full: the description, the package, the installed and fixed versions, which scanners found it, and a link to the advisory.

### Keys

| Screen | Key | Action |
|---|---|---|
| Image list | Up, Down, PgUp, PgDn, Home, End | Move |
| | Enter or Right | Open the selected image |
| | `f` | Show only findings with a fix (on/off) |
| | `q` | Quit |
| Vulnerabilities | Up, Down, PgUp, PgDn, Home, End | Move |
| | `f` | Show only findings with a fix (on/off) |
| | Left, Esc, Backspace or `q` | Back to the image list |

Esc does not quit from the image list. Over SSH an arrow key is a short sequence that starts with the Esc character; if it ever arrives split, it must not close the program.

## Reading the report

| Column | Meaning |
|---|---|
| SEVERITY | The scanners' rating. For operating-system packages this is usually the distribution's own assessment. When Grype and Trivy disagree, the higher rating is shown. The LOW count also includes Grype's NEGLIGIBLE findings. |
| SCORE | The CVSS base score. Version 3 is preferred; a version 4 or version 2 score is marked `v4` or `v2`. `n/a` means neither scanner had a score. |
| ID | The CVE number, or another advisory ID when no CVE exists. |
| PACKAGE, INSTALLED | The affected package and the version inside the image. |
| FIXED IN | The version that fixes it. `won't fix` means the vendor decided not to fix it; `-` means no fix exists yet. |
| BY | `G` = Grype, `T` = Trivy, `G+T` = both. |

Severity and score can disagree. A distribution may rate a flaw LOW because its default configuration is not exposed, while the CVE record scores it 9.8. Janus shows both and sorts by the score.

Findings without any score are placed at the bottom of their severity band: an unscored CRITICAL sorts just below the 9.0 scores, an unscored HIGH just below 7.0, and so on.

The practical reading order is: images at the top of the list first; within an image, `G+T` findings with a high score and a FIXED IN version first, because those can be closed by updating. Press `f` to see only those. Findings with no fix yet need no action until the upstream project releases one.

## Saved scans

Every scan is saved in `/mnt/BIG/filme/backups/janus/` as `janus-YYYYMMDD-HHMMSS.json`, and copied to `latest.json`. `--view` opens `latest.json`; `--view FILE` opens any older one. The twelve newest scans are kept and older ones are deleted. Each file holds every finding of that scan, so a full scan of bender takes several megabytes.

The files are plain JSON, so they can also be compared or processed with other tools.

## Configuration

Settings are constants at the top of `janus.py`. Three of them can also be set through environment variables, which survive a `git pull`:

| Setting | Environment variable | Default |
|---|---|---|
| `GRYPE_IMAGE` | `JANUS_GRYPE_IMAGE` | `anchore/grype:v0.115.0` |
| `TRIVY_IMAGE` | `JANUS_TRIVY_IMAGE` | `aquasec/trivy:0.71.2` |
| `RESULTS_DIR` | `JANUS_RESULTS_DIR` | `/mnt/BIG/filme/backups/janus` |
| `KEEP_RESULTS` | | `12` |
| `CACHE_VOLUME` | | `janus-cache` |
| `SCANNER_CPUS` | | `1.0` |
| `SCANNER_MEMORY` | | `2g` |
| `SCAN_TIMEOUT` | | 45 minutes per scanner per image |

Colour output in `--list` mode can be forced with `--color always` or switched off with `--color never`; the `NO_COLOR` environment variable is also honoured.

## How it works

**Scanning.** Each scanner runs as a short-lived container (`docker run --rm`), one image at a time, limited to one CPU and 2 GB of memory. On bender this follows the rule that no container runs without limits. Both scanners get the Docker socket read-only and read the images straight from the local Docker daemon, so nothing is pulled from a registry except the scanner images themselves. Trivy runs with only its vulnerability scanner enabled (`--scanners vuln`); secret scanning is off.

**Exact images.** Janus scans the image a container actually runs, identified by its image ID, not whatever its tag points to today. It looks for a tag that points at exactly that image, then a repository digest, and falls back to the bare ID. A container that has not been recreated since its tag moved is therefore reported as it really is.

**Databases.** Both vulnerability databases are kept in the Docker volume `janus-cache` and refreshed once at the start of each run; the individual scans then skip their own update checks. Grype refuses to scan with a database older than five days, so `--skip-db-update` only works shortly after a normal run.

**Merging.** A finding is identified by image, vulnerability ID, package and version. Grype's GitHub advisory IDs are mapped to their CVE when one exists (`--by-cve`). Java packages match even though Trivy names them `group:artifact` and Grype names them `artifact`; the more precise name is kept. Go versions match even though Grype writes `go1.22.3` and Trivy writes `v1.22.3`. Scores and fixed versions from both scanners are combined.

**Ordering.** Images are sorted by their CRITICAL count, then HIGH, MEDIUM and LOW. Findings are sorted by score, highest first, then by severity.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | A scan ran and at least one scanner failed on at least one image, or Janus could not start (no Docker access, no saved scan to view). |

## Troubleshooting

**"killed, probably out of memory".** A large image needed more than `SCANNER_MEMORY`. Raise it to `3g` and scan just that container, for example `janus.py immich_machine_learning`. bender runs close to its memory limit, so prefer a quiet moment for this.

**"timed out".** The image took longer than `SCAN_TIMEOUT`. This usually means heavy disk activity on the pool at the same time; run the scan again later.

**A scanner fails on every image.** Check the database update warnings at the start of the run. Without network access the first run cannot download the databases, and Grype stops if its database is too old.

**Arrow keys do nothing, or the screen looks garbled.** Check that `TERM` is set to a real terminal type such as `xterm-256color`. If the browser is unusable, `--list` prints the same findings as plain text.

**The counts differ from Dockhand's.** Make sure `GRYPE_IMAGE` and `TRIVY_IMAGE` match the versions Dockhand uses. Different scanner versions and database dates give different results.

**Starting over.** `docker volume rm janus-cache` removes the databases (they are downloaded again on the next run). Deleting files in the results directory removes saved scans.

## Security notes

Both scanners get read-only access to the Docker socket, the same access Dockhand gives its own scanners. Docker's API does not enforce read-only access, so this is equivalent to root access on the host for the duration of each scan. That is why the scanner images are pinned to exact versions and should only be updated deliberately, to versions published at least two weeks earlier.

Janus itself sends nothing anywhere. The only network traffic is the scanners downloading their images and databases.

## Migrating from vulnscan.py

Janus started as `vulnscan.py` in `docker-compose/scripts/`. Its results directory, cache volume and environment variables have new names, so on bender:

```bash
mv /mnt/BIG/filme/backups/vulnscan /mnt/BIG/filme/backups/janus   # keeps latest.json for --view
docker volume rm vulnscan-cache                                    # Janus uses janus-cache
rm /mnt/BIG/filme/docker-compose/scripts/vulnscan.py
```

Older saved files keep their `vulnscan-` names. Janus can still open them with `--view FILE`, but does not delete them automatically.

## Version history

See [CHANGELOG.md](CHANGELOG.md). Versions use the date-based scheme of the rest of bender's configuration: `YYYYMMDD`, with `.2`, `.3` and so on for later changes on the same day.
