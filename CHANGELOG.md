# Changelog

Versions follow the date-based scheme used across bender's configuration: `YYYYMMDD`, with `.2`, `.3` and so on for later changes on the same day.

## 20261121.2

- **Added** a visual identity in `assets/`, based on the Janus bronze *as*: two bearded faces back to back on a verdigris field, standing on a ground line drawn in the five severity colours of the browser.

  | File | Use |
  |---|---|
  | `janus-mark.svg` | The coin mark, vector, full detail. |
  | `janus-mark-simple.svg` | Simplified mark for small sizes: no beading, no texture, bolder lines. |
  | `janus-avatar.png` | 512 x 512 repository avatar for Forgejo (from the simplified mark). |
  | `janus-social.png` | 1280 x 640 social preview for GitHub. |
  | `janus-banner.png` | README banner (1800 x 680, shown at half size). |

- **Changed** the README opens with the banner.
- Lettering: Cardo (name and tagline) and Anonymous Pro (command-line text), both under the SIL Open Font License. The fonts are only in the PNG files; none are distributed.

## 20261121

- **Renamed** from `vulnscan.py` to **Janus** (`janus.py`) and moved into its own repository. It now lives at `/mnt/BIG/filme/configs/janus` on bender, like `audiobook-foundry`.
- **Renamed resources:**

  | | Before | After |
  |---|---|---|
  | Environment variables | `VULNSCAN_GRYPE_IMAGE`, `VULNSCAN_TRIVY_IMAGE`, `VULNSCAN_RESULTS_DIR` | `JANUS_GRYPE_IMAGE`, `JANUS_TRIVY_IMAGE`, `JANUS_RESULTS_DIR` |
  | Results directory | `/mnt/BIG/filme/backups/vulnscan` | `/mnt/BIG/filme/backups/janus` |
  | Saved scan files | `vulnscan-*.json` | `janus-*.json` |
  | Cache volume | `vulnscan-cache` | `janus-cache` |
  | Scanner container names | `vulnscan-*` | `janus-*` |

- **Added** `--version`.
- **Added** the Janus name to the report title and the browser.
- **Unchanged:** the saved result format. Scans saved by `vulnscan.py` open with `--view FILE`.
- **Required on bender:** see "Migrating from vulnscan.py" in the README.

## 20261120.2

- **Added** an interactive terminal browser that opens after each scan:
  - an image list sorted worst first, with CRITICAL, HIGH, MEDIUM, LOW and UNKNOWN counts on coloured backgrounds;
  - Enter on an image opens its vulnerabilities, sorted by CVSS score, highest first;
  - the selected finding is shown in full at the bottom (description, versions, scanners, advisory link);
  - `f` toggles "only findings with a fix" in both screens;
  - the `(all images)` entry shows every finding in one list.
- **Added** saved scans: every run is written to the results directory and to `latest.json`. The twelve newest are kept.
- **Added** `--view [FILE]` to browse a saved scan without scanning, and `--list` for the previous flat output.
- **Added** a warning line in the vulnerability screen when one scanner failed on that image.
- **Fixed** duplicate findings for Java packages: Trivy names them `group:artifact`, Grype `artifact`. They now merge into one `G+T` line.
- **Changed** Esc no longer quits from the image list. Over SSH an arrow key starts with the Esc character; a split sequence must not close the program.
- The flat output moved to `--list`; it is also used automatically when the output is not a terminal.

## 20261120

- First version, `vulnscan.py`.
- Scans the image behind every container, running or stopped, with Grype and Trivy, one image at a time, with CPU and memory limits.
- Merges both reports: Grype advisory IDs mapped to CVEs, Go version spellings matched, scores and fixed versions combined.
- Prints one list sorted by CVSS score with coloured severity flags, a per-container summary, and the scans that failed.
- Options: `--min-severity`, `--fixed-only`, `--csv`, `--image`, `--scanner`, `--skip-db-update`, `--color`, `--no-pager`.
