#!/usr/bin/env python3
# ============================================
# Janus - two-faced vulnerability scanner for bender's containers
# Version: 20261121
# Repository: http://git.home.arpa:3030/<user>/janus
# ============================================
# Scans the image behind every container (running or stopped) with BOTH
# Grype and Trivy, merges the two reports, saves the result, and opens an
# interactive browser:
#   1. a list of images, worst first, with CRITICAL / HIGH / MEDIUM / LOW /
#      UNKNOWN counts on coloured backgrounds
#   2. Enter on an image lists its vulnerabilities, highest CVSS score first
#
# Run as root on bender (it needs the Docker socket):
#   python3 janus.py                       scan everything, then browse
#   python3 janus.py --view                browse the last saved scan (no scanning)
#   python3 janus.py --view FILE           browse an older saved scan
#   python3 janus.py jellyfin postgres     scan only these containers
#   python3 janus.py --image lscr.io/linuxserver/sonarr:latest
#                                          add an image no container uses yet
#   python3 janus.py --min-severity high   only HIGH and CRITICAL
#   python3 janus.py --fixed-only          only findings a newer version fixes
#   python3 janus.py --list                one flat list instead of the browser
#   python3 janus.py --csv FILE            also write the findings to a CSV file
#
# KEYS
#   Image list        Up/Down PgUp/PgDn Home/End   move
#                     Enter or Right               show that image's vulnerabilities
#                     f                            only findings with a fix: on/off
#                     q                            quit
#   Vulnerabilities   Up/Down PgUp/PgDn Home/End   move; the bottom lines show the
#                                                  selected finding in full
#                     f                            only findings with a fix: on/off
#                     Left, Esc, Backspace or q    back to the image list
#   The first entry, "(all images)", lists every finding of every image.
#
# SAVED RESULTS
#   Every scan is saved in RESULTS_DIR as janus-YYYYMMDD-HHMMSS.json plus
#   latest.json, so --view opens it again without scanning. The newest
#   KEEP_RESULTS scans are kept; older ones are deleted.
#
# HOW IT WORKS
#   - The scanners run as short-lived containers, ONE image at a time, with
#     CPU and memory caps (v112 doctrine: no unconstrained container here).
#   - Both get the Docker socket read-only, the same access Dockhand gives
#     its scanners, and read the images straight from the local daemon.
#     Nothing is pulled from a registry except the scanner images themselves.
#   - Vulnerability databases live in the Docker volume "janus-cache" and
#     are refreshed once at the start of every run. Reset: docker volume rm janus-cache
#   - The exact image each container runs is scanned, even if its tag has
#     since moved to a newer image.
#
# READING THE REPORT
#   SEVERITY  the scanners' rating (for OS packages usually the distro's own
#             assessment). When Grype and Trivy disagree, the higher wins.
#             The LOW count also includes Grype's NEGLIGIBLE findings.
#   SCORE     CVSS base score. v3 is preferred; v4 or v2 is marked.
#             Findings without any score sort at the bottom of their
#             severity band and show "n/a".
#   BY        G = Grype, T = Trivy, G+T = both. G+T findings are the most reliable.
#   FIXED IN  version that fixes it; "won't fix" = the vendor declined; "-" = no fix yet.
# ============================================

import argparse
import csv
import glob
import json
import locale
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime
from itertools import count

try:
    import curses
except ImportError:          # no curses: --list output still works
    curses = None

VERSION = "20261121"

# Keep these on the same versions Dockhand uses (Settings -> General).
GRYPE_IMAGE = os.environ.get("JANUS_GRYPE_IMAGE", "anchore/grype:v0.115.0")
TRIVY_IMAGE = os.environ.get("JANUS_TRIVY_IMAGE", "aquasec/trivy:0.71.2")
RESULTS_DIR = os.environ.get("JANUS_RESULTS_DIR", "/mnt/BIG/filme/backups/janus")
KEEP_RESULTS = 12
CACHE_VOLUME = "janus-cache"
SCANNER_CPUS = "1.0"
SCANNER_MEMORY = "2g"          # raise if a large image fails with "out of memory"
SCAN_TIMEOUT = 45 * 60         # seconds per scanner per image

SEVERITIES = ["UNKNOWN", "NEGLIGIBLE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
COLUMNS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]      # counts in the image list
BAND_FLOOR = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 0.1}
FLAG = {                                   # ANSI colours for the --list output
    "CRITICAL":   "\033[1;97;41m",         # bold white on red
    "HIGH":       "\033[1;30;48;5;208m",   # bold black on orange
    "MEDIUM":     "\033[30;48;5;220m",     # black on yellow
    "LOW":        "\033[97;44m",           # white on blue
    "NEGLIGIBLE": "\033[30;47m",           # black on light grey
    "UNKNOWN":    "\033[97;100m",          # white on dark grey
}
BOLD, RESET = "\033[1m", "\033[0m"


# ---------- docker helpers ----------

def run(cmd, timeout=None):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def docker_json(*args):
    p = run(["docker", *args])
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or "docker %s failed" % args[0])
    return json.loads(p.stdout)


_serial = count(1)


def unique_name(kind):
    return "janus-%s-%d-%d" % (kind, os.getpid(), next(_serial))


def scanner_cmd(image, name, env=(), args=(), socket_mount=True):
    cmd = ["docker", "run", "--rm", "--name", name,
           "--cpus", SCANNER_CPUS, "--memory", SCANNER_MEMORY,
           "-v", "%s:/cache" % CACHE_VOLUME]
    if socket_mount:
        cmd += ["-v", "/var/run/docker.sock:/var/run/docker.sock:ro"]
    for e in env:
        cmd += ["-e", e]
    return cmd + [image, *args]


def run_scanner(cmd, name):
    """Run a scanner container; make sure it is gone afterwards."""
    try:
        return run(cmd, timeout=SCAN_TIMEOUT)
    finally:
        run(["docker", "rm", "-f", name])   # no-op when --rm already removed it


GRYPE_ENV = ["GRYPE_DB_CACHE_DIR=/cache/grype", "GRYPE_CHECK_FOR_APP_UPDATE=false"]
TRIVY_CACHE = ["--cache-dir", "/cache/trivy"]


# ---------- what to scan ----------

def collect_targets(only, extra_images):
    """Return {image_id: {"containers": [...], "ref": ..., "errors": []}} and unmatched names."""
    targets = {}
    ids = run(["docker", "ps", "-aq"]).stdout.split()
    if ids:
        for c in docker_json("inspect", *ids):
            name = c["Name"].lstrip("/")
            if name.startswith("janus-"):        # our own scanner containers
                continue
            if only and name not in only:
                continue
            targets.setdefault(c["Image"], {"containers": [], "errors": []})["containers"].append(name)
    for ref in extra_images:
        img_id = docker_json("image", "inspect", ref)[0]["Id"]
        targets.setdefault(img_id, {"containers": [], "errors": []})["containers"].append(ref)
    found = {n for t in targets.values() for n in t["containers"]}
    missing = sorted(set(only) - found)
    if targets:
        # A name that points at exactly this image: a tag, else a repo digest,
        # else the bare id. Tags always point at one image, so this is exact.
        for img in docker_json("image", "inspect", *targets.keys()):
            refs = [r for r in (img.get("RepoTags") or []) + (img.get("RepoDigests") or [])
                    if "<none>" not in r]
            targets[img["Id"]]["ref"] = refs[0] if refs else img["Id"]
    return targets, missing


# ---------- scanners ----------

def last_line(p):
    lines = (p.stderr or "").strip().splitlines()
    return (lines[-1] if lines else "exit code %d" % p.returncode)[:200]


def update_databases(use):
    warnings = []
    if "grype" in use:
        name = unique_name("grype-db")
        p = run_scanner(scanner_cmd(GRYPE_IMAGE, name, GRYPE_ENV, ["db", "update"],
                                    socket_mount=False), name)
        if p.returncode != 0:
            warnings.append("grype database update failed: " + last_line(p))
    if "trivy" in use:
        for flag in ("--download-db-only", "--download-java-db-only"):
            name = unique_name("trivy-db")
            p = run_scanner(scanner_cmd(TRIVY_IMAGE, name, [],
                                        ["image", flag, "--quiet", *TRIVY_CACHE],
                                        socket_mount=False), name)
            if p.returncode != 0:
                warnings.append("trivy %s failed: %s" % (flag, last_line(p)))
    return warnings


def scan(scanner, ref):
    name = unique_name(scanner)
    if scanner == "grype":
        cmd = scanner_cmd(GRYPE_IMAGE, name, GRYPE_ENV + ["GRYPE_DB_AUTO_UPDATE=false"],
                          ["docker:" + ref, "-o", "json", "--by-cve", "-q"])
        parse = parse_grype
    else:
        cmd = scanner_cmd(TRIVY_IMAGE, name, [],
                          ["image", "--image-src", "docker", "--scanners", "vuln",
                           "--format", "json", "--quiet", "--skip-db-update",
                           "--skip-java-db-update", "--timeout", "40m", *TRIVY_CACHE, ref])
        parse = parse_trivy
    try:
        p = run_scanner(cmd, name)
    except subprocess.TimeoutExpired:
        return None, "timed out after %d minutes" % (SCAN_TIMEOUT // 60)
    if p.returncode == 137:
        return None, "killed, probably out of memory (SCANNER_MEMORY is %s)" % SCANNER_MEMORY
    if p.returncode != 0:
        return None, last_line(p)
    try:
        return list(parse(json.loads(p.stdout))), None
    except (json.JSONDecodeError, AttributeError, TypeError):
        return None, "could not read the scanner's output"


def parse_grype(doc):
    for m in doc.get("matches") or []:
        v = m.get("vulnerability") or {}
        a = m.get("artifact") or {}
        related = m.get("relatedVulnerabilities") or []
        vid = v.get("id") or "?"
        if not vid.startswith("CVE-"):
            vid = next((r["id"] for r in related if str(r.get("id", "")).startswith("CVE-")), vid)
        scores = {}
        for entry in (v.get("cvss") or []) + [c for r in related for c in (r.get("cvss") or [])]:
            major = str(entry.get("version", "")).split(".")[0]
            base = (entry.get("metrics") or {}).get("baseScore")
            if major in ("2", "3", "4") and isinstance(base, (int, float)) and base > 0:
                scores[major] = max(scores.get(major, 0.0), float(base))
        description = v.get("description") or next(
            (r.get("description") for r in related if r.get("description")), "")
        fix = v.get("fix") or {}
        yield (vid, a.get("name"), a.get("version"), v.get("severity"), scores,
               fix.get("versions") or [], fix.get("state") == "wont-fix",
               description, v.get("dataSource") or "")


TRIVY_SCORE_KEYS = {"V3Score": "3", "V40Score": "4", "V2Score": "2"}


def parse_trivy(doc):
    for r in doc.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            scores = {}
            for src in (v.get("CVSS") or {}).values():
                for key, major in TRIVY_SCORE_KEYS.items():
                    s = src.get(key)
                    if isinstance(s, (int, float)) and s > 0:
                        scores[major] = max(scores.get(major, 0.0), float(s))
            fixed = [x.strip() for x in (v.get("FixedVersion") or "").split(",") if x.strip()]
            yield (v.get("VulnerabilityID") or "?", v.get("PkgName"), v.get("InstalledVersion"),
                   v.get("Severity"), scores, fixed, v.get("Status") == "will_not_fix",
                   v.get("Title") or v.get("Description") or "", v.get("PrimaryURL") or "")


# ---------- merging ----------

def norm_version(v):
    # Grype writes Go's stdlib as "go1.22.3", Trivy as "v1.22.3": same thing.
    return re.sub(r"^(go|v)(?=\d)", "", (v or "").strip())


def pkg_key(pkg):
    # Trivy names Java packages group:artifact, Grype only artifact.
    return (pkg or "").lower().rsplit(":", 1)[-1]


def add_finding(findings, image_id, item, scanner):
    vid, pkg, ver, sev, scores, fixed, wontfix, title, url = item
    key = (image_id, vid, pkg_key(pkg), norm_version(ver))
    f = findings.get(key)
    if f is None:
        f = findings[key] = {"image": image_id, "id": vid, "pkg": pkg or "?", "ver": ver or "?",
                             "sev": "UNKNOWN", "scores": {}, "fixed": [], "wontfix": False,
                             "by": [], "title": "", "url": ""}
    if pkg and (f["pkg"] == "?" or (":" in pkg and len(pkg) > len(f["pkg"]))):
        f["pkg"] = pkg                       # keep the more precise name
    sev = (sev or "UNKNOWN").upper()
    sev = sev if sev in RANK else "UNKNOWN"
    if RANK[sev] > RANK[f["sev"]]:
        f["sev"] = sev
    for major, s in scores.items():
        f["scores"][major] = max(f["scores"].get(major, 0.0), s)
    for x in fixed:
        if x not in f["fixed"]:
            f["fixed"].append(x)
    f["wontfix"] = f["wontfix"] or wontfix
    title = " ".join((title or "").split())
    if title and (scanner == "T" or not f["title"]):   # Trivy's titles are short
        f["title"] = title
    if url and not f["url"]:
        f["url"] = url
    if scanner not in f["by"]:
        f["by"].append(scanner)


def best_score(scores):
    for major in ("3", "4", "2"):
        if major in scores:
            return scores[major], major
    return None, None


def sort_key(f):
    score, _ = best_score(f["scores"])
    effective = score if score is not None else BAND_FLOOR.get(f["sev"], 0.0)
    return (-effective, score is None, -RANK[f["sev"]], f["id"], f["pkg"])


def count_columns(findings):
    counts = {c: 0 for c in COLUMNS}
    for f in findings:
        counts["LOW" if f["sev"] == "NEGLIGIBLE" else f["sev"]] += 1
    return counts


# ---------- scanning run ----------

def scan_all(args, use):
    targets, missing = collect_targets(args.containers, args.image)
    for name in missing:
        print("WARNING: no container named %s" % name, file=sys.stderr)
    if not targets:
        sys.exit("Nothing to scan.")

    warnings = []
    if not args.skip_db_update:
        print("Updating vulnerability databases ...", file=sys.stderr)
        warnings = update_databases(use)
        for w in warnings:
            print("WARNING: " + w, file=sys.stderr)

    findings, complete = {}, True
    order = sorted(targets.items(), key=lambda kv: kv[1]["containers"][0])
    started = time.time()
    try:
        for n, (img_id, t) in enumerate(order, 1):
            label = ", ".join(t["containers"])
            t0, status = time.time(), []
            for scanner in use:
                items, err = scan(scanner, t["ref"])
                if err:
                    t["errors"].append([scanner, err])
                    status.append("%s FAILED" % scanner)
                    continue
                for item in items:
                    add_finding(findings, img_id, item, "G" if scanner == "grype" else "T")
                status.append("%s %d" % (scanner, len(items)))
            t["scanned"] = True
            print("[%2d/%d] %-28s %-28s %4ds" % (n, len(order), fit(label, 28),
                                                 "  ".join(status), time.time() - t0),
                  file=sys.stderr)
    except KeyboardInterrupt:
        complete = False
        print("\nInterrupted - keeping what was scanned so far.", file=sys.stderr)
    for t in targets.values():
        if not t.get("scanned"):
            t["errors"].append(["-", "not scanned (the run was interrupted)"])
    print("Done in %d min." % ((time.time() - started) // 60), file=sys.stderr)

    return {"format": 1, "host": socket.gethostname(),
            "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M"), "complete": complete,
            "scanners": [GRYPE_IMAGE if s == "grype" else TRIVY_IMAGE for s in use],
            "images": targets, "findings": list(findings.values()), "warnings": warnings}


def save_results(results):
    try:
        os.makedirs(RESULTS_DIR, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = os.path.join(RESULTS_DIR, "janus-%s.json" % stamp)
        data = json.dumps(results)
        for target in (path, os.path.join(RESULTS_DIR, "latest.json")):
            with open(target + ".tmp", "w", encoding="utf-8") as fh:
                fh.write(data)
            os.replace(target + ".tmp", target)
        for old in sorted(glob.glob(os.path.join(RESULTS_DIR, "janus-*.json")))[:-KEEP_RESULTS]:
            os.remove(old)
        return path
    except OSError as e:
        print("WARNING: could not save the results in %s: %s" % (RESULTS_DIR, e), file=sys.stderr)
        return None


def load_results(arg):
    path = os.path.join(RESULTS_DIR, "latest.json") if arg == "latest" else arg
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        sys.exit("No saved scan at %s - run a scan first." % path)
    except (OSError, ValueError) as e:
        sys.exit("Cannot read %s: %s" % (path, e))
    if not isinstance(data, dict) or data.get("format") != 1:
        sys.exit("%s is not a Janus result file." % path)
    return data


# ---------- shared formatting ----------

def fit(text, width):
    text = str(text)
    return text if len(text) <= width else text[:max(width - 1, 0)] + "~"


def score_text(f):
    score, major = best_score(f["scores"])
    if score is None:
        return "n/a"
    return "%.1f" % score if major == "3" else "%.1f v%s" % (score, major)


def fixed_text(f):
    if f["fixed"]:
        return ", ".join(f["fixed"])
    return "won't fix" if f["wontfix"] else "-"


def by_text(f):
    return "+".join(s for s in ("G", "T") if s in f["by"])


def by_words(f):
    return " + ".join(n for s, n in (("G", "Grype"), ("T", "Trivy")) if s in f["by"])


def link(f):
    if f["id"].startswith("CVE-"):
        return "https://nvd.nist.gov/vuln/detail/" + f["id"]
    if f["id"].startswith("GHSA-"):
        return "https://github.com/advisories/" + f["id"]
    return f.get("url") or ""


def labels(images, f):
    return ", ".join(images[f["image"]]["containers"])


TABLE_HEADERS = ["SEVERITY", "SCORE", "ID", "PACKAGE", "INSTALLED", "FIXED IN", "BY", "CONTAINER"]
TABLE_CAPS = [12, 8, 20, 32, 26, 26, 3, 40]
TABLE_MIN = {3: 12, 4: 10, 5: 10, 7: 12}      # columns that may shrink, and how far


def table_row(f, images, with_container):
    row = [f["sev"], score_text(f), f["id"], f["pkg"], f["ver"], fixed_text(f), by_text(f)]
    return row + [labels(images, f)] if with_container else row


def natural_widths(headers, rows):
    widths = [min(cap, max([len(h)] + [len(str(r[i])) for r in rows]))
              for i, (h, cap) in enumerate(zip(headers, TABLE_CAPS))]
    widths[0] = 12
    return widths


def shrink(widths, width):
    """Narrow the flexible columns until the table fits `width` (0 = no limit)."""
    widths = list(widths)
    if width:
        mins = {k: v for k, v in TABLE_MIN.items() if k < len(widths)}
        while sum(widths) + 2 * (len(widths) - 1) > width:
            i = max(mins, key=lambda k: widths[k] - mins[k])
            if widths[i] <= mins[i]:
                break
            widths[i] -= 1
    return widths


# ---------- flat list (--list, or when not on a terminal) ----------

def ansi_flag(sev, color):
    label = " %-10s " % sev
    return FLAG[sev] + label + RESET if color else label


def render_list(results, rows, color, term_width):
    images = results["images"]
    out = []
    title = "Janus - vulnerability report - %s - %s%s" % (results["host"], results["scanned_at"],
                                                  "" if results.get("complete", True) else " (incomplete)")
    out.append(BOLD + title + RESET if color else title)
    out.append("Scanners: %s   Images: %d   Findings shown: %d"
               % (", ".join(results["scanners"]), len(images), len(rows)))
    counts = {s: 0 for s in SEVERITIES}
    for f in rows:
        counts[f["sev"]] += 1
    out.append("  ".join("%s %d" % (ansi_flag(s, color), counts[s])
                         for s in reversed(SEVERITIES) if counts[s] or RANK[s] >= RANK["LOW"]))
    out.append("")

    if rows:
        table = [table_row(f, images, True) for f in rows]
        widths = shrink(natural_widths(TABLE_HEADERS, table), term_width)
        head = "  ".join(h.ljust(w) for h, w in zip(TABLE_HEADERS, widths)).rstrip()
        out.append("\033[1;4m" + head + RESET if color else head)
        for r in table:
            cells = [ansi_flag(r[0], color)] + [fit(c, w).ljust(w) for c, w in zip(r[1:], widths[1:])]
            out.append("  ".join(cells).rstrip())
        out.append("")

    per = {}
    for f in rows:
        per.setdefault(f["image"], []).append(f)
    if per:
        label_w = min(60, max(len(", ".join(images[i]["containers"])) for i in per))
        out.append("%-*s  %8s %8s %8s %8s %8s" % (label_w, "Per container", *COLUMNS))
        summary = sorted(((i, count_columns(fs)) for i, fs in per.items()),
                         key=lambda kv: [-kv[1][c] for c in COLUMNS])
        for img_id, c in summary:
            out.append("%-*s  %8d %8d %8d %8d %8d" % (
                label_w, fit(", ".join(images[img_id]["containers"]), label_w),
                *(c[k] for k in COLUMNS)))
        out.append("")

    for w in results.get("warnings") or []:
        out.append("WARNING: " + w)
    failed = [(", ".join(i["containers"]), sc, msg)
              for i in images.values() for sc, msg in i.get("errors") or []]
    if failed:
        out.append("Scans that failed (their findings are missing above):")
        for label, scanner, msg in failed:
            out.append("  %-28s %-6s %s" % (fit(label, 28), scanner, msg))
    return "\n".join(out) + "\n"


def page(text):
    pager = subprocess.Popen(["less", "-RS"], stdin=subprocess.PIPE, text=True)
    try:
        pager.communicate(text)
    except (BrokenPipeError, KeyboardInterrupt):
        pass


def write_csv(path, rows, images):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["severity", "score", "cvss_version", "id", "package", "installed",
                    "fixed_in", "found_by", "containers", "image_ref", "title", "link"])
        for f in rows:
            score, major = best_score(f["scores"])
            w.writerow([f["sev"], "" if score is None else "%.1f" % score, major or "", f["id"],
                        f["pkg"], f["ver"], fixed_text(f), by_text(f),
                        " ".join(images[f["image"]]["containers"]), images[f["image"]]["ref"],
                        f.get("title", ""), link(f)])


# ---------- interactive browser ----------

ENTER_KEYS = (10, 13)
BACK_KEYS = (ord("q"), ord("Q"), 27, 127, 8)


def move(sel, key, visible, total):
    step = {curses.KEY_UP: -1, curses.KEY_DOWN: 1,
            curses.KEY_PPAGE: -visible, curses.KEY_NPAGE: visible}
    if key in step:
        sel += step[key]
    elif key == curses.KEY_HOME:
        sel = 0
    elif key == curses.KEY_END:
        sel = total - 1
    return max(0, min(sel, total - 1))


def keep_visible(sel, top, total, visible):
    if sel < top:
        top = sel
    elif sel >= top + visible:
        top = sel - visible + 1
    return max(0, min(top, total - visible)) if total > visible else 0


class Browser:
    CELL = 10                                   # width of one coloured count cell

    def __init__(self, results, rows, fixed_only):
        self.res = results
        self.all_rows = rows
        self.fixed_only = fixed_only
        self.sel = self.top = 0
        self.detail = None                      # label of the open image, or None
        self.dsel = self.dtop = 0
        self.visible = 1
        self.rebuild()

    # data

    def rebuild(self):
        current = self.entries[self.sel]["label"] if getattr(self, "entries", None) else None
        rows = [f for f in self.all_rows if f["fixed"] or not self.fixed_only]
        per = {}
        for f in rows:
            per.setdefault(f["image"], []).append(f)
        entries = []
        for img_id, info in self.res["images"].items():
            fs = per.get(img_id, [])
            entries.append({"label": ", ".join(info["containers"]), "ref": info["ref"],
                            "findings": fs, "counts": count_columns(fs),
                            "errors": info.get("errors") or [], "all": False})
        entries.sort(key=lambda e: [-e["counts"][c] for c in COLUMNS] + [e["label"]])
        everything = {"label": "(all images)", "findings": rows, "counts": count_columns(rows),
                      "ref": "%d images, %d findings" % (len(entries), len(rows)),
                      "errors": [], "all": True}
        self.entries = [everything] + entries
        if current:
            self.sel = next((i for i, e in enumerate(self.entries) if e["label"] == current), 0)
        if self.detail:
            self.build_table()

    def entry(self):
        return next(e for e in self.entries if e["label"] == self.detail)

    def build_table(self):
        e = self.entry()
        self.headers = TABLE_HEADERS if e["all"] else TABLE_HEADERS[:-1]
        self.table = [table_row(f, self.res["images"], e["all"]) for f in e["findings"]]
        self.widths = natural_widths(self.headers, self.table)
        self.dsel = self.dtop = 0

    # drawing

    def put(self, y, x, text, attr=0):
        h, w = self.scr.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        text = str(text)[:max(0, w - x - (1 if y == h - 1 else 0))]
        try:
            self.scr.addstr(y, x, text, attr)
        except UnicodeEncodeError:
            self.scr.addstr(y, x, text.encode("ascii", "replace").decode(), attr)
        except curses.error:
            pass

    def init_colors(self):
        self.attr = {s: curses.A_REVERSE for s in SEVERITIES}
        if not curses.has_colors():
            return
        curses.start_color()
        try:
            curses.use_default_colors()
        except curses.error:
            pass
        many, sixteen = curses.COLORS >= 256, curses.COLORS >= 16
        white = 15 if sixteen else curses.COLOR_WHITE
        spec = [("CRITICAL", white, curses.COLOR_RED, curses.A_BOLD),
                ("HIGH", curses.COLOR_BLACK, 208 if many else curses.COLOR_MAGENTA, curses.A_BOLD),
                ("MEDIUM", curses.COLOR_BLACK, 220 if many else curses.COLOR_YELLOW, 0),
                ("LOW", white, curses.COLOR_BLUE, 0),
                ("NEGLIGIBLE", curses.COLOR_BLACK, curses.COLOR_WHITE, 0),
                ("UNKNOWN", white, 8 if sixteen else curses.COLOR_BLACK, 0)]
        for i, (sev, fg, bg, extra) in enumerate(spec, 1):
            try:
                curses.init_pair(i, fg, bg)
                self.attr[sev] = curses.color_pair(i) | extra
            except curses.error:
                pass

    def draw_images(self):
        self.scr.erase()
        h, w = self.scr.getmaxyx()
        r = self.res
        self.put(0, 0, "Janus - %s - scanned %s%s - %s" % (
            r["host"], r["scanned_at"], "" if r.get("complete", True) else " (incomplete)",
            ", ".join(r["scanners"])), curses.A_BOLD)
        self.put(1, 0, "Up/Down PgUp/PgDn move   Enter open   f fixed only: %s   q quit"
                 % ("ON" if self.fixed_only else "off"), curses.A_DIM)

        cells = len(COLUMNS) * (self.CELL + 1)
        label_w = max(12, min(30, max(len(e["label"]) for e in self.entries)))
        ref_w = w - 2 - (label_w + 1) - cells - 1
        if ref_w < 12:                          # narrow terminal: drop the image column
            ref_w, label_w = 0, max(8, min(label_w, w - 2 - cells - 1))
        x, head = 2, curses.A_BOLD | curses.A_UNDERLINE
        self.put(3, x, "CONTAINER".ljust(label_w), head)
        x += label_w + 1
        if ref_w:
            self.put(3, x, "IMAGE".ljust(ref_w), head)
            x += ref_w + 1
        for c in COLUMNS:
            self.put(3, x, " %-8s " % c, self.attr[c])
            x += self.CELL + 1

        first = 4
        self.visible = max(1, h - first - 3)
        self.top = keep_visible(self.sel, self.top, len(self.entries), self.visible)
        for i in range(self.visible):
            n = self.top + i
            if n >= len(self.entries):
                break
            e, y = self.entries[n], first + i
            base = (curses.A_REVERSE if n == self.sel else 0) | (curses.A_BOLD if e["all"] else 0)
            self.put(y, 0, (">" if n == self.sel else " ") + ("!" if e["errors"] else " "),
                     curses.A_BOLD)
            x = 2
            self.put(y, x, fit(e["label"], label_w).ljust(label_w), base)
            x += label_w + 1
            if ref_w:
                self.put(y, x, fit(e["ref"], ref_w).ljust(ref_w), base)
                x += ref_w + 1
            for c in COLUMNS:
                self.put(y, x, " %8d " % e["counts"][c], self.attr[c])
                x += self.CELL + 1

        e = self.entries[self.sel]
        self.put(h - 2, 0, "%s   %s" % (e["label"], e["ref"]), curses.A_BOLD)
        if e["errors"]:
            self.put(h - 1, 0, "! scan problem - " + "; ".join("%s: %s" % (sc, m) for sc, m in e["errors"]),
                     curses.A_BOLD)
        else:
            self.put(h - 1, 0, "%d findings  (LOW includes Negligible)" % len(e["findings"]),
                     curses.A_DIM)

    def draw_detail(self):
        self.scr.erase()
        h, w = self.scr.getmaxyx()
        e = self.entry()
        self.put(0, 0, "%s   %s" % (e["label"], e["ref"]), curses.A_BOLD)
        x = 0
        for c in COLUMNS:
            text = " %s %d " % (c, e["counts"][c])
            self.put(1, x, text, self.attr[c])
            x += len(text) + 1
        self.put(1, x + 1, "fixed only: %s" % ("ON" if self.fixed_only else "off"), curses.A_DIM)

        if not self.table:
            if e["errors"]:
                msg = "Scan problem - " + "; ".join("%s: %s" % (sc, m) for sc, m in e["errors"])
            else:
                msg = "No vulnerabilities%s found." % (" with a fix" if self.fixed_only else "")
            self.put(3, 2, msg)
        else:
            if e["errors"]:
                self.put(2, 0, "! incomplete - " + "; ".join("%s: %s" % (sc, m) for sc, m in e["errors"]),
                         curses.A_BOLD)
            widths = shrink(self.widths, w - 1)
            head = "  ".join(t.ljust(n) for t, n in zip(self.headers, widths)).rstrip()
            self.put(3, 0, head, curses.A_BOLD | curses.A_UNDERLINE)
            first = 4
            self.visible = max(1, h - first - 4)
            self.dtop = keep_visible(self.dsel, self.dtop, len(self.table), self.visible)
            for i in range(self.visible):
                n = self.dtop + i
                if n >= len(self.table):
                    break
                row, y = self.table[n], first + i
                self.put(y, 0, " %-10s " % row[0], self.attr[row[0]])
                rest = "  ".join(fit(c, k).ljust(k) for c, k in zip(row[1:], widths[1:]))
                self.put(y, widths[0] + 2, rest, curses.A_REVERSE if n == self.dsel else 0)
            f = e["findings"][self.dsel]
            self.put(h - 3, 0, "%s  %s" % (f["id"], f.get("title") or "(no description)"),
                     curses.A_BOLD)
            where = "" if not e["all"] else "   in " + labels(self.res["images"], f)
            self.put(h - 2, 0, "%s %s -> %s   found by %s%s   %s" % (
                f["pkg"], f["ver"], fixed_text(f), by_words(f), where, link(f)))
        self.put(h - 1, 0, "Up/Down PgUp/PgDn Home/End move   f fixed only   Left/Esc/q back",
                 curses.A_DIM)

    # main loop

    def run(self, scr):
        self.scr = scr
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        scr.keypad(True)
        self.init_colors()
        while True:
            if self.detail:
                self.draw_detail()
            else:
                self.draw_images()
            scr.refresh()
            key = scr.getch()
            if key == curses.KEY_RESIZE:
                continue
            if key in (ord("f"), ord("F")):
                self.fixed_only = not self.fixed_only
                self.rebuild()
            elif self.detail is None:
                if key in (ord("q"), ord("Q")):    # not Esc: a split arrow key must not quit
                    return
                if key in ENTER_KEYS or key in (curses.KEY_ENTER, curses.KEY_RIGHT):
                    self.detail = self.entries[self.sel]["label"]
                    self.build_table()
                else:
                    self.sel = move(self.sel, key, self.visible, len(self.entries))
            elif key in BACK_KEYS or key in (curses.KEY_LEFT, curses.KEY_BACKSPACE):
                self.detail = None
            elif self.table:
                self.dsel = move(self.dsel, key, self.visible, len(self.table))


def browse(results, rows, fixed_only):
    os.environ.setdefault("ESCDELAY", "100")   # Esc reacts quickly; arrow keys over SSH stay whole
    try:
        locale.setlocale(locale.LC_ALL, "")
    except locale.Error:
        pass
    try:
        curses.wrapper(Browser(results, rows, fixed_only).run)
    except KeyboardInterrupt:
        pass


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(
        prog="janus.py",
        description="Janus: scan container images with Grype and Trivy, then browse the "
                    "findings per image, highest CVSS score first.")
    ap.add_argument("--version", action="version", version="Janus " + VERSION)
    ap.add_argument("containers", nargs="*",
                    help="only scan these containers (default: all, running or stopped)")
    ap.add_argument("--view", nargs="?", const="latest", metavar="FILE",
                    help="browse a saved scan instead of scanning (default: the latest)")
    ap.add_argument("--image", action="append", default=[], metavar="REF",
                    help="also scan an image no container uses (repeatable)")
    ap.add_argument("--scanner", choices=["both", "grype", "trivy"], default="both")
    ap.add_argument("--min-severity", choices=[s.lower() for s in SEVERITIES], default="unknown",
                    help="hide findings below this severity")
    ap.add_argument("--fixed-only", action="store_true",
                    help="only show findings that a newer version fixes (key f in the browser)")
    ap.add_argument("--list", action="store_true",
                    help="print one flat list instead of opening the browser")
    ap.add_argument("--csv", metavar="FILE", help="also write the findings to a CSV file")
    ap.add_argument("--skip-db-update", action="store_true",
                    help="use the cached vulnerability databases as they are")
    ap.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                    help="colours in the --list output: auto = on a terminal only")
    ap.add_argument("--no-pager", action="store_true", help="--list: do not open less")
    args = ap.parse_args()

    use = ["grype", "trivy"] if args.scanner == "both" else [args.scanner]
    tty = sys.stdout.isatty()
    color = args.color == "always" or (args.color == "auto" and tty and "NO_COLOR" not in os.environ)

    saved = None
    if args.view is not None:
        if args.containers or args.image:
            sys.exit("--view opens a saved scan; container names and --image only apply when scanning.")
        results = load_results(args.view)
    else:
        if run(["docker", "version"]).returncode != 0:
            sys.exit("Cannot talk to Docker. Run this as root on bender.")
        results = scan_all(args, use)
        saved = save_results(results)

    floor = RANK[args.min_severity.upper()]
    rows = sorted((f for f in results["findings"] if RANK.get(f["sev"], 0) >= floor), key=sort_key)
    flat = [f for f in rows if f["fixed"] or not args.fixed_only]
    if args.csv:
        write_csv(args.csv, flat, results["images"])
        print("CSV written to %s" % args.csv, file=sys.stderr)

    if not args.list and tty and sys.stdin.isatty() and curses is not None:
        browse(results, rows, args.fixed_only)
    else:
        size = shutil.get_terminal_size((200, 50))
        text = render_list(results, flat, color, size.columns if tty else 0)
        if tty and not args.no_pager and text.count("\n") > size.lines - 2 and shutil.which("less"):
            page(text)
        else:
            sys.stdout.write(text)

    if saved:
        print("Scan saved to %s  (open it again with: --view)" % saved, file=sys.stderr)
    failed = saved is not None and any(i.get("errors") for i in results["images"].values())
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
