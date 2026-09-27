#!/usr/bin/env python3
"""
aletheia - reveal what a Linux machine is hiding.

Read-only. Standard library only. One file.

It joins what a machine says about itself into a single report: which processes
are running, what binary each one is really backed by, and whether that binary
belongs to anything the package manager installed. Every line carries the source
that produced it.

    aletheia                    full report
    aletheia --json             machine readable
    aletheia --focus 4242       one process, full chain
    aletheia --all              include subjects with no signals

Nothing here writes, blocks, or remediates. It reads, and it reports.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time

VERSION = "0.0.1"

# ---------------------------------------------------------------------------
# Scoring
#
# The score is a triage sort, never a verdict, and it is never shown without the
# reasons that produced it. A number with no receipt is a claim, and this tool
# exists to be the receipts keeper.
#
# Weights are deliberately conservative. A forensics tool that cries wolf on a
# clean machine is worse than no tool, because it teaches its operator to ignore
# it.
# ---------------------------------------------------------------------------

W_UNOWNED_BINARY = 0.30
W_UNOWNED_BINARY_HOME = 0.10  # you installed it: uv, mise, nvm, cargo, ollama
W_DELETED_UNOWNED = 0.45
W_DELETED_UPGRADED = 0.10  # path still owned: normal after pacman -Syu
W_ARGV_EXE_MISMATCH = 0.20
W_WORLD_WRITABLE_DIR = 0.25
W_WORLD_WRITABLE_DIR_HOME = 0.10
W_NO_BACKING_FILE = 0.35
W_SETUID = 0.15

THRESHOLD_HIGH = 0.70
THRESHOLD_MEDIUM = 0.40


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def read_text(path, limit=None):
    """Read a file and return str, or None when it cannot be read at all.

    Returning None rather than "" matters: an empty command line and an
    unreadable one are different facts and the report must not conflate them.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit) if limit else fh.read()
    except (OSError, ValueError):
        return None
    return data.decode("utf-8", "replace")


def read_link(path):
    try:
        return os.readlink(path)
    except OSError:
        return None


def read_link_status(path):
    """Return (target, error_name). A missing target is not the same fact as an
    unreadable one, and the report must not conflate them: a kernel thread has
    no binary at all, while /proc/1/exe merely cannot be read without root."""
    try:
        return os.readlink(path), None
    except PermissionError:
        return None, "EACCES"
    except FileNotFoundError:
        return None, "ENOENT"
    except OSError as exc:
        return None, "errno-%s" % exc.errno


def boot_time(proc_root="/proc"):
    """Seconds since epoch when the machine booted, from /proc/stat btime."""
    text = read_text(os.path.join(proc_root, "stat"))
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("btime "):
            try:
                return float(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


def clock(ticks, hz, btime):
    """Process start time, in epoch seconds, from /proc/<pid>/stat field 22."""
    if not btime:
        return None
    try:
        return btime + (int(ticks) / hz)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def iso(ts):
    if not ts:
        return "unknown"
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))


# ---------------------------------------------------------------------------
# ELF
#
# Parsed by hand. The header plus the program header table is enough to answer
# "what is this really, and what does it ask to be run by", which is the
# question that matters here. Pulling in pyelftools for this would cost the
# single-file property for no gain.
# ---------------------------------------------------------------------------

ELF_MAGIC = b"\x7fELF"

ETYPE = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core"}
PT_INTERP = 3


def elf_facts(path):
    """Return what the ELF header and PT_INTERP segment say, or a reason why not."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
            if len(head) < 52 or not head.startswith(ELF_MAGIC):
                return {"kind": "not-elf"}
            ei_class = head[4]          # 1 = 32-bit, 2 = 64-bit
            ei_data = head[5]           # 1 = little endian, 2 = big endian
            if ei_class not in (1, 2) or ei_data not in (1, 2):
                return {"kind": "elf-unknown-encoding",
                        "class": ei_class, "endian": ei_data}
            # int.from_bytes takes "little"/"big", not struct's "<"/">". Getting
            # this wrong crashes on the first real binary, which is exactly what
            # the ELF tests exist to catch.
            byteorder = "little" if ei_data == 1 else "big"
            wide = ei_class == 2

            def u(offset, size):
                return int.from_bytes(head[offset:offset + size], byteorder)

            e_type = u(16, 2)
            e_machine = u(18, 2)
            if wide:
                e_phoff = u(32, 8)
                e_phentsize = u(54, 2)
                e_phnum = u(56, 2)
            else:
                e_phoff = u(28, 4)
                e_phentsize = u(42, 2)
                e_phnum = u(44, 2)

            facts = {
                "kind": "elf",
                "class": 64 if wide else 32,
                "type": ETYPE.get(e_type, "type-%d" % e_type),
                "machine": e_machine,
                "static": True,
                "interpreter": None,
            }

            # Walk the program headers looking for PT_INTERP. That segment is
            # what makes a binary dynamic; its absence makes it static.
            fh.seek(e_phoff)
            table = fh.read(e_phentsize * min(e_phnum, 128))
            for i in range(min(e_phnum, 128)):
                entry = table[i * e_phentsize:(i + 1) * e_phentsize]
                if len(entry) < e_phentsize:
                    break
                p_type = int.from_bytes(entry[0:4], byteorder)
                if p_type != PT_INTERP:
                    continue
                if wide:
                    p_offset = int.from_bytes(entry[8:16], byteorder)
                    p_filesz = int.from_bytes(entry[32:40], byteorder)
                else:
                    p_offset = int.from_bytes(entry[4:8], byteorder)
                    p_filesz = int.from_bytes(entry[16:20], byteorder)
                fh.seek(p_offset)
                raw = fh.read(min(p_filesz, 512))
                facts["interpreter"] = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
                facts["static"] = False
                break
            return facts
    except OSError as exc:
        return {"kind": "unreadable", "error": str(exc)}


# ---------------------------------------------------------------------------
# Package provenance
#
# pacman's local database is read directly rather than shelling out to
# `pacman -Qo`. One subprocess per executable would cost seconds on a box with
# a few hundred running binaries, and the database already holds the answer.
#
# The reverse index is built lazily, because a report that never needs
# provenance should not pay for it.
# ---------------------------------------------------------------------------

DEFAULT_PACMAN_ROOT = "/var/lib/pacman/local"


class PacmanOwnership(object):
    """Maps an absolute file path to the package that installed it."""

    def __init__(self, root=DEFAULT_PACMAN_ROOT):
        self.root = root
        self._index = None
        self.packages = 0

    def _build(self):
        index = {}
        packages = 0
        try:
            entries = os.listdir(self.root)
        except OSError:
            self._index = index
            return
        for entry in entries:
            pkgdir = os.path.join(self.root, entry)
            files = os.path.join(pkgdir, "files")
            if not os.path.isfile(files):
                continue
            # Directory names are name-version-release. Arch package versions
            # cannot contain a dash, so the last two segments are always
            # version and release.
            parts = entry.rsplit("-", 2)
            name = parts[0] if len(parts) >= 3 else entry
            packages += 1
            text = read_text(files)
            if not text:
                continue
            in_files = False
            for line in text.splitlines():
                if line.startswith("%"):
                    in_files = line.strip() == "%FILES%"
                    continue
                if not in_files or not line:
                    continue
                index["/" + line] = name
        self._index = index
        self.packages = packages

    def owner(self, path):
        """Package owning `path`, or None. Directories in the database are
        recorded without a trailing slash and are only matched exactly."""
        if self._index is None:
            self._build()
        return self._index.get(path)

    @property
    def built(self):
        return self._index is not None

    @property
    def file_count(self):
        return len(self._index or {})


# ---------------------------------------------------------------------------
# Process collection
# ---------------------------------------------------------------------------

def collect_processes(proc_root="/proc", hz=None):
    """Every readable process, with the facts this tool cares about."""
    if hz is None:
        hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    btime = boot_time(proc_root)
    processes = []

    try:
        names = os.listdir(proc_root)
    except OSError:
        return processes

    for name in names:
        if not name.isdigit():
            continue
        pid = int(name)
        base = os.path.join(proc_root, name)

        stat_text = read_text(os.path.join(base, "stat"))
        if not stat_text:
            continue  # exited between listing and reading

        # comm is in parentheses and may itself contain spaces and parens, so
        # split on the LAST ')' rather than naively on whitespace.
        rparen = stat_text.rfind(")")
        if rparen == -1:
            continue
        comm = stat_text[stat_text.find("(") + 1:rparen]
        rest = stat_text[rparen + 2:].split()
        # Field 1 is state. starttime is field 22, i.e. index 19 from state.
        state = rest[0] if rest else "?"
        starttime = rest[19] if len(rest) > 19 else None
        ppid = rest[1] if len(rest) > 1 else None

        exe_raw, exe_err = read_link_status(os.path.join(base, "exe"))
        deleted = False
        exe = exe_raw
        if exe_raw and exe_raw.endswith(" (deleted)"):
            deleted = True
            exe = exe_raw[:-len(" (deleted)")]

        cmdline_raw = read_text(os.path.join(base, "cmdline"))
        if cmdline_raw is None:
            argv = None
            empty_cmdline = False
        else:
            argv = [a for a in cmdline_raw.split("\x00") if a]
            # A kernel thread and a zombie both have an empty command line and
            # no executable. Neither is a finding.
            empty_cmdline = cmdline_raw == ""

        uid = None
        status = read_text(os.path.join(base, "status"))
        if status:
            for line in status.splitlines():
                if line.startswith("Uid:"):
                    uid = line.split()[1]
                    break

        processes.append({
            "pid": pid,
            "comm": comm,
            "state": state,
            "ppid": int(ppid) if ppid and ppid.isdigit() else None,
            "uid": uid,
            "exe": exe,
            "exe_raw": exe_raw,
            "exe_err": exe_err,
            "empty_cmdline": empty_cmdline,
            "deleted": deleted,
            "argv": argv,
            "argv0": argv[0] if argv else None,
            "started": clock(starttime, hz, btime),
            "sources": ["/proc/%d/stat" % pid, "/proc/%d/exe" % pid],
        })
    return processes


def world_writable_dir(path):
    """True when the directory holding `path` can be written by anyone."""
    parent = os.path.dirname(path) or "/"
    try:
        mode = os.stat(parent).st_mode
    except OSError:
        return None
    return bool(mode & stat.S_IWOTH)


def argv_exe_conflict(argv0, exe_path):
    """True only when argv[0] named a different, real file.

    Three things this must not fire on, all of which are ordinary:

      - argv[0] reaching the same file through a symlink, which is what
        `sh` -> `bash` and `python3` -> `python3.14` are.
      - argv[0] that is not a single path, because a process may rewrite its
        own argv area into one space-joined string. Electron and Chrome both do
        this, and the joined string is not a filename.
      - a bare program name with no directory part. `python3` resolving to
        python3.13 is how the system works, not a finding.
    """
    if not argv0 or not argv0.startswith("/"):
        return False
    if any(ch.isspace() for ch in argv0):
        return False
    try:
        if os.path.exists(argv0) and os.path.samefile(argv0, exe_path):
            return False
    except OSError:
        pass
    return os.path.basename(argv0) != os.path.basename(exe_path)


def setuid_bits(path):
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return None
    return bool(mode & (stat.S_ISUID | stat.S_ISGID))


# ---------------------------------------------------------------------------
# Analysis: the join
# ---------------------------------------------------------------------------

def analyse(processes, ownership, proc_root="/proc"):
    """Turn processes into scored subjects.

    The join is the product. A binary that no package owns, whose directory is
    world writable, running with its backing file deleted, is not three
    findings. It is one finding with three receipts.
    """
    by_exe = {}
    for proc in processes:
        exe = proc["exe"]
        if not exe:
            # An unreadable or fd-backed exe is its own finding, keyed by pid.
            by_exe.setdefault(("pid", proc["pid"]), []).append(proc)
            continue
        by_exe.setdefault(("exe", exe), []).append(proc)

    home = os.path.expanduser("~")
    subjects = []
    for key, procs in by_exe.items():
        kind, value = key
        proc = procs[0]
        signals = []
        sources = ["/proc/%d/exe" % proc["pid"]]
        # A binary you installed into your own home is expected to belong to no
        # package. uv, mise, nvm, cargo and ollama all live there, and scoring
        # them like a system path would make the tool cry wolf on a healthy box.
        in_home = bool(home) and kind == "exe" and str(value).startswith(home + os.sep)

        if kind == "pid":
            # A kernel thread or a zombie has no command line and no binary.
            # Reporting either as "no executable is backing this process" is
            # true and useless, and it buries the real findings.
            if proc.get("empty_cmdline"):
                continue
            if proc.get("exe_err") == "EACCES":
                # Not readable as this user, which is not the same as absent.
                signals.append((0.0,
                                "executable not readable as this user "
                                "(run as root for a complete report)",
                                "/proc/%d/exe" % proc["pid"]))
            else:
                signals.append((W_NO_BACKING_FILE,
                                "no readable executable is backing this process",
                                "/proc/%d/exe" % proc["pid"]))
            exe_facts = {"kind": "absent"}
            owner = None
        else:
            exe_facts = elf_facts(value)
            owner = ownership.owner(value)

            if proc["deleted"]:
                # A deleted executable owned by a package is the ordinary state
                # of a process that outlived a `pacman -Syu`, not a finding.
                if owner:
                    signals.append((W_DELETED_UPGRADED,
                                    "running from a deleted file, but %s still owns that path "
                                    "(normal after an upgrade)" % owner,
                                    "/proc/%d/exe" % proc["pid"]))
                else:
                    signals.append((W_DELETED_UNOWNED,
                                    "running from a deleted file and no package owns the path",
                                    "/proc/%d/exe" % proc["pid"]))

            # Unowned is checked whenever the database exists. If pacman's local
            # database is absent the tool must not manufacture findings: an
            # empty answer is not the same as a negative one.
            if ownership.built:
                if owner is None:
                    # Independent of the deleted check. The file is gone if it
                    # was deleted; the path is unclaimed if no package owns it.
                    # Two facts, two sources, both counted.
                    if in_home:
                        signals.append((W_UNOWNED_BINARY_HOME,
                                        "no package owns this path, which is normal for "
                                        "a toolchain installed into your own home",
                                        ownership.root))
                    else:
                        signals.append((W_UNOWNED_BINARY,
                                        "no installed package owns this path",
                                        ownership.root))
                    sources.append(ownership.root)
                else:
                    signals.append((0.0, "owned by %s" % owner, ownership.root))

            if world_writable_dir(value):
                signals.append((W_WORLD_WRITABLE_DIR_HOME if in_home
                                else W_WORLD_WRITABLE_DIR,
                                "the directory holding it is world writable",
                                os.path.dirname(value)))
            sd = setuid_bits(value)
            if sd:
                signals.append((W_SETUID,
                                "setuid or setgid bit is set",
                                value))

        # argv[0] disagreeing with the binary is only interesting when the
        # caller named a different, real path. The helper carries the three
        # exclusions, because getting this wrong produced seven false positives
        # out of seven on a healthy machine.
        if kind == "exe" and argv_exe_conflict(proc["argv0"], value):
            signals.append((W_ARGV_EXE_MISMATCH,
                            "argv[0] named %s but the process is running %s"
                            % (proc["argv0"], value),
                            "/proc/%d/cmdline" % proc["pid"]))

        score = round(min(sum(s[0] for s in signals), 1.0), 2)
        subjects.append({
            "key": "%s:%s" % (kind, value),
            "kind": kind,
            "path": value if kind == "exe" else None,
            "pids": [p["pid"] for p in procs],
            "comm": proc["comm"],
            "uid": proc["uid"],
            "started": proc["started"],
            "argv": proc["argv"],
            "deleted": proc["deleted"],
            "owner": owner,
            "elf": exe_facts,
            "score": score,
            "signals": [
                {"weight": w, "reason": r, "source": s} for w, r, s in signals
            ],
            "sources": sorted(set(sources)),
        })

    subjects.sort(key=lambda s: (-s["score"], s["key"]))
    return subjects


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
RESET = "\033[0m"


def colour(enabled):
    if enabled:
        return BOLD, DIM, RED, YELLOW, GREEN, RESET
    return "", "", "", "", "", ""


def severity(score):
    if score >= THRESHOLD_HIGH:
        return "high"
    if score >= THRESHOLD_MEDIUM:
        return "medium"
    if score > 0:
        return "low"
    return "clear"


def render_human(subjects, stats, use_colour, show_all=False):
    B, D, R, Y, G, X = colour(use_colour)
    out = []
    out.append("%saletheia %s%s - what this machine is hiding" % (B, VERSION, X))
    out.append("%sread-only. every line carries the source that produced it.%s" % (D, X))
    out.append("")

    shown = [s for s in subjects if show_all or s["score"] > 0]
    if not shown:
        out.append("%sno subjects carry any signal.%s" % (G, X))
        out.append("")

    for sub in shown:
        tag = severity(sub["score"])
        tint = R if tag == "high" else (Y if tag == "medium" else D)
        label = sub["path"] or ("pid %d (no executable)" % sub["pids"][0])
        out.append("%s%4.2f  %s%s" % (tint, sub["score"], label, X))
        out.append("      %spid %s  uid %s  started %s%s"
                   % (D, ",".join(str(p) for p in sub["pids"]), sub["uid"],
                      iso(sub["started"]), X))
        if sub["argv"]:
            out.append("      %sargv  %s%s" % (D, " ".join(sub["argv"])[:160], X))
        elf = sub["elf"]
        if elf.get("kind") == "elf":
            out.append("      %self  %d-bit %s, %s%s"
                       % (D, elf.get("class"), elf.get("type"),
                          ("interpreter %s" % elf["interpreter"]) if not elf.get("static")
                          else "static", X))
        for sig in sub["signals"]:
            if sig["weight"] <= 0:
                continue
            out.append("      %s+%.2f  %s%s" % (tint, sig["weight"], sig["reason"], X))
            out.append("            %ssource %s%s" % (D, sig["source"], X))
        out.append("")

    out.append("%ssummary%s" % (B, X))
    for key in ("processes", "executables", "owned", "unowned", "deleted",
                "high", "medium", "elapsed"):
        out.append("  %-14s %s" % (key, stats[key]))
    if stats["unowned"] and not show_all:
        out.append("  %sunowned binaries are not automatically a problem. The "
                   "score is a triage sort, not a verdict.%s" % (D, X))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build(args):
    proc_root = args.proc_root
    started = time.time()

    ownership = PacmanOwnership(args.pacman_root)
    processes = collect_processes(proc_root)
    subjects = analyse(processes, ownership, proc_root)

    if args.focus:
        wanted = str(args.focus)
        subjects = [s for s in subjects
                    if wanted in [str(p) for p in s["pids"]]
                    or (s["path"] and wanted in s["path"])]
        processes = [p for p in processes if str(p["pid"]) == wanted]

    stats = {
        "processes": len(processes),
        "executables": len([s for s in subjects if s["kind"] == "exe"]),
        "owned": len([s for s in subjects if s["owner"]]),
        "unowned": len([s for s in subjects if s["kind"] == "exe" and not s["owner"]]),
        "deleted": len([s for s in subjects if s["deleted"]]),
        "high": len([s for s in subjects if s["score"] >= THRESHOLD_HIGH]),
        "medium": len([s for s in subjects if s["score"] >= THRESHOLD_MEDIUM]),
        "packages_indexed": ownership.packages,
        "package_files": ownership.file_count,
        "elapsed": "%.2fs" % (time.time() - started),
    }
    return subjects, stats


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="aletheia",
        description="Reveal what a Linux machine is hiding. Read-only.")
    parser.add_argument("--json", action="store_true",
                        help="emit JSON instead of a report")
    parser.add_argument("--focus", metavar="PID_OR_PATH",
                        help="limit the report to one process or path")
    parser.add_argument("--all", action="store_true",
                        help="include subjects that carry no signal")
    parser.add_argument("--no-color", action="store_true",
                        help="never colour the output")
    parser.add_argument("--proc-root", default="/proc", help=argparse.SUPPRESS)
    parser.add_argument("--pacman-root", default=DEFAULT_PACMAN_ROOT,
                        help=argparse.SUPPRESS)
    parser.add_argument("--version", action="version",
                        version="aletheia %s" % VERSION)
    args = parser.parse_args(argv)

    if not os.path.isdir(args.proc_root):
        sys.stderr.write("aletheia: %s is not a directory. This tool reads Linux "
                         "process state and does not run on other systems.\n"
                         % args.proc_root)
        return 2

    subjects, stats = build(args)

    if args.json:
        print(json.dumps({"version": VERSION, "stats": stats,
                          "subjects": subjects}, indent=2))
    else:
        use_colour = (not args.no_color) and sys.stdout.isatty()
        print(render_human(subjects, stats, use_colour, show_all=args.all))

    if stats["medium"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
