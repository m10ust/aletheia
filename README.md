# aletheia

**A read-only forensics reader for Linux.** It joins the processes running on a machine to the
binaries backing them, and those binaries to the packages that installed them, then reports what
does not add up. Every line carries the source that produced it.

Single file. Standard library only. Nothing installed, nothing written, nothing blocked.

```
aletheia                    full report
aletheia --json             machine readable
aletheia --focus 4242       one process, the whole chain
aletheia --all              include subjects carrying no signal
```

## Why this exists

Linux has four good layers that *produce signal*: `pacman` for what was allowed in and by whose
signature, `AIDE` for what changed, `Falco` for what is doing it right now, and logs for what
happened. None of them answers the question their own alarm raises:

> what is this process, what file backs it, what started it, what does it touch, and is that
> binary actually what the package manager thinks it is?

That answer currently lives in five tools and one human memory. This is the reader that joins
them. On macOS the equivalent job is done by [`machscope`](https://github.com/m10ust/machscope).

## Install

There is nothing to install.

```sh
curl -O https://raw.githubusercontent.com/m10ust/aletheia/master/aletheia.py
chmod +x aletheia.py
./aletheia.py
```

Or clone it and run it in place. It has no dependencies, no build step, and no package on any
index.

## What it reads

- `/proc/<pid>/{stat,exe,cmdline,status}`, for every process it can see
- ELF headers and `PT_INTERP`, parsed by hand, to separate static from dynamic and to learn each
  binary's interpreter
- `/var/lib/pacman/local/*/files`, for which package owns which path

It does not read memory, does not install hooks, and does not require a daemon. Run it as a
normal user for reduced coverage, or as root for the complete picture. It tells you when a
process exists that it could not read rather than quietly omitting it.

## What it reports

A scored subject for each distinct executable, ordered worst first, each one carrying the weights
that produced its score and the source behind each weight:

```
 0.75  /usr/local/bin/planted
      pid 4242  uid 0  started 2026-09-27T18:03:11
      argv  /usr/local/bin/planted --quiet
      elf  64-bit executable, interpreter /lib64/ld-linux-x86-64.so.2
      +0.45  running from a deleted file and no package owns the path
            source /proc/4242/exe
      +0.30  no installed package owns this path
            source /var/lib/pacman/local
```

Three signals is not three findings. It is one finding with three receipts.

Two of the signals are deliberately quiet, because they are the normal state of a healthy
machine:

- **A deleted executable that a package still owns** is what a process looks like after it
  outlived a `pacman -Syu`. That scores 0.10, not 0.45.
- **`argv[0]` disagreeing with the binary** is only interesting when the caller named a path
  explicitly. `python3` resolving to `python3.13` is how the system works, not a finding.

## Scoring

The score is a **triage sort, not a verdict**, and it is never printed without the reasons behind
it. A number with no receipt is a claim, and this tool is meant to be the receipts keeper.

| weight | signal |
|---|---|
| +0.45 | running from a deleted file, and no package owns the path |
| +0.35 | no readable executable is backing the process |
| +0.30 | no installed package owns the path |
| +0.25 | the directory holding the binary is world writable |
| +0.20 | `argv[0]` named a different absolute path |
| +0.15 | setuid or setgid bit set |
| +0.10 | running from a deleted file that a package still owns |

Thresholds: **0.70** high, **0.40** medium. Exit code `1` when anything reaches medium, so it
drops straight into a script or a timer.

The weights are conservative on purpose. A forensics tool that cries wolf on a clean machine is
worse than no tool, because it teaches its operator to ignore it.

## Name

*aletheia* (ἀλήθεια) is un-concealment: `a-` not, `λήθη` Lethe, the river of forgetting. Truth as
the act of revealing what was hidden, rather than a claim that happens to be correct. That is the
whole job description.

The word is shared with several unrelated projects, which is recorded rather than hidden:
`aletheia` exists on PyPI and crates.io, and there are several same-named repositories. That
costs this project nothing, because it ships as a single file from git and was never going to
publish to a package index.

## Status: v0.0.1

This is the first slice, and it says what it does not do yet.

**Working:** process inventory, deleted-executable detection, executable provenance against the
package database, basic ELF classification, per-subject scoring with receipts, human and JSON
output, `--focus`.

**Not built yet:** systemd units and drop-in overrides, transient units, persistence surfaces
(cron, udev, `ld.so.preload`, kernel modules, eBPF), network attribution, hash comparison
against the package's own record, baselines, and the HUD feed.

**Out of scope permanently:** memory forensics (that is Volatility), syscall capture (that is
`sysdig` and Falco), blocking (that is `fapolicyd`), and remediation. This tool reads and
reports.

The full design is in the spec, including the falsifiable claims it intends to be held to.

## Design notes

- **One pass over the process table.** The expensive part is doing something per process that
  needs the whole table. Build the join once, then look up.
- **Return `None`, never `""`, for an unreadable file.** An empty command line and an unreadable
  one are different facts and the report must not conflate them.
- **No dependency is worth the single-file property.** ELF is parsed by hand and the pacman
  database is read directly, because `pyelftools` and a subprocess per executable would each cost
  more than they return.

## Licence

MIT.
