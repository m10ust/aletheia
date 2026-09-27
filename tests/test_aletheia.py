#!/usr/bin/env python3
"""
Tests for aletheia.

Every fixture is built in a temp directory: a fake /proc and a fake pacman
database. Nothing here reads the real machine, so the suite runs anywhere and
produces the same result on a busy box and an idle one.
"""

import importlib.util
import os
import shutil
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

spec = importlib.util.spec_from_file_location("aletheia", os.path.join(ROOT, "aletheia.py"))
aletheia = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aletheia)


# --------------------------------------------------------------------------
# fixture builders
# --------------------------------------------------------------------------

def make_stat_line(pid, comm, ppid=1, state="S", starttime=1000, fields=22):
    """A /proc/<pid>/stat line with the fields aletheia reads.

    Field 1 is pid and field 2 is comm, both consumed before the split, so the
    remainder holds fields 3 through 22. starttime is field 22, which is index
    19 of that remainder.
    """
    rest = ["0"] * (fields - 2)
    rest[0] = state
    rest[1] = str(ppid)
    rest[19] = str(starttime)
    return "%d (%s) %s\n" % (pid, comm, " ".join(rest))


def write_proc(root, pid, comm, exe_target, argv=None, uid="0", ppid=1,
               starttime=1000, statline=None, make_exe_link=True):
    base = os.path.join(root, str(pid))
    os.makedirs(base, exist_ok=True)
    with open(os.path.join(base, "stat"), "w") as fh:
        fh.write(statline if statline is not None else
                 make_stat_line(pid, comm, ppid=ppid, starttime=starttime))
    if make_exe_link and exe_target:
        link = os.path.join(base, "exe")
        if not os.path.lexists(link):
            os.symlink(exe_target, link)
    if argv is not None:
        with open(os.path.join(base, "cmdline"), "wb") as fh:
            fh.write(b"\x00".join(a.encode() for a in argv) + b"\x00")
    with open(os.path.join(base, "status"), "w") as fh:
        fh.write("Name:\t%s\nUid:\t%s\t%s\t%s\t%s\n" % (comm, uid, uid, uid, uid))


def write_pacman(root, packages):
    """packages: {"name-version-rel": ["usr/bin/thing", ...]}"""
    os.makedirs(root, exist_ok=True)
    for entry, files in packages.items():
        d = os.path.join(root, entry)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "files"), "w") as fh:
            fh.write("%FILES%\n")
            for f in files:
                fh.write(f + "\n")


def make_elf(path, interpreter="/lib64/ld-linux-x86-64.so.2", etype=2):
    """A minimal but genuinely valid ELF64 little-endian file with PT_INTERP."""
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    phoff = 64
    phentsize = 56
    str_off = phoff + phentsize
    interp = interpreter.encode() + b"\x00"

    ehdr = ident
    ehdr += struct.pack("<HHI", etype, 62, 1)      # e_type, e_machine, e_version
    ehdr += struct.pack("<QQQ", 0, phoff, 0)        # e_entry, e_phoff, e_shoff
    ehdr += struct.pack("<IHHHHHH", 0, 64, phentsize, 1, 0, 0, 0)
    assert len(ehdr) == 64, len(ehdr)

    phdr = struct.pack("<II", 3, 4)                 # PT_INTERP, flags
    phdr += struct.pack("<QQQ", str_off, 0, 0)      # offset, vaddr, paddr
    phdr += struct.pack("<QQQ", len(interp), len(interp), 1)
    assert len(phdr) == 56, len(phdr)

    with open(path, "wb") as fh:
        fh.write(ehdr + phdr)
        fh.write(b"\x00" * (str_off - 64 - phentsize))
        fh.write(interp)


def make_static_elf(path):
    """An ELF with no PT_INTERP segment: a static binary."""
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = ident + struct.pack("<HHI", 2, 62, 1)
    ehdr += struct.pack("<QQQ", 0, 64, 0)
    ehdr += struct.pack("<IHHHHHH", 0, 64, 56, 1, 0, 0, 0)
    # one program header of type PT_LOAD, which is not PT_INTERP
    phdr = struct.pack("<II", 1, 4) + struct.pack("<QQQ", 0, 0, 0) + struct.pack("<QQQ", 0, 0, 1)
    with open(path, "wb") as fh:
        fh.write(ehdr + phdr)


# --------------------------------------------------------------------------

class EndpointTests(unittest.TestCase):
    """The small rules the rest of the tool depends on."""

    def test_read_text_distinguishes_missing_from_empty(self):
        with tempfile.TemporaryDirectory() as td:
            empty = os.path.join(td, "empty")
            open(empty, "w").close()
            self.assertEqual(aletheia.read_text(empty), "")
            self.assertIsNone(aletheia.read_text(os.path.join(td, "nope")))

    def test_boot_time_read_from_proc_stat(self):
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "stat"), "w") as fh:
                fh.write("cpu  1 2 3\nbtime 1700000000\n")
            self.assertEqual(aletheia.boot_time(td), 1700000000.0)

    def test_iso_handles_none(self):
        self.assertEqual(aletheia.iso(None), "unknown")


class StatParsingTests(unittest.TestCase):
    """comm can contain spaces and parentheses, which breaks naive splitting."""

    def setUp(self):
        self.td = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.td)

    def test_comm_with_spaces_and_parens(self):
        write_proc(self.td, 10, "my (weird) comm", None,
                   statline=make_stat_line(10, "my (weird) comm"),
                   make_exe_link=False)
        with open(os.path.join(self.td, "stat"), "w") as fh:
            fh.write("btime 1700000000\n")
        procs = aletheia.collect_processes(self.td)
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0]["comm"], "my (weird) comm")

    def test_start_time_comes_from_field_22(self):
        write_proc(self.td, 11, "thing", None, starttime=5000, make_exe_link=False)
        with open(os.path.join(self.td, "stat"), "w") as fh:
            fh.write("btime 1700000000\n")
        procs = aletheia.collect_processes(self.td)
        hz = os.sysconf("SC_CLK_TCK")
        self.assertAlmostEqual(procs[0]["started"], 1700000000.0 + 5000.0 / hz, places=3)

    def test_arg_null_separated_and_trailing_nul_dropped(self):
        write_proc(self.td, 12, "thing", None, argv=["/bin/thing", "--flag", "x"],
                   make_exe_link=False)
        with open(os.path.join(self.td, "stat"), "w") as fh:
            fh.write("btime 1700000000\n")
        procs = aletheia.collect_processes(self.td)
        self.assertEqual(procs[0]["argv"], ["/bin/thing", "--flag", "x"])

    def test_non_numeric_proc_entries_ignored(self):
        write_proc(self.td, 13, "real", None, make_exe_link=False)
        os.makedirs(os.path.join(self.td, "sys"), exist_ok=True)
        os.makedirs(os.path.join(self.td, "self"), exist_ok=True)
        with open(os.path.join(self.td, "stat"), "w") as fh:
            fh.write("btime 1700000000\n")
        procs = aletheia.collect_processes(self.td)
        self.assertEqual([p["pid"] for p in procs], [13])


class ElfTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.td)

    def test_dynamic_elf_and_interpreter(self):
        p = os.path.join(self.td, "dyn")
        make_elf(p)
        facts = aletheia.elf_facts(p)
        self.assertEqual(facts["kind"], "elf")
        self.assertEqual(facts["class"], 64)
        self.assertEqual(facts["type"], "executable")
        self.assertFalse(facts["static"])
        self.assertEqual(facts["interpreter"], "/lib64/ld-linux-x86-64.so.2")

    def test_static_elf_has_no_interpreter(self):
        p = os.path.join(self.td, "static")
        make_static_elf(p)
        facts = aletheia.elf_facts(p)
        self.assertTrue(facts["static"])
        self.assertIsNone(facts["interpreter"])

    def test_non_elf_is_named_as_such(self):
        p = os.path.join(self.td, "script.sh")
        with open(p, "w") as fh:
            fh.write("#!/bin/sh\necho hi\n")
        self.assertEqual(aletheia.elf_facts(p)["kind"], "not-elf")

    def test_missing_file_is_unreadable_not_not_elf(self):
        facts = aletheia.elf_facts(os.path.join(self.td, "gone"))
        self.assertEqual(facts["kind"], "unreadable")


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        write_pacman(self.td, {
            "bash-5.3.15-1": ["usr/bin/bash", "usr/share/man/man1/bash.1"],
            "python-3.13.2-1": ["usr/bin/python3"],
        })
        self.own = aletheia.PacmanOwnership(self.td)

    def tearDown(self):
        shutil.rmtree(self.td)

    def test_finds_owner(self):
        self.assertEqual(self.own.owner("/usr/bin/bash"), "bash")

    def test_version_with_dashes_does_not_break_the_name(self):
        # name-version-release; the split must take the first segment only
        self.assertEqual(self.own.owner("/usr/bin/python3"), "python")

    def test_unowned_returns_none(self):
        self.assertIsNone(self.own.owner("/usr/local/bin/planted"))

    def test_missing_database_is_not_a_crash(self):
        own = aletheia.PacmanOwnership(os.path.join(self.td, "nope"))
        self.assertIsNone(own.owner("/usr/bin/bash"))
        self.assertEqual(own.packages, 0)


class ScoringTests(unittest.TestCase):
    """The claims the README makes, tested rather than asserted."""

    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.proc = os.path.join(self.td, "proc")
        self.pac = os.path.join(self.td, "pacman")
        os.makedirs(self.proc)
        os.makedirs(self.pac)
        with open(os.path.join(self.proc, "stat"), "w") as fh:
            fh.write("btime 1700000000\n")

    def tearDown(self):
        shutil.rmtree(self.td)

    def _run(self):
        own = aletheia.PacmanOwnership(self.pac)
        procs = aletheia.collect_processes(self.proc)
        return aletheia.analyse(procs, own, self.proc)

    def _bin(self, name, world_writable=False):
        d = os.path.join(self.td, "bins")
        if world_writable:
            d = os.path.join(self.td, "open")
            os.makedirs(d, exist_ok=True)
            os.chmod(d, 0o777)
        else:
            os.makedirs(d, exist_ok=True)
        p = os.path.join(d, name)
        make_elf(p)
        return p

    def test_clean_owned_binary_scores_zero(self):
        binp = self._bin("bash")
        write_pacman(self.pac, {"bash-5.3.15-1": [binp.lstrip("/")]})
        write_proc(self.proc, 100, "bash", binp, argv=["/usr/bin/bash"])
        subjects = self._run()
        self.assertEqual(subjects[0]["score"], 0.0)
        self.assertEqual(subjects[0]["owner"], "bash")

    def test_unowned_binary_scores_unowned_weight(self):
        binp = self._bin("planted")
        write_pacman(self.pac, {"bash-5.3.15-1": ["usr/bin/bash"]})
        write_proc(self.proc, 101, "planted", binp, argv=[binp])
        subjects = self._run()
        self.assertAlmostEqual(subjects[0]["score"], aletheia.W_UNOWNED_BINARY, places=2)

    def test_deleted_and_unowned_is_high(self):
        binp = self._bin("ghost")
        write_pacman(self.pac, {"bash-5.3.15-1": ["usr/bin/bash"]})
        write_proc(self.proc, 102, "ghost", binp + " (deleted)", argv=[binp])
        subjects = self._run()
        self.assertGreaterEqual(subjects[0]["score"], aletheia.THRESHOLD_HIGH)

    def test_deleted_but_owned_stays_quiet(self):
        """The ordinary state of a process that outlived pacman -Syu."""
        binp = self._bin("upgraded")
        write_pacman(self.pac, {"thing-1.0-1": [binp.lstrip("/")]})
        write_proc(self.proc, 103, "upgraded", binp + " (deleted)", argv=[binp])
        subjects = self._run()
        self.assertLess(subjects[0]["score"], aletheia.THRESHOLD_MEDIUM)

    def test_world_writable_directory_is_flagged(self):
        binp = self._bin("inopen", world_writable=True)
        write_pacman(self.pac, {"thing-1.0-1": [binp.lstrip("/")]})
        write_proc(self.proc, 104, "inopen", binp, argv=[binp])
        subjects = self._run()
        reasons = [s["reason"] for s in subjects[0]["signals"]]
        self.assertTrue(any("world writable" in r for r in reasons), reasons)

    def test_argv_path_mismatch_is_flagged(self):
        binp = self._bin("real")
        other = self._bin("shadow")
        write_pacman(self.pac, {"thing-1.0-1": [binp.lstrip("/"), other.lstrip("/")]})
        write_proc(self.proc, 105, "real", binp, argv=[other])
        subjects = self._run()
        reasons = [s["reason"] for s in subjects[0]["signals"]]
        self.assertTrue(any("argv[0] named" in r for r in reasons), reasons)

    def test_symlink_to_the_same_file_is_not_a_mismatch(self):
        """sh -> bash, python3 -> python3.14: how the system works."""
        real = self._bin("python3.14")
        link = os.path.join(os.path.dirname(real), "python3")
        os.symlink(real, link)
        write_pacman(self.pac, {"python-3.14-1": [real.lstrip("/")]})
        write_proc(self.proc, 120, "python3.14", real, argv=[link])
        subjects = self._run()
        reasons = [s["reason"] for s in subjects[0]["signals"]]
        self.assertFalse(any("argv[0] named" in r for r in reasons), reasons)

    def test_space_joined_argv_is_not_a_mismatch(self):
        """Electron and Chrome rewrite their argv area into one string."""
        binp = self._bin("electron")
        write_pacman(self.pac, {"electron-1-1": [binp.lstrip("/")]})
        write_proc(self.proc, 121, "electron", binp,
                   argv=[binp + " --disable-gpu --enable-wayland-ime /opt/app.asar"])
        subjects = self._run()
        reasons = [s["reason"] for s in subjects[0]["signals"]]
        self.assertFalse(any("argv[0] named" in r for r in reasons), reasons)

    def test_bare_argv0_is_never_a_mismatch(self):
        binp = self._bin("python3.13")
        write_pacman(self.pac, {"python-3.13-1": [binp.lstrip("/")]})
        write_proc(self.proc, 122, "python3.13", binp, argv=["python3"])
        subjects = self._run()
        self.assertEqual(subjects[0]["score"], 0.0)

    def test_unowned_inside_home_scores_lower_than_unowned_in_usr(self):
        """uv, mise, nvm and cargo live in the home and belong to no package.
        Scoring them like a system path is how a tool starts crying wolf."""
        home = self._bin("toolchain")          # lives under the temp dir
        write_pacman(self.pac, {"thing-1.0-1": ["usr/bin/other"]})
        write_proc(self.proc, 123, "toolchain", home, argv=[home])
        subjects = self._run()

        # same file, but pretend it is a system binary: the weight must be higher
        sys_path = aletheia.W_UNOWNED_BINARY
        home_path = aletheia.W_UNOWNED_BINARY_HOME
        self.assertLess(home_path, sys_path)

        got = [s["weight"] for s in subjects[0]["signals"]
               if "no package owns this path" in s["reason"]
               or "no installed package owns" in s["reason"]]
        self.assertTrue(got, subjects[0]["signals"])
        # the fixture is under /tmp, so it takes the system weight here
        self.assertEqual(max(got), sys_path)

    def test_bare_argv0_version_difference_is_not_a_finding(self):
        """python3 resolving to python3.13 is how the system works."""
        binp = self._bin("python3.13")
        write_pacman(self.pac, {"python-3.13.2-1": [binp.lstrip("/")]})
        write_proc(self.proc, 106, "python3.13", binp, argv=["python3"])
        subjects = self._run()
        self.assertEqual(subjects[0]["score"], 0.0)

    def test_no_readable_exe_is_its_own_signal(self):
        write_proc(self.proc, 107, "nameless", None, make_exe_link=False, argv=None)
        write_pacman(self.pac, {"thing-1.0-1": ["usr/bin/x"]})
        subjects = self._run()
        reasons = [s["reason"] for s in subjects[0]["signals"]]
        self.assertTrue(any("no readable executable" in r for r in reasons), reasons)

    def test_kernel_thread_is_not_a_finding(self):
        """Empty command line plus no executable: a kernel thread or a zombie.
        Reporting those is true and useless, and it buries the real findings."""
        base = os.path.join(self.proc, "2")
        os.makedirs(base, exist_ok=True)
        with open(os.path.join(base, "stat"), "w") as fh:
            fh.write(make_stat_line(2, "kworker/0:0"))
        open(os.path.join(base, "cmdline"), "wb").close()   # empty
        with open(os.path.join(base, "status"), "w") as fh:
            fh.write("Name:\tkworker\nUid:\t0\t0\t0\t0\n")
        write_pacman(self.pac, {"thing-1.0-1": ["usr/bin/other"]})
        subjects = self._run()
        self.assertEqual(subjects, [])

    def test_unreadable_executable_is_not_reported_as_absent(self):
        """EACCES means 'not readable as this user', which is a different fact
        from 'there is no binary', and it must not score."""
        with mock.patch.object(aletheia.os, "readlink", side_effect=PermissionError()):
            target, err = aletheia.read_link_status("/proc/1/exe")
        self.assertIsNone(target)
        self.assertEqual(err, "EACCES")

    def test_missing_executable_is_enoent(self):
        target, err = aletheia.read_link_status(os.path.join(self.td, "nothing-here"))
        self.assertIsNone(target)
        self.assertEqual(err, "ENOENT")

    def test_score_is_capped_at_one(self):
        binp = self._bin("everything", world_writable=True)
        write_pacman(self.pac, {"thing-1.0-1": ["usr/bin/other"]})
        write_proc(self.proc, 108, "everything", binp + " (deleted)", argv=["/elsewhere/x"])
        subjects = self._run()
        self.assertLessEqual(subjects[0]["score"], 1.0)

    def test_every_nonzero_signal_carries_a_source(self):
        binp = self._bin("planted")
        write_pacman(self.pac, {"thing-1.0-1": ["usr/bin/other"]})
        write_proc(self.proc, 109, "planted", binp, argv=[binp])
        subjects = self._run()
        for sig in subjects[0]["signals"]:
            if sig["weight"] > 0:
                self.assertTrue(sig["source"], sig)
        self.assertTrue(subjects[0]["sources"])

    def test_two_processes_sharing_an_exe_are_one_subject(self):
        binp = self._bin("shared")
        write_pacman(self.pac, {"thing-1.0-1": [binp.lstrip("/")]})
        write_proc(self.proc, 110, "shared", binp, argv=[binp])
        write_proc(self.proc, 111, "shared", binp, argv=[binp])
        subjects = self._run()
        self.assertEqual(len(subjects), 1)
        self.assertEqual(sorted(subjects[0]["pids"]), [110, 111])


class CleanMachineClaimTests(unittest.TestCase):
    """Claim 6, the one the design rests on: a clean box reports nothing medium.

    If this fails the tool cries wolf, and a tool that cries wolf trains its
    operator to ignore it.
    """

    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.proc = os.path.join(self.td, "proc")
        self.pac = os.path.join(self.td, "pacman")
        os.makedirs(self.proc)
        os.makedirs(os.path.join(self.td, "usr", "bin"))
        with open(os.path.join(self.proc, "stat"), "w") as fh:
            fh.write("btime 1700000000\n")

    def tearDown(self):
        shutil.rmtree(self.td)

    def test_clean_machine_yields_no_medium_findings(self):
        pkgs = {}
        names = ["bash", "systemd", "sshd", "python3.13", "cron"]
        for i, name in enumerate(names):
            p = os.path.join(self.td, "usr", "bin", name)
            make_elf(p)
            # register the path the binary is actually at, not a pretend /usr path
            pkgs["%s-1.0-1" % name] = [p.lstrip("/")]
            write_proc(self.proc, 200 + i, name, p, argv=["/usr/bin/" + name])
        write_pacman(self.pac, pkgs)

        own = aletheia.PacmanOwnership(self.pac)
        subjects = aletheia.analyse(aletheia.collect_processes(self.proc), own, self.proc)

        medium = [s for s in subjects if s["score"] >= aletheia.THRESHOLD_MEDIUM]
        self.assertEqual(medium, [], "clean machine produced findings: %s"
                         % [(s["path"], s["score"]) for s in medium])
        self.assertTrue(all(s["score"] == 0.0 for s in subjects))

    def test_one_planted_binary_is_the_only_finding(self):
        """The negative control for the test above: planting must move exactly
        one subject and leave the rest at zero."""
        pkgs = {}
        for i, name in enumerate(["bash", "sshd", "cron"]):
            p = os.path.join(self.td, "usr", "bin", name)
            make_elf(p)
            pkgs["%s-1.0-1" % name] = [p.lstrip("/")]
            write_proc(self.proc, 300 + i, name, p, argv=["/usr/bin/" + name])

        planted_dir = os.path.join(self.td, "usr", "local", "bin")
        os.makedirs(planted_dir, exist_ok=True)
        planted = os.path.join(planted_dir, "backdoor")
        make_elf(planted)
        write_proc(self.proc, 399, "backdoor", planted, argv=[planted])

        write_pacman(self.pac, pkgs)
        own = aletheia.PacmanOwnership(self.pac)
        subjects = aletheia.analyse(aletheia.collect_processes(self.proc), own, self.proc)

        nonzero = [s for s in subjects if s["score"] > 0]
        self.assertEqual(len(nonzero), 1, [s["path"] for s in nonzero])
        self.assertEqual(nonzero[0]["path"], planted)


class CliTests(unittest.TestCase):
    def test_version_exits_zero(self):
        try:
            aletheia.main(["--version"])
        except SystemExit as exc:
            self.assertEqual(exc.code, 0)
        else:
            self.fail("--version did not exit")

    def test_missing_proc_root_is_error_two(self):
        code = aletheia.main(["--proc-root", "/definitely/not/here"])
        self.assertEqual(code, 2)

    @unittest.skipUnless(os.path.isdir("/proc"), "needs a real /proc")
    def test_json_output_is_parseable(self):
        import io
        import json
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            aletheia.main(["--json"])
        payload = json.loads(buf.getvalue())
        self.assertIn("subjects", payload)
        self.assertIn("stats", payload)
        self.assertIn("version", payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
