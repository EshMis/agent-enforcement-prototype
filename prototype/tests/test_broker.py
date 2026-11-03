"""Local unit tests (run on the Mac): broker record-and-recheck logic and the decision log.
No Linux-only enforcement (seccomp, namespaces, rlimits) is tested here.

    cd prototype && python3 -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from runtime import authority  # noqa: E402
from runtime.broker import Broker  # noqa: E402
from runtime.decisionlog import DecisionLog  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="asg-test-")
        self.scope = os.path.join(self.tmp, "scope")
        self.prot = os.path.join(self.tmp, "protected")
        os.makedirs(self.scope)
        os.makedirs(self.prot)
        self.rec = os.path.join(self.tmp, "authority.json")
        authority.create(self.rec, authority.new_record("t1", [self.scope], [self.scope], 5, 1 << 28))
        self.log = DecisionLog(os.path.join(self.tmp, "decisions.log"))
        self.b = Broker(self.rec, self.log)

    def read(self, p):
        with open(p) as f:
            return f.read()


class TestScope(Base):
    def test_write_inside_scope_allowed(self):
        p = os.path.join(self.scope, "a.txt")
        r = self.b.write(p, "hi")
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.read(p), "hi")

    def test_write_outside_scope_refused(self):
        p = os.path.join(self.prot, "x.txt")
        r = self.b.write(p, "no")
        self.assertFalse(r["ok"])
        self.assertEqual(r["reason"], "out_of_scope")
        self.assertFalse(os.path.exists(p))

    def test_dotdot_escape_refused(self):
        p = os.path.join(self.scope, "..", "protected", "x.txt")
        r = self.b.write(p, "no")
        self.assertEqual(r["reason"], "out_of_scope")
        self.assertFalse(os.path.exists(os.path.join(self.prot, "x.txt")))

    def test_symlink_escape_refused(self):
        os.symlink(self.prot, os.path.join(self.scope, "link"))
        p = os.path.join(self.scope, "link", "x.txt")
        r = self.b.write(p, "no")
        self.assertEqual(r["reason"], "out_of_scope")
        self.assertFalse(os.path.exists(os.path.join(self.prot, "x.txt")))

    def test_sibling_prefix_is_not_inside(self):
        sib = self.scope + "-evil"
        os.makedirs(sib)
        r = self.b.write(os.path.join(sib, "x.txt"), "no")
        self.assertEqual(r["reason"], "out_of_scope")

    def test_relative_path_refused(self):
        r = self.b.write("scope/a.txt", "no")
        self.assertEqual(r["reason"], "bad_path")


class TestRecheck(Base):
    def _queue(self, name="q.txt"):
        p = os.path.join(self.scope, name)
        q = self.b.enqueue(p, "queued")
        self.assertTrue(q["ok"], q)
        return p, q["qid"]

    def test_commit_without_change_allowed(self):
        p, qid = self._queue()
        r = self.b.commit(qid)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.read(p), "queued")

    def test_revoke_then_commit_refused(self):
        p, qid = self._queue()
        authority.revoke(self.rec)
        r = self.b.commit(qid)
        self.assertFalse(r["ok"])
        self.assertFalse(os.path.exists(p))

    def test_flag_flip_without_version_bump_refused_as_revoked(self):
        p, qid = self._queue()
        authority.edit_without_version_bump(self.rec, revoked=True)
        r = self.b.commit(qid)
        self.assertEqual(r["reason"], "revoked")
        self.assertFalse(os.path.exists(p))

    def test_version_bump_without_revoke_refused_as_stale(self):
        p, qid = self._queue()
        authority.update(self.rec, cpu_seconds=10)
        r = self.b.commit(qid)
        self.assertEqual(r["reason"], "stale_version")
        self.assertFalse(os.path.exists(p))

    def test_reenqueue_after_bump_allowed(self):
        p, qid = self._queue()
        authority.update(self.rec, cpu_seconds=10)
        self.assertFalse(self.b.commit(qid)["ok"])
        q2 = self.b.enqueue(p, "again")
        self.assertTrue(self.b.commit(q2["qid"])["ok"])
        self.assertEqual(self.read(p), "again")

    def test_narrowed_scope_refused(self):
        p, qid = self._queue()
        authority.update(self.rec, write_paths=[])
        r = self.b.commit(qid)
        self.assertFalse(r["ok"])
        self.assertFalse(os.path.exists(p))

    def test_commit_twice_unknown(self):
        _, qid = self._queue()
        self.assertTrue(self.b.commit(qid)["ok"])
        self.assertEqual(self.b.commit(qid)["reason"], "unknown_qid")

    def test_enqueue_after_revoke_refused(self):
        authority.revoke(self.rec)
        q = self.b.enqueue(os.path.join(self.scope, "z.txt"), "x")
        self.assertFalse(q["ok"])

    def test_version_is_monotonic(self):
        v0 = authority.load(self.rec)["version"]
        authority.update(self.rec, cpu_seconds=1)
        authority.revoke(self.rec)
        self.assertEqual(authority.load(self.rec)["version"], v0 + 2)

    def test_mutation_sanity_snapshot_recheck_would_allow(self):
        """Documents what the mutation test relies on: a recheck against the ENQUEUE-time snapshot
        would have allowed the stale commit, so the live-record read is what refuses it."""
        p, qid = self._queue()
        snap = self.b.pending[qid]["snapshot"]
        authority.revoke(self.rec)
        ok_snapshot, _, _ = self.b._decide(snap, p, self.b.pending[qid]["version"])
        ok_current, _, _ = self.b._decide(authority.load(self.rec), p, self.b.pending[qid]["version"])
        self.assertTrue(ok_snapshot)
        self.assertFalse(ok_current)


class TestLog(Base):
    def test_every_decision_logged(self):
        self.b.write(os.path.join(self.scope, "a"), "1")
        self.b.write(os.path.join(self.prot, "b"), "2")
        ev = self.log.entries()
        self.assertEqual([e["decision"] for e in ev], ["allow", "deny"])
        self.assertEqual(ev[1]["reason"], "out_of_scope")

    def test_hash_chain_verifies_and_detects_tamper(self):
        for i in range(5):
            self.b.write(os.path.join(self.scope, "f%d" % i), "x")
        ok, msg = self.log.verify()
        self.assertTrue(ok, msg)
        with open(self.log.path) as f:
            lines = f.read().splitlines()
        e = json.loads(lines[2])
        e["decision"] = "allow" if e["decision"] != "allow" else "deny"
        lines[2] = json.dumps(e, sort_keys=True)
        with open(self.log.path, "w") as f:
            f.write("\n".join(lines) + "\n")
        ok, msg = self.log.verify()
        self.assertFalse(ok)

    def test_log_only_grows(self):
        self.b.write(os.path.join(self.scope, "a"), "1")
        n1 = os.path.getsize(self.log.path)
        self.b.write(os.path.join(self.scope, "b"), "2")
        self.assertGreater(os.path.getsize(self.log.path), n1)


if __name__ == "__main__":
    unittest.main()
