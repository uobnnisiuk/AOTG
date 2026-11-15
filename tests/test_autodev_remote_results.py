"""Exercise two-service receipt publication with fixed synthetic comment identities."""

import json
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from aotg.autodev.coordinator import Result
from aotg.autodev.remote_results import (
    BOOTSTRAP_BODY,
    CommentObservation,
    CommentTarget,
    RemoteResultSlot,
)
from aotg.autodev.result_slot import LocalResultSlot, ResultSlotError

BASE = "1" * 40
HEAD = "2" * 40
TIME = "2026-01-01T00:00:00+00:00"
GITHUB = CommentTarget("github", "uobnnisiuk/AOTG#3", 3, 44, 55)
LINEAR = CommentTarget(
    "linear", "UOB-58", "10000000-0000-4000-8000-000000000000",
    "20000000-0000-4000-8000-000000000000", "30000000-0000-4000-8000-000000000000",
)
CLAIM = Result("claim_started", "reserved", "UOB-50", TIME, BASE).redacted()
DRAFT = Result("draft_pr", "draft-verified", "UOB-50", TIME, BASE, HEAD, 8).redacted()


class FixedComments:
    def __init__(self):
        self.comments = {
            target: CommentObservation(target, BOOTSTRAP_BODY) for target in (GITHUB, LINEAR)
        }
        self.attempts = []
        self.fail = None
        self.commit_before_failure = False

    def read(self, target):
        return self.comments[target]

    def update(self, target, body, *, expected_body):
        self.attempts.append(target)
        if self.comments[target].body != expected_body:
            raise ValueError("Stale update")
        if self.fail == target and not self.commit_before_failure:
            raise TimeoutError("Response unavailable")
        self.comments[target] = CommentObservation(target, body)
        if self.fail == target:
            raise TimeoutError("Response unavailable")


class RemoteResultSlotTests(TestCase):
    def setUp(self):
        root = TemporaryDirectory()
        self.addCleanup(root.cleanup)
        directory = Path(root.name).resolve() / "results"
        directory.mkdir(mode=0o700)
        self.local = LocalResultSlot(directory / "latest.json")
        self.transport = FixedComments()
        self.slot = RemoteResultSlot(self.local, GITHUB, LINEAR, self.transport)

    def test_updates_two_exact_slots_in_order_and_rechecks_both(self):
        self.slot.write(CLAIM)
        self.assertEqual(self.transport.attempts, [GITHUB, LINEAR])
        self.assertEqual(self.slot.read(), CLAIM)
        self.slot.write(DRAFT)
        self.assertEqual(self.slot.read(), DRAFT)
        self.slot.write(DRAFT)
        self.assertEqual(self.transport.attempts, [GITHUB, LINEAR, GITHUB, LINEAR])
        for observation in self.transport.comments.values():
            marker, blank, fence, data, closing = observation.body.splitlines()
            self.assertEqual((marker, blank, fence, closing), (BOOTSTRAP_BODY, "", "```json", "```"))
            self.assertEqual(json.loads(data), DRAFT)
        self.assertFalse(self.slot.pending.exists())

    def test_rejects_wrong_targets_and_identity_before_any_write(self):
        with self.assertRaises(ResultSlotError):
            RemoteResultSlot(self.local, replace(GITHUB, issue_id=True), LINEAR, self.transport)
        with self.assertRaises(ResultSlotError):
            RemoteResultSlot(self.local, GITHUB, replace(LINEAR, issue="UOB-59"), self.transport)
        for altered in (
            replace(GITHUB, issue_id=4), replace(GITHUB, comment_id=45),
            replace(GITHUB, author_id=56), replace(GITHUB, issue="other/AOTG#3"),
        ):
            with self.subTest(altered=altered), self.assertRaises(ResultSlotError):
                self.transport.comments[GITHUB] = CommentObservation(altered, BOOTSTRAP_BODY)
                self.slot.write(CLAIM)
        self.assertEqual(self.transport.attempts, [])

    def test_protects_other_comment_content_and_unredacted_values(self):
        self.transport.comments[LINEAR] = CommentObservation(LINEAR, "Human audit comment")
        with self.assertRaises(ResultSlotError):
            self.slot.write(CLAIM)
        self.transport.comments[LINEAR] = CommentObservation(LINEAR, BOOTSTRAP_BODY)
        with self.assertRaises(ResultSlotError):
            self.slot.write({**CLAIM, "private": "arbitrary input"})
        with self.assertRaises(ResultSlotError):
            self.slot.write({**CLAIM, "reason": "arbitrary input"})
        self.assertEqual(self.transport.attempts, [])
        self.assertFalse(self.slot.pending.exists())

    def test_first_timeout_is_never_retried_and_pending_survives_reopen(self):
        self.transport.fail = GITHUB
        with self.assertRaisesRegex(ResultSlotError, "Unconfirmed"):
            self.slot.write(CLAIM)
        self.assertEqual(self.transport.attempts, [GITHUB])
        self.assertEqual(json.loads(self.slot.pending.read_bytes()), CLAIM)
        restarted = RemoteResultSlot(self.local, GITHUB, LINEAR, self.transport)
        for action in (restarted.read, lambda: restarted.write(CLAIM)):
            with self.assertRaisesRegex(ResultSlotError, "needs inspection"):
                action()
        self.assertEqual(self.transport.attempts, [GITHUB])

    def test_can_verify_that_a_timed_out_update_was_applied(self):
        self.transport.fail = GITHUB
        self.transport.commit_before_failure = True
        self.slot.write(CLAIM)
        self.assertEqual(self.transport.attempts, [GITHUB, LINEAR])
        self.assertEqual(self.slot.read(), CLAIM)
        self.assertFalse(self.slot.pending.exists())

    def test_partial_success_leaves_pending_and_preserves_prior_local_receipt(self):
        self.slot.write(CLAIM)
        self.transport.fail = LINEAR
        with self.assertRaisesRegex(ResultSlotError, "Unconfirmed"):
            self.slot.write(DRAFT)
        self.assertEqual(self.transport.attempts, [GITHUB, LINEAR, GITHUB, LINEAR])
        self.assertIn("draft-verified", self.transport.comments[GITHUB].body)
        self.assertIn("claim_started", self.transport.comments[LINEAR].body)
        self.assertEqual(self.local.read(), CLAIM)
        with self.assertRaisesRegex(ResultSlotError, "needs inspection"):
            self.slot.write(DRAFT)
        self.assertEqual(len(self.transport.attempts), 4)

    def test_write_refuses_stale_local_result_and_read_detects_external_edit(self):
        self.slot.write(CLAIM)
        self.slot.write(DRAFT)
        with self.assertRaises(ResultSlotError):
            self.slot.write(CLAIM)
        self.transport.comments[GITHUB] = CommentObservation(GITHUB, BOOTSTRAP_BODY)
        with self.assertRaisesRegex(ResultSlotError, "differs"):
            self.slot.read()
        self.assertEqual(len(self.transport.attempts), 4)
