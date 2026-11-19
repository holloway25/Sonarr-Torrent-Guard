"""Timing regressions use fake senders; no production transport is called."""

import time
import unittest
from unittest.mock import patch

import production
from production import wait_for_event_boundary as actual_wait, event_boundary_reached as actual_reached
from safety import SafetyError


class TimingTests(unittest.TestCase):
    def test_boundary_wait_is_bounded_when_wall_clock_stalls(self):
        elapsed = [0.0]
        def sleep(amount):
            elapsed[0] += amount
        with patch("production.event_boundary_reached", actual_reached), patch(
                "production.time.time", return_value=100.5), patch(
                "production.time.monotonic", side_effect=lambda: elapsed[0]), patch(
                "production.time.sleep", side_effect=sleep):
            with self.assertRaisesRegex(SafetyError, "dispatch_clock_unavailable"):
                actual_wait(100.5)
        self.assertLessEqual(elapsed[0], 1.11)

    def test_boundary_wait_advances_to_next_second_without_rounding_intent_down(self):
        elapsed = [0.0]
        def sleep(amount):
            elapsed[0] += amount
        with patch("production.event_boundary_reached", actual_reached), patch(
                "production.time.time", side_effect=lambda: 100.8 + elapsed[0]), patch(
                "production.time.monotonic", side_effect=lambda: elapsed[0]), patch(
                "production.time.sleep", side_effect=sleep):
            self.assertEqual(actual_wait(100.8), 101)
        self.assertGreaterEqual(elapsed[0], .2)
        self.assertLess(elapsed[0], .4)

    def test_invalid_dispatch_clock_is_refused(self):
        for stamp in (None, True, 0, float("nan"), float("inf")):
            with self.subTest(stamp=stamp), self.assertRaises(SafetyError):
                actual_wait(stamp)

if __name__ == "__main__":
    unittest.main()
