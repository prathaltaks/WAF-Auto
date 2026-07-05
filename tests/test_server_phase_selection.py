import unittest

from server import build_phase_flags


class PhaseFlagsTest(unittest.TestCase):
    def test_all_selected_phases_enable_every_phase(self):
        flags = build_phase_flags([1, 2, 3, 4, 5, 6, 7])
        self.assertTrue(flags["phase1_preflight"])
        self.assertTrue(flags["phase2_config"])
        self.assertTrue(flags["phase3_rules"])
        self.assertTrue(flags["phase4_attacks"])
        self.assertTrue(flags["phase5_features"])
        self.assertTrue(flags["phase6_incidents"])
        self.assertTrue(flags["phase7_report"])

    def test_single_phase_only_enables_that_phase(self):
        flags = build_phase_flags([4])
        self.assertFalse(flags["phase1_preflight"])
        self.assertFalse(flags["phase2_config"])
        self.assertFalse(flags["phase3_rules"])
        self.assertTrue(flags["phase4_attacks"])
        self.assertFalse(flags["phase5_features"])
        self.assertFalse(flags["phase6_incidents"])
        self.assertTrue(flags["phase7_report"])


if __name__ == "__main__":
    unittest.main()
