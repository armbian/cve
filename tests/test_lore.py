"""Tests for the stable-list lookup."""
import unittest

from fasttrack import lore


class TestLore(unittest.TestCase):
    def test_prerequisite_in_series_does_not_count(self):
        fix = "1" * 40
        dep = f"Subject: [PATCH 6.1.y 1/2] foo: refactor\n\n[ Upstream commit {'2' * 40} ]\n\nStable-dep-of: {fix[:12]} (\"foo: fix\")\n"
        own = f"Subject: [PATCH 6.1.y 2/2] foo: fix\n\n[ Upstream commit {fix} ]\n\n"
        gkh = f"Subject: [PATCH 6.1 12/80] foo: fix\n\ncommit {fix} upstream.\n\n"
        self.assertFalse(lore.cites_as_upstream(dep.replace(fix[:12], fix), fix))
        self.assertTrue(lore.cites_as_upstream(own, fix))
        self.assertTrue(lore.cites_as_upstream(gkh, fix))
        self.assertTrue(lore.cites_as_upstream(f"Upstream commit {fix}\n", fix))

if __name__ == "__main__":
    unittest.main()
