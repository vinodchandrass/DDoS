"""Unit tests for arithmetic consistency; not source-data replication."""
import json
import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]

class TestFrozenAggregates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=json.loads((ROOT/"results"/"published_aggregate_metrics.json").read_text())

    def test_confusion_matrices(self):
        for name in ("internal_validation","external_TCP_SYN"):
            with self.subTest(name=name):
                m=self.data[name]
                self.assertEqual(sum(m[k] for k in ("TP","FN","FP","TN")),m["n"])
                self.assertGreater(m["TP"]+m["FN"],0)
                self.assertGreater(m["FP"]+m["TN"],0)

    def test_internal_detection(self):
        m=self.data["internal_validation"]
        self.assertAlmostEqual(m["TP"]/(m["TP"]+m["FN"]), 9683/10269, places=12)

    def test_external_detection(self):
        m=self.data["external_TCP_SYN"]
        self.assertEqual(m["TP"],1)
        self.assertEqual(m["TP"]+m["FN"],3554)

    def test_segmentation_counts(self):
        x=self.data["segmentation_diagnostic"]
        self.assertEqual((x["short_flow_matched"],x["short_flow_total"]),(3272,3272))
        self.assertEqual((x["long_flow_matched"],x["long_flow_total"]),(0,281))

if __name__=="__main__":
    unittest.main()
