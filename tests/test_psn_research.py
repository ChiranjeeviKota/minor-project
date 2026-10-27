"""Unit tests for the additive PSN research utilities."""
import unittest
from psn_research import (
    cohort_summary, compare_patients, csv_template, network_metrics,
    profile_summary, quality_audit, report_payload, valid_iso_date,
)

DOMAINS = ["memory", "attention", "executive", "language", "visuospatial", "processing_speed", "orientation"]

def patient(pid, code, diagnosis="MCI", base=60):
    row = {"id": pid, "patient_code": code, "age": 70 + pid, "sex": "Unknown",
           "diagnosis": diagnosis, "mmse": 24, "moca": 22, "visit": 1, "visit_date": "2026-01-01"}
    row.update({key: base + index for index, key in enumerate(DOMAINS)})
    return row

def similarity(left, right):
    gap = sum(abs(float(left[d]) - float(right[d])) for d in DOMAINS) / len(DOMAINS)
    return max(0, 100 - gap)

class DateValidationTests(unittest.TestCase):
    def test_iso_date(self):
        self.assertTrue(valid_iso_date("2026-10-28"))
    def test_non_iso_date(self):
        self.assertFalse(valid_iso_date("28/10/2026"))
        self.assertFalse(valid_iso_date("not-a-date"))
        self.assertFalse(valid_iso_date(None))

class ProfileTests(unittest.TestCase):
    def test_summary_statistics(self):
        result = profile_summary([patient(1, "A", base=10), patient(2, "B", base=20)], DOMAINS)
        self.assertEqual(result["memory"]["mean"], 15)
        self.assertEqual(result["memory"]["median"], 15)
        self.assertEqual(result["memory"]["min"], 10)
        self.assertEqual(result["memory"]["max"], 20)
        self.assertEqual(result["memory"]["count"], 2)
    def test_empty_profile_has_null_values(self):
        result = profile_summary([], DOMAINS)
        self.assertIsNone(result["memory"]["mean"])
        self.assertIsNone(result["memory"]["median"])
        self.assertEqual(result["memory"]["count"], 0)
    def test_nan_is_not_counted(self):
        row = patient(1, "A")
        row["memory"] = float("nan")
        self.assertEqual(profile_summary([row], DOMAINS)["memory"]["count"], 0)
    def test_infinity_is_not_counted(self):
        row = patient(1, "A")
        row["memory"] = float("inf")
        self.assertEqual(profile_summary([row], DOMAINS)["memory"]["count"], 0)

class CohortTests(unittest.TestCase):
    def test_cohort_counts_and_means(self):
        rows = [patient(1, "A", "Healthy", 80), patient(2, "B", "Healthy", 60), patient(3, "C", "MCI", 40)]
        result = cohort_summary(rows, DOMAINS)
        groups = {x["diagnosis"]: x for x in result["cohorts"]}
        self.assertEqual(result["total_patients"], 3)
        self.assertEqual(groups["Healthy"]["count"], 2)
        self.assertEqual(groups["Healthy"]["mean_mmse"], 24)
        self.assertEqual(groups["MCI"]["count"], 1)
    def test_missing_cohort_label(self):
        row = patient(1, "A")
        row["diagnosis"] = None
        self.assertEqual(cohort_summary([row], DOMAINS)["cohorts"][0]["diagnosis"], "Unspecified")
    def test_empty_cohort_summary(self):
        result = cohort_summary([], DOMAINS)
        self.assertEqual(result["total_patients"], 0)
        self.assertEqual(result["cohorts"], [])

class QualityTests(unittest.TestCase):
    def test_clean_data_passes(self):
        result = quality_audit([patient(1, "A")], DOMAINS)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["error_count"], 0)
    def test_missing_field_warning(self):
        row = patient(1, "A")
        row["memory"] = None
        result = quality_audit([row], DOMAINS)
        self.assertGreater(result["missing_values_count"], 0)
        self.assertTrue(any(x["type"] == "missing_fields" for x in result["findings"]))
    def test_score_bounds_are_enforced(self):
        row = patient(1, "A")
        row["mmse"], row["attention"] = 31, -2
        result = quality_audit([row], DOMAINS)
        self.assertEqual(result["status"], "review_required")
        self.assertGreaterEqual(result["out_of_range_values_count"], 2)
    def test_non_numeric_score_is_flagged(self):
        row = patient(1, "A")
        row["moca"] = "unknown"
        result = quality_audit([row], DOMAINS)
        self.assertGreater(result["out_of_range_values_count"], 0)
    def test_duplicate_codes_are_reported(self):
        result = quality_audit([patient(1, "DUP"), patient(2, "DUP")], DOMAINS)
        self.assertEqual(result["duplicate_patient_codes"], ["DUP"])
        self.assertTrue(any(x["type"] == "duplicate_patient_code" for x in result["findings"]))
    def test_unusual_cohort_is_informational(self):
        result = quality_audit([patient(1, "A", "Other")], DOMAINS)
        self.assertTrue(any(x["type"] == "unexpected_cohort" for x in result["findings"]))
    def test_invalid_date_is_reported(self):
        row = patient(1, "A")
        row["visit_date"] = "28/10/2026"
        result = quality_audit([row], DOMAINS)
        self.assertTrue(any(x["type"] == "invalid_date" for x in result["findings"]))
    def test_empty_dataset_passes_without_errors(self):
        result = quality_audit([], DOMAINS)
        self.assertEqual(result["total_patients"], 0)
        self.assertEqual(result["error_count"], 0)

class NetworkTests(unittest.TestCase):
    def test_edge_count_and_density(self):
        rows = [patient(1, "A", base=60), patient(2, "B", base=60), patient(3, "C", base=10)]
        result = network_metrics(rows, similarity, 90)
        self.assertEqual(result["nodes"], 3)
        self.assertEqual(result["edge_count"], 1)
        self.assertAlmostEqual(result["density"], 1 / 3, places=4)
    def test_empty_network(self):
        result = network_metrics([], similarity, 85)
        self.assertEqual(result["nodes"], 0)
        self.assertEqual(result["edge_count"], 0)
        self.assertEqual(result["density"], 0)
    def test_isolated_nodes_are_components(self):
        rows = [patient(1, "A", base=10), patient(2, "B", base=10), patient(3, "C", base=90)]
        result = network_metrics(rows, similarity, 99)
        self.assertEqual(sorted(c["size"] for c in result["components"]), [1, 2])
    def test_invalid_threshold_rejected(self):
        with self.assertRaises(ValueError):
            network_metrics([patient(1, "A")], similarity, 101)
    def test_single_node_centrality_is_zero(self):
        result = network_metrics([patient(1, "A")], similarity, 0)
        self.assertEqual(result["top_degree"][0]["degree_centrality"], 0)
    def test_threshold_changes_edge_count(self):
        rows = [patient(1, "A", base=50), patient(2, "B", base=50)]
        self.assertGreaterEqual(network_metrics(rows, similarity, 50)["edges"],
                                network_metrics(rows, similarity, 99)["edges"])

class ComparisonTests(unittest.TestCase):
    def test_largest_gap_first(self):
        left, right = patient(1, "A"), patient(2, "B")
        right["memory"] = left["memory"] + 25
        result = compare_patients([left, right], [1, 2], DOMAINS)
        self.assertEqual(result["domains"][0]["domain"], "memory")
        self.assertEqual(result["domains"][0]["range"], 25)
    def test_requires_two_records(self):
        with self.assertRaises(ValueError):
            compare_patients([patient(1, "A")], [1], DOMAINS)
    def test_eight_record_limit(self):
        rows = [patient(i, "P" + str(i)) for i in range(1, 10)]
        with self.assertRaises(ValueError):
            compare_patients(rows, list(range(1, 10)), DOMAINS)
    def test_duplicate_ids_rejected(self):
        with self.assertRaises(ValueError):
            compare_patients([patient(1, "A")], [1, 1], DOMAINS)
    def test_missing_id_reported(self):
        with self.assertRaises(LookupError):
            compare_patients([patient(1, "A")], [1, 99], DOMAINS)
    def test_values_preserve_selected_patient_order(self):
        left, right = patient(1, "A", base=10), patient(2, "B", base=20)
        result = compare_patients([left, right], [2, 1], DOMAINS)
        self.assertEqual([p["patient_code"] for p in result["patients"]], ["B", "A"])

class ExportTests(unittest.TestCase):
    def test_csv_template_fields_and_example_marker(self):
        data = csv_template(DOMAINS)
        self.assertIn("patient_code,age,sex,diagnosis,mmse,moca", data)
        self.assertIn("EXAMPLE-REMOVE-ME", data)
        self.assertIn("processing_speed", data)
    def test_report_has_version_quality_and_disclaimer(self):
        report = report_payload([patient(1, "A"), patient(2, "B")], DOMAINS, 85, similarity)
        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(report["summary"]["patient_count"], 2)
        self.assertIn("quality", report)
        self.assertIn("network", report)
        self.assertIn("not a diagnosis", report["disclaimer"].lower())

if __name__ == "__main__":
    unittest.main()
