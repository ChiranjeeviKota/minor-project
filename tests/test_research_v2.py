"""Regression tests for the Patient Similarity Network Research Toolkit v2."""
import unittest
from psn_research import (
    cognitive_correlations, domain_distributions, export_patients_csv,
    filtered_patients, iqr_outliers, pearson_correlation, preview_csv_import,
    shortest_similarity_path,
)

DOMAINS = ["memory", "attention", "executive", "language", "visuospatial",
           "processing_speed", "orientation"]

def patient(pid, code, diagnosis="MCI", base=40, age=65, mmse=24):
    row = {"id": pid, "patient_code": code, "diagnosis": diagnosis,
           "age": age, "sex": "Unknown", "mmse": mmse, "moca": 22,
           "visit": 1, "visit_date": "2026-01-01"}
    row.update({domain: base + i for i, domain in enumerate(DOMAINS)})
    return row

def similarity(a, b):
    distance = sum(abs(a[d] - b[d]) for d in DOMAINS) / len(DOMAINS)
    return 100 - distance

def csv_header():
    return ",".join(["patient_code", "age", "sex", "diagnosis", "mmse", "moca", *DOMAINS])

def csv_row(code="P-001", age=70, mmse=24, memory=50):
    values = [code, age, "Unknown", "MCI", mmse, 22, memory, 51, 52, 53, 54, 55, 56]
    return ",".join(map(str, values))

class FilteredPatientTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            patient(1, "PSN-A", "Healthy", age=60, mmse=29),
            patient(2, "PSN-B", "MCI", age=72, mmse=24),
            patient(3, "CASE-C", "Alzheimer's", age=80, mmse=18),
            patient(4, "PSN-D", "MCI", age=75, mmse=21),
        ]

    def test_pagination_reports_total_and_more(self):
        result = filtered_patients(self.rows, limit=2, offset=0)
        self.assertEqual(result["total"], 4)
        self.assertEqual(len(result["patients"]), 2)
        self.assertTrue(result["has_more"])

    def test_last_page_has_no_more(self):
        result = filtered_patients(self.rows, limit=2, offset=2)
        self.assertFalse(result["has_more"])
        self.assertEqual(len(result["patients"]), 2)

    def test_query_matches_code_case_insensitively(self):
        result = filtered_patients(self.rows, q="psn-a")
        self.assertEqual([p["id"] for p in result["patients"]], [1])

    def test_query_can_match_numeric_id(self):
        result = filtered_patients(self.rows, q="3")
        self.assertIn(3, [p["id"] for p in result["patients"]])

    def test_diagnosis_filter(self):
        result = filtered_patients(self.rows, diagnosis="MCI")
        self.assertEqual(result["total"], 2)

    def test_age_and_score_filters_combine(self):
        result = filtered_patients(self.rows, min_age=70, max_age=76,
                                   min_mmse=20, max_mmse=25)
        self.assertEqual([p["id"] for p in result["patients"]], [2, 4])

    def test_descending_sort(self):
        result = filtered_patients(self.rows, sort_by="mmse", order="desc")
        self.assertEqual(result["patients"][0]["id"], 1)

    def test_unknown_sort_rejected(self):
        with self.assertRaises(ValueError):
            filtered_patients(self.rows, sort_by="password")

    def test_invalid_pagination_rejected(self):
        for kwargs in ({"limit": 0}, {"limit": 201}, {"offset": -1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                filtered_patients(self.rows, **kwargs)

    def test_reversed_age_bounds_rejected(self):
        with self.assertRaises(ValueError):
            filtered_patients(self.rows, min_age=90, max_age=40)

    def test_empty_search_is_valid(self):
        self.assertEqual(filtered_patients([], limit=10)["total"], 0)

class CorrelationTests(unittest.TestCase):
    def test_perfect_positive_correlation(self):
        self.assertEqual(pearson_correlation([1, 2, 3], [2, 4, 6]), 1.0)

    def test_perfect_negative_correlation(self):
        self.assertEqual(pearson_correlation([1, 2, 3], [6, 4, 2]), -1.0)

    def test_constant_values_return_none(self):
        self.assertIsNone(pearson_correlation([1, 1, 1], [2, 3, 4]))

    def test_one_observation_returns_none(self):
        self.assertIsNone(pearson_correlation([1], [1]))

    def test_missing_and_nan_pairs_are_skipped(self):
        self.assertEqual(pearson_correlation([1, None, 3, float("nan")],
                                             [2, 7, 6, 9]), 1.0)

    def test_matrix_contains_sample_counts(self):
        rows = [patient(1, "A", base=10), patient(2, "B", base=20)]
        result = cognitive_correlations(rows, DOMAINS)
        self.assertEqual(result["sample_counts"]["memory"]["attention"], 2)
        self.assertEqual(result["matrix"]["memory"]["memory"], 1.0)

class DistributionAndOutlierTests(unittest.TestCase):
    def test_distribution_bins_cover_valid_score_range(self):
        rows = [patient(1, "A", base=0), patient(2, "B", base=20),
                patient(3, "C", base=80)]
        result = domain_distributions(rows, DOMAINS, bin_width=20)
        bins = result["domains"]["memory"]["bins"]
        self.assertEqual(sum(x["count"] for x in bins), 3)
        self.assertEqual(len(bins), 5)

    def test_invalid_bin_width_rejected(self):
        with self.assertRaises(ValueError):
            domain_distributions([], DOMAINS, bin_width=13)

    def test_distribution_ignores_invalid_values(self):
        row = patient(1, "A")
        row["memory"] = float("nan")
        result = domain_distributions([row], DOMAINS)
        self.assertEqual(result["domains"]["memory"]["count"], 0)

    def test_iqr_screen_flags_extreme_score(self):
        rows = [patient(i, f"P-{i}", base=50) for i in range(1, 6)]
        rows[-1]["memory"] = 100
        result = iqr_outliers(rows, ["memory"])
        self.assertGreaterEqual(result["outlier_count"], 1)
        self.assertTrue(any(x["patient_code"] == "P-5" for x in result["findings"]))

    def test_iqr_screen_explains_small_samples(self):
        result = iqr_outliers([patient(1, "A")], ["memory"])
        self.assertEqual(result["outlier_count"], 0)
        self.assertEqual(result["skipped_domains"][0]["valid_count"], 1)

class SimilarityPathTests(unittest.TestCase):
    def test_source_equals_target_has_zero_hops(self):
        result = shortest_similarity_path([patient(1, "A")], similarity, 1, 1)
        self.assertEqual(result["hops"], 0)
        self.assertEqual(result["path"], [1])

    def test_direct_path_has_one_hop(self):
        rows = [patient(1, "A", base=40), patient(2, "B", base=40)]
        result = shortest_similarity_path(rows, similarity, 1, 2, threshold=90)
        self.assertTrue(result["found"])
        self.assertEqual(result["hops"], 1)

    def test_missing_path_is_reported(self):
        rows = [patient(1, "A", base=0), patient(2, "B", base=90)]
        result = shortest_similarity_path(rows, similarity, 1, 2, threshold=99)
        self.assertFalse(result["found"])
        self.assertEqual(result["path"], [])

    def test_missing_patient_raises_lookup_error(self):
        with self.assertRaises(LookupError):
            shortest_similarity_path([patient(1, "A")], similarity, 1, 9)

    def test_invalid_threshold_rejected(self):
        with self.assertRaises(ValueError):
            shortest_similarity_path([patient(1, "A")], similarity, 1, 1, 101)

class CSVPreviewTests(unittest.TestCase):
    def test_valid_csv_can_be_previewed_without_writing(self):
        data = csv_header() + "\n" + csv_row()
        result = preview_csv_import(data, DOMAINS)
        self.assertTrue(result["can_import"])
        self.assertEqual(result["valid_rows"], 1)
        self.assertIn("does not write", result["note"])

    def test_duplicate_codes_are_flagged(self):
        data = csv_header() + "\n" + csv_row("DUP") + "\n" + csv_row("DUP")
        result = preview_csv_import(data, DOMAINS)
        self.assertFalse(result["can_import"])
        self.assertTrue(any("duplicated" in x["message"] for x in result["findings"]))

    def test_score_outside_range_is_flagged(self):
        data = csv_header() + "\n" + csv_row(mmse=31)
        result = preview_csv_import(data, DOMAINS)
        self.assertEqual(result["invalid_rows"], 1)

    def test_missing_headers_are_flagged(self):
        result = preview_csv_import("patient_code,age\nP1,70", DOMAINS)
        self.assertFalse(result["can_import"])
        self.assertTrue(result["missing_headers"])

    def test_empty_csv_rejected(self):
        with self.assertRaises(ValueError):
            preview_csv_import("  ", DOMAINS)

    def test_csv_size_limit_rejected(self):
        with self.assertRaises(ValueError):
            preview_csv_import("x" * 1_000_001, DOMAINS)

    def test_duplicate_header_names_are_flagged(self):
        result = preview_csv_import(csv_header() + ",age\n" + csv_row() + ",70", DOMAINS)
        self.assertTrue(result["duplicate_headers"])

    def test_preview_rows_are_limited_to_twenty(self):
        data = csv_header() + "\n" + "\n".join(csv_row(f"P-{i}") for i in range(25))
        result = preview_csv_import(data, DOMAINS)
        self.assertEqual(len(result["preview"]), 20)
        self.assertEqual(result["row_count"], 25)

    def test_csv_export_includes_expected_columns_and_values(self):
        content = export_patients_csv([patient(1, "A")], DOMAINS)
        self.assertIn("patient_code", content.splitlines()[0])
        self.assertIn("A", content.splitlines()[1])

if __name__ == "__main__":
    unittest.main()
