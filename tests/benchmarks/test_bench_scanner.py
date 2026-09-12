"""APKRadar benchmarks."""
import pytest
from apkradar.scanner import (
    ScanResult,
    TRACKER_SIGNATURES,
    SENSITIVE_PERMISSIONS,
    EXTRA_EU_TRANSFERS,
)


def test_bench_tracker_signatures_lookup(benchmark):
    def lookup():
        return [k for k in TRACKER_SIGNATURES if "google" in k]
    benchmark(lookup)


def test_bench_sensitive_permissions_lookup(benchmark):
    def lookup():
        return [k for k in SENSITIVE_PERMISSIONS if "LOCATION" in k]
    benchmark(lookup)


def test_bench_scan_result_score(benchmark):
    result = ScanResult(apk_path="test.apk")
    benchmark(lambda: result.score)


def test_bench_extra_eu_lookup(benchmark):
    def lookup():
        return [v for k, v in EXTRA_EU_TRANSFERS.items() if "USA" in v]
    benchmark(lookup)
