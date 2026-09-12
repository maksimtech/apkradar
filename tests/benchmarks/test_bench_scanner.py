"""CookieRadar benchmarks — instrumentation mode only."""
import pytest
from apkradar.scanner import (
    ScanResult,
    TRACKER_SIGNATURES,
    SENSITIVE_PERMISSIONS,
    EXTRA_EU_TRANSFERS,
    TrackerFound,
)


def test_bench_is_tracker_known(benchmark):
    """Benchmark tracker signature lookup — known tracker."""
    def lookup():
        return "com.google.android.gms.analytics" in TRACKER_SIGNATURES
    benchmark(lookup)


def test_bench_is_tracker_unknown(benchmark):
    """Benchmark tracker signature lookup — unknown domain."""
    def lookup():
        return "com.example.cleanapp" in TRACKER_SIGNATURES
    benchmark(lookup)


def test_bench_scan_result_construction(benchmark):
    """Benchmark ScanResult construction."""
    def construct():
        return ScanResult(apk_path="test.apk")
    benchmark(construct)


def test_bench_scan_result_score_computation(benchmark):
    """Benchmark score computation with trackers."""
    result = ScanResult(apk_path="test.apk")
    result.trackers = [
        TrackerFound(package=f"com.tracker{i}", name=f"Tracker {i}")
        for i in range(5)
    ]
    benchmark(lambda: result.score)
