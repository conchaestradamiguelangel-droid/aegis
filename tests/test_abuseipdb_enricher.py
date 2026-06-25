"""Tests for core/abuseipdb_enricher.py"""
import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.abuseipdb_enricher import enrich_ips, _empty


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _mock_session(status=200, data=None):
    mock_resp = AsyncMock()
    mock_resp.status = status
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)
    mock_resp.json = AsyncMock(return_value={"data": data or {}})
    mock_s = AsyncMock()
    mock_s.get = MagicMock(return_value=mock_resp)
    mock_s.__aenter__ = AsyncMock(return_value=mock_s)
    mock_s.__aexit__ = AsyncMock(return_value=False)
    return mock_s


class TestAbuseIPDBEnricher(unittest.TestCase):

    def setUp(self):
        os.environ.pop("ABUSEIPDB_API_KEY", None)

    def test_no_api_key_returns_no_enrichment(self):
        result = _run(enrich_ips(["1.2.3.4"]))
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0]["enriched"])
        self.assertEqual(result[0]["reason"], "no_api_key")

    def test_empty_ip_list(self):
        self.assertEqual(_run(enrich_ips([])), [])

    def test_multiple_ips_no_key(self):
        result = _run(enrich_ips(["1.1.1.1", "8.8.8.8", "9.9.9.9"]))
        self.assertEqual(len(result), 3)
        for r in result:
            self.assertFalse(r["enriched"])

    def test_empty_helper_structure(self):
        r = _empty("10.0.0.1", "test_reason")
        self.assertEqual(r["ip"], "10.0.0.1")
        self.assertFalse(r["enriched"])
        self.assertEqual(r["reason"], "test_reason")

    def test_successful_enrichment(self):
        os.environ["ABUSEIPDB_API_KEY"] = "test_key_abc"
        data = {
            "abuseConfidenceScore": 87, "totalReports": 50, "numDistinctUsers": 12,
            "countryCode": "CN", "domain": "evil.example.com", "isp": "Evil ISP",
            "isTor": False, "lastReportedAt": "2024-01-01T00:00:00+00:00", "usageType": "DCH",
        }
        with patch("aiohttp.ClientSession", return_value=_mock_session(200, data)):
            result = _run(enrich_ips(["1.2.3.4"]))
        r = result[0]
        self.assertTrue(r["enriched"])
        self.assertEqual(r["abuse_confidence_score"], 87)
        self.assertEqual(r["country_code"], "CN")
        self.assertIn("checked_at", r)

    def test_rate_limit_returns_empty(self):
        os.environ["ABUSEIPDB_API_KEY"] = "test_key_abc"
        with patch("aiohttp.ClientSession", return_value=_mock_session(429)):
            result = _run(enrich_ips(["1.2.3.4"]))
        self.assertFalse(result[0]["enriched"])
        self.assertEqual(result[0]["reason"], "rate_limit")

    def test_http_error_returns_empty(self):
        os.environ["ABUSEIPDB_API_KEY"] = "test_key_abc"
        with patch("aiohttp.ClientSession", return_value=_mock_session(403)):
            result = _run(enrich_ips(["1.2.3.4"]))
        self.assertFalse(result[0]["enriched"])
        self.assertEqual(result[0]["reason"], "http_403")

    def test_exception_handled_gracefully(self):
        os.environ["ABUSEIPDB_API_KEY"] = "test_key_abc"
        mock_s = AsyncMock()
        mock_s.get = MagicMock(side_effect=Exception("Network error"))
        mock_s.__aenter__ = AsyncMock(return_value=mock_s)
        mock_s.__aexit__ = AsyncMock(return_value=False)
        with patch("aiohttp.ClientSession", return_value=mock_s):
            result = _run(enrich_ips(["1.2.3.4"]))
        self.assertFalse(result[0]["enriched"])
        self.assertEqual(result[0]["reason"], "error")

    def test_tor_flag_detected(self):
        os.environ["ABUSEIPDB_API_KEY"] = "test_key_abc"
        data = {
            "abuseConfidenceScore": 100, "totalReports": 999, "numDistinctUsers": 500,
            "countryCode": "DE", "domain": "", "isp": "TOR Project",
            "isTor": True, "lastReportedAt": "", "usageType": "",
        }
        with patch("aiohttp.ClientSession", return_value=_mock_session(200, data)):
            result = _run(enrich_ips(["5.6.7.8"]))
        self.assertTrue(result[0]["is_tor"])
        self.assertEqual(result[0]["abuse_confidence_score"], 100)

    def test_multiple_ips_concurrent_mock(self):
        os.environ["ABUSEIPDB_API_KEY"] = "test_key_abc"
        data = {"abuseConfidenceScore": 0, "totalReports": 0, "numDistinctUsers": 0, "countryCode": "US", "domain": "", "isp": "", "isTor": False, "lastReportedAt": "", "usageType": ""}
        with patch("aiohttp.ClientSession", return_value=_mock_session(200, data)):
            result = _run(enrich_ips(["1.1.1.1", "8.8.8.8", "9.9.9.9"]))
        self.assertEqual(len(result), 3)
        for r in result:
            self.assertTrue(r["enriched"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
