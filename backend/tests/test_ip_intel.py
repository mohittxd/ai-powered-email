"""
Unit tests — Phase 6: IP Intelligence and Geolocation.
"""
import os
import sys
from unittest.mock import patch, MagicMock
import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from services.geoip import get_geolocation, is_valid_public_ip as geo_valid_ip
from services.threat_intel import get_threat_intel, is_valid_public_ip as threat_valid_ip
import geoip2.errors


class TestIPValidation:
    def test_valid_public(self):
        assert geo_valid_ip("8.8.8.8") is True
        assert threat_valid_ip("8.8.8.8") is True

    def test_private(self):
        assert geo_valid_ip("192.168.1.1") is False
        assert threat_valid_ip("10.0.0.1") is False
        assert threat_valid_ip("127.0.0.1") is False

    def test_invalid(self):
        assert geo_valid_ip("not_an_ip") is False
        assert threat_valid_ip(None) is False


class TestGeolocation:
    @patch("services.geoip.GEOIP_AVAILABLE", False)
    def test_no_library(self):
        res = get_geolocation("8.8.8.8")
        assert res["status"] == "unavailable"

    @patch("services.geoip.GEOIP_AVAILABLE", True)
    @patch("services.geoip.settings.maxmind_db_path", None)
    def test_no_db_path(self):
        res = get_geolocation("8.8.8.8")
        assert res["status"] == "unavailable"

    @patch("services.geoip.GEOIP_AVAILABLE", True)
    @patch("services.geoip.settings.maxmind_db_path", "/fake/path")
    @patch("os.path.exists", return_value=False)
    def test_missing_db_file(self, _):
        res = get_geolocation("8.8.8.8")
        assert res["status"] == "unavailable"

    def test_invalid_ip(self):
        res = get_geolocation("127.0.0.1")
        assert res["status"] == "unavailable"

    @patch("services.geoip.GEOIP_AVAILABLE", True)
    @patch("services.geoip.settings.maxmind_db_path", "/fake/path")
    @patch("os.path.exists", return_value=True)
    @patch("geoip2.database.Reader")
    def test_lookup_success(self, mock_reader_class, _):
        mock_reader = MagicMock()
        mock_reader_class.return_value.__enter__.return_value = mock_reader
        
        mock_response = MagicMock()
        mock_response.country.iso_code = "US"
        mock_response.subdivisions.most_specific.iso_code = "CA"
        mock_response.city.name = "San Jose"
        mock_response.location.latitude = 37.3393
        mock_response.location.longitude = -121.8949
        mock_reader.city.return_value = mock_response

        res = get_geolocation("8.8.8.8")
        assert res["status"] == "success"
        assert res["country"] == "US"
        assert res["city"] == "San Jose"

    @patch("services.geoip.GEOIP_AVAILABLE", True)
    @patch("services.geoip.settings.maxmind_db_path", "/fake/path")
    @patch("os.path.exists", return_value=True)
    @patch("geoip2.database.Reader")
    def test_ip_not_found(self, mock_reader_class, _):
        mock_reader = MagicMock()
        mock_reader_class.return_value.__enter__.return_value = mock_reader
        mock_reader.city.side_effect = geoip2.errors.AddressNotFoundError("Not found")

        res = get_geolocation("8.8.8.8")
        assert res["status"] == "not_found"


class TestThreatIntel:
    def test_invalid_ip(self):
        res = get_threat_intel("192.168.1.1")
        assert res["status"] == "unavailable"
        assert res["reputation"] == "unknown"

    @patch("services.threat_intel.settings.abuseipdb_api_key", None)
    def test_no_api_key(self):
        res = get_threat_intel("8.8.8.8")
        assert res["status"] == "unavailable"
        assert res["reputation"] == "unknown"

    @patch("services.threat_intel.settings.abuseipdb_api_key", "secret")
    @patch("requests.get")
    def test_api_success_clean(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"abuseConfidenceScore": 0}}
        mock_get.return_value = mock_resp

        res = get_threat_intel("8.8.8.8")
        assert res["status"] == "success"
        assert res["abuse_confidence"] == 0
        assert res["reputation"] == "clean"

    @patch("services.threat_intel.settings.abuseipdb_api_key", "secret")
    @patch("requests.get")
    def test_api_success_malicious(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"abuseConfidenceScore": 100}}
        mock_get.return_value = mock_resp

        res = get_threat_intel("8.8.8.8")
        assert res["status"] == "success"
        assert res["abuse_confidence"] == 100
        assert res["reputation"] == "malicious"

    @patch("services.threat_intel.settings.abuseipdb_api_key", "secret")
    @patch("requests.get", side_effect=requests.RequestException("Timeout"))
    def test_api_failure(self, mock_get):
        res = get_threat_intel("8.8.8.8")
        assert res["status"] == "unavailable"
        assert res["reputation"] == "unknown"
