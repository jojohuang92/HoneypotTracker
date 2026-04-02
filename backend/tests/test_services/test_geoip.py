"""Tests for GeoIP lookup service."""

from unittest.mock import MagicMock, patch

from app.services.geoip import GeoIPLookup, GeoResult


class TestGeoIPLookup:
    def test_no_reader_returns_empty(self):
        with patch("app.services.geoip.HAS_MAXMIND", False):
            geo = GeoIPLookup("/nonexistent/path.mmdb")
        result = geo.lookup("8.8.8.8")
        assert result == GeoResult()

    def test_private_ip_returns_empty(self):
        geo = GeoIPLookup.__new__(GeoIPLookup)
        geo._reader = MagicMock()
        for ip in ["10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1"]:
            result = geo.lookup(ip)
            assert result == GeoResult()
            geo._reader.get.assert_not_called()

    def test_successful_lookup(self):
        geo = GeoIPLookup.__new__(GeoIPLookup)
        geo._reader = MagicMock()
        geo._reader.get.return_value = {
            "country": {"iso_code": "US", "names": {"en": "United States"}},
            "city": {"names": {"en": "Mountain View"}},
            "location": {"latitude": 37.38, "longitude": -122.08},
            "traits": {"autonomous_system_number": 15169, "autonomous_system_organization": "Google"},
        }

        result = geo.lookup("8.8.8.8")
        assert result.country_code == "US"
        assert result.country_name == "United States"
        assert result.city == "Mountain View"
        assert result.latitude == 37.38
        assert result.asn == 15169

    def test_missing_fields_fallback(self):
        geo = GeoIPLookup.__new__(GeoIPLookup)
        geo._reader = MagicMock()
        geo._reader.get.return_value = {"country": {}}

        result = geo.lookup("8.8.8.8")
        assert result.country_code == ""
        assert result.city == ""
        assert result.latitude == 0.0

    def test_reader_returns_none(self):
        geo = GeoIPLookup.__new__(GeoIPLookup)
        geo._reader = MagicMock()
        geo._reader.get.return_value = None

        result = geo.lookup("8.8.8.8")
        assert result == GeoResult()

    def test_reader_raises_exception(self):
        geo = GeoIPLookup.__new__(GeoIPLookup)
        geo._reader = MagicMock()
        geo._reader.get.side_effect = RuntimeError("corrupt db")

        result = geo.lookup("8.8.8.8")
        assert result == GeoResult()

    def test_subdivision_fallback_for_city(self):
        geo = GeoIPLookup.__new__(GeoIPLookup)
        geo._reader = MagicMock()
        geo._reader.get.return_value = {
            "country": {"iso_code": "US", "names": {"en": "United States"}},
            "city": {},  # No city
            "subdivisions": [{"names": {"en": "California"}}],
            "location": {"latitude": 37.0, "longitude": -122.0},
        }

        result = geo.lookup("8.8.8.8")
        assert result.city == "California"
