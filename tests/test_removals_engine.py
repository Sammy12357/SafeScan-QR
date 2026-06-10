"""Unit tests for the Go Ghost multi-broker removal engine.

Importing ``removals.engine`` is safe without Playwright installed: the
Playwright import is deferred until ``run_broker_removal`` actually runs, so
the config registry and pure helpers can be tested in isolation.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from removals.engine import (  # noqa: E402
    BROKER_CONFIGS,
    RemovalProfile,
    split_name,
    supported_broker,
)


# The eight first-tier brokers Go Ghost runs backend automation against.
EXPECTED_BROKERS = {
    "fastpeoplesearch",
    "thatsthem",
    "truepeoplesearch",
    "spokeo",
    "nuwber",
    "beenverified",
    "whitepages",
    "radaris",
}


class TestBrokerRegistry:
    def test_all_eight_brokers_configured(self):
        assert set(BROKER_CONFIGS) == EXPECTED_BROKERS

    def test_supported_broker_is_case_insensitive(self):
        assert supported_broker("FastPeopleSearch") is BROKER_CONFIGS["fastpeoplesearch"]
        assert supported_broker("  SPOKEO ") is BROKER_CONFIGS["spokeo"]

    def test_supported_broker_unknown_returns_none(self):
        assert supported_broker("not-a-broker") is None
        assert supported_broker("") is None

    def test_every_optout_url_is_https(self):
        for config in BROKER_CONFIGS.values():
            assert config.optout_url.startswith("https://"), config.id

    def test_each_config_id_matches_key(self):
        for key, config in BROKER_CONFIGS.items():
            assert config.id == key

    def test_form_based_brokers_are_not_record_based(self):
        # FastPeopleSearch and Thatsthem complete from name + email alone.
        assert BROKER_CONFIGS["fastpeoplesearch"].record_based is False
        assert BROKER_CONFIGS["thatsthem"].record_based is False

    def test_listing_based_brokers_require_profile_url(self):
        # These remove a specific listing, so they must flag a record checkpoint.
        for broker_id in ("spokeo", "nuwber", "beenverified", "radaris", "whitepages", "truepeoplesearch"):
            assert BROKER_CONFIGS[broker_id].record_based is True

    def test_fastpeoplesearch_needs_requester_type(self):
        assert BROKER_CONFIGS["fastpeoplesearch"].requester_type is True


class TestSplitName:
    def test_empty(self):
        assert split_name("") == {"first": "", "middle": "", "last": ""}

    def test_single(self):
        assert split_name("Cher") == {"first": "Cher", "middle": "", "last": ""}

    def test_two_parts(self):
        assert split_name("Joseph Homza") == {"first": "Joseph", "middle": "", "last": "Homza"}

    def test_three_parts_middle(self):
        assert split_name("Joseph Allen Homza") == {"first": "Joseph", "middle": "Allen", "last": "Homza"}

    def test_collapses_dots_and_extra_spaces(self):
        assert split_name("J. R. R. Tolkien") == {"first": "J", "middle": "R R", "last": "Tolkien"}


class TestRemovalProfile:
    def test_defaults_are_blank(self):
        profile = RemovalProfile(name="Joseph Homza")
        assert profile.address == ""
        assert profile.city_state == ""
        assert profile.phone == ""
        assert profile.email == ""
