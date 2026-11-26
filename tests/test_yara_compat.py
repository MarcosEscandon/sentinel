from types import SimpleNamespace

from sentinel.engine.yara import _string_indicator


def test_yara_string_match_objects():
    item = SimpleNamespace(
        identifier="$suspicious",
        instances=[SimpleNamespace(offset=42, matched_data=b"x"), SimpleNamespace(offset=99)],
    )
    assert _string_indicator(item) == "$suspicious:42"


def test_yara_legacy_tuple():
    assert _string_indicator((42, "$suspicious", b"x")) == "$suspicious:42"


def test_yara_unknown_item_is_ignored():
    assert _string_indicator(object()) is None
