# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Existing operator property names must survive append-only migrations."""

import importlib.util
from pathlib import Path

import pytest

_path = (Path(__file__).resolve().parents[2] / "ansible" / "roles" /
         "carlos_podman" / "filter_plugins" / "java_properties.py")
_spec = importlib.util.spec_from_file_location("java_properties_filter", _path)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)


@pytest.mark.parametrize("content", [
    "cds.import.enabled=false\n",
    "  cds.import.enabled : false\r\n",
    "\tcds.import.enabled false\r",
    r"cds\.import\.enabled=false",
    r"\u0063ds\u002eimport.enabled=false",
    "cds.import.enab\\\n  led=false\n",
    "! ignored\n#cds.import.enabled=true\ncds.import.enabled=false\n",
])
def test_existing_java_property_names_are_recognized(content):
    assert _module.java_properties_keys(content) == ["cds.import.enabled"]


def test_escaped_separators_and_value_continuations_do_not_create_property_keys():
    assert _module.java_properties_keys(
        "escaped\\ key\\:name=value\\\n #continued=value\nnext.key=actual\n"
    ) == ["escaped key:name", "next.key"]


def test_malformed_unicode_key_is_refused_without_returning_values():
    with pytest.raises(ValueError, match="Invalid Unicode escape in a Java property name"):
        _module.java_properties_keys(r"cds.\uXX00.enabled=value")
