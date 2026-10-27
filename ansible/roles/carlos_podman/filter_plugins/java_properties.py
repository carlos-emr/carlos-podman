# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Read property names without exposing values or rewriting operator files."""

import re


def _unescape(value):
    result = []
    index = 0
    escapes = {"t": "\t", "r": "\r", "n": "\n", "f": "\f"}
    while index < len(value):
        char = value[index]
        index += 1
        if char != "\\":
            result.append(char)
            continue
        if index == len(value):
            break
        char = value[index]
        index += 1
        if char == "u":
            digits = value[index:index + 4]
            if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                raise ValueError("Invalid Unicode escape in a Java property name")
            result.append(chr(int(digits, 16)))
            index += 4
        else:
            result.append(escapes.get(char, char))
    return "".join(result)


def java_properties_keys(content):
    """Match Properties.load key escapes, separators, comments and continuations."""
    keys = []
    pending = ""
    continuing = False
    for physical in re.split(r"\r\n?|\n", content):
        line = pending + physical.lstrip(" \t\f")
        if not continuing and (not line or line.startswith(("#", "!"))):
            continue
        slash_count = len(line) - len(line.rstrip("\\"))
        if slash_count % 2:
            pending, continuing = line[:-1], True
            continue
        pending, continuing = "", False
        index = 0
        while index < len(line):
            if line[index] in "=: \t\f":
                break
            index += 2 if line[index] == "\\" else 1
        keys.append(_unescape(line[:index]))
    if continuing:
        index = 0
        while index < len(pending):
            if pending[index] in "=: \t\f":
                break
            index += 2 if pending[index] == "\\" else 1
        keys.append(_unescape(pending[:index]))
    return keys


class FilterModule:
    def filters(self):
        return {"java_properties_keys": java_properties_keys}
