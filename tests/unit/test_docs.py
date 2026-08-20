# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Doc/CLI consistency: the README's verb inventory must match cli.py.

The README's files-catalogue carries the CLI's canonical verb list; it has
drifted before (db-migrate, logs, cert-renew, backup status and two rotate
targets were all missing at one point). These tests pin the inventory to the
dispatcher so the next new verb fails CI until it is documented — and so a
documented verb that no longer exists fails too.
"""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _dispatch_verbs() -> set:
    """Every verb literal cli.py dispatches on, extracted structurally.

    Walks the AST for ``verb == <literal>`` and ``verb in <literals>``
    comparisons, so quote style or a tuple-to-set refactor in the
    dispatcher cannot silently drop verbs from this guard.
    """
    src = (ROOT / "carlos_ctl" / "cli.py").read_text(encoding="utf-8")
    verbs = set()
    for node in ast.walk(ast.parse(src)):
        if (
            isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Name)
            and node.left.id == "verb"
            and len(node.ops) == 1
            and isinstance(node.ops[0], (ast.Eq, ast.In))
        ):
            verbs.update(
                child.value
                for child in ast.walk(node.comparators[0])
                if isinstance(child, ast.Constant)
                and isinstance(child.value, str)
                and re.fullmatch(r"[a-z][a-z0-9-]*", child.value)
            )
    assert len(verbs) > 15, "dispatch parse failed — cli.py layout changed?"
    return verbs


def _inventory_block() -> str:
    """The verb-inventory paragraph in the README's files catalogue."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(
        r"Lifecycle-grouped verbs:(.*?)plus `help` and `version`",
        readme,
        re.S,
    )
    assert m, "README verb inventory block not found (marker text changed?)"
    return m.group(0)


def _documented_verbs() -> set:
    """First word of each backticked token in the inventory that looks like
    a verb (skips flags, env keys, paths, and placeholder syntax)."""
    verbs = set()
    for token in re.findall(r"`([^`]+)`", _inventory_block()):
        first = token.split()[0]
        first = first.split("<")[0].strip()
        if not first or first.startswith(("-", "$")) or "/" in first:
            continue
        if re.fullmatch(r"[a-z][a-z0-9-]*", first):
            verbs.add(first)
    return verbs


class TestVerbInventory:
    def test_every_dispatch_verb_is_documented(self) -> None:
        documented = _documented_verbs() | {"help", "version"}
        missing = _dispatch_verbs() - documented
        assert not missing, (
            f"cli.py dispatches verbs absent from the README inventory: "
            f"{sorted(missing)} — add them to the Lifecycle-grouped verbs "
            f"paragraph (and the relevant section)"
        )

    def test_every_documented_verb_exists(self) -> None:
        known = _dispatch_verbs() | {"help", "version"}
        phantom = _documented_verbs() - known
        assert not phantom, (
            f"README documents verbs cli.py does not dispatch: "
            f"{sorted(phantom)} — remove or correct the inventory"
        )
