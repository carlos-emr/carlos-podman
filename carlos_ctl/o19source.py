# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Fetch, verify and load the OSCAR 19 import engine from the pinned CARLOS.

Why the engine is not vendored here. Its two manifests
(`o19map_schema.py`, `o19map_props.py`) are GENERATED from CARLOS's own Flyway
migrations and from the OSCAR 19 schema — every ruling in them ("this column
merges there", "this table is archive-only") is correct for exactly one CARLOS
version. A copy in this repository would be right on the day it was copied and
silently wrong after the next CARLOS release, in a way no test here could see.
This deployment already pins a CARLOS release AND its commit SHA and builds
the WAR from that tree (`carlos_ctl.source`); taking the importer from the
same tree makes "the manifest matches the schema the app will read" structural
instead of a sync chore.

What is loaded is a SYNTHETIC package (`carlos_o19_engine`) whose `util`,
`dbops` and `config` members are podman's shims (`o19compat`), so the engine's
own relative imports resolve to this deployment's answers with the engine
source unmodified.

Everything here fails CLOSED and says which CARLOS version would be needed:
an unpinned or branch-only selection, a tree missing a module, a module
importing a name the shim does not provide — none of them may reach a
clinic's data as a half-loaded import.
"""

from __future__ import annotations

import ast
import importlib
import importlib.machinery
import os
import re
import shutil
import sys
import tempfile
import types
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import o19compat, source
from .runner import Runner
from .util import CtlError, log

#: The synthetic package the engine is loaded under. Distinct from
#: `carlos_ctl` so an engine module can never shadow (or be shadowed by) a
#: podman module of the same name.
PACKAGE = "carlos_o19_engine"

#: Where the engine lives inside the CARLOS source tarball.
ENGINE_SUBDIR = "debian/assets/carlos_ctl"

#: Every module the import needs. A tree missing one is refused BEFORE the
#: workspace is touched; a tree carrying an extra o19*.py is fine (it is
#: fetched and simply never imported).
REQUIRED_MODULES: Tuple[str, ...] = (
    "o19_preflight", "o19bundle", "o19digest", "o19docs", "o19etl",
    "o19host", "o19import", "o19map_props", "o19map_schema", "o19props",
    "o19report", "o19roles",
)

#: The engine's own SQL escape — the standalone copy `o19_preflight` carries
#: so it can be run alone on a 2014-era OSCAR 19 server, pinned against
#: `util.sql_escape` by the CARLOS suite's `test_sql_escape_contract.py`.
#: Taking it from the fetched engine is what keeps podman from becoming a
#: THIRD copy of a function that has already drifted once.
ENGINE_ESCAPE_ATTR = "_sql_literal"

_SHA40 = re.compile(r"^[0-9a-f]{40}$")

#: Ceiling on the fetched source tarball. The CARLOS tree is ~60 MB; this is
#: a runaway/redirect stop, not a size policy.
_MAX_TARBALL_BYTES = 512 * 1024 * 1024


class Engine:
    """The loaded engine: its modules, and which CARLOS produced them."""

    def __init__(self, package: types.ModuleType, commit: str,
                 described: str, root: Path) -> None:
        self.package = package
        self.commit = commit
        self.described = described
        self.root = root
        for name in REQUIRED_MODULES:
            setattr(self, name, getattr(package, name))

    def __getattr__(self, name: str) -> Any:
        # Every engine module is set in __init__; this exists so a typo
        # reads as a plain AttributeError naming the module, and so the
        # dynamically-set members type-check as what they are.
        raise AttributeError(
            f"the loaded OSCAR 19 engine has no module {name!r}")

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"<Engine {self.commit[:12]} at {self.root}>"


# --- which CARLOS ------------------------------------------------------------


def pinned_commit(runner: Runner) -> Tuple[str, str]:
    """(40-hex commit, human description) of the CARLOS this host deploys.

    Read from the build pin, never resolved fresh: the importer must come
    from the tree the RUNNING WAR was built from, and a live resolve would
    quietly take a newer release's manifest — rulings written against a
    schema this host has not migrated to."""
    pin = source.read_pin(runner, source.CARLOS)
    if pin is None:
        raise CtlError(
            "no pinned CARLOS version — the OSCAR 19 importer is taken from "
            "the CARLOS tree this host deploys, so there has to be one. Run "
            "'carlos-ctl build' (or 'carlos-ctl source update') first, then "
            "'carlos-ctl source show' to confirm the pin. (A pin file "
            "that fails its own structural check is ignored with a warning, "
            "and reaches here as no pin at all.)"
        )
    commit = pin.commit or (pin.ref if _SHA40.match(pin.ref or "") else "")
    if not _SHA40.match(commit or ""):
        # Defence in depth: `read_pin` already refuses a pin whose ref is not
        # 40 hex, so this is unreachable through the normal path. It stays
        # because the consequence of a moving ref reaching the loader is a
        # clinic migrated under another version's manifest, and that must
        # never rest on one caller's validation staying as strict as it is
        # today.
        raise CtlError(
            f"the CARLOS selection is {pin.describe()}, which names no "
            "commit — the importer's manifests are generated per CARLOS "
            "version, so a moving ref cannot identify one. Pin a release or "
            "a 40-hex commit ('carlos-ctl source set <tag|sha>') and re-run."
        )
    return commit, pin.describe()


def engine_root(runner: Runner, commit: str) -> Path:
    """Where a given CARLOS commit's engine is unpacked. Keyed by commit, so
    an upgrade fetches beside the old one instead of over it — and a resume
    started under the previous manifest still finds the modules it began
    with (the engine's own manifest-change refusal then explains itself)."""
    return runner.settings.emr_home / "o19-import" / "engine" / commit


# --- fetching ----------------------------------------------------------------


def _tarball_url(commit: str) -> str:
    return f"https://codeload.github.com/{source.CARLOS.repo}/tar.gz/{commit}"


def fetch_engine(runner: Runner, commit: str) -> Path:
    """Download the pinned CARLOS tree and unpack ONLY the engine modules.

    The whole tarball is fetched (GitHub serves no partial archive) but
    nothing outside `debian/assets/carlos_ctl/o19*.py` is ever written to
    disk: the extract is member-scoped, so a tampered archive cannot drop a
    file anywhere else in $EMR_HOME. The unpack lands in a sibling temp
    directory and is renamed into place only once every required module is
    present — a half-fetched engine is never visible under its commit."""
    root = engine_root(runner, commit)
    root.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(dir=str(root.parent),
                                  prefix=f".engine-{commit[:12]}."))
    try:
        tarball = stage / "carlos-src.tar.gz"
        log(f"fetching the OSCAR 19 import engine from CARLOS {commit[:12]} ...")
        cp = runner.run([
            "curl", "-fsSL", "--max-time", "900",
            "--max-filesize", str(_MAX_TARBALL_BYTES),
            "-o", str(tarball), _tarball_url(commit),
        ])
        if cp.returncode != 0 or not tarball.is_file():
            raise CtlError(
                "could not download the CARLOS source tarball for commit "
                f"{commit[:12]} ({_tarball_url(commit)}) — the importer "
                "needs it. Check outbound network access to "
                "codeload.github.com and re-run.")
        unpack = stage / "engine"
        unpack.mkdir()
        # --strip-components drops '<repo>-<commit>/debian/assets/carlos_ctl'
        # so the modules land flat; the wildcard is what keeps the extract
        # scoped to them. '--' is not usable with a pattern operand, so the
        # pattern is anchored with the leading '*/' instead.
        cp = runner.run([
            "tar", "-xzf", str(tarball), "-C", str(unpack),
            "--strip-components", "4", "--wildcards", "--no-same-owner",
            "--no-same-permissions",
            f"*/{ENGINE_SUBDIR}/o19*.py",
        ])
        if cp.returncode != 0:
            raise CtlError(
                f"the CARLOS {commit[:12]} source tarball carries no "
                f"{ENGINE_SUBDIR}/o19*.py — this CARLOS release predates the "
                "OSCAR 19 importer. Deploy a release that ships it and "
                "re-run.")
        missing = [m for m in REQUIRED_MODULES
                   if not (unpack / (m + ".py")).is_file()]
        if missing:
            raise CtlError(
                f"the CARLOS {commit[:12]} tree is missing importer "
                f"module(s): {', '.join(missing)}. This is not a CARLOS "
                "release the podman importer can run against; deploy a "
                "newer one and re-run.")
        os.replace(str(unpack), str(root))
        return root
    finally:
        shutil.rmtree(str(stage), ignore_errors=True)


def ensure_engine(runner: Runner, commit: str) -> Path:
    """The unpacked engine for `commit`, fetching it if this host has not
    seen that CARLOS before. Idempotent: a complete tree is reused offline."""
    root = engine_root(runner, commit)
    if all((root / (m + ".py")).is_file() for m in REQUIRED_MODULES):
        return root
    if root.exists():
        # Present but incomplete — an interrupted older fetch, or a tree
        # pruned by hand. Refetching is the repair; keep nothing partial.
        shutil.rmtree(str(root), ignore_errors=True)
    return fetch_engine(runner, commit)


# --- verification ------------------------------------------------------------


def imported_sibling_names(root: Path) -> Dict[str, List[str]]:
    """{sibling module: [names]} the engine imports from its non-o19 siblings.

    Parsed from the fetched SOURCE, not from an executed module: this runs
    BEFORE anything is imported, so a CARLOS release that reaches for a name
    podman does not provide is refused by name instead of raising ImportError
    (or, worse, AttributeError) somewhere inside a phase."""
    wanted: Dict[str, List[str]] = {}
    for path in sorted(root.glob("o19*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError) as exc:
            raise CtlError(
                f"could not read the fetched importer module {path.name}: {exc}") from exc
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or node.level != 1:
                continue
            if node.module is None:
                # `from . import dbops` — the ALIASES are sibling modules,
                # imported whole. The engine reaches its own o19* siblings
                # this way too; only the rest are shim surface.
                for alias in node.names:
                    if not alias.name.startswith("o19"):
                        wanted.setdefault(alias.name, [])
                continue
            # `from .util import log, run` — the module is the sibling and
            # the aliases are names it must provide.
            if str(node.module).startswith("o19"):
                continue
            names = wanted.setdefault(str(node.module), [])
            for alias in node.names:
                if alias.name not in names:
                    names.append(alias.name)
    return wanted


def verify_engine(root: Path, shims: Dict[str, types.ModuleType]) -> None:
    """Refuse a fetched engine this deployment cannot fully answer.

    Two directions, and both matter. The DECLARED surface
    (`o19compat.REQUIRED_*`) is what the shims promise; the OBSERVED surface
    is what this CARLOS release actually imports. A name in the observed set
    that the shim lacks would be an ImportError mid-import; a name the shim
    declares but no longer provides is a shim that was edited without its
    contract — both are refused here, before the workspace lock is taken."""
    declared: Sequence[Tuple[str, Sequence[str]]] = (
        ("util", o19compat.REQUIRED_UTIL_NAMES),
        ("dbops", o19compat.REQUIRED_DBOPS_NAMES),
        ("config", o19compat.REQUIRED_CONFIG_NAMES),
    )
    for module, names in declared:
        gone = o19compat.missing_names(shims, module, names)
        if gone:
            raise CtlError(
                f"carlos_ctl.o19compat declares {module}.{gone[0]} in its "
                f"contract but does not provide {', '.join(gone)} — the "
                "shim and its declared surface disagree")
    for module, names in sorted(imported_sibling_names(root).items()):
        if module not in shims:
            raise CtlError(
                f"this CARLOS release's importer imports a '{module}' "
                "package sibling that carlos-podman does not provide "
                f"(names: {', '.join(sorted(names))}). The podman port needs "
                "a shim for it — file an issue against "
                "carlos-emr/carlos-podman naming this CARLOS version.")
        gone = o19compat.missing_names(shims, module, names)
        if gone:
            raise CtlError(
                f"this CARLOS release's importer imports "
                f"{', '.join(sorted(gone))} from its '{module}' sibling, "
                "which carlos-podman's shim does not answer. The podman port "
                "has to be extended before this CARLOS version can migrate a "
                "clinic.")


# --- loading -----------------------------------------------------------------


def _make_package(root: Path) -> types.ModuleType:
    pkg = types.ModuleType(PACKAGE)
    pkg.__doc__ = ("the OSCAR 19 import engine, loaded verbatim from the "
                   "pinned CARLOS source tree")
    pkg.__path__ = [str(root)]
    pkg.__package__ = PACKAGE
    spec = importlib.machinery.ModuleSpec(PACKAGE, None, is_package=True)
    if spec.submodule_search_locations is not None:
        spec.submodule_search_locations.append(str(root))
    pkg.__spec__ = spec
    return pkg


def _unload() -> None:
    for name in list(sys.modules):
        if name == PACKAGE or name.startswith(PACKAGE + "."):
            del sys.modules[name]


_LOADED: Optional[Engine] = None


def load_engine(runner: Runner) -> Engine:
    """The engine, ready to run, with podman's shims wired underneath it.

    Load order is not incidental. `o19_preflight` imports nothing from its
    package (it is the file an operator copies alone onto the OSCAR 19
    server), so it can be imported before the shims exist — and it carries
    the SQL escape the shims hand to every other module. Only then are the
    three siblings registered, and only then does the rest of the engine
    import."""
    global _LOADED
    if _LOADED is not None:
        return _LOADED
    commit, described = pinned_commit(runner)
    root = ensure_engine(runner, commit)
    _unload()
    pkg = _make_package(root)
    sys.modules[PACKAGE] = pkg
    try:
        preflight = importlib.import_module(PACKAGE + ".o19_preflight")
        escape = getattr(preflight, ENGINE_ESCAPE_ATTR, None)
        if not callable(escape):
            raise CtlError(
                f"this CARLOS release's o19_preflight carries no {ENGINE_ESCAPE_ATTR}() — "
                "carlos-podman takes the importer's SQL escape from it so "
                "the two can never drift. The podman port needs updating "
                "for this CARLOS version.")
        shims = o19compat.build_shims(runner, escape)
        verify_engine(root, shims)
        for name, module in shims.items():
            module.__name__ = PACKAGE + "." + name
            module.__package__ = PACKAGE
            sys.modules[PACKAGE + "." + name] = module
            setattr(pkg, name, module)
        for name in REQUIRED_MODULES:
            setattr(pkg, name, importlib.import_module(PACKAGE + "." + name))
    except BaseException:
        _unload()
        raise
    _LOADED = Engine(pkg, commit, described, root)
    return _LOADED


def unload_engine() -> None:
    """Drop the loaded engine (tests; and a verb that loads twice in one
    process must not reuse a differently-bound one)."""
    global _LOADED
    _LOADED = None
    _unload()


def loaded_engine() -> Optional[Engine]:
    return _LOADED


def engine_modules_present(root: Path) -> Sequence[str]:
    """Which required modules a directory holds — diagnostics for `status`
    style reporting and for the tests."""
    return tuple(m for m in REQUIRED_MODULES if (root / (m + ".py")).is_file())
