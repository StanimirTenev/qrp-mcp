"""`.qrp.toml`: the owner's settings for a tree, read from its root.

    profile     = "us-cnsa2"            # whose replacements (command line: --profile)
    level       = "masked"              # what the quoted line carries (--level)
    exclude     = ["legacy/", "*.min.js"]
    baseline    = ".qrp-baseline.json"  # relative to this file (--baseline)
    mandate     = ["cnsa-2.0"]          # (--mandate)
    lead_months = 24                    # (--lead-months)

The command line wins over the file. `--no-config` ignores it and `--config FILE` names
another. An unknown key or a wrong value is an error, not a default: a misspelt `exclud`
silently doing nothing is a setting the owner believes in and the scan does not apply.

What the file did is in the result: `coverage.config` names it with its digest, and the files
it excluded are `not_examined` with the reason `excluded_by_config`. An in-tree configuration
that zeroes a scan with no output saying so is CryptoScan #9 (open, October 2026).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

FILENAME = ".qrp.toml"
LEVELS = ("full", "masked", "trimmed")


class ConfigError(ValueError):
    pass


def _toml(raw: bytes) -> dict[str, Any]:
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ModuleNotFoundError:
            raise ConfigError("reading a .qrp.toml needs Python 3.11 or the `tomli` package; "
                              "pass the settings on the command line instead") from None
    try:
        return tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as err:
        raise ConfigError(f"not valid TOML: {err}") from None


def _check(values: dict[str, Any]) -> dict[str, Any]:
    from . import mandates, profiles

    def strings(key: str) -> list[str]:
        v = values[key]
        if not (isinstance(v, list) and all(isinstance(i, str) and i for i in v)):
            raise ConfigError(f"`{key}` must be a list of strings")
        return v

    out: dict[str, Any] = {}
    for key in values:
        if key not in ("profile", "level", "exclude", "baseline", "mandate", "lead_months"):
            raise ConfigError(f"unknown key `{key}`; known: profile, level, exclude, baseline, "
                              f"mandate, lead_months")
    if "profile" in values:
        if values["profile"] not in profiles.names():
            raise ConfigError(f"`profile` must be one of {', '.join(profiles.names())}")
        out["profile"] = values["profile"]
    if "level" in values:
        if values["level"] not in LEVELS:
            raise ConfigError(f"`level` must be one of {', '.join(LEVELS)}")
        out["level"] = values["level"]
    if "exclude" in values:
        out["exclude"] = strings("exclude")
    if "baseline" in values:
        if not isinstance(values["baseline"], str) or not values["baseline"]:
            raise ConfigError("`baseline` must be a path")
        out["baseline"] = values["baseline"]
    if "mandate" in values:
        bad = [m for m in strings("mandate") if m not in mandates.MANDATES]
        if bad:
            raise ConfigError(f"`mandate` {bad[0]!r} is not one of {', '.join(mandates.MANDATES)}")
        out["mandate"] = values["mandate"]
    if "lead_months" in values:
        v = values["lead_months"]
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            raise ConfigError("`lead_months` must be a whole number of months, 0 or more")
        out["lead_months"] = v
    return out


def load(root: Path, explicit: str | Path | None = None,
         disabled: bool = False) -> dict[str, Any] | None:
    """The settings, or None where there is no file (or `disabled`).

    Returns {"file": Path, "path": as shown, "sha256": ..., "values": {...}}; `baseline`
    in the values is resolved against the file's own folder."""
    if disabled:
        return None
    root = Path(root).expanduser().resolve()
    if explicit is not None:
        file = Path(explicit).expanduser().resolve()
        if not file.is_file():
            raise ConfigError(f"no config file at {explicit}")
    else:
        file = root / FILENAME
        if not file.is_file():
            return None
    raw = file.read_bytes()
    values = _check(_toml(raw))
    if "baseline" in values:
        values["baseline"] = str((file.parent / values["baseline"]).resolve())
    try:
        shown = file.relative_to(root).as_posix()
    except ValueError:
        shown = str(file)
    return {"file": file, "path": shown, "sha256": hashlib.sha256(raw).hexdigest(),
            "values": values}


def coverage_block(config: dict[str, Any]) -> dict[str, Any]:
    """What `coverage.config` says: the file, its digest, and what it set."""
    values = config["values"]
    return {"path": config["path"], "sha256": config["sha256"],
            **{k: values[k] for k in ("profile", "level", "exclude", "mandate", "lead_months")
               if k in values},
            **({"baseline": values["baseline"]} if "baseline" in values else {})}
