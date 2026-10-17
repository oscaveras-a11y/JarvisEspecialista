"""Optional TOML defaults. The file is a convenience, never a security boundary.

Values are read, in order, from the file named by the CYBER_CONFIG environment
variable, otherwise from ``config/default.toml`` in the current working
directory when present. Anything missing falls back to the built-in defaults
below, so a missing or partial file never breaks startup. Environment variables
and CLI flags still override whatever is loaded here.
"""
import os
from pathlib import Path
import tomllib
from cyber_core.errors import CoreError

BUILTIN = {'max_bytes': 67108864, 'timeout_seconds': 60, 'max_attempts': 3, 'agent_calls_per_case': 5}


def config_path():
    override = os.environ.get('CYBER_CONFIG')
    if override:
        return Path(override)
    local = Path('config/default.toml')
    return local if local.is_file() else None


def load_defaults():
    values = dict(BUILTIN)
    path = config_path()
    if path is not None:
        try:
            with path.open('rb') as handle:
                loaded = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise CoreError('Invalid configuration file') from exc
        for key in BUILTIN:
            if key in loaded:
                value = loaded[key]
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise CoreError('Configuration value for ' + key + ' must be a non-negative integer')
                values[key] = value
    return values
