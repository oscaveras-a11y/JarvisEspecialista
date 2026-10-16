"""Local path and scope validation. Never execute analyzed files."""
import os
from pathlib import Path
import stat
from cyber_core.errors import CoreError


def local_path(value, *, directory=False):
    raw = str(value)
    if not raw or raw.startswith(('\\\\', '//')) or '..' in Path(raw).parts:
        raise CoreError('A local path without traversal is required')
    path = Path(raw).absolute()
    tail = str(path)[len(path.anchor):]
    if ':' in tail:
        raise CoreError('Alternate streams and device paths are forbidden')
    for node in (path, *path.parents):
        try:
            info = node.lstat()
        except OSError as exc:
            raise CoreError('Path is missing or inaccessible') from exc
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise CoreError('Symlinks and reparse points are forbidden')
    resolved = path.resolve(strict=True)
    if directory and not resolved.is_dir():
        raise CoreError('Scope must be an existing directory')
    if not directory and not resolved.is_file():
        raise CoreError('Evidence must be a regular file')
    return resolved


def scoped_path(value, scope):
    path = local_path(value)
    root = local_path(scope, directory=True)
    if not path.is_relative_to(root):
        raise CoreError('File is outside the authorized scope')
    return path


def storage_root(value):
    path = Path(value).absolute()
    if str(value).startswith(('\\\\', '//')) or '..' in Path(value).parts:
        raise CoreError('Storage must be local without traversal')
    if ':' in str(path)[len(path.anchor):]:
        raise CoreError('Invalid storage path')
    # Check all existing ancestors before creating any directory.
    for node in (path, *path.parents):
        if node.exists() or node.is_symlink():
            info = node.lstat()
            if node.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise CoreError('Storage reparse points are forbidden')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    local_path(path, directory=True)
    # Never place operational data under a Git working tree.
    if any((p / '.git').exists() for p in (path, *path.parents)):
        raise CoreError('Operational data must be outside Git repositories')
    return path
