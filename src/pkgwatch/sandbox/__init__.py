"""Safe archive extraction.

Nothing outside this package may decompress package content. Every member is
validated before anything is written; symlinks are recorded in the manifest and
never materialised on disk.
"""

from pkgwatch.models import ArchiveFormat, ManifestEntry, RejectionCode, SandboxLimits
from pkgwatch.sandbox.errors import ArchiveRejected
from pkgwatch.sandbox.extract import extract_archive, sha256_file, sniff_archive

__all__ = [
    "ArchiveFormat",
    "ArchiveRejected",
    "ManifestEntry",
    "RejectionCode",
    "SandboxLimits",
    "extract_archive",
    "sha256_file",
    "sniff_archive",
]
