"""Dataset export, split assignment and schema validation (M3)."""

from pkgwatch.dataset.export import ExportResult, export_dataset
from pkgwatch.dataset.record import RecordOutcome, record_filename, record_pair
from pkgwatch.dataset.split import assign_split, split_bucket
from pkgwatch.dataset.validate import ValidationReport, validate_dataset

__all__ = [
    "ExportResult",
    "RecordOutcome",
    "ValidationReport",
    "assign_split",
    "export_dataset",
    "record_filename",
    "record_pair",
    "split_bucket",
    "validate_dataset",
]
