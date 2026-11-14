"""Label sources and the label policy (M3)."""

from pkgwatch.labeling.advisory import AdvisoryLabel, load_advisories
from pkgwatch.labeling.human import HumanLabel, load_human_labels
from pkgwatch.labeling.policy import LabelConflict, LabelDecision, resolve_label

__all__ = [
    "AdvisoryLabel",
    "HumanLabel",
    "LabelConflict",
    "LabelDecision",
    "load_advisories",
    "load_human_labels",
    "resolve_label",
]
