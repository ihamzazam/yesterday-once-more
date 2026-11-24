"""Target rules pick exactly the lab files they should."""

import pytest

from software.conftest import SAMPLES
from software.ransomware.runtime.targets import WANNACRY_EXTENSIONS, TargetRules
from software.ransomware.tests.helpers import SUFFIX


def test_wannacry_preset_selection(documents):
    (documents / "READ_ME.txt").write_text("note")
    (documents / ".hidden.txt").write_text("x")
    (documents / "old.txt.WNCRY").write_bytes(b"x")
    (documents / "link.txt").symlink_to(documents / "notes.txt")
    (documents / "sub").mkdir()
    (documents / "sub" / "deep.csv").write_text("a,b\n")
    rules = TargetRules([documents], WANNACRY_EXTENSIONS, ["READ_ME.txt"], SUFFIX)
    names = sorted(rules.display_name(p) for p in rules.collect())
    # .md is not in the WannaCry list; excluded, hidden, symlinked and
    # already-suffixed files are skipped.
    assert names == ["budget.csv", "notes.txt", "photo.jpg", "sub/deep.csv"]
    assert [p.name for p in rules.envelopes()] == ["old.txt.WNCRY"]


def test_all_files_and_added_extension(documents):
    assert len(TargetRules([documents], None, [], SUFFIX).collect()) == len(SAMPLES)
    rules = TargetRules([documents], WANNACRY_EXTENSIONS + [".md"], [], SUFFIX)
    assert "report.md" in [p.name for p in rules.collect()]


def test_rules_validate_input():
    with pytest.raises(ValueError):
        TargetRules([], None, [], SUFFIX)
    with pytest.raises(ValueError):
        TargetRules(["/x"], None, [], "WNCRY")
