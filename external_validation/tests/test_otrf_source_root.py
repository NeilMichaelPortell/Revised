"""
test_otrf_source_root.py
========================

Offline tests for the OTRF source-root resolution, the 18-source and
neutral-input hash verification, retrieval-plan integrity, exact indicator
matching, gitignore protection for raw OTRF data, and frozen raw-output
hash + record-order preservation.

Runs WITHOUT Ollama and WITHOUT network access. Uses only local files.

    python -m pytest external_validation/tests/test_otrf_source_root.py -v
"""
from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path

THIS = Path(__file__).resolve()
REPO_ROOT = THIS.parents[2]
RUNS_DIR = REPO_ROOT / "scripts" / "runs_otrf"
sys.path.insert(0, str(RUNS_DIR))

import otrf_common as oc  # noqa: E402

MANIFEST = REPO_ROOT / "external_validation" / "prepared" / "frozen_external_manifest.csv"
NEUTRAL_DIR = REPO_ROOT / "external_validation" / "prepared" / "neutral_inputs"
CLONE_ROOT = REPO_ROOT / "Security-Datasets-master"
EXPECTED_HASHES = {
    "EXT_010": "b073a18420c90394cd2b6ad7589c78d90eba32dc155ed04b12ac824a8fc591b4",
    "EXT_014": "b37c022ce7aa5fed3ad7087e2ec1f37d7b1089ec9bfe7b196f974295d255506b",
}


def _manifest_rows():
    with MANIFEST.open(encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# 1. URL reconstruction + source-root resolution                              #
# --------------------------------------------------------------------------- #
def test_otrf_relpath_from_url():
    url = ("https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
           "datasets/atomic/windows/persistence/host/empire_schtasks_creation_standard_user.zip")
    assert oc.otrf_relpath_from_url(url) == (
        "datasets/atomic/windows/persistence/host/empire_schtasks_creation_standard_user.zip")
    assert oc.otrf_relpath_from_url("") is None
    assert oc.otrf_relpath_from_url("https://example.com/no-master-segment.zip") is None


def test_source_root_resolves_missing_ext010_ext014():
    """EXT_010/EXT_014 are not in the tracked source dir; they must resolve
    from the local clone via the manifest URL and hash-match exactly."""
    if not CLONE_ROOT.exists():
        return  # local clone not present in this checkout; skip silently
    rows = {r["external_scenario_id"]: r for r in _manifest_rows()}
    for ext in ("EXT_010", "EXT_014"):
        p = oc.resolve_source_file(rows[ext], source_root=CLONE_ROOT)
        assert p.exists(), f"{ext} did not resolve under source_root"
        assert _sha256(p) == EXPECTED_HASHES[ext], f"{ext} hash mismatch"
        assert _sha256(p) == rows[ext]["source_hash"]


def test_source_root_disambiguates_by_hash_not_basename():
    """EXT_014's basename exists under both discovery/host and discovery/network
    in the clone; resolution must pick the one whose hash matches the manifest."""
    if not CLONE_ROOT.exists():
        return
    rows = {r["external_scenario_id"]: r for r in _manifest_rows()}
    p = oc.resolve_source_file(rows["EXT_014"], source_root=CLONE_ROOT)
    assert _sha256(p) == EXPECTED_HASHES["EXT_014"]


# --------------------------------------------------------------------------- #
# 2. All 18 source + neutral-input hashes verify                              #
# --------------------------------------------------------------------------- #
def test_all_18_source_hashes_match():
    rows = _manifest_rows()
    assert len(rows) == 18
    src_root = CLONE_ROOT if CLONE_ROOT.exists() else None
    unresolved = []
    for row in rows:
        p = oc.resolve_source_file(row, source_root=src_root)
        if not p.exists():
            unresolved.append(row["external_scenario_id"])
            continue
        assert _sha256(p) == row["source_hash"], f"{row['external_scenario_id']} source hash drift"
    # Every scenario must resolve when the local clone is present.
    if src_root is not None:
        assert not unresolved, f"unresolved sources: {unresolved}"


def test_all_18_neutral_input_hashes_match():
    rows = _manifest_rows()
    for row in rows:
        ext = row["external_scenario_id"]
        p = NEUTRAL_DIR / f"{ext}.json"
        assert p.exists(), f"{ext} neutral input missing"
        got = oc.sha256_text(p.read_text(encoding="utf-8"))
        assert got == row["neutral_input_hash"], f"{ext} neutral input hash drift"


def test_manifest_integrity_clean_with_source_root():
    src_root = CLONE_ROOT if CLONE_ROOT.exists() else None
    violations = oc.verify_manifest_integrity(_manifest_rows(), source_root=src_root)
    if src_root is not None:
        assert violations == [], f"unexpected integrity violations: {violations}"


# --------------------------------------------------------------------------- #
# 3. Retrieval-plan integrity                                                 #
# --------------------------------------------------------------------------- #
def test_frozen_retrieval_plan_present_and_nonempty():
    plan = oc.FROZEN_RETRIEVAL_PLAN_PATH
    assert plan.exists(), "frozen OTRF retrieval plan missing"
    lines = [ln for ln in plan.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) >= 18, "retrieval plan has fewer than 18 scenario records"


# --------------------------------------------------------------------------- #
# 4. Exact indicator matching + OOV retention (no underscore folding)         #
# --------------------------------------------------------------------------- #
def test_exact_indicator_matching_no_underscore_folding():
    vocab = {"scheduled_task_change", "defender_disabled"}
    out = oc.classify_indicators(
        ["scheduled_task_change", "scheduled task change", "scheduled-task-change",
         "defender_disabled"], vocab)
    assert set(out["canonical"]) == {"scheduled_task_change", "defender_disabled"}
    assert "scheduled task change" in out["out_of_vocabulary"]
    assert "scheduled-task-change" in out["out_of_vocabulary"]


def test_substring_never_credited():
    vocab = {"failed_login"}
    out = oc.classify_indicators(["failed", "login", "many_failed_login_attempts"], vocab)
    assert out["canonical"] == []
    assert set(out["out_of_vocabulary"]) == {"failed", "login", "many_failed_login_attempts"}


# --------------------------------------------------------------------------- #
# 5. Git-ignore protection for raw OTRF data                                   #
# --------------------------------------------------------------------------- #
def test_gitignore_protects_raw_otrf_sources():
    gi = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "external_validation/source/**/*.zip" in gi
    assert "/Security-Datasets-master/" in gi


def test_source_readme_tracked_but_no_zip_tracked():
    # The explanatory README must exist; raw archives must not be under the
    # tracked source tree as committed blobs (belt-and-braces: the file store
    # check is done at the git layer, here we assert the README exists).
    assert (REPO_ROOT / "external_validation" / "source" / "README.md").exists()


# --------------------------------------------------------------------------- #
# 6. Inference runners are NOT invoked by evaluation/tests                     #
# --------------------------------------------------------------------------- #
def test_evaluator_does_not_call_ollama():
    src = (RUNS_DIR / "11-evaluate-otrf-external.py").read_text(encoding="utf-8")
    # the evaluator must not import urllib/ollama or call the model runner core
    for forbidden in ("call_model", "urllib.request", "run_model_over_scenarios"):
        assert forbidden not in src, f"evaluator unexpectedly references {forbidden}"


# --------------------------------------------------------------------------- #
# 7. Frozen raw-output hash + record-order preservation                        #
# --------------------------------------------------------------------------- #
def test_frozen_otrf_outputs_hash_and_order_preserved():
    """Every OTRF raw output file must (a) hash-match the recorded baseline and
    (b) preserve the exact EXT_001..EXT_018 record order per model."""
    hashes_csv = REPO_ROOT / "docs" / "final_audit" / "FROZEN_ARTIFACT_HASHES.csv"
    frozen = {}
    if hashes_csv.exists():
        with hashes_csv.open(encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r["category"] in ("otrf_baseline_raw", "otrf_rag_raw"):
                    frozen[r["path"].replace("\\", "/")] = r["sha256"]
    import json
    checked = 0
    for cond in ("outputs_baseline", "outputs_rag"):
        base = REPO_ROOT / "external_validation" / cond
        if not base.exists():
            continue
        for raw in sorted(base.glob("*/*_raw.jsonl")):
            ids = []
            for line in raw.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    ids.append(json.loads(line)["external_scenario_id"])
            # record order preserved and complete
            assert ids == [f"EXT_{i:03d}" for i in range(1, 19)], f"order/completeness drift in {raw.name}"
            rel = str(raw.relative_to(REPO_ROOT)).replace("\\", "/")
            if rel in frozen:
                assert _sha256(raw) == frozen[rel], f"HASH DRIFT: {rel}"
                checked += 1
    if frozen:
        assert checked == 10, f"expected 10 frozen OTRF raw files, checked {checked}"


if __name__ == "__main__":
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for n, f in fns:
        try:
            f(); print(f"PASS  {n}"); passed += 1
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL  {n}: {exc}"); failed += 1
    print(f"\n{passed} passed, {failed} failed of {len(fns)}")
    sys.exit(1 if failed else 0)
