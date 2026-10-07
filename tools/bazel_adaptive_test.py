#!/usr/bin/env python3
"""Unit and fake-Bazel integration tests for the adaptive Bazel wrapper."""

import importlib.util
import io
import os
import signal
import subprocess
import sys
import tempfile
import threading
import textwrap
import time
import unittest
from contextlib import contextmanager
from pathlib import Path


sys.dont_write_bytecode = True

TOOLS_DIR = Path(__file__).resolve().parent
WRAPPER = TOOLS_DIR / "bazel_adaptive.py"

spec = importlib.util.spec_from_file_location("bazel_adaptive", WRAPPER)
bazel_adaptive = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["bazel_adaptive"] = bazel_adaptive
spec.loader.exec_module(bazel_adaptive)


def write_meminfo(path: Path, total_kb: int, available_kb: int) -> None:
    path.write_text(
        f"MemTotal:       {total_kb} kB\n"
        f"MemFree:        {available_kb} kB\n"
        f"MemAvailable:   {available_kb} kB\n",
        encoding="utf-8",
    )


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


@contextmanager
def temporary_env(name: str, value: str):
    old_value = os.environ.get(name)
    os.environ[name] = value
    try:
        yield
    finally:
        if old_value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = old_value


class ParsingTest(unittest.TestCase):
    def test_parses_integer_jobs_and_uses_environment_timeout(self) -> None:
        parsed = bazel_adaptive.parse_bazel_args(
            ["test", "--jobs=6", "--test_timeout", "999", "//tests/..."],
            action_timeout=42,
        )

        self.assertEqual(parsed.initial_jobs, 6)
        self.assertEqual(parsed.action_timeout, 42)

    def test_build_timeout_from_environment(self) -> None:
        self.assertEqual(
            bazel_adaptive.build_timeout_from_env({"BAZEL_ADAPTIVE_BUILD_TIMEOUT": "17"}),
            17,
        )
        self.assertEqual(bazel_adaptive.build_timeout_from_env({}), 150)
        with self.assertRaises(ValueError):
            bazel_adaptive.build_timeout_from_env({"BAZEL_ADAPTIVE_BUILD_TIMEOUT": "1m"})

    def test_bazel_nice_increment_from_environment(self) -> None:
        with temporary_env("BAZEL_ADAPTIVE_BAZEL_NICE", "0"):
            self.assertEqual(bazel_adaptive.bazel_nice_increment(), 0)
        with temporary_env("BAZEL_ADAPTIVE_BAZEL_NICE", "7"):
            self.assertEqual(bazel_adaptive.bazel_nice_increment(), 7)
        with temporary_env("BAZEL_ADAPTIVE_BAZEL_NICE", "999"):
            self.assertEqual(bazel_adaptive.bazel_nice_increment(), 19)
        with temporary_env("BAZEL_ADAPTIVE_BAZEL_NICE", "bad"):
            self.assertEqual(
                bazel_adaptive.bazel_nice_increment(),
                bazel_adaptive.DEFAULT_BAZEL_NICE,
            )

    def test_low_memory_threshold_from_environment(self) -> None:
        self.assertEqual(bazel_adaptive.low_memory_threshold_kb({}), 1024 * 1024)
        self.assertEqual(
            bazel_adaptive.low_memory_threshold_kb(
                {"BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB": "1024"}
            ),
            1024 * 1024,
        )
        with self.assertRaises(ValueError):
            bazel_adaptive.low_memory_threshold_kb(
                {"BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB": "2GB"}
            )

    def test_host_cpus_jobs_expression_sets_initial_cap(self) -> None:
        host_cpus = os.cpu_count() or 1
        half_cpus = max(1, int(host_cpus * 0.5))

        parsed = bazel_adaptive.parse_bazel_args(
            ["test", "--jobs=HOST_CPUS*.5"],
            action_timeout=100,
        )
        self.assertEqual(parsed.initial_jobs, half_cpus)

        parsed = bazel_adaptive.parse_bazel_args(
            ["test", "--jobs", "HOST_CPUS"],
            action_timeout=100,
        )
        self.assertEqual(parsed.initial_jobs, host_cpus)

    def test_host_ram_jobs_expression_sets_initial_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            meminfo = Path(tmp) / "meminfo"
            write_meminfo(meminfo, total_kb=10 * 1024 * 1024, available_kb=8 * 1024 * 1024)
            with temporary_env("BAZEL_ADAPTIVE_MEMINFO", str(meminfo)):
                parsed = bazel_adaptive.parse_bazel_args(
                    ["test", "--jobs=HOST_RAM*.0002"], action_timeout=100
                )
                self.assertEqual(parsed.initial_jobs, 2)

                parsed = bazel_adaptive.parse_bazel_args(
                    ["test", "--jobs", "HOST_RAM"],
                    action_timeout=100,
                )
                self.assertEqual(parsed.initial_jobs, 10 * 1024)

    def test_unknown_non_integer_jobs_falls_back_to_cpu_count(self) -> None:
        parsed = bazel_adaptive.parse_bazel_args(["test", "--jobs=auto"], action_timeout=100)

        self.assertEqual(parsed.initial_jobs, os.cpu_count() or 1)

    def test_rewrites_existing_jobs_for_attempt(self) -> None:
        parsed = bazel_adaptive.parse_bazel_args(
            ["test", "--jobs=HOST_CPUS", "//tests/..."], action_timeout=100
        )
        self.assertEqual(
            bazel_adaptive.bazel_args_with_jobs(parsed, 3),
            ["test", "--jobs=3", "//tests/..."],
        )

        parsed = bazel_adaptive.parse_bazel_args(
            ["test", "--jobs", "HOST_RAM", "//tests/..."], action_timeout=100
        )
        self.assertEqual(
            bazel_adaptive.bazel_args_with_jobs(parsed, 4),
            ["test", "--jobs", "4", "//tests/..."],
        )

    def test_inserts_jobs_without_parsing_startup_options(self) -> None:
        parsed = bazel_adaptive.parse_bazel_args(
            ["--future_startup_option", "value", "test", "//tests/..."],
            action_timeout=100,
        )

        self.assertEqual(parsed.job_locations, [])
        self.assertEqual(
            bazel_adaptive.bazel_args_with_jobs(parsed, 5),
            ["--future_startup_option", "value", "test", "//tests/...", "--jobs=5"],
        )

    def test_jobs_after_bazel_delimiter_are_target_arguments(self) -> None:
        parsed = bazel_adaptive.parse_bazel_args(
            ["run", "//tool", "--", "--jobs=2"],
            action_timeout=100,
        )

        self.assertEqual(parsed.job_locations, [])
        self.assertEqual(
            bazel_adaptive.bazel_args_with_jobs(parsed, 7),
            ["run", "//tool", "--jobs=7", "--", "--jobs=2"],
        )

    def test_does_not_add_jobs_to_commands_without_jobs_flag(self) -> None:
        parsed = bazel_adaptive.parse_bazel_args(
            ["query", "deps(//tests:all)"],
            action_timeout=100,
        )

        self.assertFalse(parsed.supports_jobs)
        self.assertEqual(parsed.job_locations, [])
        self.assertEqual(
            bazel_adaptive.bazel_args_with_jobs(parsed, 7),
            ["query", "deps(//tests:all)"],
        )

    def test_unknown_commands_pass_through_without_jobs(self) -> None:
        parsed = bazel_adaptive.parse_bazel_args(
            ["future-command", "--some_flag"],
            action_timeout=100,
        )

        self.assertFalse(parsed.supports_jobs)
        self.assertEqual(
            bazel_adaptive.bazel_args_with_jobs(parsed, 7),
            ["future-command", "--some_flag"],
        )

    def test_does_not_rewrite_jobs_on_commands_without_jobs_flag(self) -> None:
        parsed = bazel_adaptive.parse_bazel_args(
            ["query", "--jobs=99", "deps(//tests:all)"],
            action_timeout=100,
        )

        self.assertFalse(parsed.supports_jobs)
        self.assertEqual(parsed.job_locations, [])
        self.assertEqual(
            bazel_adaptive.bazel_args_with_jobs(parsed, 7),
            ["query", "--jobs=99", "deps(//tests:all)"],
        )

    def test_recognizes_jobs_commands_after_startup_options(self) -> None:
        parsed = bazel_adaptive.parse_bazel_args(
            ["--future_startup_option", "value", "aquery", "//tests:all"],
            action_timeout=100,
        )

        self.assertTrue(parsed.supports_jobs)
        self.assertEqual(
            bazel_adaptive.bazel_args_with_jobs(parsed, 7),
            ["--future_startup_option", "value", "aquery", "//tests:all", "--jobs=7"],
        )

    def test_jobs_command_word_as_possible_startup_option_value_passes_through(self) -> None:
        parsed = bazel_adaptive.parse_bazel_args(
            ["--future_startup_option", "run"],
            action_timeout=100,
        )

        self.assertFalse(parsed.supports_jobs)
        self.assertEqual(
            bazel_adaptive.bazel_args_with_jobs(parsed, 7),
            ["--future_startup_option", "run"],
        )

    def test_duration_parser(self) -> None:
        self.assertEqual(bazel_adaptive.parse_duration_seconds("Compiling x; 27s sandbox"), 27)
        self.assertEqual(bazel_adaptive.parse_duration_seconds("Compiling x; 27s remote"), 27)
        self.assertEqual(
            bazel_adaptive.parse_duration_seconds(
                "GoCompilePkg //proxylib:go_default_library; 27s remote"
            ),
            27,
        )
        self.assertEqual(bazel_adaptive.parse_duration_seconds("Rustc //crate:lib; 13s worker"), 13)
        self.assertEqual(
            bazel_adaptive.parse_duration_seconds("ProtoCompile //api:v1_proto; 9s linux-sandbox"),
            9,
        )
        self.assertEqual(bazel_adaptive.parse_duration_seconds("Compiling x; 2m13s sandbox"), 133)
        self.assertEqual(
            bazel_adaptive.parse_duration_seconds("Compiling x; 1h02m03s sandbox"),
            3723,
        )

    def test_displayed_action_durations_subtract_paused_time(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.note_actions_paused(100.0)

        displayed = bazel_adaptive.rewrite_action_duration_display(
            "    Compiling tests/a.cc; 56s processwrapper-sandbox\n"
            "    Compiling tests/b.cc; 2m13s processwrapper-sandbox\n",
            parser,
            now=130.0,
            paused_count=2,
        )

        self.assertIn("tests/a.cc; 26s processwrapper-sandbox", displayed)
        self.assertIn("tests/b.cc; 103s processwrapper-sandbox", displayed)

    def test_displayed_action_duration_rewrite_is_limited_to_paused_count(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.note_actions_paused(100.0)

        displayed = bazel_adaptive.rewrite_action_duration_display(
            "    Compiling tests/a.cc; 56s processwrapper-sandbox\n"
            "    Compiling tests/b.cc; 55s processwrapper-sandbox\n"
            "    Compiling tests/c.cc; 54s processwrapper-sandbox\n",
            parser,
            now=130.0,
            paused_count=2,
        )

        self.assertIn("tests/a.cc; 26s processwrapper-sandbox", displayed)
        self.assertIn("tests/b.cc; 25s processwrapper-sandbox", displayed)
        self.assertIn("tests/c.cc; 54s processwrapper-sandbox", displayed)

    def test_displayed_action_duration_rewrite_uses_paused_labels(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.note_actions_paused(100.0)
        parser.note_paused_labels({"tests/b.cc"}, 100.0)

        displayed = bazel_adaptive.rewrite_action_duration_display(
            "    Compiling tests/a.cc; 56s processwrapper-sandbox\n"
            "    Compiling tests/b.cc; 55s processwrapper-sandbox\n"
            "    Compiling tests/c.cc; 54s processwrapper-sandbox\n",
            parser,
            now=130.0,
            paused_count=2,
            paused_labels={"tests/b.cc"},
        )

        self.assertIn("tests/a.cc; 56s processwrapper-sandbox", displayed)
        self.assertIn("tests/b.cc; 25s processwrapper-sandbox", displayed)
        self.assertIn("tests/c.cc; 54s processwrapper-sandbox", displayed)

    def test_displayed_action_duration_keeps_adjusting_after_resume(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.note_actions_paused(100.0)
        parser.note_paused_labels({"tests/a.cc"}, 100.0)
        parser.note_actions_resumed(200.0)
        parser.note_paused_labels(set(), 200.0)

        displayed = bazel_adaptive.rewrite_action_duration_display(
            "    Compiling tests/a.cc; 101s processwrapper-sandbox\n"
            "    Compiling tests/b.cc; 101s processwrapper-sandbox\n",
            parser,
            now=201.0,
            paused_count=0,
        )

        self.assertIn("tests/a.cc; 1s processwrapper-sandbox", displayed)
        self.assertIn("tests/b.cc; 101s processwrapper-sandbox", displayed)

    def test_displayed_action_duration_freezes_when_paused_again(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.note_actions_paused(100.0)
        parser.note_paused_labels({"tests/a.cc"}, 100.0)
        parser.note_actions_resumed(200.0)
        parser.note_paused_labels(set(), 200.0)
        parser.note_actions_paused(210.0)
        parser.note_paused_labels({"tests/a.cc"}, 210.0)

        displayed = bazel_adaptive.rewrite_action_duration_display(
            "    Compiling tests/a.cc; 130s processwrapper-sandbox\n",
            parser,
            now=230.0,
            paused_count=1,
            paused_labels={"tests/a.cc"},
        )

        self.assertIn("tests/a.cc; 10s processwrapper-sandbox", displayed)

    def test_displayed_action_duration_history_is_kept_until_label_is_gone(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.note_paused_labels({"tests/a.cc"}, 100.0)
        parser.note_paused_labels(set(), 101.0)
        parser.note_live_action_labels({"tests/a.cc"}, 500.0)

        self.assertIn("tests/a.cc", parser.paused_duration_labels())

    def test_displayed_action_duration_history_is_pruned_after_label_is_gone(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.note_paused_labels({"tests/a.cc"}, 100.0)
        parser.note_paused_labels(set(), 101.0)
        parser.note_live_action_labels(set(), 500.0)

        self.assertNotIn("tests/a.cc", parser.paused_duration_labels())

    def test_displayed_action_durations_are_unchanged_without_paused_actions(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        text = "    Compiling tests/a.cc; 56s processwrapper-sandbox\n"

        displayed = bazel_adaptive.rewrite_action_duration_display(
            text,
            parser,
            now=130.0,
            paused_count=0,
        )

        self.assertEqual(displayed, text)


class MatchPatternTest(unittest.TestCase):
    def test_line_separator_pattern_splits_newline_and_carriage_return(self) -> None:
        self.assertEqual(
            bazel_adaptive.LINE_SEPARATOR_RE.split("first\rsecond\nthird"),
            ["first", "second", "third"],
        )

    def test_ansi_pattern_strips_terminal_control_sequences(self) -> None:
        self.assertEqual(
            bazel_adaptive.ANSI_RE.sub("", "\x1b[32mINFO: Build completed successfully\x1b[0m"),
            "INFO: Build completed successfully",
        )

    def test_progress_header_and_count_patterns_extract_done_and_total(self) -> None:
        line = "[10,586 / 10,588] 13 / 15 tests; 2 actions running"

        self.assertIsNotNone(bazel_adaptive.PROGRESS_HEADER_RE.match(line))
        match = bazel_adaptive.PROGRESS_COUNT_RE.match(line)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group("done"), "10,586")
        self.assertEqual(match.group("total"), "10,588")

    def test_running_count_pattern_extracts_each_bazel_form(self) -> None:
        match = bazel_adaptive.RUNNING_COUNT_RE.search("7 actions, 6 running")
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group("listed_actions"), "7")
        self.assertEqual(match.group("listed_running"), "6")

        match = bazel_adaptive.RUNNING_COUNT_RE.search("2 actions running")
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group("actions_running"), "2")

        match = bazel_adaptive.RUNNING_COUNT_RE.search("6 running")
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group("running"), "6")

        match = bazel_adaptive.RUNNING_COUNT_RE.search("1 action; last test: //tests:foo")
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group("action_only"), "1")

        match = bazel_adaptive.RUNNING_COUNT_RE.search("no actions running")
        self.assertIsNotNone(match)
        assert match is not None
        self.assertTrue(all(value is None for value in match.groupdict().values()))

    def test_action_duration_pattern_extracts_duration_fields(self) -> None:
        match = bazel_adaptive.ACTION_DURATION_RE.search(
            "GoCompilePkg //proxylib:go_default_library; 2m13s remote"
        )
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group("duration"), "2m13s")
        self.assertIsNone(match.group("hours"))
        self.assertEqual(match.group("minutes"), "2")
        self.assertEqual(match.group("seconds"), "13")

        match = bazel_adaptive.ACTION_DURATION_RE.search("Compiling x; 1h02m03s sandbox")
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group("hours"), "1")
        self.assertEqual(match.group("minutes"), "02")
        self.assertEqual(match.group("seconds"), "03")

    def test_jobs_keyword_pattern_extracts_keyword_and_multiplier(self) -> None:
        match = bazel_adaptive.JOBS_KEYWORD_RE.match("HOST_RAM*.0002")
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group("keyword"), "HOST_RAM")
        self.assertEqual(match.group("multiplier"), ".0002")

        match = bazel_adaptive.JOBS_KEYWORD_RE.match("HOST_CPUS")
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group("keyword"), "HOST_CPUS")
        self.assertIsNone(match.group("multiplier"))

    def test_failure_patterns_match_documented_examples(self) -> None:
        self.assertIsNotNone(
            bazel_adaptive.MEMORY_KILL_RE.search("ERROR: ... failed: (Killed): clang failed")
        )
        self.assertIsNotNone(
            bazel_adaptive.BUILD_FAILURE_RE.search(
                "ERROR: /tmp/example: Compiling example.cc failed: error executing CppCompile"
            )
        )
        self.assertIsNone(
            bazel_adaptive.BUILD_FAILURE_RE.search("Target //:envoy_binary_test failed to build")
        )
        self.assertIsNotNone(
            bazel_adaptive.SERVER_ABRUPT_RE.search(
                "Server terminated abruptly (error code: 14, error message: 'Socket closed')"
            )
        )
        self.assertIsNotNone(
            bazel_adaptive.INTERNAL_CRASH_RE.search(
                "FATAL: bazel crashed due to an internal error. Printing stack trace:"
            )
        )
        self.assertIsNotNone(
            bazel_adaptive.JAVA_INTERRUPTED_RE.search(
                "Caused by: java.lang.InterruptedException"
            )
        )
        self.assertIsNotNone(
            bazel_adaptive.BAZEL_USER_INTERRUPT_RE.search(
                "Bazel caught interrupt signal; cancelling pending invocation."
            )
        )
        self.assertIsNotNone(
            bazel_adaptive.BAZEL_USER_INTERRUPT_RE.search("ERROR: build interrupted")
        )

    def test_output_base_log_pattern_extracts_output_base(self) -> None:
        match = bazel_adaptive.OUTPUT_BASE_LOG_RE.search(
            "log file: '/home/user/.cache/bazel/_bazel_user/hash/server/jvm.out'"
        )
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group("output_base"), "/home/user/.cache/bazel/_bazel_user/hash")


class ProgressFrameTest(unittest.TestCase):
    def test_all_running_actions_must_be_over_limit(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[1 / 4] 2 actions, 2 running\n"
            "    GoCompilePkg //proxylib:go_default_library; 12s remote\n"
            "    Rustc //crate:lib; 8s worker\n"
        )

        self.assertFalse(parser.all_reported_actions_over(10))

        parser.feed(
            "[1 / 4] 2 actions, 2 running\r"
            "    ProtoCompile //api:v1_proto; 12s linux-sandbox\r"
            "    GoLink //cmd:proxy; 11s remote\r"
        )

        self.assertTrue(parser.all_reported_actions_over(10))

    def test_visible_action_sample_can_stand_in_for_hidden_running_actions(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[1 / 4] 2 actions, 2 running\n"
            "    Compiling a.cc; 12s processwrapper-sandbox\n"
        )

        self.assertTrue(parser.all_reported_actions_over(10))

    def test_visible_timeout_evidence_can_override_young_process_group_sample(self) -> None:
        class YoungGroupSample:
            def all_running_action_groups_over(self, _limit_seconds: int, _now: float) -> bool:
                return False

        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[5,617 / 5,640] 3 / 15 tests; 9 actions, 6 running\n"
            "    Compiling tests/cilium_network_policy_test.cc; "
            "252s processwrapper-sandbox\n",
            now=0.0,
        )

        has_evidence, subject = bazel_adaptive.action_timeout_evidence(
            parser,
            YoungGroupSample(),
            100,
            0.0,
        )

        self.assertTrue(has_evidence)
        self.assertEqual(subject, "all reported running actions")

    def test_partial_action_line_with_duration_counts_for_downscale(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed("[1 / 4] 2 actions, 2 running\n", now=0.0)
        parser.feed("    Compiling a.cc; 101s processwrapper-sandbox\n", now=0.0)
        parser.feed("    Compiling b.cc; 102s processwrapper-sandbox", now=0.0)

        self.assertTrue(parser.all_reported_actions_over(100, now=0.0))

    def test_incomplete_progress_frame_can_infer_missing_action_durations(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[10,543 / 10,576] 3 / 15 tests; 12 actions running; "
            "last test: //tests:health_check_sink_test\n",
            now=0.0,
        )
        parser.feed(
            "    Compiling tests/cilium_network_policy_test.cc; 136s processwrapper-sandbox\n"
            "    Compiling tests/bpf_metadata_config_test.cc; 131s processwrapper-sandbox\n"
            "    Compiling tests/bpf_metadata_integration_test.cc; 126s processwrapper-sandbox\n"
            "    Compiling tests/cilium_http_upstream_integration_test.cc; "
            "125s processwrapper-sandbox\n"
            "    Compiling tests/cilium_tls_tcp_integration_test.cc",
            now=0.0,
        )

        self.assertTrue(parser.all_reported_actions_over(100, now=0.0))

    def test_incomplete_progress_frame_ages_visible_actions_by_wall_clock(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed("[1 / 8] 4 actions running\n", now=0.0)
        parser.feed(
            "    Rustc //crate:lib; 80s remote\n"
            "    GoCompilePkg //pkg:go_default_library",
            now=0.0,
        )

        self.assertFalse(parser.all_reported_actions_over(100, now=10.0))
        self.assertTrue(parser.all_reported_actions_over(100, now=21.0))

    def test_complete_progress_frame_ages_visible_actions_during_silence(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[10,538 / 10,574] 2 / 14 tests; 7 actions, 6 running\n"
            "    Compiling tests/cilium_network_policy_test.cc; 76s processwrapper-sandbox\n"
            "    Compiling tests/bpf_metadata_config_test.cc; 76s processwrapper-sandbox\n"
            "    Compiling tests/bpf_metadata_integration_test.cc; 76s processwrapper-sandbox\n"
            "    Compiling tests/cilium_tcp_integration_test.cc; 76s processwrapper-sandbox\n"
            "    Compiling tests/cilium_tcp_integration.cc; 76s processwrapper-sandbox\n"
            "    Compiling tests/cilium_tcp_integration.cc; 76s processwrapper-sandbox\n",
            now=0.0,
        )

        self.assertFalse(parser.all_reported_actions_over(100, now=24.0))
        self.assertTrue(parser.all_reported_actions_over(100, now=25.0))

    def test_paused_time_does_not_count_toward_action_timeout(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[1 / 4] 2 actions, 2 running\n"
            "    Compiling a.cc; 90s processwrapper-sandbox\n"
            "    Compiling b.cc; 90s processwrapper-sandbox\n",
            now=90.0,
        )

        parser.note_actions_paused(95.0)
        parser.note_actions_resumed(125.0)
        parser.feed(
            "[1 / 4] 2 actions, 2 running\n"
            "    Compiling a.cc; 130s processwrapper-sandbox\n"
            "    Compiling b.cc; 130s processwrapper-sandbox\n",
            now=130.0,
        )

        self.assertFalse(parser.all_reported_actions_over(100, now=130.0))

        parser.feed(
            "[1 / 4] 2 actions, 2 running\n"
            "    Compiling a.cc; 131s processwrapper-sandbox\n"
            "    Compiling b.cc; 131s processwrapper-sandbox\n",
            now=131.0,
        )

        self.assertTrue(parser.all_reported_actions_over(100, now=131.0))

    def test_paused_time_does_not_age_actions_during_silent_output(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[1 / 4] 2 actions, 2 running\n"
            "    Compiling a.cc; 95s processwrapper-sandbox\n"
            "    Compiling b.cc; 95s processwrapper-sandbox\n",
            now=95.0,
        )

        parser.note_actions_paused(96.0)
        self.assertFalse(parser.all_reported_actions_over(100, now=200.0))
        parser.note_actions_resumed(200.0)

        self.assertFalse(parser.all_reported_actions_over(100, now=204.0))
        self.assertTrue(parser.all_reported_actions_over(100, now=205.1))

    def test_incomplete_progress_frame_without_visible_durations_uses_frame_age(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed("[1 / 8] 4 actions running\n", now=0.0)
        parser.feed("    Compiling tests/cilium_network_policy_test.cc", now=0.0)

        self.assertFalse(parser.all_reported_actions_over(100, now=100.0))
        self.assertTrue(parser.all_reported_actions_over(100, now=101.0))

    def test_actions_running_header_counts_all_running_actions(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[1 / 10] 3 actions running\n"
            "    Compiling a.cc; 12s processwrapper-sandbox\n"
            "    Compiling b.cc; 12s processwrapper-sandbox\n"
            "[2 / 10] 3 actions running\n"
            "    Compiling a.cc; 12s processwrapper-sandbox\n"
            "    Compiling b.cc; 12s processwrapper-sandbox\n"
        )

        self.assertTrue(parser.has_running_actions())
        self.assertTrue(parser.all_reported_actions_over(10))
        self.assertIsNone(parser.upscale_action_skip_reason(15, 2))

    def test_comma_actions_header_uses_running_count(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[10,501 / 10,575] 1 / 15 tests; 7 actions, 6 running\n"
            "    Compiling a.cc; 12s processwrapper-sandbox\n"
            "    Compiling b.cc; 12s processwrapper-sandbox\n"
            "    Compiling c.cc; 12s processwrapper-sandbox\n"
            "    Compiling d.cc; 12s processwrapper-sandbox\n"
            "    Compiling e.cc; 12s processwrapper-sandbox\n"
            "    Compiling f.cc; 12s processwrapper-sandbox\n"
        )

        self.assertEqual(parser.running_count, 6)
        self.assertTrue(parser.all_reported_actions_over(10))

    def test_non_pty_one_line_progress_extracts_summary_state(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[9,890 / 10,553] Compiling cilium/api/nphds.pb.cc; "
            "2s processwrapper-sandbox ... (13 actions, 12 running)\n",
            now=0.0,
        )

        self.assertEqual(parser.completed_count, 9890)
        self.assertEqual(parser.total_count, 10553)
        self.assertEqual(parser.running_count, 12)
        self.assertEqual(parser.current_action_durations(now=0.0), [2.0])
        self.assertFalse(parser.all_reported_actions_over(100, now=0.0))

    def test_non_pty_one_line_progress_can_trigger_timeout_downscale(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[9,890 / 10,553] Compiling cilium/api/nphds.pb.cc; "
            "101s processwrapper-sandbox ... (13 actions, 12 running)\n",
            now=0.0,
        )

        self.assertTrue(parser.all_reported_actions_over(100, now=0.0))

    def test_non_pty_one_line_progress_can_be_a_cheap_upscale_point(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[9,890 / 10,553] Compiling cilium/api/nphds.pb.cc; "
            "0s processwrapper-sandbox ... (12 actions, 11 running)\n"
            "[9,891 / 10,553] Compiling cilium/api/npds.pb.cc; "
            "5s processwrapper-sandbox ... (13 actions, 12 running)\n",
            now=0.0,
        )

        self.assertTrue(parser.meaningful_work_done)
        self.assertIsNone(parser.upscale_action_skip_reason(15, 2, now=0.0))

    def test_recent_completed_progress_is_tracked(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[9,890 / 10,553] Compiling a.cc; 1s processwrapper-sandbox "
            "... (13 actions, 12 running)\n",
            now=10.0,
        )
        parser.feed(
            "[9,891 / 10,553] Compiling b.cc; 1s processwrapper-sandbox "
            "... (13 actions, 12 running)\n",
            now=20.0,
        )

        self.assertTrue(parser.completed_progress_recent(now=50.0, window_seconds=31.0))
        self.assertFalse(parser.completed_progress_recent(now=52.0, window_seconds=31.0))

    def test_mid_build_running_count_fluctuation_is_not_winding_down(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[10,429 / 10,553] Compiling source/common/upstream/upstream_impl.cc; "
            "11s processwrapper-sandbox ... (12 actions, 11 running)\n"
            "[10,429 / 10,553] Compiling source/common/upstream/upstream_impl.cc; "
            "13s processwrapper-sandbox ... (13 actions, 12 running)\n"
            "[10,430 / 10,553] Compiling source/common/upstream/upstream_impl.cc; "
            "15s processwrapper-sandbox ... (12 actions, 11 running)\n"
            "[10,430 / 10,553] Compiling source/common/upstream/upstream_impl.cc; "
            "16s processwrapper-sandbox ... (13 actions, 12 running)\n"
            "[10,441 / 10,553] Compiling source/extensions/upstreams/http/generic/config.cc; "
            "9s processwrapper-sandbox ... (13 actions, 12 running)\n"
            "[10,442 / 10,553] Compiling source/extensions/clusters/logical_dns/"
            "logical_dns_cluster.cc; 10s processwrapper-sandbox ... "
            "(12 actions, 11 running)\n",
            now=0.0,
        )

        self.assertEqual(parser.running_count, 11)
        self.assertTrue(parser.running_count_decreased)
        self.assertIsNone(parser.upscale_action_skip_reason(15, 2, now=0.0))

    def test_non_pty_one_line_test_progress_extracts_summary_state(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[8,182 / 8,369] Compiling source/common/listener_manager/"
            "listener_manager_impl.cc; 18s processwrapper-sandbox ... "
            "(12 actions, 11 running)\n"
            "[8,183 / 8,369] Compiling source/common/listener_manager/"
            "listener_manager_impl.cc; 19s processwrapper-sandbox ... "
            "(13 actions, 12 running)\n"
            "[8,190 / 8,369] 1 / 15 tests; Compiling test/mocks/upstream/"
            "host_set.cc; 15s processwrapper-sandbox ... (13 actions, 12 running)\n"
            "[8,191 / 8,369] 1 / 15 tests; Compiling source/common/tcp_proxy/"
            "upstream.cc; 15s processwrapper-sandbox ... (13 actions, 12 running)\n"
            "[8,192 / 8,369] 1 / 15 tests; Compiling test/mocks/upstream/"
            "cluster_info.cc; 15s processwrapper-sandbox ... (12 actions, 11 running)\n"
            "[8,195 / 8,369] 1 / 15 tests; Compiling test/mocks/upstream/"
            "cluster_info.cc; 23s processwrapper-sandbox ... (13 actions, 12 running)\n",
            now=0.0,
        )

        self.assertEqual(parser.completed_count, 8195)
        self.assertEqual(parser.total_count, 8369)
        self.assertEqual(parser.running_count, 12)
        self.assertEqual(parser.current_action_durations(now=0.0), [23.0])
        self.assertTrue(parser.meaningful_work_done)
        self.assertTrue(parser.current_frame_has_summary_duration)
        self.assertTrue(parser.all_reported_actions_over(20, now=0.0))

    def test_upscale_action_age_guard(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[1 / 10] 2 actions, 2 running\n"
            "    Compiling a.cc; 14s processwrapper-sandbox\n"
            "    Compiling b.cc; 3s processwrapper-sandbox\n"
            "[2 / 10] 2 actions, 2 running\n"
            "    Compiling a.cc; 14s remote\n"
            "    Compiling b.cc; 3s remote\n"
        )
        self.assertIsNone(parser.upscale_action_skip_reason(15, 2))
        self.assertEqual(
            parser.current_action_age_description(),
            "oldest current action 14s",
        )

        parser.feed(
            "[1 / 4] 2 actions, 2 running\n"
            "    Compiling a.cc; 15s processwrapper-sandbox\n"
            "    Compiling b.cc; 3s processwrapper-sandbox\n"
        )
        self.assertIn(
            "oldest current running action is 15s",
            parser.upscale_action_skip_reason(15, 2),
        )

    def test_upscale_action_age_uses_wall_clock_when_bazel_is_silent(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[1 / 10] 2 actions, 2 running\n"
            "    Compiling a.cc; 0s processwrapper-sandbox\n"
            "    Compiling b.cc; 0s processwrapper-sandbox\n"
            "[2 / 10] 2 actions, 2 running\n"
            "    Compiling a.cc; 0s processwrapper-sandbox\n"
            "    Compiling b.cc; 0s processwrapper-sandbox\n",
            now=0.0,
        )

        self.assertIsNone(parser.upscale_action_skip_reason(15, 2, now=14.0))
        self.assertIn(
            "oldest current running action is 15s",
            parser.upscale_action_skip_reason(15, 2, now=15.0),
        )

    def test_upscale_requires_meaningful_work(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[1 / 4] 2 actions, 2 running\n"
            "    Compiling a.cc; 1s remote\n"
            "    Compiling b.cc; 1s remote\n"
        )

        self.assertIn(
            "completed action count has not advanced",
            parser.upscale_action_skip_reason(15, 2),
        )

    def test_upscale_skips_when_actions_are_winding_down(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[1 / 10] 3 actions, 3 running\n"
            "    Compiling a.cc; 1s remote\n"
            "    Compiling b.cc; 1s remote\n"
            "    Compiling c.cc; 1s remote\n"
            "[2 / 10] 2 actions, 2 running\n"
            "    Compiling b.cc; 1s remote\n"
            "    Compiling c.cc; 1s remote\n"
        )

        self.assertIn("running action count is decreasing", parser.upscale_action_skip_reason(15, 2))

        parser.feed("[3 / 4] no actions running\n")
        self.assertIn("no actions are currently running", parser.upscale_action_skip_reason(15, 2))

    def test_upscale_skips_when_all_remaining_actions_are_running(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[10,585 / 10,588] 13 / 15 tests; 2 actions running\n"
            "    Testing //tests:cilium_tls_http_integration_test; 0s processwrapper-sandbox\n"
            "    Testing //tests:cilium_tls_tcp_integration_test; 0s processwrapper-sandbox\n"
            "[10,586 / 10,588] 13 / 15 tests; 2 actions running; "
            "last test: //tests:cilium_http_integration_test\n"
            "    Testing //tests:cilium_tls_http_integration_test; 0s processwrapper-sandbox\n"
            "    Testing //tests:cilium_tls_tcp_integration_test; 0s processwrapper-sandbox\n"
        )

        self.assertIn("only 2 action(s) remain", parser.upscale_action_skip_reason(15, 2))

    def test_upscale_skips_singular_action_near_finish(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[10,419 / 10,421] 13 / 14 tests; 2 actions running; last test: //tests:foo\n"
            "    Testing //tests:foo; 1s processwrapper-sandbox\n"
            "    Testing //tests:bar; 1s processwrapper-sandbox\n"
            "[10,420 / 10,421] 13 / 14 tests;  1 action; last test: //tests:foo\n"
            "    Testing //tests:foo; 2s processwrapper-sandbox\n"
        )

        self.assertEqual(parser.running_count, 1)
        self.assertIn("only 1 action(s) remain", parser.upscale_action_skip_reason(15, 2))

    def test_upscale_skips_compact_near_finish_without_running_count(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[5,641 / 5,642] 14 / 15 tests; [Prepa] "
            "Linking tests/cilium_websocket_codec_integration_test\n"
            "[5,642 / 5,643] 14 / 15 tests; "
            "Testing //tests:cilium_websocket_codec_integration_test; "
            "0s processwrapper-sandbox\n"
        )

        self.assertIsNone(parser.running_count)
        self.assertIn("only 1 action(s) remain", parser.upscale_action_skip_reason(15, 2))

    def test_upscale_near_finish_guard_uses_current_jobs_threshold(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[100 / 120] 8 actions running\n"
            "    Compiling a.cc; 1s processwrapper-sandbox\n"
            "[110 / 120] 8 actions running\n"
            "    Compiling b.cc; 1s processwrapper-sandbox\n"
        )

        self.assertIsNone(parser.upscale_action_skip_reason(15, 8))
        self.assertIn("need more than 12", parser.upscale_action_skip_reason(15, 12))


class DiagnosticsTest(unittest.TestCase):
    def test_diag_clears_terminal_line_only_for_tty(self) -> None:
        class FakeStderr(io.StringIO):
            def fileno(self) -> int:
                return 123

        old_stderr = sys.stderr
        old_isatty = bazel_adaptive.os.isatty
        old_start_time = bazel_adaptive.WRAPPER_START_TIME
        old_buffer_interactive = bazel_adaptive.DIAG_BUFFER_INTERACTIVE
        old_buffer = bazel_adaptive.DIAG_BUFFER
        try:
            bazel_adaptive.DIAG_BUFFER_INTERACTIVE = False
            bazel_adaptive.DIAG_BUFFER = []
            tty_output = FakeStderr()
            sys.stderr = tty_output
            bazel_adaptive.os.isatty = lambda fd: fd == 123
            bazel_adaptive.WRAPPER_START_TIME = time.monotonic() - 5
            bazel_adaptive.diag("hello")
            self.assertEqual(tty_output.getvalue(), "\r\x1b[K[bazel-adaptive/5s] hello\n")

            plain_output = FakeStderr()
            sys.stderr = plain_output
            bazel_adaptive.os.isatty = lambda _fd: False
            bazel_adaptive.WRAPPER_START_TIME = time.monotonic() - 7
            bazel_adaptive.diag("hello")
            self.assertEqual(plain_output.getvalue(), "[bazel-adaptive/7s] hello\n")
        finally:
            sys.stderr = old_stderr
            bazel_adaptive.os.isatty = old_isatty
            bazel_adaptive.WRAPPER_START_TIME = old_start_time
            bazel_adaptive.DIAG_BUFFER_INTERACTIVE = old_buffer_interactive
            bazel_adaptive.DIAG_BUFFER = old_buffer

    def test_diag_buffers_while_interactive_bazel_is_running(self) -> None:
        class FakeStderr(io.StringIO):
            def fileno(self) -> int:
                return 123

        old_stderr = sys.stderr
        old_isatty = bazel_adaptive.os.isatty
        old_start_time = bazel_adaptive.WRAPPER_START_TIME
        old_buffer_interactive = bazel_adaptive.DIAG_BUFFER_INTERACTIVE
        old_buffer = bazel_adaptive.DIAG_BUFFER
        try:
            output = FakeStderr()
            sys.stderr = output
            bazel_adaptive.os.isatty = lambda fd: fd == 123
            bazel_adaptive.WRAPPER_START_TIME = time.monotonic() - 5
            bazel_adaptive.DIAG_BUFFER_INTERACTIVE = False
            bazel_adaptive.DIAG_BUFFER = []

            bazel_adaptive.start_interactive_diag_buffering(True)
            bazel_adaptive.diag("pause event")
            self.assertEqual(output.getvalue(), "")

            bazel_adaptive.stop_interactive_diag_buffering()
            bazel_adaptive.flush_interactive_diag_buffer()
            self.assertEqual(
                output.getvalue(),
                "\r\x1b[K[bazel-adaptive/5s] pause event\n",
            )
        finally:
            sys.stderr = old_stderr
            bazel_adaptive.os.isatty = old_isatty
            bazel_adaptive.WRAPPER_START_TIME = old_start_time
            bazel_adaptive.DIAG_BUFFER_INTERACTIVE = old_buffer_interactive
            bazel_adaptive.DIAG_BUFFER = old_buffer


class StreamForwardingTest(unittest.TestCase):
    def test_drain_ready_streams_forwards_partial_lines_immediately(self) -> None:
        read_fd, write_fd = os.pipe()
        selector = None
        try:
            output = io.BytesIO()
            selector = bazel_adaptive.selectors.DefaultSelector()
            selector.register(
                read_fd,
                bazel_adaptive.selectors.EVENT_READ,
                bazel_adaptive.StreamTarget(output, lambda: os.close(read_fd)),
            )
            os.write(write_fd, b"partial Bazel progress without newline")
            parser = bazel_adaptive.ProgressFrameParser()

            bazel_adaptive.drain_ready_streams(selector, parser, 1.0)

            self.assertEqual(output.getvalue(), b"partial Bazel progress without newline")
            self.assertEqual(parser._buffer, "partial Bazel progress without newline")
        finally:
            os.close(write_fd)
            if selector is not None:
                selector.close()
            try:
                os.close(read_fd)
            except OSError:
                pass

    def test_drain_ready_streams_rewrites_paused_action_counts(self) -> None:
        read_fd, write_fd = os.pipe()
        selector = None
        try:
            output = io.BytesIO()
            selector = bazel_adaptive.selectors.DefaultSelector()
            selector.register(
                read_fd,
                bazel_adaptive.selectors.EVENT_READ,
                bazel_adaptive.StreamTarget(output, lambda: os.close(read_fd)),
            )
            data = (
                b"[1 / 4] Compiling a.cc; 1s processwrapper-sandbox ... "
                b"(12 actions, 11 running)\n"
                b"[2 / 4] Compiling b.cc; 1s processwrapper-sandbox ... "
                b"(8 actions running)\n"
                b"[3 / 4] 8 actions running\n"
                b"[4 / 4] 13 actions, 12 running\n"
            )
            os.write(write_fd, data)
            parser = bazel_adaptive.ProgressFrameParser()

            bazel_adaptive.drain_ready_streams(selector, parser, 1.0, lambda: 10)

            displayed = output.getvalue().decode("utf-8")
            self.assertIn("(12 actions, 10 paused, 1 running)", displayed)
            self.assertIn("(8 actions, 8 paused, 0 running)", displayed)
            self.assertIn("[3 / 4] 8 actions, 8 paused, 0 running", displayed)
            self.assertIn("[4 / 4] 13 actions, 10 paused, 2 running", displayed)
            self.assertEqual(parser.running_count, 12)
        finally:
            os.close(write_fd)
            if selector is not None:
                selector.close()
            try:
                os.close(read_fd)
            except OSError:
                pass


class MemoryTest(unittest.TestCase):
    def test_memory_thresholds(self) -> None:
        low = bazel_adaptive.MemInfo(total_kb=8 * 1024 * 1024, available_kb=512 * 1024)
        high = bazel_adaptive.MemInfo(total_kb=8 * 1024 * 1024, available_kb=5 * 1024 * 1024)

        self.assertLess(low.available_kb, bazel_adaptive.low_memory_threshold_kb())
        self.assertLessEqual(low.available_kb * 2, low.total_kb)
        self.assertGreaterEqual(high.available_kb, bazel_adaptive.low_memory_threshold_kb())
        self.assertGreater(high.available_kb * 2, high.total_kb)
        self.assertEqual(bazel_adaptive.downscale_jobs(12), 6)
        self.assertEqual(bazel_adaptive.downscale_jobs(6), 3)
        self.assertEqual(bazel_adaptive.downscale_jobs(5), 3)
        self.assertEqual(bazel_adaptive.downscale_jobs(3), 2)
        self.assertEqual(bazel_adaptive.downscale_jobs(2), 1)
        self.assertEqual(bazel_adaptive.downscale_jobs(1), 1)
        self.assertEqual(bazel_adaptive.upscale_jobs(2, 12), 3)
        self.assertEqual(bazel_adaptive.upscale_jobs(3, 12), 5)
        self.assertEqual(bazel_adaptive.upscale_jobs(8, 12), 12)

    def test_configurable_memory_threshold(self) -> None:
        meminfo = bazel_adaptive.MemInfo(total_kb=8 * 1024 * 1024, available_kb=1536 * 1024)

        self.assertGreaterEqual(meminfo.available_kb, bazel_adaptive.low_memory_threshold_kb())
        with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "2048"):
            self.assertLess(meminfo.available_kb, bazel_adaptive.low_memory_threshold_kb())

    def test_recent_average_controls_upscale_decision(self) -> None:
        monitor = bazel_adaptive.MemoryPressureMonitor(poll_interval=1.0)
        now = 100.0
        monitor.samples = [
            (
                now - 29,
                bazel_adaptive.MemInfo(
                    total_kb=8 * 1024 * 1024,
                    available_kb=5 * 1024 * 1024,
                ),
            ),
            (
                now - 10,
                bazel_adaptive.MemInfo(
                    total_kb=8 * 1024 * 1024,
                    available_kb=5 * 1024 * 1024,
                ),
            ),
        ]
        monitor.last = monitor.samples[-1][1]

        self.assertIsNone(
            monitor.upscale_skip_reason(
                now,
                running_actions_seconds=30.0,
                required_running_actions_seconds=30.0,
            )
        )
        self.assertTrue(monitor.retry_same_jobs_after_failure(now))

        monitor.samples.append(
            (
                now,
                bazel_adaptive.MemInfo(
                    total_kb=8 * 1024 * 1024,
                    available_kb=512 * 1024,
                ),
            )
        )
        monitor.last = monitor.samples[-1][1]
        self.assertIn(
            "memory dipped below low-memory threshold",
            monitor.upscale_skip_reason(
                now,
                running_actions_seconds=30.0,
                required_running_actions_seconds=30.0,
            ),
        )
        self.assertFalse(monitor.retry_same_jobs_after_failure(now))

    def test_upscale_waits_for_running_action_window(self) -> None:
        monitor = bazel_adaptive.MemoryPressureMonitor(poll_interval=1.0)
        now = 100.0
        monitor.samples = [
            (
                now - 29,
                bazel_adaptive.MemInfo(
                    total_kb=8 * 1024 * 1024,
                    available_kb=5 * 1024 * 1024,
                ),
            ),
            (
                now,
                bazel_adaptive.MemInfo(
                    total_kb=8 * 1024 * 1024,
                    available_kb=5 * 1024 * 1024,
                ),
            ),
        ]
        monitor.last = monitor.samples[-1][1]

        self.assertIn(
            "not been observed",
            monitor.upscale_skip_reason(
                now,
                running_actions_seconds=None,
                required_running_actions_seconds=30.0,
            ),
        )
        self.assertIn(
            "observed for 10s",
            monitor.upscale_skip_reason(
                now,
                running_actions_seconds=10.0,
                required_running_actions_seconds=30.0,
            ),
        )
        self.assertIsNone(
            monitor.upscale_skip_reason(
                now,
                running_actions_seconds=30.0,
                required_running_actions_seconds=30.0,
            )
        )

    def test_recent_low_memory_blocks_upscale_even_if_average_is_high(self) -> None:
        monitor = bazel_adaptive.MemoryPressureMonitor(poll_interval=1.0)
        now = 100.0
        monitor.samples = [
            (
                now - 29,
                bazel_adaptive.MemInfo(
                    total_kb=16 * 1024 * 1024,
                    available_kb=16 * 1024 * 1024,
                ),
            ),
            (
                now,
                bazel_adaptive.MemInfo(
                    total_kb=16 * 1024 * 1024,
                    available_kb=512 * 1024,
                ),
            ),
        ]
        monitor.last = monitor.samples[-1][1]

        self.assertIn(
            "memory dipped below low-memory threshold",
            monitor.upscale_skip_reason(
                now,
                running_actions_seconds=30.0,
                required_running_actions_seconds=30.0,
            ),
        )

    def test_failure_report_is_compact(self) -> None:
        monitor = bazel_adaptive.MemoryPressureMonitor(poll_interval=1.0)
        now = 100.0
        monitor.samples = [
            (now - 20, bazel_adaptive.MemInfo(total_kb=8 * 1024 * 1024, available_kb=1024 * 1024)),
            (now, bazel_adaptive.MemInfo(total_kb=8 * 1024 * 1024, available_kb=3 * 1024 * 1024)),
        ]
        monitor.last = monitor.samples[-1][1]
        monitor.last_low_at = now - 5
        monitor.last_low = monitor.samples[0][1]

        self.assertEqual(
            monitor.failure_report(now),
            "memory pressure: latest 3072/8192 MiB; 30s average 2048 MiB; "
            "min 1024 MiB; less than low-memory threshold 1024 MiB: yes",
        )

    def test_renice_build_processes_updates_detected_children(self) -> None:
        old_dangling = bazel_adaptive.dangling_build_processes
        old_setpriority = bazel_adaptive.os.setpriority
        old_env = os.environ.get("BAZEL_ADAPTIVE_BAZEL_NICE")
        calls: list[tuple[int, int, int]] = []
        try:
            os.environ["BAZEL_ADAPTIVE_BAZEL_NICE"] = "5"
            bazel_adaptive.dangling_build_processes = lambda _context: [
                bazel_adaptive.ProcessInfo(101, "clang", "/tmp/out", 0, 10),
                bazel_adaptive.ProcessInfo(102, "clang", "/tmp/out", 5, 20),
                bazel_adaptive.ProcessInfo(103, "clang", "/tmp/out", None, 30),
            ]
            bazel_adaptive.os.setpriority = (
                lambda which, pid, priority: calls.append((which, pid, priority))
            )

            bazel_adaptive.renice_build_processes(bazel_adaptive.BuildContext("/tmp/work"))

            self.assertEqual(
                calls,
                [
                    (os.PRIO_PROCESS, 101, 5),
                    (os.PRIO_PROCESS, 103, 5),
                ],
            )
        finally:
            bazel_adaptive.dangling_build_processes = old_dangling
            bazel_adaptive.os.setpriority = old_setpriority
            if old_env is None:
                os.environ.pop("BAZEL_ADAPTIVE_BAZEL_NICE", None)
            else:
                os.environ["BAZEL_ADAPTIVE_BAZEL_NICE"] = old_env

    def test_build_process_groups_use_sandbox_action_key(self) -> None:
        old_dangling = bazel_adaptive.dangling_build_processes
        try:
            bazel_adaptive.dangling_build_processes = lambda _context: [
                bazel_adaptive.ProcessInfo(
                    201,
                    "process-wrapper",
                    "/tmp/out/sandbox/processwrapper-sandbox/7/execroot/ws",
                    0,
                    100,
                ),
                bazel_adaptive.ProcessInfo(
                    202,
                    "clang /tmp/out/execroot/cilium/external/envoy/test/mocks/server/foo.cc",
                    "/tmp/out/sandbox/processwrapper-sandbox/7/execroot/ws",
                    0,
                    105,
                ),
                bazel_adaptive.ProcessInfo(
                    203,
                    "clang /tmp/out/sandbox/processwrapper-sandbox/8/execroot/ws/input",
                    None,
                    0,
                    200,
                ),
            ]

            groups = bazel_adaptive.build_process_groups(bazel_adaptive.BuildContext("/tmp/work"))

            groups_by_key = {group.key: group for group in groups}
            self.assertEqual(groups_by_key["processwrapper-sandbox/7"].pids, [201, 202])
            self.assertEqual(groups_by_key["processwrapper-sandbox/7"].started_at_ticks, 100)
            self.assertIn(
                "test/mocks/server/foo.cc",
                groups_by_key["processwrapper-sandbox/7"].action_labels,
            )
            self.assertEqual(groups_by_key["processwrapper-sandbox/8"].pids, [203])
        finally:
            bazel_adaptive.dangling_build_processes = old_dangling

    def test_build_process_groups_include_sandbox_descendants(self) -> None:
        old_dangling = bazel_adaptive.dangling_build_processes
        try:
            bazel_adaptive.dangling_build_processes = lambda _context: [
                bazel_adaptive.ProcessInfo(
                    211,
                    "process-wrapper",
                    "/tmp/out/sandbox/processwrapper-sandbox/9/execroot/ws",
                    0,
                    100,
                ),
                bazel_adaptive.ProcessInfo(
                    212,
                    "clang -c tests/child.cc",
                    None,
                    0,
                    110,
                    ppid=211,
                ),
            ]

            groups = bazel_adaptive.build_process_groups(bazel_adaptive.BuildContext("/tmp/work"))

            self.assertEqual(groups[0].key, "processwrapper-sandbox/9")
            self.assertEqual(groups[0].pids, [211, 212])
            self.assertIn("tests/child.cc", groups[0].action_labels)
        finally:
            bazel_adaptive.dangling_build_processes = old_dangling

    def test_bazel_servers_for_workspace_are_scoped_to_wrapper_cgroup(self) -> None:
        old_proc_pids = bazel_adaptive.proc_pids
        old_process_info = bazel_adaptive.process_info
        own_cgroup = (("", "/docker/build-a"),)
        other_cgroup = (("", "/docker/build-b"),)
        infos = {
            401: bazel_adaptive.ProcessInfo(
                401,
                "java -jar A-server.jar --workspace_directory=/tmp/work "
                "--output_base=/tmp/out-a",
                None,
                0,
                10,
                cgroups=own_cgroup,
            ),
            402: bazel_adaptive.ProcessInfo(
                402,
                "java -jar A-server.jar --workspace_directory=/tmp/work "
                "--output_base=/tmp/out-b",
                None,
                0,
                20,
                cgroups=other_cgroup,
            ),
        }
        try:
            bazel_adaptive.proc_pids = lambda: sorted(infos)
            bazel_adaptive.process_info = lambda pid: infos.get(pid)

            servers = bazel_adaptive.bazel_servers_for_workspace("/tmp/work", own_cgroup)

            self.assertEqual([server.pid for server in servers], [401])
            self.assertEqual(servers[0].output_base, "/tmp/out-a")
        finally:
            bazel_adaptive.proc_pids = old_proc_pids
            bazel_adaptive.process_info = old_process_info

    def test_dangling_build_processes_ignores_other_cgroup_output_base(self) -> None:
        old_proc_pids = bazel_adaptive.proc_pids
        old_process_info = bazel_adaptive.process_info
        own_cgroup = (("", "/docker/build-a"),)
        other_cgroup = (("", "/docker/build-b"),)
        infos = {
            411: bazel_adaptive.ProcessInfo(
                411,
                "process-wrapper /tmp/out-a/sandbox/processwrapper-sandbox/1/execroot/ws",
                "/tmp/out-a/sandbox/processwrapper-sandbox/1/execroot/ws",
                0,
                10,
                cgroups=own_cgroup,
            ),
            412: bazel_adaptive.ProcessInfo(
                412,
                "clang -c a.cc",
                None,
                0,
                20,
                ppid=411,
                cgroups=own_cgroup,
            ),
            421: bazel_adaptive.ProcessInfo(
                421,
                "process-wrapper /tmp/out-b/sandbox/processwrapper-sandbox/1/execroot/ws",
                "/tmp/out-b/sandbox/processwrapper-sandbox/1/execroot/ws",
                0,
                30,
                cgroups=other_cgroup,
            ),
            422: bazel_adaptive.ProcessInfo(
                422,
                "clang -c /tmp/out-b/execroot/ws/b.cc",
                None,
                0,
                40,
                ppid=421,
                cgroups=other_cgroup,
            ),
        }
        try:
            bazel_adaptive.proc_pids = lambda: sorted(infos)
            bazel_adaptive.process_info = lambda pid: infos.get(pid)
            context = bazel_adaptive.BuildContext("/tmp/work", cgroups=own_cgroup)
            context.add_output_base("/tmp/out-a")
            context.add_output_base("/tmp/out-b")

            processes = bazel_adaptive.dangling_build_processes(context)

            self.assertEqual([process.pid for process in processes], [411, 412])
        finally:
            bazel_adaptive.proc_pids = old_proc_pids
            bazel_adaptive.process_info = old_process_info

    def test_action_throttler_pauses_youngest_and_resumes_oldest(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        signals: list[tuple[int, int]] = []
        groups = [
            bazel_adaptive.ActionProcessGroup("old", [301, 302], 100),
            bazel_adaptive.ActionProcessGroup("middle", [303], 200),
            bazel_adaptive.ActionProcessGroup("young", [304], 300, {"tests/young.cc"}),
        ]
        try:
            stderr = io.StringIO()
            sys.stderr = stderr
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "2048"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )

                throttler.pause_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=5 * 1024 * 1024,
                    )
                )
                throttler.pause_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=4 * 1024 * 1024,
                    )
                )
                throttler.pause_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=3 * 1024 * 1024,
                    )
                )
                throttler.pause_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=2 * 1024 * 1024,
                    )
                )
                throttler.resume_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=3 * 1024 * 1024,
                    )
                )

            self.assertEqual(
                signals,
                [
                    (304, signal.SIGSTOP),
                ],
            )
            self.assertEqual(throttler.paused_keys, {"young"})
            self.assertEqual(throttler.paused_pids, {"young": {304}})
            self.assertEqual(throttler.paused_labels(), {"tests/young.cc"})
            self.assertEqual(stderr.getvalue(), "")
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.os.kill = old_kill
            sys.stderr = old_stderr

    def test_action_throttler_does_not_resume_into_immediate_repause(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        signals: list[tuple[int, int]] = []
        groups = [
            bazel_adaptive.ActionProcessGroup("old", [601], 100),
            bazel_adaptive.ActionProcessGroup("young", [602], 200),
        ]
        try:
            sys.stderr = io.StringIO()
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "2048"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )

                throttler.pause_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=4 * 1024 * 1024,
                    )
                )
                throttler.resume_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=3 * 1024 * 1024,
                    )
                )
                throttler.resume_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=5 * 1024 * 1024,
                    )
                )

            self.assertEqual(
                signals,
                [
                    (602, signal.SIGSTOP),
                    (602, signal.SIGCONT),
                ],
            )
            self.assertEqual(throttler.paused_keys, set())
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.os.kill = old_kill
            sys.stderr = old_stderr

    def test_action_throttler_waits_for_swap_in_budget_before_resume(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_process_swap_kb = bazel_adaptive.process_swap_kb
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        signals: list[tuple[int, int]] = []
        groups = [
            bazel_adaptive.ActionProcessGroup("old", [701], 100),
            bazel_adaptive.ActionProcessGroup("young", [702], 200),
        ]
        try:
            sys.stderr = io.StringIO()
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.process_swap_kb = lambda _pid: 3 * 1024 * 1024
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "2048"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )

                throttler.pause_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=4 * 1024 * 1024,
                    )
                )
                throttler.resume_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=5 * 1024 * 1024,
                    )
                )
                throttler.resume_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=6 * 1024 * 1024,
                    )
                )

            self.assertEqual(
                signals,
                [
                    (702, signal.SIGSTOP),
                    (702, signal.SIGCONT),
                ],
            )
            self.assertEqual(throttler.paused_keys, set())
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.process_swap_kb = old_process_swap_kb
            bazel_adaptive.os.kill = old_kill
            sys.stderr = old_stderr

    def test_action_throttler_waits_for_running_io_stalls_to_clear_before_resume_when_memory_is_tight(
        self,
    ) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_process_swap_kb = bazel_adaptive.process_swap_kb
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        signals: list[tuple[int, int]] = []
        groups = [
            bazel_adaptive.ActionProcessGroup("old", [711], 100),
            bazel_adaptive.ActionProcessGroup("middle", [712], 200, states={"T"}),
            bazel_adaptive.ActionProcessGroup("young", [713], 300, states={"T"}),
        ]
        try:
            sys.stderr = io.StringIO()
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.process_swap_kb = lambda _pid: 0
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "2048"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )
                throttler.paused_keys = {"middle", "young"}
                throttler.paused_pids = {"middle": {712}, "young": {713}}
                groups = [
                    bazel_adaptive.ActionProcessGroup("old", [711], 100, states={"D"}),
                    bazel_adaptive.ActionProcessGroup("middle", [712], 200, states={"T"}),
                    bazel_adaptive.ActionProcessGroup("young", [713], 300, states={"T"}),
                ]
                throttler.resume_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=3 * 1024 * 1024,
                    )
                )
                groups = [
                    bazel_adaptive.ActionProcessGroup("old", [711], 100),
                    bazel_adaptive.ActionProcessGroup("middle", [712], 200, states={"T"}),
                    bazel_adaptive.ActionProcessGroup("young", [713], 300, states={"T"}),
                ]
                throttler.resume_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=3 * 1024 * 1024,
                    )
                )
                throttler.last_running_io_stall_at = (
                    time.monotonic() - bazel_adaptive.RESUME_IO_STALL_CLEAR_SECONDS
                )
                throttler.resume_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=3 * 1024 * 1024,
                    )
                )
                groups = [
                    bazel_adaptive.ActionProcessGroup("old", [711], 100),
                    bazel_adaptive.ActionProcessGroup("middle", [712], 200),
                    bazel_adaptive.ActionProcessGroup("young", [713], 300, states={"T"}),
                ]
                throttler.resume_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=8 * 1024 * 1024,
                    )
                )

            self.assertEqual(
                signals,
                [
                    (712, signal.SIGCONT),
                ],
            )
            self.assertEqual(throttler.paused_keys, {"young"})
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.process_swap_kb = old_process_swap_kb
            bazel_adaptive.os.kill = old_kill
            sys.stderr = old_stderr

    def test_action_throttler_waits_for_resumed_memory_to_settle(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_process_swap_kb = bazel_adaptive.process_swap_kb
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        signals: list[tuple[int, int]] = []
        groups = [
            bazel_adaptive.ActionProcessGroup("old", [713], 100),
            bazel_adaptive.ActionProcessGroup("middle", [714], 200, states={"T"}),
            bazel_adaptive.ActionProcessGroup("young", [715], 300, states={"T"}),
        ]
        try:
            sys.stderr = io.StringIO()
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.process_swap_kb = lambda _pid: 0
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "2048"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )
                throttler.paused_keys = {"middle", "young"}
                throttler.paused_pids = {"middle": {714}, "young": {715}}

                throttler.resume_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=8 * 1024 * 1024,
                    )
                )
                groups = [
                    bazel_adaptive.ActionProcessGroup("old", [713], 100),
                    bazel_adaptive.ActionProcessGroup("middle", [714], 200),
                    bazel_adaptive.ActionProcessGroup("young", [715], 300, states={"T"}),
                ]
                throttler.resume_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=8 * 1024 * 1024,
                    )
                )
                throttler.next_normal_resume_at = (
                    time.monotonic() - bazel_adaptive.RESUME_MEMORY_SETTLE_SECONDS
                )
                throttler.resume_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=8 * 1024 * 1024,
                    )
                )

            self.assertEqual(
                signals,
                [
                    (714, signal.SIGCONT),
                    (715, signal.SIGCONT),
                ],
            )
            self.assertEqual(throttler.paused_keys, set())
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.process_swap_kb = old_process_swap_kb
            bazel_adaptive.os.kill = old_kill
            sys.stderr = old_stderr

    def test_action_throttler_applies_lowered_stall_floor_without_waiting_for_lower_memory(
        self,
    ) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_process_swap_kb = bazel_adaptive.process_swap_kb
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        signals: list[tuple[int, int]] = []
        groups = [
            bazel_adaptive.ActionProcessGroup(
                f"running-{index}",
                [720 + index],
                100 + index,
                states={"D"} if index == 0 else set(),
            )
            for index in range(6)
        ] + [
            bazel_adaptive.ActionProcessGroup(
                f"paused-{index}",
                [730 + index],
                200 + index,
                states={"T"},
            )
            for index in range(6)
        ]
        try:
            sys.stderr = io.StringIO()
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.process_swap_kb = lambda _pid: 0
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "2048"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )
                throttler.paused_keys = {f"paused-{index}" for index in range(6)}
                throttler.paused_pids = {
                    f"paused-{index}": {730 + index} for index in range(6)
                }
                throttler.io_stall_started_at = (
                    time.monotonic() - bazel_adaptive.DEFAULT_IO_STALL_FLOOR_SECONDS
                )

                throttler.update(
                    bazel_adaptive.MemInfo(
                        total_kb=16 * 1024 * 1024,
                        available_kb=2500 * 1024,
                    )
                )

            self.assertEqual(signals, [(725, signal.SIGSTOP)])
            self.assertEqual(throttler.io_stall_floor_groups, 3)
            self.assertEqual(len(throttler.paused_keys), 7)
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.process_swap_kb = old_process_swap_kb
            bazel_adaptive.os.kill = old_kill
            sys.stderr = old_stderr

    def test_action_throttler_resumes_one_group_if_all_current_groups_are_paused(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        signals: list[tuple[int, int]] = []
        groups = [
            bazel_adaptive.ActionProcessGroup("old", [721], 100),
            bazel_adaptive.ActionProcessGroup("young", [722], 200),
        ]
        try:
            stderr = io.StringIO()
            sys.stderr = stderr
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "2048"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )
                throttler.paused_keys = {"old", "young"}
                throttler.paused_pids = {"old": {721}, "young": {722}}

                throttler.resume_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=1 * 1024 * 1024,
                    )
                )

            self.assertEqual(signals, [(721, signal.SIGCONT)])
            self.assertEqual(throttler.paused_keys, {"young"})
            self.assertIn(
                "to keep at least one action group running",
                stderr.getvalue(),
            )
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.os.kill = old_kill
            sys.stderr = old_stderr

    def test_action_throttler_resumes_one_group_if_all_current_groups_are_physically_stopped(
        self,
    ) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        signals: list[tuple[int, int]] = []
        groups = [
            bazel_adaptive.ActionProcessGroup("old", [731], 100, states={"T"}),
            bazel_adaptive.ActionProcessGroup("young", [732], 200, states={"T"}),
        ]
        try:
            stderr = io.StringIO()
            sys.stderr = stderr
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "2048"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )

                throttler.pause_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=1 * 1024 * 1024,
                    )
                )

            self.assertEqual(signals, [(731, signal.SIGCONT)])
            self.assertIn(
                "to keep at least one action group running",
                stderr.getvalue(),
            )
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.os.kill = old_kill
            sys.stderr = old_stderr

    def test_action_throttler_ignores_non_action_helpers_for_running_floor(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        signals: list[tuple[int, int]] = []
        groups = [
            bazel_adaptive.ActionProcessGroup(
                "processwrapper-sandbox/1",
                [741],
                100,
                states={"T"},
            ),
            bazel_adaptive.ActionProcessGroup("pid:900", [900], 200, states={"S"}),
        ]
        try:
            stderr = io.StringIO()
            sys.stderr = stderr
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "2048"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )

                throttler.pause_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=1 * 1024 * 1024,
                    )
                )

            self.assertEqual(signals, [(741, signal.SIGCONT)])
            self.assertIn(
                "to keep at least one action group running",
                stderr.getvalue(),
            )
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.os.kill = old_kill
            sys.stderr = old_stderr

    def test_action_throttler_keeps_half_running_for_memory_pressure_alone(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        signals: list[tuple[int, int]] = []
        groups = [
            bazel_adaptive.ActionProcessGroup(f"group-{index}", [800 + index], index)
            for index in range(12)
        ]
        try:
            sys.stderr = io.StringIO()
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "1024"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )

                for _ in range(20):
                    throttler.pause_if_needed(
                        bazel_adaptive.MemInfo(
                            total_kb=8 * 1024 * 1024,
                            available_kb=512 * 1024,
                        )
                    )

            self.assertEqual(
                len([sig for _pid, sig in signals if sig == signal.SIGSTOP]),
                6,
            )
            self.assertEqual(len(throttler.paused_keys), 6)
            self.assertEqual(len(groups) - len(throttler.paused_keys), 6)
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.os.kill = old_kill
            sys.stderr = old_stderr

    def test_downscale_memory_threshold_uses_pause_watch_threshold_when_paused(self) -> None:
        with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "1024"):
            throttler = bazel_adaptive.ActionThrottler(
                bazel_adaptive.BuildContext("/tmp/work")
            )

            self.assertEqual(
                throttler.downscale_memory_threshold_kb(),
                1024 * 1024,
            )
            throttler.paused_keys = {"processwrapper-sandbox/1"}
            self.assertEqual(
                throttler.downscale_memory_threshold_kb(),
                2 * 1024 * 1024,
            )

    def test_running_action_group_timeout_ignores_paused_groups(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_monotonic = bazel_adaptive.time.monotonic
        now = 1000.0

        def ticks_for_age(seconds: float) -> int:
            return int((now - seconds) * bazel_adaptive.CLOCK_TICKS_PER_SECOND)

        groups = [
            bazel_adaptive.ActionProcessGroup("running", [840], ticks_for_age(50)),
            bazel_adaptive.ActionProcessGroup(
                "paused",
                [841],
                ticks_for_age(500),
                states={"T"},
            ),
        ]
        try:
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.time.monotonic = lambda: now
            throttler = bazel_adaptive.ActionThrottler(
                bazel_adaptive.BuildContext("/tmp/work")
            )
            throttler.paused_keys = {"paused"}

            self.assertFalse(throttler.all_running_action_groups_over(100, now))

            groups[0] = bazel_adaptive.ActionProcessGroup(
                "running",
                [840],
                ticks_for_age(150),
            )
            throttler.paused_total_seconds["running"] = 60.0
            self.assertFalse(throttler.all_running_action_groups_over(100, now))

            throttler.paused_total_seconds["running"] = 40.0
            self.assertTrue(throttler.all_running_action_groups_over(100, now))
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.time.monotonic = old_monotonic

    def test_timeout_downscale_defers_after_recent_progress_without_io_stall(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[5,617 / 5,640] 3 / 15 tests; Compiling a.cc; "
            "101s processwrapper-sandbox ... (9 actions, 6 running)\n",
            now=1000.0,
        )
        parser.feed(
            "[5,618 / 5,640] 3 / 15 tests; Compiling b.cc; "
            "101s processwrapper-sandbox ... (9 actions, 6 running)\n",
            now=1010.0,
        )
        throttler = bazel_adaptive.ActionThrottler(bazel_adaptive.BuildContext("/tmp/work"))

        self.assertTrue(
            bazel_adaptive.action_timeout_evidence(parser, throttler, 100, 1010.0)[0]
        )
        self.assertIsNotNone(
            bazel_adaptive.timeout_downscale_defer_reason(parser, throttler, 100, 1010.0)
        )

        throttler.current_io_stall_observed = True
        self.assertIsNone(
            bazel_adaptive.timeout_downscale_defer_reason(parser, throttler, 100, 1010.0)
        )

    def test_timeout_downscale_does_not_defer_after_progress_gets_old(self) -> None:
        parser = bazel_adaptive.ProgressFrameParser()
        parser.feed(
            "[5,617 / 5,640] 3 / 15 tests; Compiling a.cc; "
            "101s processwrapper-sandbox ... (9 actions, 6 running)\n",
            now=1000.0,
        )
        parser.feed(
            "[5,618 / 5,640] 3 / 15 tests; Compiling b.cc; "
            "101s processwrapper-sandbox ... (9 actions, 6 running)\n",
            now=1010.0,
        )
        throttler = bazel_adaptive.ActionThrottler(bazel_adaptive.BuildContext("/tmp/work"))

        self.assertIsNone(
            bazel_adaptive.timeout_downscale_defer_reason(parser, throttler, 100, 1111.0)
        )

    def test_action_throttler_halves_floor_after_sustained_io_stall(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        old_monotonic = bazel_adaptive.time.monotonic
        signals: list[tuple[int, int]] = []
        groups = [
            bazel_adaptive.ActionProcessGroup(f"group-{index}", [900 + index], index, states={"D"})
            for index in range(12)
        ]
        try:
            stderr = io.StringIO()
            sys.stderr = stderr
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            bazel_adaptive.time.monotonic = lambda: 11.0
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "1024"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )
                throttler.io_stall_started_at = 0.0

                for _ in range(20):
                    throttler.pause_if_needed(
                        bazel_adaptive.MemInfo(
                            total_kb=8 * 1024 * 1024,
                            available_kb=512 * 1024,
                        )
                    )

            self.assertEqual(throttler.io_stall_floor_groups, 3)
            self.assertEqual(
                len([sig for _pid, sig in signals if sig == signal.SIGSTOP]),
                9,
            )
            self.assertEqual(len(groups) - len(throttler.paused_keys), 3)
            self.assertIn(
                "lowering pause floor from 6 to 3 running action group(s)",
                stderr.getvalue(),
            )
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.os.kill = old_kill
            bazel_adaptive.time.monotonic = old_monotonic
            sys.stderr = old_stderr

    def test_action_throttler_repeatedly_halves_floor_while_io_stall_remains(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        old_monotonic = bazel_adaptive.time.monotonic
        signals: list[tuple[int, int]] = []
        now = 0.0
        groups = [
            bazel_adaptive.ActionProcessGroup(f"group-{index}", [920 + index], index, states={"D"})
            for index in range(12)
        ]
        try:
            stderr = io.StringIO()
            sys.stderr = stderr
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            bazel_adaptive.time.monotonic = lambda: now
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "1024"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )
                throttler.io_stall_started_at = 0.0

                for expected_now, expected_floor, expected_running in (
                    (11.0, 3, 3),
                    (21.0, 2, 2),
                    (31.0, 1, 1),
                ):
                    now = expected_now
                    for _ in range(20):
                        throttler.pause_if_needed(
                            bazel_adaptive.MemInfo(
                                total_kb=8 * 1024 * 1024,
                                available_kb=512 * 1024,
                            )
                        )
                    self.assertEqual(throttler.io_stall_floor_groups, expected_floor)
                    self.assertEqual(
                        len(groups) - len(throttler.paused_keys),
                        expected_running,
                    )

            self.assertIn(
                "lowering pause floor from 6 to 3 running action group(s)",
                stderr.getvalue(),
            )
            self.assertIn(
                "lowering pause floor from 3 to 2 running action group(s)",
                stderr.getvalue(),
            )
            self.assertIn(
                "lowering pause floor from 2 to 1 running action group(s)",
                stderr.getvalue(),
            )
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.os.kill = old_kill
            bazel_adaptive.time.monotonic = old_monotonic
            sys.stderr = old_stderr

    def test_action_throttler_resets_io_stall_window_when_blocking_clears(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        old_monotonic = bazel_adaptive.time.monotonic
        signals: list[tuple[int, int]] = []
        now = 0.0
        stalled = True

        def groups() -> list[bazel_adaptive.ActionProcessGroup]:
            states = {"D"} if stalled else {"R"}
            return [
                bazel_adaptive.ActionProcessGroup(
                    f"group-{index}",
                    [940 + index],
                    index,
                    states=states,
                )
                for index in range(12)
            ]

        try:
            sys.stderr = io.StringIO()
            bazel_adaptive.build_process_groups = lambda _context: groups()
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            bazel_adaptive.time.monotonic = lambda: now
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "1024"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )

                for _ in range(20):
                    throttler.pause_if_needed(
                        bazel_adaptive.MemInfo(
                            total_kb=8 * 1024 * 1024,
                            available_kb=512 * 1024,
                        )
                    )
                self.assertEqual(throttler.io_stall_started_at, 0.0)

                now = 4.9
                stalled = False
                throttler.pause_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=512 * 1024,
                    )
                )
                self.assertIsNone(throttler.io_stall_started_at)

                now = 11.0
                stalled = True
                for _ in range(20):
                    throttler.pause_if_needed(
                        bazel_adaptive.MemInfo(
                            total_kb=8 * 1024 * 1024,
                            available_kb=512 * 1024,
                        )
                    )

            self.assertIsNone(throttler.io_stall_floor_groups)
            self.assertEqual(len(groups()) - len(throttler.paused_keys), 6)
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.os.kill = old_kill
            bazel_adaptive.time.monotonic = old_monotonic
            sys.stderr = old_stderr

    def test_action_throttler_halves_floor_after_sustained_swap_io(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        old_monotonic = bazel_adaptive.time.monotonic
        old_read_swap_io = bazel_adaptive.read_swap_io
        signals: list[tuple[int, int]] = []
        now = 0.0
        groups = [
            bazel_adaptive.ActionProcessGroup(f"group-{index}", [960 + index], index)
            for index in range(12)
        ]

        def fake_swap_io() -> bazel_adaptive.SwapIo:
            return bazel_adaptive.SwapIo(pages_in=int(now * 20000))

        try:
            sys.stderr = io.StringIO()
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            bazel_adaptive.time.monotonic = lambda: now
            bazel_adaptive.read_swap_io = fake_swap_io
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "1024"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )

                now = 0.0
                throttler.pause_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=512 * 1024,
                    )
                )
                now = 1.0
                for _ in range(20):
                    throttler.pause_if_needed(
                        bazel_adaptive.MemInfo(
                            total_kb=8 * 1024 * 1024,
                            available_kb=512 * 1024,
                        )
                    )
                self.assertEqual(len(groups) - len(throttler.paused_keys), 6)

                now = 11.5
                for _ in range(20):
                    throttler.pause_if_needed(
                        bazel_adaptive.MemInfo(
                            total_kb=8 * 1024 * 1024,
                            available_kb=512 * 1024,
                        )
                    )
                    now += 0.1

            self.assertEqual(throttler.io_stall_floor_groups, 3)
            self.assertEqual(len(groups) - len(throttler.paused_keys), 3)
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.os.kill = old_kill
            bazel_adaptive.time.monotonic = old_monotonic
            bazel_adaptive.read_swap_io = old_read_swap_io
            sys.stderr = old_stderr

    def test_action_throttler_ignores_swap_in_during_resume_grace(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        old_monotonic = bazel_adaptive.time.monotonic
        old_read_swap_io = bazel_adaptive.read_swap_io
        signals: list[tuple[int, int]] = []
        now = 0.0
        groups = [
            bazel_adaptive.ActionProcessGroup(f"running-{index}", [980 + index], index)
            for index in range(6)
        ] + [
            bazel_adaptive.ActionProcessGroup(
                f"paused-{index}",
                [990 + index],
                100 + index,
                states={"T"},
            )
            for index in range(6)
        ]

        def fake_swap_io() -> bazel_adaptive.SwapIo:
            return bazel_adaptive.SwapIo(pages_in=int(now * 20000))

        def fake_kill(pid: int, sig: int) -> None:
            signals.append((pid, sig))
            if sig == signal.SIGCONT:
                for group in groups:
                    if pid in group.pids:
                        group.states = set()

        try:
            sys.stderr = io.StringIO()
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.os.kill = fake_kill
            bazel_adaptive.time.monotonic = lambda: now
            bazel_adaptive.read_swap_io = fake_swap_io
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "1024"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )
                throttler.paused_keys = {f"paused-{index}" for index in range(6)}
                throttler.paused_pids = {
                    f"paused-{index}": {990 + index} for index in range(6)
                }

                throttler.resume_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=8 * 1024 * 1024,
                    )
                )
                for sample_now in (1.0, 2.0, 4.0):
                    now = sample_now
                    throttler.resume_if_needed(
                        bazel_adaptive.MemInfo(
                            total_kb=8 * 1024 * 1024,
                            available_kb=8 * 1024 * 1024,
                        )
                    )

            self.assertEqual(signals, [(990, signal.SIGCONT)])
            self.assertIsNone(throttler.io_stall_started_at)
            self.assertIsNone(throttler.io_stall_floor_groups)
            self.assertEqual(throttler.low_memory_threshold_kb(), 1024 * 1024)
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.os.kill = old_kill
            bazel_adaptive.time.monotonic = old_monotonic
            bazel_adaptive.read_swap_io = old_read_swap_io
            sys.stderr = old_stderr

    def test_action_throttler_never_pauses_the_last_running_group(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        signals: list[tuple[int, int]] = []
        groups = [
            bazel_adaptive.ActionProcessGroup("only", [1001], 100, states={"D"}),
        ]
        try:
            sys.stderr = io.StringIO()
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "1024"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )
                throttler.io_stall_floor_groups = 1

                throttler.pause_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=128 * 1024,
                    )
                )

            self.assertEqual(signals, [])
            self.assertEqual(throttler.paused_keys, set())
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.os.kill = old_kill
            sys.stderr = old_stderr

    def test_action_throttler_raises_threshold_when_running_jobs_stall_on_io(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        signals: list[tuple[int, int]] = []
        groups = [
            bazel_adaptive.ActionProcessGroup("old", [801], 100, states={"R"}),
            bazel_adaptive.ActionProcessGroup("young", [802], 200, states={"D"}),
        ]
        try:
            stderr = io.StringIO()
            sys.stderr = stderr
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "1024"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )

                throttler.pause_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=2 * 1024 * 1024,
                    )
                )

            self.assertEqual(throttler.low_memory_threshold_kb(), 1280 * 1024)
            self.assertEqual(signals, [(802, signal.SIGSTOP)])
            self.assertIn(
                "raising low-memory threshold from 1024 to 1280 MiB",
                stderr.getvalue(),
            )
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.os.kill = old_kill
            sys.stderr = old_stderr

    def test_action_throttler_lowers_threshold_after_stalls_clear(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        groups = [
            bazel_adaptive.ActionProcessGroup("old", [811], 100, states={"R"}),
            bazel_adaptive.ActionProcessGroup("young", [812], 200, states={"R"}),
        ]
        try:
            stderr = io.StringIO()
            sys.stderr = stderr
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.os.kill = lambda _pid, _sig: None
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "1024"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )
                throttler.effective_threshold_kb = 1536 * 1024
                throttler.next_threshold_lower_at = 0.0

                throttler.resume_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=4 * 1024 * 1024,
                    )
                )

            self.assertEqual(throttler.low_memory_threshold_kb(), 1280 * 1024)
            self.assertIn(
                "lowering low-memory threshold from 1536 to 1280 MiB",
                stderr.getvalue(),
            )
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.os.kill = old_kill
            sys.stderr = old_stderr

    def test_action_throttler_resume_all_clears_stopped_groups(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        signals: list[tuple[int, int]] = []
        groups = [
            bazel_adaptive.ActionProcessGroup("old", [401], 100),
            bazel_adaptive.ActionProcessGroup("young", [402, 403], 200),
        ]
        try:
            sys.stderr = io.StringIO()
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "2048"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )

                throttler.pause_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=4 * 1024 * 1024,
                    )
                )
                resumed = throttler.resume_all("before test restart")

            self.assertEqual(
                signals,
                [
                    (402, signal.SIGSTOP),
                    (403, signal.SIGSTOP),
                    (402, signal.SIGCONT),
                    (403, signal.SIGCONT),
                ],
            )
            self.assertEqual(resumed, 1)
            self.assertEqual(throttler.paused_keys, set())
            self.assertEqual(throttler.paused_pids, {})
            self.assertIn(
                "resumed 1 paused Bazel action group(s) before test restart",
                sys.stderr.getvalue(),
            )
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.os.kill = old_kill
            sys.stderr = old_stderr

    def test_action_throttler_resume_all_uses_remembered_pids(self) -> None:
        old_build_process_groups = bazel_adaptive.build_process_groups
        old_kill = bazel_adaptive.os.kill
        old_stderr = sys.stderr
        signals: list[tuple[int, int]] = []
        groups = [
            bazel_adaptive.ActionProcessGroup("old", [501], 100),
            bazel_adaptive.ActionProcessGroup("young", [502], 200),
        ]
        try:
            sys.stderr = io.StringIO()
            bazel_adaptive.build_process_groups = lambda _context: groups
            bazel_adaptive.os.kill = lambda pid, sig: signals.append((pid, sig))
            with temporary_env("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB", "2048"):
                throttler = bazel_adaptive.ActionThrottler(
                    bazel_adaptive.BuildContext("/tmp/work")
                )

                throttler.pause_if_needed(
                    bazel_adaptive.MemInfo(
                        total_kb=8 * 1024 * 1024,
                        available_kb=4 * 1024 * 1024,
                    )
                )
                bazel_adaptive.build_process_groups = lambda _context: []
                resumed = throttler.resume_all("before test exit")

            self.assertEqual(
                signals,
                [
                    (502, signal.SIGSTOP),
                    (502, signal.SIGCONT),
                ],
            )
            self.assertEqual(resumed, 1)
            self.assertEqual(throttler.paused_keys, set())
            self.assertEqual(throttler.paused_pids, {})
        finally:
            bazel_adaptive.build_process_groups = old_build_process_groups
            bazel_adaptive.os.kill = old_kill
            sys.stderr = old_stderr

    def test_memory_kill_resumes_paused_groups_before_bazel_exits(self) -> None:
        old_action_throttler = bazel_adaptive.ActionThrottler
        old_stderr = sys.stderr
        meminfo_env = "BAZEL_ADAPTIVE_MEMINFO"
        old_meminfo_env = os.environ.get(meminfo_env)
        resume_reasons: list[str | None] = []

        class CapturingStderr(io.StringIO):
            def __init__(self) -> None:
                super().__init__()
                self.buffer = io.BytesIO()

            def fileno(self) -> int:
                raise OSError("test stderr has no file descriptor")

        class FakeActionThrottler:
            def __init__(self, _context: bazel_adaptive.BuildContext) -> None:
                pass

            def update(self, _meminfo: bazel_adaptive.MemInfo | None) -> None:
                pass

            def pause_if_needed(self, _meminfo: bazel_adaptive.MemInfo | None) -> None:
                pass

            def resume_if_needed(self, _meminfo: bazel_adaptive.MemInfo | None) -> None:
                pass

            def paused_count(self) -> int:
                return 0

            def paused_labels(self) -> set[str]:
                return set()

            def resume_all(self, reason: str | None = None) -> int:
                resume_reasons.append(reason)
                return 1

        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            meminfo = tmpdir / "meminfo"
            script = tmpdir / "bazel"
            write_meminfo(meminfo, total_kb=8 * 1024 * 1024, available_kb=7 * 1024 * 1024)
            script.write_text(
                "#!/usr/bin/env python3\n"
                "import sys, time\n"
                "print('ERROR: Compiling tests/example.cc failed: (Killed): clang failed', "
                "file=sys.stderr, flush=True)\n"
                "time.sleep(0.2)\n"
                "sys.exit(1)\n",
                encoding="utf-8",
            )
            script.chmod(0o755)

            try:
                sys.stderr = CapturingStderr()
                os.environ[meminfo_env] = str(meminfo)
                bazel_adaptive.ActionThrottler = FakeActionThrottler
                parsed = bazel_adaptive.parse_bazel_args(
                    ["build", "--jobs=2", "//:target"],
                    action_timeout=1,
                )

                result = bazel_adaptive.run_once(
                    str(script),
                    parsed,
                    jobs=2,
                    max_jobs=2,
                    context=bazel_adaptive.BuildContext(str(tmpdir)),
                )

                self.assertEqual(result.restart, "same")
                self.assertEqual(
                    resume_reasons[0],
                    "because Bazel reported a killed or terminated action",
                )
            finally:
                sys.stderr = old_stderr
                bazel_adaptive.ActionThrottler = old_action_throttler
                if old_meminfo_env is None:
                    os.environ.pop(meminfo_env, None)
                else:
                    os.environ[meminfo_env] = old_meminfo_env

    def test_user_signal_resumes_paused_groups_before_bazel_exits(self) -> None:
        old_action_throttler = bazel_adaptive.ActionThrottler
        old_stderr = sys.stderr
        old_user_terminating = bazel_adaptive.USER_TERMINATING
        meminfo_env = "BAZEL_ADAPTIVE_MEMINFO"
        old_meminfo_env = os.environ.get(meminfo_env)
        resume_reasons: list[str | None] = []

        class CapturingStderr(io.StringIO):
            def __init__(self) -> None:
                super().__init__()
                self.buffer = io.BytesIO()

            def fileno(self) -> int:
                raise OSError("test stderr has no file descriptor")

        class FakeActionThrottler:
            def __init__(self, _context: bazel_adaptive.BuildContext) -> None:
                self.paused = True

            def update(self, _meminfo: bazel_adaptive.MemInfo | None) -> None:
                pass

            def pause_if_needed(self, _meminfo: bazel_adaptive.MemInfo | None) -> None:
                pass

            def resume_if_needed(self, _meminfo: bazel_adaptive.MemInfo | None) -> None:
                pass

            def paused_count(self) -> int:
                return 1 if self.paused else 0

            def paused_labels(self) -> set[str]:
                return {"tests/example.cc"} if self.paused else set()

            def resume_all(self, reason: str | None = None) -> int:
                resume_reasons.append(reason)
                was_paused = self.paused
                self.paused = False
                return 1 if was_paused else 0

        def send_user_signal() -> None:
            bazel_adaptive.USER_TERMINATING = True
            process = bazel_adaptive.ACTIVE_PROCESS
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass

        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            meminfo = tmpdir / "meminfo"
            script = tmpdir / "bazel"
            write_meminfo(meminfo, total_kb=8 * 1024 * 1024, available_kb=7 * 1024 * 1024)
            script.write_text(
                "#!/usr/bin/env python3\n"
                "import signal, sys, time\n"
                "def on_sigint(signum, frame):\n"
                "    sys.exit(130)\n"
                "signal.signal(signal.SIGINT, on_sigint)\n"
                "print('[1 / 2] 1 action running', flush=True)\n"
                "time.sleep(30)\n",
                encoding="utf-8",
            )
            script.chmod(0o755)

            timer = threading.Timer(0.2, send_user_signal)
            try:
                sys.stderr = CapturingStderr()
                os.environ[meminfo_env] = str(meminfo)
                bazel_adaptive.ActionThrottler = FakeActionThrottler
                bazel_adaptive.USER_TERMINATING = False
                parsed = bazel_adaptive.parse_bazel_args(
                    ["build", "--jobs=2", "//:target"],
                    action_timeout=1,
                )

                timer.start()
                result = bazel_adaptive.run_once(
                    str(script),
                    parsed,
                    jobs=2,
                    max_jobs=2,
                    context=bazel_adaptive.BuildContext(str(tmpdir)),
                )

                self.assertEqual(result.exit_code, 130)
                self.assertEqual(
                    resume_reasons[0],
                    "because the wrapper received a user signal",
                )
            finally:
                timer.cancel()
                sys.stderr = old_stderr
                bazel_adaptive.ActionThrottler = old_action_throttler
                bazel_adaptive.USER_TERMINATING = old_user_terminating
                if old_meminfo_env is None:
                    os.environ.pop(meminfo_env, None)
                else:
                    os.environ[meminfo_env] = old_meminfo_env


class FakeBazelIntegrationTest(unittest.TestCase):
    def make_fake_bazel(self, tmpdir: Path) -> Path:
        fake = tmpdir / "fake_bazel.py"
        fake.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import os
                import signal
                import subprocess
                import sys
                import time
                from pathlib import Path

                log = Path(os.environ["FAKE_BAZEL_LOG"])
                meminfo = Path(os.environ["BAZEL_ADAPTIVE_MEMINFO"])
                mode = os.environ.get("FAKE_BAZEL_MODE", "scale")
                count_path = Path(os.environ["FAKE_BAZEL_COUNT"])

                def append(message):
                    with log.open("a", encoding="utf-8") as output:
                        output.write(message + "\\n")

                def count_invocation():
                    try:
                        count = int(count_path.read_text(encoding="utf-8"))
                    except FileNotFoundError:
                        count = 0
                    count += 1
                    count_path.write_text(str(count), encoding="utf-8")
                    return count

                def write_meminfo_text(text):
                    tmp = meminfo.with_suffix(".tmp")
                    tmp.write_text(text, encoding="utf-8")
                    tmp.replace(meminfo)

                def write_high_mem():
                    write_meminfo_text(
                        "MemTotal:       4194304 kB\\n"
                        "MemFree:        3145728 kB\\n"
                        "MemAvailable:   3145728 kB\\n"
                    )

                def write_high_mem_later():
                    subprocess.Popen(
                        [
                            sys.executable,
                            "-c",
                            "import os, time; from pathlib import Path; "
                            "time.sleep(0.5); "
                            "Path(os.environ['BAZEL_ADAPTIVE_MEMINFO']).write_text("
                            "'MemTotal:       4194304 kB\\\\n'"
                            "'MemFree:        3145728 kB\\\\n'"
                            "'MemAvailable:   3145728 kB\\\\n', encoding='utf-8')",
                        ],
                        env=os.environ.copy(),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )

                def write_recovered_mem():
                    write_meminfo_text(
                        "MemTotal:       4194304 kB\\n"
                        "MemFree:        2200000 kB\\n"
                        "MemAvailable:   2200000 kB\\n"
                    )

                def write_low_mem():
                    write_meminfo_text(
                        "MemTotal:       4194304 kB\\n"
                        "MemFree:        1048576 kB\\n"
                        "MemAvailable:   1048576 kB\\n"
                    )

                def write_mid_large_mem():
                    write_meminfo_text(
                        "MemTotal:       8388608 kB\\n"
                        "MemFree:        3145728 kB\\n"
                        "MemAvailable:   3145728 kB\\n"
                    )

                def write_high_large_mem():
                    write_meminfo_text(
                        "MemTotal:       8388608 kB\\n"
                        "MemFree:        6291456 kB\\n"
                        "MemAvailable:   6291456 kB\\n"
                    )

                if len(sys.argv) > 1 and sys.argv[1] == "shutdown":
                    append("shutdown")
                    write_high_mem()
                    sys.exit(0)

                if len(sys.argv) == 1:
                    print("[bazel release fake]")
                    print("Usage: bazel <command> <options> ...")
                    sys.exit(0)

                invocation = count_invocation()
                append("argv " + " ".join(sys.argv[1:]))
                append(f"nice {os.nice(0)}")
                print("stdout-marker", flush=True)
                print("stderr-marker", file=sys.stderr, flush=True)

                def exit_on_sigint(signum, frame):
                    append(f"sigint {invocation}")
                    print(
                        "Bazel caught interrupt signal; cancelling pending invocation.",
                        file=sys.stderr,
                        flush=True,
                    )
                    print("ERROR: build interrupted", file=sys.stderr, flush=True)
                    if mode == "upscale_failure" and invocation == 2:
                        print(
                            "ERROR: /tmp/example: Compiling example.cc failed: "
                            "error executing CppCompile",
                            file=sys.stderr,
                            flush=True,
                        )
                        sys.exit(1)
                    if mode == "scale" and invocation == 2:
                        write_high_mem()
                        sys.exit(0)
                    if mode == "skip_upscale":
                        write_recovered_mem()
                    else:
                        write_high_mem()
                    sys.exit(130)

                def print_running_actions(seconds=1, completed=2, running=2, total=100):
                    actions = [
                        "GoCompilePkg //proxylib:go_default_library",
                        "Rustc //crate:lib",
                        "ProtoCompile //api:v1_proto",
                        "GoLink //cmd:proxy",
                    ]
                    print(
                        f"[{completed} / {total}] {running} actions, "
                        f"{running} running",
                        flush=True,
                    )
                    for index in range(running):
                        print(
                            f"    {actions[index % len(actions)]}; {seconds}s remote",
                            flush=True,
                        )

                def print_meaningful_running_actions(seconds=1, running=2):
                    print_running_actions(seconds, completed=2, running=running)
                    time.sleep(0.3)
                    print_running_actions(seconds, completed=3, running=running)

                if mode == "ignore":
                    signal.signal(signal.SIGINT, signal.SIG_IGN)
                else:
                    signal.signal(signal.SIGINT, exit_on_sigint)

                if mode == "signal":
                    time.sleep(30)
                    sys.exit(0)

                if mode == "killed_exit" and invocation == 1:
                    print(
                        "ERROR: Compiling tests/example.cc failed: "
                        "(Killed): clang failed",
                        file=sys.stderr,
                    )
                    write_high_mem_later()
                    sys.exit(1)

                if mode == "killed_high" and invocation == 1:
                    print(
                        "ERROR: Compiling tests/example.cc failed: "
                        "(Killed): clang failed",
                        file=sys.stderr,
                    )
                    write_high_mem()
                    sys.exit(1)

                if mode == "terminated_exit" and invocation == 1:
                    print(
                        "ERROR: Compiling tests/example.cc failed: "
                        "(Terminated): clang failed",
                        file=sys.stderr,
                    )
                    write_high_mem_later()
                    sys.exit(1)

                if mode == "terminated_high_twice" and invocation <= 2:
                    print(
                        "ERROR: Compiling tests/example.cc failed: "
                        "(Terminated): clang failed",
                        file=sys.stderr,
                    )
                    write_high_mem()
                    sys.exit(1)

                if mode == "terminated_high_always":
                    print(
                        "ERROR: Compiling tests/example.cc failed: "
                        "(Terminated): clang failed",
                        file=sys.stderr,
                    )
                    write_high_mem()
                    sys.exit(1)

                if mode == "server_abrupt" and invocation == 1:
                    print(
                        "Server terminated abruptly "
                        "(error code: 14, error message: 'Socket closed')",
                        file=sys.stderr,
                    )
                    write_high_mem_later()
                    sys.exit(37)

                if mode == "internal_interrupted_crash" and invocation == 1:
                    print(
                        "FATAL: bazel crashed due to an internal error. "
                        "Printing stack trace:",
                        file=sys.stderr,
                    )
                    print(
                        "Caused by: java.lang.InterruptedException",
                        file=sys.stderr,
                    )
                    write_high_mem()
                    sys.exit(37)

                if mode == "internal_interrupted_crash_twice" and invocation <= 2:
                    print(
                        "FATAL: bazel crashed due to an internal error. "
                        "Printing stack trace:",
                        file=sys.stderr,
                    )
                    print(
                        "Caused by: java.lang.InterruptedException",
                        file=sys.stderr,
                    )
                    write_high_mem()
                    sys.exit(37)

                if mode == "bazel_user_interrupt" and invocation == 1:
                    print(
                        "ERROR: Compiling tests/example.cc failed: "
                        "(Terminated): clang failed",
                        file=sys.stderr,
                    )
                    print(
                        "Bazel caught interrupt signal; cancelling pending invocation.",
                        file=sys.stderr,
                    )
                    print("ERROR: build interrupted", file=sys.stderr)
                    write_high_mem()
                    sys.exit(8)

                if mode == "server_abrupt_stall" and invocation == 1:
                    print("[10,535 / 10,567] 13 actions, 12 running", flush=True)
                    print("    Compiling tests/a.cc; 110s processwrapper-sandbox", flush=True)
                    print("    Compiling tests/b.cc; 110s processwrapper-sandbox", flush=True)
                    print(
                        "Server terminated abruptly "
                        "(error code: 14, error message: 'Connection reset by peer')",
                        file=sys.stderr,
                    )
                    write_high_mem()
                    sys.exit(37)

                if mode == "leak_child" and invocation == 1:
                    output_base = Path(os.environ["FAKE_BAZEL_OUTPUT_BASE"])
                    child_cwd = output_base / "execroot" / "cilium"
                    child_cwd.mkdir(parents=True, exist_ok=True)
                    child = subprocess.Popen(
                        [
                            sys.executable,
                            "-c",
                            "import os, time; "
                            "os.chdir(os.environ['FAKE_CHILD_CWD']); "
                            "time.sleep(60)",
                        ],
                        env={**os.environ, "FAKE_CHILD_CWD": str(child_cwd)},
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    append(f"leak_child_pid {child.pid}")
                    print(
                        "Server terminated abruptly "
                        "(error code: 14, error message: 'Socket closed', "
                        f"log file: '{output_base}/server/jvm.out')",
                        file=sys.stderr,
                    )
                    sys.exit(37)

                if mode == "leak_child_then_success" and invocation == 1:
                    output_base = Path(os.environ["FAKE_BAZEL_OUTPUT_BASE"])
                    child_cwd = output_base / "execroot" / "cilium"
                    child_cwd.mkdir(parents=True, exist_ok=True)
                    child = subprocess.Popen(
                        [
                            sys.executable,
                            "-c",
                            "import os, time; "
                            "os.chdir(os.environ['FAKE_CHILD_CWD']); "
                            "time.sleep(60)",
                        ],
                        env={**os.environ, "FAKE_CHILD_CWD": str(child_cwd)},
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    append(f"leak_child_pid {child.pid}")
                    print("[10,535 / 10,567] 13 actions, 12 running", flush=True)
                    print("    Compiling tests/a.cc; 67s processwrapper-sandbox", flush=True)
                    print(
                        "Server terminated abruptly "
                        "(error code: 14, error message: 'Connection reset by peer', "
                        f"log file: '{output_base}/server/jvm.out')",
                        file=sys.stderr,
                    )
                    sys.exit(37)

                if mode == "silent_wall_clock" and invocation == 1:
                    print("[1 / 4] 2 actions, 2 running", flush=True)
                    print("    Compiling a.cc; 0s processwrapper-sandbox", flush=True)
                    print("    Compiling b.cc; 0s processwrapper-sandbox", flush=True)
                    time.sleep(30)
                    sys.exit(1)

                if invocation == 1:
                    print("[1 / 4] 2 actions, 2 running", flush=True)
                    print("    Compiling a.cc; 2s processwrapper-sandbox", flush=True)
                    print("    Compiling b.cc; 2s processwrapper-sandbox", flush=True)
                    time.sleep(30)
                elif invocation == 2 and mode == "scale":
                    print_meaningful_running_actions()
                    time.sleep(2)
                    sys.exit(0)
                elif invocation == 2 and mode == "skip_upscale":
                    write_low_mem()
                    print_meaningful_running_actions()
                    time.sleep(2)
                    sys.exit(0)
                elif invocation == 2 and mode == "long_action_skip_upscale":
                    print_meaningful_running_actions(16)
                    time.sleep(2)
                    sys.exit(0)
                elif invocation == 2 and mode == "postpone_then_upscale":
                    print_running_actions(16, completed=2)
                    time.sleep(0.3)
                    print_running_actions(16, completed=3)
                    time.sleep(0.8)
                    print_running_actions(1, completed=4)
                    time.sleep(2)
                    sys.exit(0)
                elif invocation == 2 and mode == "postpone_memory_then_upscale":
                    print_running_actions(16, completed=2)
                    time.sleep(0.3)
                    print_running_actions(16, completed=3)
                    time.sleep(0.8)
                    write_mid_large_mem()
                    print_running_actions(1, completed=4)
                    time.sleep(0.8)
                    write_high_large_mem()
                    print_running_actions(1, completed=4)
                    time.sleep(4)
                    sys.exit(0)
                elif invocation == 2 and mode == "pending_upscale_then_downscale":
                    print_running_actions(16, completed=2)
                    time.sleep(0.3)
                    print_running_actions(16, completed=3)
                    time.sleep(0.8)
                    write_low_mem()
                    print_running_actions(3, completed=4)
                    time.sleep(2)
                    sys.exit(0)
                elif invocation == 2 and mode == "no_meaningful_work":
                    print_running_actions(1, completed=2)
                    time.sleep(0.8)
                    print_running_actions(1, completed=2)
                    time.sleep(2)
                    sys.exit(0)
                elif invocation == 2 and mode == "winding_down":
                    print_running_actions(1, completed=2, running=3, total=6)
                    time.sleep(0.2)
                    print_running_actions(1, completed=3, running=3, total=6)
                    time.sleep(0.2)
                    print_running_actions(1, completed=4, running=2, total=6)
                    time.sleep(0.8)
                    print("[6 / 6] no actions running", flush=True)
                    time.sleep(2)
                    sys.exit(0)
                elif invocation == 2 and mode == "near_complete":
                    print_running_actions(1, completed=10585, running=2, total=10588)
                    time.sleep(0.8)
                    print(
                        "[10,586 / 10,588] 13 / 15 tests; 2 actions running; "
                        "last test: //tests:cilium_http_integration_test",
                        flush=True,
                    )
                    print(
                        "    Testing //tests:cilium_tls_http_integration_test; "
                        "0s processwrapper-sandbox",
                        flush=True,
                    )
                    print(
                        "    Testing //tests:cilium_tls_tcp_integration_test; "
                        "0s processwrapper-sandbox",
                        flush=True,
                    )
                    time.sleep(2)
                    sys.exit(0)
                elif invocation == 2 and mode == "upscale_failure":
                    print_meaningful_running_actions()
                    time.sleep(30)
                else:
                    sys.exit(0)
                """
            ),
            encoding="utf-8",
        )
        fake.chmod(0o755)
        return fake

    def run_wrapper(
        self,
        tmpdir: Path,
        fake_bazel: Path,
        mode: str = "scale",
        extra_args: list[str] | None = None,
        extra_env: dict[str, str] | None = None,
        initial_available_kb: int = 512 * 1024,
        jobs: int = 4,
        build_timeout: int = 1,
    ) -> subprocess.CompletedProcess:
        log = tmpdir / "fake.log"
        count = tmpdir / "count"
        meminfo = tmpdir / "meminfo"
        output_base = tmpdir / "output_base"
        workspace = tmpdir / "workspace"
        workspace.mkdir()
        write_meminfo(meminfo, total_kb=4 * 1024 * 1024, available_kb=initial_available_kb)

        env = os.environ.copy()
        env.update(
            {
                "BAZEL": str(fake_bazel),
                "BAZEL_ADAPTIVE_MEMINFO": str(meminfo),
                "BAZEL_ADAPTIVE_BUILD_TIMEOUT": str(build_timeout),
                "BAZEL_ADAPTIVE_MEMORY_POLL_INTERVAL": "0.05",
                "BAZEL_ADAPTIVE_UPSCALE_CHECK_INTERVAL": "0.5",
                "BAZEL_ADAPTIVE_RESTART_SETTLE_DELAY": "0.05",
                "FAKE_BAZEL_LOG": str(log),
                "FAKE_BAZEL_COUNT": str(count),
                "FAKE_BAZEL_MODE": mode,
                "FAKE_BAZEL_OUTPUT_BASE": str(output_base),
            }
        )
        if extra_env:
            env.update(extra_env)
        args = [sys.executable, str(WRAPPER), "build", f"--jobs={jobs}"]
        if extra_args:
            args.extend(extra_args)
        return subprocess.run(
            args,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
            cwd=workspace,
        )

    def test_downscale_then_upscale_with_fake_bazel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("stdout-marker", result.stdout)
            self.assertIn("stderr-marker", result.stderr)
            self.assertIn(
                "action timeout and low memory detected; retrying with fewer jobs",
                result.stderr,
            )
            self.assertIn("upscale:", result.stderr)
            self.assertIn("stopping Bazel at --jobs=2", result.stderr)
            self.assertIn("restart at --jobs=3", result.stderr)
            self.assertIn("Bazel stopped at --jobs=2; restarting with --jobs=3", result.stderr)
            self.assertIn("settling for 0.05s before restarting with --jobs=2", result.stderr)
            self.assertIn("settling for 0.05s before restarting with --jobs=3", result.stderr)
            self.assertIn("memory latest", result.stderr)
            self.assertIn("running actions observed", result.stderr)
            self.assertIn("interrupting Bazel at a cheap upscale point", result.stderr)
            self.assertNotIn("restarting Bazel with", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn("argv build --jobs=4", log)
            self.assertIn("argv build --jobs=2", log)
            self.assertIn("argv build --jobs=3", log)
            self.assertEqual(log.count("argv build --jobs=4"), 1)

    def test_bazel_child_priority_can_be_lowered(self) -> None:
        current_nice = os.nice(0)
        if current_nice > 16:
            self.skipTest("test process is already too nice to assert an increment")
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(
                tmpdir,
                fake,
                mode="killed_high",
                extra_env={"BAZEL_ADAPTIVE_BAZEL_NICE": "3"},
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn(f"nice {current_nice + 3}", log)

    def test_bazel_child_priority_can_be_left_unchanged(self) -> None:
        current_nice = os.nice(0)
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(
                tmpdir,
                fake,
                mode="killed_high",
                extra_env={"BAZEL_ADAPTIVE_BAZEL_NICE": "0"},
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn(f"nice {current_nice}", log)

    def test_silent_bazel_output_downscales_by_wall_clock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake, mode="silent_wall_clock")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Compiling a.cc; 0s", result.stdout)
            self.assertIn("action timeout and low memory detected", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn("argv build --jobs=4", log)
            self.assertIn("argv build --jobs=2", log)

    def test_internal_interrupted_crash_retries_once_with_same_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake, mode="internal_interrupted_crash")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "Bazel crashed internally after java.lang.InterruptedException; "
                "retrying with same --jobs=4",
                result.stderr,
            )
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertEqual(log.count("argv build --jobs=4"), 2)
            self.assertNotIn("argv build --jobs=2", log)

    def test_internal_interrupted_crash_retry_is_capped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake, mode="internal_interrupted_crash_twice")

            self.assertEqual(result.returncode, 37, result.stderr)
            self.assertIn(
                "Bazel crashed internally after java.lang.InterruptedException again; "
                "not retrying",
                result.stderr,
            )
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertEqual(log.count("argv build --jobs=4"), 2)
            self.assertNotIn("argv build --jobs=2", log)

    def test_bazel_user_interrupt_is_not_retried(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake, mode="bazel_user_interrupt")

            self.assertEqual(result.returncode, 130, result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertEqual(log.count("argv build --jobs=4"), 1)
            self.assertNotIn("retrying with same", result.stderr)
            self.assertNotIn("retrying with fewer", result.stderr)

    def test_upscale_cancelled_if_bazel_reports_failure_while_stopping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake, mode="upscale_failure")

            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("upscale cancelled because Bazel reported a build failure", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn("argv build --jobs=4", log)
            self.assertIn("argv build --jobs=2", log)
            self.assertNotIn("argv build --jobs=3", log)

    def test_upscale_skip_reports_average_memory_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(
                tmpdir,
                fake,
                mode="skip_upscale",
                build_timeout=5,
                extra_env={"BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB": "2048"},
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(
                result.stderr,
                r"upscale watch skipped after 1 scheduled attempt and [1-9][0-9]* reevaluations",
            )
            self.assertRegex(result.stderr, r"memory skips: [1-9][0-9]*; job-runtime skips: 0")
            self.assertIn("memory dipped below low-memory threshold", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn("argv build --jobs=4", log)
            self.assertIn("argv build --jobs=2", log)
            self.assertEqual(log.count("argv build --jobs=4"), 1)

    def test_upscale_waits_for_young_current_actions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake, mode="long_action_skip_upscale")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(result.stderr, r"oldest current running action is 1[56]s")
            self.assertRegex(
                result.stderr,
                r"memory skips: 0; job-runtime skips: [1-9][0-9]*",
            )
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn("argv build --jobs=4", log)
            self.assertIn("argv build --jobs=2", log)
            self.assertNotIn("argv build --jobs=3", log)

    def test_pending_upscale_runs_when_current_actions_become_young(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake, mode="postpone_then_upscale")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "upscale watch active: oldest current running action is 16s",
                result.stderr,
            )
            self.assertIn("interrupting Bazel at a cheap upscale point", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn("argv build --jobs=4", log)
            self.assertIn("argv build --jobs=2", log)
            self.assertIn("argv build --jobs=3", log)

    def test_pending_upscale_rechecks_memory_before_running(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake, mode="postpone_memory_then_upscale")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "upscale watch active: oldest current running action is 16s",
                result.stderr,
            )
            self.assertIn("upscale: memory latest", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn("argv build --jobs=3", log)

    def test_downscale_watch_takes_priority_over_pending_upscale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(
                tmpdir,
                fake,
                mode="pending_upscale_then_downscale",
                extra_env={"BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB": "2048"},
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("upscale watch active", result.stderr)
            self.assertIn("action timeout and low memory detected", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn("argv build --jobs=1", log)
            self.assertNotIn("argv build --jobs=3", log)

    def test_upscale_requires_meaningful_work_before_restarting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake, mode="no_meaningful_work")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("completed action count has not advanced", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn("argv build --jobs=4", log)
            self.assertIn("argv build --jobs=2", log)
            self.assertNotIn("argv build --jobs=3", log)

    def test_upscale_lets_winding_down_bazel_finish(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake, mode="winding_down")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("letting Bazel finish", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn("argv build --jobs=4", log)
            self.assertIn("argv build --jobs=2", log)
            self.assertNotIn("argv build --jobs=3", log)

    def test_upscale_skips_when_all_remaining_actions_are_running_in_fake_bazel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake, mode="near_complete")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("only 2 action(s) remain", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn("argv build --jobs=4", log)
            self.assertIn("argv build --jobs=2", log)
            self.assertNotIn("argv build --jobs=3", log)

    def test_user_signal_is_forwarded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            workspace = tmpdir / "workspace"
            workspace.mkdir()
            log = tmpdir / "fake.log"
            count = tmpdir / "count"
            meminfo = tmpdir / "meminfo"
            write_meminfo(meminfo, total_kb=4 * 1024 * 1024, available_kb=3 * 1024 * 1024)
            env = os.environ.copy()
            env.update(
                {
                    "BAZEL": str(fake),
                    "BAZEL_ADAPTIVE_MEMINFO": str(meminfo),
                    "BAZEL_ADAPTIVE_BUILD_TIMEOUT": "10",
                    "FAKE_BAZEL_LOG": str(log),
                    "FAKE_BAZEL_COUNT": str(count),
                    "FAKE_BAZEL_MODE": "signal",
                }
            )
            process = subprocess.Popen(
                [sys.executable, str(WRAPPER), "build", "--jobs=1"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=workspace,
            )
            time.sleep(0.5)
            process.send_signal(signal.SIGINT)
            stdout, stderr = process.communicate(timeout=10)

            self.assertEqual(process.returncode, 130, stderr)
            self.assertIn("stdout-marker", stdout)
            self.assertIn("sigint 1", log.read_text(encoding="utf-8"))

    def test_cleanup_escalates_to_shutdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake, mode="ignore")

            self.assertEqual(result.returncode, 0, result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn("shutdown", log)
            self.assertIn("argv build --jobs=2", log)

    def test_killed_action_exit_retries_with_fewer_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake, mode="killed_exit")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("(Killed): clang failed", result.stderr)
            self.assertIn("memory pressure:", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn("argv build --jobs=4", log)
            self.assertIn("argv build --jobs=2", log)

    def test_killed_action_retries_same_jobs_when_memory_average_is_high(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(
                tmpdir,
                fake,
                mode="killed_high",
                initial_available_kb=3 * 1024 * 1024,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("retrying with same --jobs=4", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertEqual(log.count("argv build --jobs=4"), 2)
            self.assertNotIn("shutdown", log)
            self.assertNotIn("argv build --jobs=2", log)

    def test_terminated_action_exit_retries_with_fewer_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake, mode="terminated_exit")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("(Terminated): clang failed", result.stderr)
            self.assertIn("killed or terminated action; retrying with fewer jobs", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn("argv build --jobs=4", log)
            self.assertIn("argv build --jobs=2", log)

    def test_repeated_same_job_terminated_action_waits_before_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(
                tmpdir,
                fake,
                mode="terminated_high_twice",
                initial_available_kb=3 * 1024 * 1024,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("retrying with same --jobs=4", result.stderr)
            self.assertIn(
                "waiting up to 0.05s for Bazel build processes to exit "
                "before retrying with same --jobs=4",
                result.stderr,
            )
            self.assertIn("settling for 0.05s before retrying with same --jobs=4", result.stderr)
            self.assertIn("asking Bazel server to shut down before retrying", result.stderr)
            self.assertIn("bazel shutdown completed with exit code 0", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertEqual(log.count("argv build --jobs=4"), 3)
            self.assertEqual(log.count("shutdown"), 1)
            self.assertNotIn("argv build --jobs=2", log)

    def test_repeated_same_job_terminated_action_retry_is_capped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(
                tmpdir,
                fake,
                mode="terminated_high_always",
                extra_env={"BAZEL_ADAPTIVE_SAME_JOB_RETRY_LIMIT": "2"},
                initial_available_kb=3 * 1024 * 1024,
            )

            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn(
                "after 2 same-job retry attempt(s); not retrying",
                result.stderr,
            )
            self.assertIn("bazel shutdown completed with exit code 0", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertEqual(log.count("argv build --jobs=4"), 3)
            self.assertEqual(log.count("shutdown"), 1)
            self.assertNotIn("argv build --jobs=2", log)

    def test_killed_action_at_one_job_does_not_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake, mode="killed_exit", jobs=1)

            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("(Killed): clang failed", result.stderr)
            self.assertIn("memory pressure:", result.stderr)
            self.assertNotIn("retrying with fewer jobs", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn("argv build --jobs=1", log)
            self.assertNotIn("argv build --jobs=0", log)

    def test_abrupt_server_exit_after_recent_memory_pressure_retries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake, mode="server_abrupt")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Server terminated abruptly", result.stderr)
            self.assertIn("memory pressure:", result.stderr)
            self.assertIn("recent memory pressure", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn("argv build --jobs=4", log)
            self.assertIn("argv build --jobs=2", log)

    def test_abrupt_server_exit_after_visible_stall_retries_without_low_memory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(
                tmpdir,
                fake,
                mode="server_abrupt_stall",
                initial_available_kb=3 * 1024 * 1024,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Connection reset by peer", result.stderr)
            self.assertIn("memory pressure:", result.stderr)
            self.assertIn("recent visible action stall over 1s", result.stderr)
            self.assertIn("retrying with same --jobs=4", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertEqual(log.count("argv build --jobs=4"), 2)
            self.assertNotIn("argv build --jobs=2", log)

    def test_abrupt_server_exit_without_memory_pressure_retries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(
                tmpdir,
                fake,
                mode="server_abrupt",
                initial_available_kb=3 * 1024 * 1024,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Server terminated abruptly", result.stderr)
            self.assertIn("memory pressure:", result.stderr)
            self.assertIn("retrying with same --jobs=4", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertEqual(log.count("argv build --jobs=4"), 2)
            self.assertNotIn("argv build --jobs=2", log)

    def test_abrupt_server_exit_at_one_job_does_not_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(tmpdir, fake, mode="server_abrupt", jobs=1)

            self.assertEqual(result.returncode, 37, result.stderr)
            self.assertIn("Server terminated abruptly", result.stderr)
            self.assertNotIn("retrying with fewer jobs", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertIn("argv build --jobs=1", log)
            self.assertNotIn("argv build --jobs=0", log)

    def test_dangling_build_process_is_reported_and_killed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(
                tmpdir,
                fake,
                mode="leak_child",
                initial_available_kb=3 * 1024 * 1024,
                jobs=1,
            )

            self.assertEqual(result.returncode, 37, result.stderr)
            self.assertIn("dangling Bazel build process", result.stderr)
            self.assertNotIn("dangling build process: pid=", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            child_pid = None
            for line in log.splitlines():
                if line.startswith("leak_child_pid "):
                    child_pid = int(line.split()[1])
                    break
            self.assertIsNotNone(child_pid)
            self.assertFalse(process_exists(child_pid))

    def test_dangling_build_process_after_failure_triggers_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            result = self.run_wrapper(
                tmpdir,
                fake,
                mode="leak_child_then_success",
                initial_available_kb=3 * 1024 * 1024,
                build_timeout=100,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("dangling Bazel build process", result.stderr)
            self.assertNotIn("dangling build process: pid=", result.stderr)
            self.assertIn("retrying with same --jobs=4", result.stderr)
            log = (tmpdir / "fake.log").read_text(encoding="utf-8")
            self.assertEqual(log.count("argv build --jobs=4"), 2)
            self.assertNotIn("argv build --jobs=2", log)
            child_pid = None
            for line in log.splitlines():
                if line.startswith("leak_child_pid "):
                    child_pid = int(line.split()[1])
                    break
            self.assertIsNotNone(child_pid)
            self.assertFalse(process_exists(child_pid))

    def test_no_args_prints_bazel_usage_then_wrapper_hint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake = self.make_fake_bazel(tmpdir)
            log = tmpdir / "fake.log"
            count = tmpdir / "count"
            meminfo = tmpdir / "meminfo"
            write_meminfo(meminfo, total_kb=4 * 1024 * 1024, available_kb=3 * 1024 * 1024)
            env = os.environ.copy()
            env.update(
                {
                    "BAZEL": str(fake),
                    "BAZEL_ADAPTIVE_MEMINFO": str(meminfo),
                    "FAKE_BAZEL_LOG": str(log),
                    "FAKE_BAZEL_COUNT": str(count),
                    "FAKE_BAZEL_MODE": "scale",
                }
            )

            result = subprocess.run(
                [sys.executable, str(WRAPPER)],
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Usage: bazel <command> <options> ...", result.stdout)
            self.assertIn("BAZEL_ADAPTIVE_BUILD_TIMEOUT=<seconds>", result.stderr)
            self.assertIn("BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB=<MiB>", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
