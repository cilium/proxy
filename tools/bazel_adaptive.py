#!/usr/bin/env python3
"""Adaptive Bazel wrapper.

This is a Bazel wrapper for adaptive building. This is intentionally self-contained and uses only
the Python 3 standard library. Both command line and environment are passed through, except that
--jobs is converted to a concrete integer and may be adapted between Bazel retries.

Interface and argument handling:
- Resolve the real Bazel binary from BAZEL, otherwise find bazel on PATH without
  recursing into this wrapper. If BAZEL points at this wrapper, ignore it and
  fall back to PATH lookup.
- Pass stdin, stdout, stderr, command arguments, and environment through to the
  real Bazel command. Forward Bazel output as-is while also decoding a copy for
  monitoring; bytes are written to the terminal immediately even when Bazel is
  under stress and emits partial lines without CR/LF. Wrapper diagnostics go to
  stderr with a [bazel-adaptive/<seconds>s] prefix, where seconds is elapsed
  monotonic time since the wrapper started.
- Parse --jobs=N and --jobs N. Integer values are used directly. Values of
  HOST_CPUS, HOST_CPUS*MULTIPLIER, HOST_RAM, and HOST_RAM*MULTIPLIER are
  resolved once at startup and used as the maximum adaptive jobs cap; for
  example HOST_CPUS*.5 or HOST_RAM*.0002. If --jobs is absent or invalid, start
  from the host CPU count. Every real Bazel invocation receives an integer
  --jobs value. The wrapper does not keep a built-in table of Bazel startup
  options. It only scans arguments before Bazel's "--" delimiter for --jobs,
  and when --jobs is absent inserts the adaptive --jobs value immediately before
  that delimiter or at the end of the argument list.
- Only adapt commands that accept --jobs: build, test, run, coverage, fetch,
  cquery, and aquery. Other Bazel commands are exec'd directly without adding or
  rewriting --jobs, so the wrapper can be used as a general Bazel entry point.
  The detector is conservative around unknown startup options with separate
  values; ambiguous commands pass through unchanged.
- Read the action timeout from BAZEL_ADAPTIVE_BUILD_TIMEOUT as a bare positive
  number of seconds; default to 150 seconds. This applies to builds and tests
  and is independent of Bazel's --test_timeout.
- Read the low-memory threshold from BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB as
  MiB; default to 1024 MiB. Memory is read from /proc/meminfo, using
  MemAvailable and MemTotal.
- Start the real Bazel command with a positive nice increment so the wrapper
  stays at normal scheduler priority and can keep sampling memory even when
  Bazel's compile/test process tree is CPU-heavy or memory pressure causes
  scheduler churn. Read the increment from BAZEL_ADAPTIVE_BAZEL_NICE; default
  to 5, clamp to 0..19, and use 0 to disable this behavior. Also periodically
  renice detected Bazel build child processes under the Bazel output base after
  memory first enters the pause-watch band, because actions may be launched by
  the Bazel server rather than by the client process that inherited the initial
  nice value. This covers sandbox wrappers, compilers, language tools, and tests
  without interpreting the action language. This does not make the wrapper
  realtime or immune to kernel-level stalls, but it gives the monitor a better
  chance to run when it matters.

Terminal behavior:
- For interactive runs, attach Bazel stdout/stderr to a PTY so Bazel keeps its
  live progress UI and Ctrl-C works naturally through process groups and
  foreground terminal handoff. Size the PTY from the real terminal so progress
  lines are not truncated to 80 columns. For non-interactive runs, use normal
  pipes unless BAZEL_ADAPTIVE_FORCE_PTY=1 is set; PTY columns/rows can be
  overridden with BAZEL_ADAPTIVE_PTY_COLUMNS and BAZEL_ADAPTIVE_PTY_ROWS.

Monitoring model:
- Sample memory once per second by default, configurable with
  BAZEL_ADAPTIVE_MEMORY_POLL_INTERVAL and clamped to at least 0.05 seconds to
  avoid busy looping. Keep a rolling 30-second memory window for reports and
  retry decisions.
- Every 50ms, decide whether to pause one detected Bazel action process group
  with SIGSTOP, choosing the youngest action group first and always leaving at
  least one action group running. Pausing is staggered across the range from
  twice to once the current effective low-memory threshold: with N detected
  action groups, the first pause is allowed when MemAvailable drops below 2x
  the effective threshold, and later pauses require progressively lower
  MemAvailable until the current running-action floor is reached. Under plain
  memory pressure that floor is half of the maximum action groups observed in
  the attempt; while uninterruptible I/O evidence remains sustained, that floor
  is halved, rounded up, once per BAZEL_ADAPTIVE_IO_STALL_FLOOR_SECONDS window.
  This tight pause watch is intentionally faster than Bazel's progress output
  so a newly spawned action can be paused before it grows into a large memory
  consumer, but the staggered thresholds avoid pausing every action group at
  once when memory first crosses one cliff. Every 5 seconds, if MemAvailable is
  above the effective low-memory threshold, high enough that the group would not
  immediately qualify for pausing again, and high enough to cover the selected
  group's estimated swap-in cost, resume at most one paused action group with
  SIGCONT, choosing the oldest paused group first. After a normal resume,
  suppress further normal resumes for one resume interval so that group's memory
  use can settle before reassessing. While memory remains tight, resume is also
  blocked while any running action group is in uninterruptible I/O wait, and for
  one resume interval after that stall clears, to avoid immediately
  reintroducing swap pressure. The
  swap-in estimate is the sum of VmSwap from /proc/<pid>/status for the action
  group's processes; the resume gate requires MemAvailable to cover both that
  estimate and the low-memory reserve. Paused processes stay in their
  original cgroup. The wrapper deliberately does not create or migrate cgroups;
  it lets normal kernel reclaim and any configured swap policy decide whether
  stopped processes should be swapped out while running actions continue.
- Plain memory pressure alone does not pause down to a single active action
  group. The normal floor is half of the maximum action groups observed
  in the attempt, rounded up, so a --jobs=12 build keeps at least 6 action
  groups running. If running action groups stay in uninterruptible I/O wait for
  BAZEL_ADAPTIVE_IO_STALL_FLOOR_SECONDS, default 10 seconds, the floor is
  halved, rounded up. If that stall evidence remains present, the floor is
  halved again after each additional interval, for example 6 -> 3 -> 2 -> 1.
  Sustained I/O blocking is based on repeated observations in the current stall
  window, not a single D-state sighting. The evidence can come from running
  action groups in D state or heavy swap-in reported by /proc/vmstat. Pausing
  below the normal floor requires both tight memory and currently sustained I/O
  blocking.
- After every fresh process-group scan, enforce the "at least one action group
  running" invariant operationally: if all currently detected action groups are
  wrapper-paused, immediately resume the oldest paused group even when memory is
  still below the normal resume threshold. This covers races where Bazel's
  action set changes after a pause decision and prevents an all-stopped
  deadlock.
- The low-memory reserve is adaptive within the range from the configured base
  threshold to twice that base. It starts at the base threshold, which should let
  the kernel use some swap. If any still-running action group has a process in
  uninterruptible I/O wait ("D" state), or if /proc/vmstat shows heavy swap-in,
  the wrapper treats that as evidence that running jobs are stalling on memory
  pressure and raises the effective threshold by 256 MiB, up to the 2x cap. Once
  no running action is stalled, no wrapper-paused actions remain, and memory is
  healthy, the threshold decays back toward the base in the same small steps.
  For BAZEL_ADAPTIVE_RESUME_SWAP_IN_GRACE_SECONDS after resuming an action
  group, default 10 seconds, heavy global swap-in is sampled but not counted as
  stall evidence while MemAvailable remains above the effective low-memory
  threshold. This lets the resumed group fault itself back in without causing
  its own immediate stall response. This avoids guessing one static memory
  threshold while still preventing pause/resume flapping.
- While any wrapper-paused action group is stopped, the progress parser records
  a pause interval. Action-age decisions and forwarded Bazel action-duration
  displays subtract pause overlap from Bazel's displayed action time and from
  wall-clock aging, so an action that Bazel reports as 130s old after being
  paused for 30s is treated and shown as roughly 100s of active runtime for the
  display. Downscale timeout checks use the active runtime of real, non-paused
  Bazel action process groups when that proves all active groups are old, but
  Bazel's visible action-duration sample can also trigger the timeout path when
  Bazel caps the displayed action list. Where possible, duration rewriting is
  matched to the source files associated with the paused action groups so
  running action durations continue to advance. Rewritten durations keep Bazel's
  plain seconds format, for example "100s" rather than "1m40s".
- If pausing is not enough and the normal timeout/low memory condition is
  reached, the existing restart/downscale fallback still applies.
- When the wrapper starts stopping Bazel for upscale/downscale, first resume
  every action group paused by that attempt with SIGCONT and stop doing normal
  throttle pause/resume checks for that attempt. Before any Bazel attempt ends,
  including retry, Ctrl-C, exception, or final exit paths, run the same resume
  sweep again. Remember the exact stopped PIDs so resume can still run if a
  later process scan cannot reconstruct the sandbox group. Cleanup and process
  termination run only after this resume sweep, so the wrapper does not leave
  stopped build jobs behind.
- As soon as Bazel reports a killed or terminated action, resume all paused
  action groups and stop normal pause/resume checks for that attempt. Bazel is
  already winding down after an action death, and keeping stopped actions around
  can make the server cancellation path look stuck.
- As soon as the wrapper observes Ctrl-C/SIGTERM, resume all paused action
  groups and stop normal pause/resume checks while Bazel cancels. Bazel also
  receives the user signal, but stopped action children must be resumed so the
  server can finish cancelling the pending invocation. Bazel's own interrupt
  text is treated as user cancellation only when the wrapper did not already
  ask Bazel to stop for an adaptive up/downscale restart.
- Parse Bazel progress frames from both newline and carriage-return updates.
  Track completed action counts, the currently reported number of running
  actions, and the visible action durations. Action lines are detected by their
  Bazel-style duration suffix, such as "Compiling x.cc; 27s
  processwrapper-sandbox", "GoCompilePkg //pkg:go_default_library; 27s remote",
  "Rustc //crate:lib; 27s linux-sandbox", or "ProtoCompile //api:v1; 27s
  worker"; the action name, language, file extension, and execution backend are
  not otherwise interpreted. Treat forms like "7 actions, 6 running", "6
  actions running", "1 action", and "no actions running" as running-action
  counts. Track the "[done / total]" progress count when Bazel prints it.
- In non-PTY mode Bazel can print compact one-line progress updates like
  "[9,890 / 10,553] Compiling x.cc; 2s processwrapper-sandbox ... (13 actions,
  12 running)" instead of a header followed by one line per running action.
  Test builds may add a test-progress prefix, for example
  "[8,190 / 8,369] 1 / 15 tests; Compiling x.cc; 15s processwrapper-sandbox
  ... (13 actions, 12 running)". Treat the duration on such a progress-header
  line as Bazel's summarized current-action age for timeout and cheap-upscale
  decisions, while still using the running-action count and completed/total
  counts from the same line.
- If memory pressure leaves Bazel output stuck mid-frame or mid-line, keep
  forwarding the partial bytes but also account for them in monitoring instead
  of waiting for CR/LF. A partial action line that already contains a duration
  is counted immediately. Bazel can report N running actions while displaying
  only a capped subset of their duration lines, so visible action durations are
  treated as the available current-action sample rather than requiring all N
  lines. Under the normal low-memory downscale gate, visible action durations
  that are already over BAZEL_ADAPTIVE_BUILD_TIMEOUT can stand in for hidden
  action lines. If there are no visible durations yet and Bazel output is stuck
  mid-frame or mid-line, wall-clock time since the progress frame is used until
  the frame has been stuck past the timeout. This same wall-clock aging applies
  when Bazel printed action lines and then stopped updating output entirely; the
  wrapper estimates the current action ages from the last displayed durations
  instead of waiting for Bazel's next progress update.
- Swap should be configured to allow paused jobs to be swapped out on demand
  and make memory available for the running builds.

Downscale behavior:
- Downscale checks stay active for the whole run and take priority over any
  pending upscale. Low memory alone does not interrupt a progressing build.
- If the latest progress frame reports at least one running action, action-age
  evidence is over the action timeout, and the current MemAvailable is below
  the effective low-memory threshold, gracefully interrupt Bazel and retry with
  half as many jobs, rounded up. If the completed action count advanced within
  the timeout window and the wrapper currently observes no running-action I/O
  distress, defer this downscale because long action age alone is not failure
  evidence while the build is still progressing. If action groups are already
  wrapper-paused, use the higher pause-watch threshold for this gate, because
  pausing has already proven that the current attempt is under memory pressure.
  For example, 12 -> 6, 6 -> 3, 5 -> 3, 3 -> 2, and 2 -> 1. Before retrying,
  wait until memory has recovered to at least half of total memory.
- If Bazel reports a killed or terminated action, exits with an abrupt server
  failure, or exits while Bazel build processes are still dangling under the
  output base, retry. If the recent rolling average memory is more than half of
  total memory, retry with the same job count; otherwise downscale by half,
  rounded up. Repeated killed/terminated action failures at the same job count
  are retried after the standard restart-settle gate instead of downscaling,
  because they can be stale Bazel/server fallout after an earlier interruption.
  Cap those same-job retries with BAZEL_ADAPTIVE_SAME_JOB_RETRY_LIMIT, default
  10 per job count, so a deterministic failure cannot loop forever. When the
  cap is exceeded, return the failing Bazel exit code. Keep the first same-job
  retry cheap. If that retry then reports another killed/terminated action
  before making meaningful Bazel action progress, treat that repeated restart
  failure as evidence that Bazel/server state has not wound down yet: run bazel
  shutdown, wait for known build children to disappear, add the normal settle
  delay, and then retry again with the same jobs.
- If Bazel crashes with both "FATAL: bazel crashed due to an internal error"
  and "Caused by: java.lang.InterruptedException", retry with the same job
  count. This is deliberately narrow and is disabled when the wrapper itself is
  handling Ctrl-C/SIGTERM or when the wrapper intentionally interrupted Bazel
  for an adaptive restart. Retry this crash signature at most once per wrapper
  run; if it repeats, return the failing Bazel exit code.
- If Bazel reports a build failure while the wrapper is stopping Bazel for an
  upscale, cancel the upscale and return that failure after cleanup.
- Do not retry a downscale when jobs is already 1.

Upscale behavior:
- The first upscale analysis interval starts only after running Bazel actions
  have actually been observed, not at Bazel process start. The interval is 30
  seconds by default, with BAZEL_ADAPTIVE_UPSCALE_CHECK_INTERVAL available for
  tests.
- After that warm-up interval, continuously watch on each monitoring loop for a
  cheap and memory-safe upscale point. Restart with 1.5x jobs, rounded up and
  capped at the initial maximum, at the first moment all of these are true:
  * Bazel has reported meaningful work in this attempt, meaning the completed
    action count has advanced at least once;
  * the rolling 30-second average MemAvailable is more than half of MemTotal;
  * the rolling 30-second minimum MemAvailable did not dip below the configured
    low-memory threshold;
  * no action groups are currently wrapper-paused;
  * Bazel still has current running actions;
  * Bazel's known remaining action count is more than twice the current --jobs
    value, because a restart this close to the end usually costs more than it
    saves;
  * Bazel's known remaining action count is greater than the reported running
    action count, because if all remaining actions are already running Bazel is
    winding down;
  * when Bazel reports completed/total counts, a decreased running-action count
    is only treated as winding down near the end of the build. Normal mid-build
    fluctuations such as 12 -> 11 -> 12 are not enough to block upscale when
    many actions remain;
  * at least one visible current running action duration is available, and
    every visible current running action is less than 15 seconds old. Bazel may
    report more running actions than it prints duration lines for, especially
    when the progress UI is truncated; hidden durations do not by themselves
    block upscale.
- Bazel has no drain-current-actions-then-exit mode for changing --jobs, so the
  wrapper does not try to finish old actions before restarting. Instead, if the
  memory condition is good but current actions are already 15+ seconds old, no
  meaningful work has completed yet, no actions are running, no more than two
  current job waves are known to remain, all known remaining actions are already
  running, or the running count has decreased while Bazel is already near the
  end of the build, keep a pending upscale and re-evaluate every monitoring
  loop. If memory pressure increases while waiting, keep
  postponing. When memory is still safe, work has advanced, and the current
  action set becomes cheap to abandon, gracefully interrupt Bazel and restart at
  the higher job count. Skipped-upscale diagnostics report both scheduled
  upscale attempts and the continuous pending-watch re-evaluations, plus
  separate skip counts for memory gates and job-runtime/action-state gates.

Cleanup behavior:
- Before every retry and before final exit, refresh Bazel server/output-base
  knowledge for this wrapper's process cgroup and sweep for dangling build
  processes under those Bazel output bases. Terminate only processes in that
  same cgroup domain; print individual process details only for jobs that could
  not be killed. Escalate stalled Bazel shutdowns with bazel shutdown and
  cgroup-scoped process-tree killing as needed. This keeps two simultaneous
  Docker build instances on the same host from pausing or killing each other's
  Bazel actions.
- Before every Bazel restart, including same-job retries, downscales, and
  upscales, wait up to BAZEL_ADAPTIVE_RESTART_SETTLE_DELAY seconds for known
  Bazel build child processes under the output base to disappear, then pause for
  that same small delay. The default is 3 seconds. This gives the Bazel server
  and processwrapper-sandbox children time to wind down and avoids immediate
  restart churn.
- Discover Bazel output bases from same-cgroup Bazel server process command
  lines and from abrupt-server log-file diagnostics. Treat same-cgroup
  non-server processes as Bazel build children when their cwd is under a known
  output base or their command line mentions that output base. This is
  intentionally independent of action language and catches processwrapper,
  clang, Go, Rust, proto, test runner, and other sandbox children the same way.
"""

import errno
import fcntl
import os
import pty
import re
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import termios
import time
from dataclasses import dataclass, field


DEFAULT_ACTION_TIMEOUT_SECONDS = 150
BUILD_TIMEOUT_ENV = "BAZEL_ADAPTIVE_BUILD_TIMEOUT"

JOBS_COMMANDS = frozenset({"build", "test", "run", "coverage", "fetch", "cquery", "aquery"})

DEFAULT_LOW_MEMORY_THRESHOLD_MB = 1024
LOW_MEMORY_THRESHOLD_ENV = "BAZEL_ADAPTIVE_LOW_MEMORY_THRESHOLD_MB"

ADAPTIVE_THRESHOLD_STEP_MB = 256
ADAPTIVE_THRESHOLD_RAISE_COOLDOWN_SECONDS = 10.0
ADAPTIVE_THRESHOLD_LOWER_COOLDOWN_SECONDS = 30.0

DEFAULT_IO_STALL_FLOOR_SECONDS = 3
IO_STALL_FLOOR_SECONDS_ENV = "BAZEL_ADAPTIVE_IO_STALL_FLOOR_SECONDS"

DEFAULT_IO_STALL_SWAP_RATE_MB_PER_SECOND = 32
IO_STALL_SWAP_RATE_ENV = "BAZEL_ADAPTIVE_IO_STALL_SWAP_RATE_MB_PER_SECOND"

DEFAULT_RESUME_SWAP_IN_GRACE_SECONDS = ADAPTIVE_THRESHOLD_RAISE_COOLDOWN_SECONDS
RESUME_SWAP_IN_GRACE_ENV = "BAZEL_ADAPTIVE_RESUME_SWAP_IN_GRACE_SECONDS"

DISPLAY_PAUSE_LABEL_GRACE_SECONDS = 60.0
DISPLAY_PAUSE_LABEL_HISTORY_LIMIT = 512

DEFAULT_MEMORY_POLL_INTERVAL_SECONDS = 1.0
MEMORY_POLL_INTERVAL_ENV = "BAZEL_ADAPTIVE_MEMORY_POLL_INTERVAL"
MIN_MEMORY_POLL_INTERVAL_SECONDS = 0.05

DEFAULT_UPSCALE_CHECK_INTERVAL_SECONDS = 30.0
UPSCALE_CHECK_INTERVAL_ENV = "BAZEL_ADAPTIVE_UPSCALE_CHECK_INTERVAL"

DEFAULT_SAME_JOB_RETRY_LIMIT = 10
SAME_JOB_RETRY_LIMIT_ENV = "BAZEL_ADAPTIVE_SAME_JOB_RETRY_LIMIT"

DEFAULT_RESTART_SETTLE_DELAY_SECONDS = 3.0
RESTART_SETTLE_DELAY_ENV = "BAZEL_ADAPTIVE_RESTART_SETTLE_DELAY"

DEFAULT_BAZEL_NICE = 5
BAZEL_NICE_ENV = "BAZEL_ADAPTIVE_BAZEL_NICE"
MIN_BAZEL_NICE = 0
MAX_BAZEL_NICE = 19

DEFAULT_MEMINFO_PATH = "/proc/meminfo"
MEMINFO_ENV = "BAZEL_ADAPTIVE_MEMINFO"
DEFAULT_VMSTAT_PATH = "/proc/vmstat"
VMSTAT_ENV = "BAZEL_ADAPTIVE_VMSTAT"

WRAPPER_START_TIME = time.monotonic()
try:
    CLOCK_TICKS_PER_SECOND = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
except (AttributeError, KeyError, OSError, ValueError):
    CLOCK_TICKS_PER_SECOND = 100
try:
    PAGE_SIZE_KB = max(1, os.sysconf("SC_PAGE_SIZE") // 1024)
except (AttributeError, OSError, ValueError):
    PAGE_SIZE_KB = 4
DEFAULT_ENV_FLAG_VALUE = ""

FORCE_PTY_ENV = "BAZEL_ADAPTIVE_FORCE_PTY"
DISABLE_PTY_ENV = "BAZEL_ADAPTIVE_DISABLE_PTY"
DEFAULT_PTY_COLUMNS = ""
PTY_COLUMNS_ENV = "BAZEL_ADAPTIVE_PTY_COLUMNS"
DEFAULT_PTY_ROWS = ""
PTY_ROWS_ENV = "BAZEL_ADAPTIVE_PTY_ROWS"
DEFAULT_TERMINAL_COLUMNS = 240
DEFAULT_TERMINAL_ROWS = 24

BAZEL_ENV = "BAZEL"
DEFAULT_PATH = ""
PATH_ENV = "PATH"

UPSCALE_READY = "ready"
UPSCALE_PENDING = "pending"
UPSCALE_BLOCKED = "blocked"
SKIP_MEMORY = "memory"
SKIP_JOB_RUNTIME = "job-runtime"

RECENT_MEMORY_PRESSURE_SECONDS = 10.0
MEMORY_REPORT_SECONDS = 30.0
UPSCALE_MAX_ACTION_SECONDS = 15
UPSCALE_REMAINING_ACTION_FINISH_JOBS_MULTIPLIER = 2
RECENT_STALL_SECONDS = 30.0
TIMEOUT_DOWNSCALE_DEFER_REPORT_SECONDS = 30.0
DANGLING_PROCESS_TERM_WAIT_SECONDS = 3.0
DANGLING_PROCESS_KILL_WAIT_SECONDS = 1.0
BAZEL_SHUTDOWN_MIN_TIMEOUT_SECONDS = 1
BAZEL_SHUTDOWN_MAX_TIMEOUT_SECONDS = 30
RENICE_BUILD_CHILDREN_SECONDS = 2.0
THROTTLE_PAUSE_CHECK_SECONDS = 0.05
THROTTLE_IDLE_PAUSE_CHECK_SECONDS = 0.5
THROTTLE_RESUME_CHECK_SECONDS = 5.0
RESUME_IO_STALL_CLEAR_SECONDS = THROTTLE_RESUME_CHECK_SECONDS
RESUME_MEMORY_SETTLE_SECONDS = THROTTLE_RESUME_CHECK_SECONDS
IO_STALL_RECENT_OBSERVATION_SECONDS = 1.0
IO_STALL_MIN_OBSERVATIONS = 2

# Use: split Bazel output into progress frames. Bazel can update progress with
# either newline or carriage-return records; splitting on both lets the parser
# see each progress update independently.
# Example: "[1 / 4] 2 actions running\r[2 / 4] 1 action running\n"
# Extracted fields: none; this only separates records at "\r" and "\n".
# Breakage risk: low; it relies on terminal control characters, not Bazel text.
LINE_SEPARATOR_RE = re.compile(r"[\r\n]")

# Use: strip ANSI/VT100 escape sequences before matching Bazel text. This keeps
# color and cursor-control output from interfering with progress/failure parsing.
# Example: "\x1b[32mINFO: Build completed successfully\x1b[0m"
# Extracted fields: none; the whole escape sequence is removed.
# Breakage risk: low; this is the conventional CSI escape shape.
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

# Use: identify a Bazel progress-frame header before resetting current action
# durations and parsing progress/running-action state.
# Example: "[10,586 / 10,588] 13 / 15 tests; 2 actions running"
# Extracted fields: none here; PROGRESS_COUNT_RE extracts done/total separately.
# Breakage risk: medium; the "[done / total]" prefix is common but not a formal
# API, so a future Bazel progress UI redesign could require an update.
PROGRESS_HEADER_RE = re.compile(r"^\[[0-9,]+(?:\s*/\s*[0-9,]+)?\]")

# Use: extract Bazel's completed/total action counts from a progress header.
# The wrapper uses this to detect meaningful progress and to avoid upscaling
# when every known remaining action is already running.
# Example: "[10,586 / 10,588] 13 / 15 tests; 2 actions running"
# Extracted fields: done="10,586"; total="10,588". Commas are stripped before
# converting to integers.
# Breakage risk: medium; small whitespace changes are tolerated, but a different
# delimiter or ordering for Bazel progress counts would break it.
PROGRESS_COUNT_RE = re.compile(r"^\[(?P<done>[0-9,]+)(?:\s*/\s*(?P<total>[0-9,]+))?\]")

# Use: extract the number of currently running Bazel actions from a progress
# frame. This lets the wrapper track whether Bazel currently has active work,
# detect running-count decreases, and combine Bazel's count with the wrapper's
# paused-action count when rewriting display summaries. Bazel may cap the
# number of action-duration lines it prints, so duration samples are treated as
# visible evidence rather than a complete list of all running actions.
# Example: "[10,501 / 10,575] 1 / 15 tests; 7 actions, 6 running"
# Extracted fields: listed_actions="7" and listed_running="6" for
# "7 actions, 6 running"; actions_running="2" for "2 actions running";
# running="6" for "6 running"; action_only="1" for "1 action"; no named field
# is present for "no actions running", which maps to zero. The action_only form
# covers Bazel's near-finish output, for example
# "[10,420 / 10,421] 13 / 14 tests; 1 action; last test: //tests:foo".
# Breakage risk: medium-high; it tolerates singular/plural "action(s)" and
# Bazel omitting "running" for a lone action, but different wording such as
# "jobs running" or substantially reordered phrases would need a new pattern.
RUNNING_COUNT_RE = re.compile(
    r"\b(?:"
    r"(?P<listed_actions>[0-9]+)\s+actions?,\s*(?P<listed_running>[0-9]+)\s+running"
    r"|(?P<actions_running>[0-9]+)\s+actions?\s+running"
    r"|(?P<running>[0-9]+)\s+running"
    r"|(?P<action_only>[0-9]+)\s+actions?"
    r"|no\s+actions?\s+running"
    r")\b"
)

# Use: extract Bazel's displayed age for an action from any action line,
# independent of language, mnemonic, filename, or execution backend. These ages
# drive stall detection and the "only upscale when current jobs are cheap to
# abandon" rule.
# Example: "GoCompilePkg //proxylib:go_default_library; 2m13s remote"
# Extracted fields: duration="2m13s"; hours=None; minutes="2"; seconds="13".
# For "1h02m03s", hours="1", minutes="02", seconds="03".
# Breakage risk: medium; the action text is flexible, but the parser depends on
# Bazel continuing to print durations as "; <duration>s" with h/m/s units.
ACTION_DURATION_RE = re.compile(
    r";\s*(?P<duration>(?:(?P<hours>[0-9]+)h)?(?:(?P<minutes>[0-9]+)m)?(?P<seconds>[0-9]+)s)\b"
)

# Use: resolve Bazel-style --jobs host expressions accepted by this wrapper.
# This is wrapper input syntax, not Bazel output. The extracted keyword selects
# CPU count or RAM in MiB, and the optional multiplier scales it.
# Example: "HOST_RAM*.0002"
# Extracted fields: keyword="HOST_RAM"; multiplier=".0002". For "HOST_CPUS",
# keyword="HOST_CPUS"; multiplier=None.
# Breakage risk: low; this is our own documented interface.
JOBS_KEYWORD_RE = re.compile(
    r"^(?P<keyword>HOST_CPUS|HOST_RAM)(?:\*(?P<multiplier>(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)))?$"
)

# Use: detect output indicating an action probably died due to memory pressure
# or termination. This makes a failed Bazel invocation eligible for a retry with
# fewer or same jobs depending on recent memory history.
# Example: "ERROR: ... failed: (Killed): clang failed"
# Extracted fields: none; any match sets saw_memory_kill=True.
# Breakage risk: medium-high; compiler, worker, or kernel messages vary across
# tools and platforms, so new OOM/termination wording may need to be added.
MEMORY_KILL_RE = re.compile(
    r"\b(?:Killed|Cannot allocate memory|OutOfMemoryError)\b|\(\s*Terminated\s*\)",
    re.IGNORECASE,
)

# Use: detect that Bazel reported an actual action failure while the wrapper was
# stopping Bazel for an upscale. In that case, the upscale is cancelled and the
# action failure is returned instead of retrying as if the interruption
# succeeded. Generic summaries such as "Target //x failed to build" are
# intentionally excluded because Bazel also prints them after the wrapper's own
# interrupt.
# Example: "ERROR: /tmp/example: Compiling example.cc failed: error executing CppCompile"
# Extracted fields: none; any match sets saw_build_failure=True.
# Breakage risk: medium-high; Bazel and rule-specific failure text is not a
# stable API, and localized or substantially reformatted errors could escape it.
BUILD_FAILURE_RE = re.compile(
    r"\bfailed:\s+(?:\(|error executing)",
    re.IGNORECASE,
)

# Use: detect abrupt Bazel server/client disconnects. These failures are treated
# as retry candidates because they often happen during severe memory pressure or
# server death.
# Example: "Server terminated abruptly (error code: 14, error message: 'Socket closed')"
# Extracted fields: none; any match sets saw_server_abrupt=True.
# Breakage risk: medium; these phrases have been observed in Bazel output, but
# future versions may change error wording or transport diagnostics.
SERVER_ABRUPT_RE = re.compile(
    r"\b(?:Server terminated abruptly|Socket closed|Connection reset by peer)\b", re.IGNORECASE
)

# Use: detect the first half of a narrow retryable Bazel crash signature. This
# is only retried when paired with JAVA_INTERRUPTED_RE and not caused by a user
# or wrapper interrupt.
# Example: "FATAL: bazel crashed due to an internal error. Printing stack trace:"
# Extracted fields: none; any match sets saw_internal_crash=True.
# Breakage risk: medium; this is Bazel's human crash text, so wording changes
# would require an update, but the phrase is intentionally specific.
INTERNAL_CRASH_RE = re.compile(
    r"\bFATAL:\s+bazel crashed due to an internal error\b",
    re.IGNORECASE,
)

# Use: detect the second half of the narrow retryable Bazel crash signature.
# InterruptedException alone is not enough to retry, because user interrupts can
# also involve interruption; it must be paired with INTERNAL_CRASH_RE.
# Example: "Caused by: java.lang.InterruptedException"
# Extracted fields: none; any match sets saw_java_interrupted=True.
# Breakage risk: low-medium; Java exception names are stable, but Bazel could
# stop printing causes in this exact text form.
JAVA_INTERRUPTED_RE = re.compile(
    r"\bCaused by:\s+java\.lang\.InterruptedException\b",
    re.IGNORECASE,
)

# Use: detect Bazel output proving that a user interrupt reached Bazel even if
# the wrapper process did not receive SIGINT because Bazel owned the foreground
# terminal process group. This makes the wrapper stop retrying and return 130.
# Example: "Bazel caught interrupt signal; cancelling pending invocation."
# Example: "ERROR: build interrupted"
# Extracted fields: none; any match sets saw_user_interrupt=True.
# Breakage risk: medium; this depends on Bazel's human interrupt text, but the
# alternatives are treating a user cancel as retryable killed actions.
BAZEL_USER_INTERRUPT_RE = re.compile(
    r"\b(?:Bazel caught interrupt signal|build interrupted)\b",
    re.IGNORECASE,
)

# Use: rewrite Bazel progress summaries in the forwarded output when the wrapper
# has paused action groups. This is display-only; parser state still sees the
# original Bazel text. It handles both one-line non-PTY summaries and regular
# progress headers.
# Example: "(12 actions, 11 running)" or "12 actions, 11 running"
# Extracted fields: actions="12", running="11" for the parenthesized form, and
# bare_actions="12", bare_running="11" for the bare form. Rewritten as
# "(12 actions, 10 paused, 1 running)" or "12 actions, 10 paused, 1 running"
# when paused_count is 10.
# Example: "12 actions running" or "(8 actions running)"
# Extracted fields: only_running="12" or parenthesized_only_running="8"; rewritten
# as "12 actions, 10 paused, 2 running" or
# "(8 actions, 6 paused, 2 running)" when paused_count is 10 or 6.
# Breakage risk: medium; it depends on Bazel's human progress summary wording,
# but failures only affect display prettiness, not adaptive decisions.
ACTION_SUMMARY_DISPLAY_RE = re.compile(
    r"\((?P<actions>[0-9]+) actions?, (?P<running>[0-9]+) running\)"
    r"|(?P<bare_actions>[0-9]+) actions?, (?P<bare_running>[0-9]+) running"
    r"|\((?P<parenthesized_only_running>[0-9]+) actions running\)"
    r"|(?P<only_running>[0-9]+) actions running"
)

# Use: extract Bazel's output base from abrupt-server log-file diagnostics. The
# cleanup code uses it to find and terminate dangling sandbox/build processes.
# Example: "log file: '/home/user/.cache/bazel/_bazel_user/hash/server/jvm.out'"
# Extracted fields: output_base="/home/user/.cache/bazel/_bazel_user/hash".
# Breakage risk: medium; it depends on single quotes and the server/jvm.out path
# suffix. Different quoting or log-file naming would require adjustment.
OUTPUT_BASE_LOG_RE = re.compile(r"log file: '(?P<output_base>[^']+)/server/jvm\.out'")

# Use: extract the Bazel sandbox action directory from a process cwd or command
# line. Processes in the same sandbox directory are treated as one action group
# for SIGSTOP/SIGCONT throttling, renicing, and cleanup reasoning.
# Example: "/home/user/.cache/bazel/_bazel_user/hash/sandbox/processwrapper-sandbox/17/execroot/ws"
# Extracted fields: sandbox_key="processwrapper-sandbox/17".
# Breakage risk: medium; Bazel has used this sandbox path shape for a long time,
# but a future sandbox layout change would require updating this extraction.
SANDBOX_ACTION_RE = re.compile(r"/sandbox/(?P<sandbox_key>[^/\s]+/[0-9]+)(?:/|\s|$)")

# Use: identify source-like path tokens from compiler command lines so paused
# sandbox process groups can be associated with the action labels Bazel prints.
# This makes displayed action durations pause only for the files whose process
# groups are actually SIGSTOPed.
# Example: ".../external/envoy/test/integration/http_integration.cc"
# Extracted fields: none; matching tokens are normalized into candidate labels.
# Breakage risk: low-medium; this is an extension allow-list, so uncommon source
# extensions may need to be added if they appear in Bazel action output.
SOURCE_FILE_RE = re.compile(
    r"\.(?:c|cc|cpp|cxx|c\+\+|C|m|mm|h|hh|hpp|hxx|inc|S|s|rs|go|proto)$"
)

ACTIVE_PROCESS = None
USER_TERMINATING = False
DIAG_BUFFER_INTERACTIVE = False
DIAG_BUFFER: list[str] = []


@dataclass
class MemInfo:
    total_kb: int
    available_kb: int


@dataclass
class SwapIo:
    pages_in: int


@dataclass
class ParsedArgs:
    original_args: list[str]
    initial_jobs: int
    action_timeout: int
    job_locations: list[tuple[str, int]]
    supports_jobs: bool


@dataclass
class RunResult:
    exit_code: int
    restart: str | None = None
    upscale_skip_reason: str | None = None
    upscale_skip_count: int = 0
    upscale_reevaluation_count: int = 0
    upscale_memory_skip_count: int = 0
    upscale_job_runtime_skip_count: int = 0
    upscale_description: str | None = None
    failure_retry_same: bool = False
    failure_average_description: str | None = None
    retry_after_dangling_processes: bool = True
    internal_interrupted_crash: bool = False
    retryable_action_failure: bool = False
    meaningful_work_done: bool = False
    user_interrupted: bool = False


@dataclass
class UpscaleEvaluation:
    status: str
    reason: str | None
    skip_category: str | None


# Remember one displayed Bazel action duration and its estimated start time.
@dataclass
class ObservedActionDuration:
    displayed_seconds: int
    started_at: float | None
    observed_at: float | None


@dataclass
class BazelServer:
    pid: int
    output_base: str | None


@dataclass
class ProcessInfo:
    pid: int
    cmdline: str
    cwd: str | None
    nice: int | None
    started_at_ticks: int | None
    ppid: int | None = None
    state: str | None = None
    cgroups: tuple[tuple[str, str], ...] = field(default_factory=tuple)


@dataclass
class CleanupResult:
    count: int


@dataclass
class ActionProcessGroup:
    key: str
    pids: list[int]
    started_at_ticks: int | None
    action_labels: set[str] = field(default_factory=set)
    states: set[str] = field(default_factory=set)


# Format the diagnostic prefix with elapsed seconds since wrapper start.
def diag_prefix() -> str:
    elapsed_seconds = max(0, int(time.monotonic() - WRAPPER_START_TIME))
    return f"[bazel-adaptive/{elapsed_seconds}s]"


# Emit wrapper diagnostics without corrupting Bazel's active TTY progress line.
def diag(message: str) -> None:
    line = f"{diag_prefix()} {message}"
    if DIAG_BUFFER_INTERACTIVE:
        DIAG_BUFFER.append(line)
        return

    write_diag_line(line)


def write_diag_line(line: str) -> None:
    try:
        stderr_is_tty = os.isatty(sys.stderr.fileno())
    except (AttributeError, OSError):
        stderr_is_tty = False

    if stderr_is_tty:
        sys.stderr.write(f"\r\x1b[K{line}\n")
    else:
        sys.stderr.write(f"{line}\n")
    sys.stderr.flush()


def start_interactive_diag_buffering(enabled: bool) -> None:
    global DIAG_BUFFER_INTERACTIVE
    if enabled:
        DIAG_BUFFER_INTERACTIVE = True


def stop_interactive_diag_buffering() -> None:
    global DIAG_BUFFER_INTERACTIVE
    DIAG_BUFFER_INTERACTIVE = False


def flush_interactive_diag_buffer() -> None:
    global DIAG_BUFFER
    if not DIAG_BUFFER:
        return
    buffered = DIAG_BUFFER
    DIAG_BUFFER = []
    for line in buffered:
        write_diag_line(line)


# Parse a positive integer option value, returning None for invalid input.
def positive_int(value: str) -> int | None:
    try:
        parsed = int(value, 10)
    except ValueError:
        return None
    if parsed <= 0:
        return None
    return parsed


# Parse a Bazel --jobs value, including HOST_CPUS/HOST_RAM expressions.
def jobs_value(value: str) -> int | None:
    parsed = positive_int(value)
    if parsed is not None:
        return parsed

    match = JOBS_KEYWORD_RE.match(value)
    if not match:
        return None

    keyword = match.group("keyword")
    if keyword == "HOST_CPUS":
        base = os.cpu_count() or 1
    else:
        try:
            # Resolve HOST_RAM job expressions against MemTotal in MiB.
            base = read_meminfo().total_kb // 1024
        except OSError:
            base = 0
    if base <= 0:
        return None

    multiplier = float(match.group("multiplier") or "1")
    if multiplier <= 0:
        return None
    return max(1, int(base * multiplier))


# Read the adaptive action timeout from the environment.
def build_timeout_from_env(env: dict[str, str] | None = None) -> int:
    value = (env or os.environ).get(BUILD_TIMEOUT_ENV)
    if value is None:
        return DEFAULT_ACTION_TIMEOUT_SECONDS

    timeout = positive_int(value)
    if timeout is None:
        raise ValueError(f"{BUILD_TIMEOUT_ENV} must be a positive integer number of seconds")
    return timeout


# Read the low-memory threshold from the environment in KiB.
def low_memory_threshold_kb(env: dict[str, str] | None = None) -> int:
    value = (env or os.environ).get(LOW_MEMORY_THRESHOLD_ENV)
    if value is None:
        return DEFAULT_LOW_MEMORY_THRESHOLD_MB * 1024

    threshold_mb = positive_int(value)
    if threshold_mb is None:
        raise ValueError(f"{LOW_MEMORY_THRESHOLD_ENV} must be a positive integer number of MiB")
    return threshold_mb * 1024


# Read how long I/O stalls must persist before lowering the running-action floor.
def io_stall_floor_seconds(env: dict[str, str] | None = None) -> int:
    value = (env or os.environ).get(IO_STALL_FLOOR_SECONDS_ENV)
    if value is None:
        return DEFAULT_IO_STALL_FLOOR_SECONDS

    seconds = positive_int(value)
    if seconds is None:
        raise ValueError(f"{IO_STALL_FLOOR_SECONDS_ENV} must be a positive integer")
    return seconds


def io_stall_swap_rate_kb_per_second(env: dict[str, str] | None = None) -> int:
    value = (env or os.environ).get(IO_STALL_SWAP_RATE_ENV)
    if value is None:
        return DEFAULT_IO_STALL_SWAP_RATE_MB_PER_SECOND * 1024

    rate_mb = positive_int(value)
    if rate_mb is None:
        raise ValueError(f"{IO_STALL_SWAP_RATE_ENV} must be a positive integer")
    return rate_mb * 1024


def resume_swap_in_grace_seconds(env: dict[str, str] | None = None) -> float:
    value = (env or os.environ).get(RESUME_SWAP_IN_GRACE_ENV)
    if value is None:
        return DEFAULT_RESUME_SWAP_IN_GRACE_SECONDS

    try:
        seconds = float(value)
    except ValueError as error:
        raise ValueError(
            f"{RESUME_SWAP_IN_GRACE_ENV} must be a non-negative number"
        ) from error
    if seconds < 0:
        raise ValueError(f"{RESUME_SWAP_IN_GRACE_ENV} must be a non-negative number")
    return seconds


# Return the index of Bazel's "--" delimiter, or the end of args if absent.
def bazel_option_end(args: list[str]) -> int:
    try:
        return args.index("--")
    except ValueError:
        return len(args)


def bazel_command_supports_jobs(args: list[str]) -> bool:
    end = bazel_option_end(args)
    skip_possible_option_value = False
    for arg in args[:end]:
        if skip_possible_option_value:
            skip_possible_option_value = False
            continue
        if arg.startswith("-"):
            if "=" not in arg:
                skip_possible_option_value = True
            continue
        return arg in JOBS_COMMANDS
    return False


# Parse Bazel arguments enough to find the initial jobs cap.
def parse_bazel_args(args: list[str], action_timeout: int | None = None) -> ParsedArgs:
    initial_jobs = None
    job_locations: list[tuple[str, int]] = []
    supports_jobs = bazel_command_supports_jobs(args)

    end = bazel_option_end(args)
    if supports_jobs:
        i = 0
        while i < end:
            arg = args[i]
            if arg.startswith("--jobs="):
                job_locations.append(("equals", i))
                parsed = jobs_value(arg.split("=", 1)[1])
                if parsed is not None:
                    initial_jobs = parsed
            elif arg == "--jobs" and i + 1 < end:
                job_locations.append(("separate", i))
                parsed = jobs_value(args[i + 1])
                if parsed is not None:
                    initial_jobs = parsed
                i += 1
            i += 1

    if initial_jobs is None:
        initial_jobs = os.cpu_count() or 1
    if action_timeout is None:
        action_timeout = build_timeout_from_env()

    return ParsedArgs(
        original_args=list(args),
        initial_jobs=initial_jobs,
        action_timeout=action_timeout,
        job_locations=job_locations,
        supports_jobs=supports_jobs,
    )


# Return Bazel args with this attempt's concrete --jobs value applied.
def bazel_args_with_jobs(parsed: ParsedArgs, jobs: int) -> list[str]:
    bazel_args = list(parsed.original_args)
    if not parsed.supports_jobs:
        return bazel_args
    if parsed.job_locations:
        for kind, index in parsed.job_locations:
            if kind == "equals":
                bazel_args[index] = f"--jobs={jobs}"
            elif kind == "separate" and index + 1 < len(bazel_args):
                bazel_args[index + 1] = str(jobs)
        return bazel_args

    insert_at = bazel_option_end(bazel_args)
    return bazel_args[:insert_at] + [f"--jobs={jobs}"] + bazel_args[insert_at:]


# Extract Bazel's displayed action duration from a progress line.
def parse_duration_seconds(line: str) -> int | None:
    match = ACTION_DURATION_RE.search(line)
    if not match:
        return None
    hours = int(match.group("hours") or 0)
    minutes = int(match.group("minutes") or 0)
    seconds = int(match.group("seconds") or 0)
    return hours * 3600 + minutes * 60 + seconds

# Track Bazel progress frames and failure hints from forwarded output.
class ProgressFrameParser:
    def __init__(self) -> None:
        self._buffer = ""
        self._buffer_updated_at: float | None = None
        self.running_count: int | None = None
        self.running_count_decreased = False
        self.completed_count: int | None = None
        self.completed_count_advanced_at: float | None = None
        self.total_count: int | None = None
        self.meaningful_work_done = False
        self.action_durations: list[ObservedActionDuration] = []
        self.current_frame_started_at: float | None = None
        self.current_frame_has_summary_duration = False
        self._pause_started_at: float | None = None
        self._pause_intervals: list[tuple[float, float]] = []
        self._label_pause_started_at: dict[str, float] = {}
        self._label_pause_intervals: dict[str, list[tuple[float, float]]] = {}
        self._label_last_seen_at: dict[str, float] = {}
        self._live_action_labels: set[str] = set()
        self.saw_memory_kill = False
        self.saw_build_failure = False
        self.saw_server_abrupt = False
        self.saw_internal_crash = False
        self.saw_java_interrupted = False
        self.saw_user_interrupt = False
        self.output_bases: set[str] = set()

    def feed(self, text: str, now: float | None = None) -> None:
        if text:
            self._buffer_updated_at = now
        self._buffer += text
        parts = LINE_SEPARATOR_RE.split(self._buffer)
        self._buffer = parts.pop()
        for line in parts:
            self._process_line(line, now)

    def _process_line(self, line: str, now: float | None = None) -> None:
        clean = ANSI_RE.sub("", line).rstrip()
        if not clean:
            return

        if MEMORY_KILL_RE.search(clean):
            self.saw_memory_kill = True
        if BUILD_FAILURE_RE.search(clean):
            self.saw_build_failure = True
        if SERVER_ABRUPT_RE.search(clean):
            self.saw_server_abrupt = True
        if INTERNAL_CRASH_RE.search(clean):
            self.saw_internal_crash = True
        if JAVA_INTERRUPTED_RE.search(clean):
            self.saw_java_interrupted = True
        if BAZEL_USER_INTERRUPT_RE.search(clean):
            self.saw_user_interrupt = True
        for match in OUTPUT_BASE_LOG_RE.finditer(clean):
            self.output_bases.add(os.path.realpath(match.group("output_base")))

        if PROGRESS_HEADER_RE.match(clean):
            self.current_frame_started_at = now
            progress_match = PROGRESS_COUNT_RE.match(clean)
            if progress_match:
                completed_count = int(progress_match.group("done").replace(",", ""))
                if self.completed_count is not None and completed_count > self.completed_count:
                    self.meaningful_work_done = True
                    self.completed_count_advanced_at = now
                self.completed_count = completed_count

                total = progress_match.group("total")
                if total is None:
                    self.total_count = None
                else:
                    self.total_count = int(total.replace(",", ""))

            previous_running_count = self.running_count
            running_match = RUNNING_COUNT_RE.search(clean)
            if running_match:
                running_value = running_match.group("listed_running")
                if running_value is None:
                    running_value = running_match.group("actions_running")
                if running_value is None:
                    running_value = running_match.group("running")
                if running_value is None:
                    running_value = running_match.group("action_only")

                if running_value is None:
                    self.running_count = 0
                else:
                    self.running_count = int(running_value)
            else:
                self.running_count = None

            if previous_running_count is not None and self.running_count is not None:
                if self.running_count < previous_running_count:
                    self.running_count_decreased = True
                elif self.running_count > previous_running_count:
                    self.running_count_decreased = False

            self.action_durations = []
            self.current_frame_has_summary_duration = False
            duration = parse_duration_seconds(clean)
            if duration is not None:
                self._remember_duration(duration, now)
                self.current_frame_has_summary_duration = True
            return

        duration = parse_duration_seconds(clean)
        if duration is None:
            return

        self._remember_duration(duration, now)

    # Store a displayed action duration with the wall-clock time it was seen.
    def _remember_duration(self, duration: int, now: float | None) -> None:
        if now is None:
            action_started_at = None
        else:
            action_started_at = now - duration
        self.action_durations.append(
            ObservedActionDuration(
                displayed_seconds=duration,
                started_at=action_started_at,
                observed_at=now,
            )
        )

    # Start a pause interval while at least one action group is SIGSTOPped.
    def note_actions_paused(self, now: float) -> None:
        if self._pause_started_at is None:
            self._pause_started_at = now

    # End the current pause interval when all paused action groups are resumed.
    def note_actions_resumed(self, now: float) -> None:
        if self._pause_started_at is None:
            return
        start = self._pause_started_at
        end = max(start, now)
        self._pause_intervals.append((start, end))
        self._pause_started_at = None

    # Track pause intervals for the concrete source labels attached to stopped actions.
    def note_paused_labels(self, labels: set[str], now: float) -> None:
        labels = {label for label in labels if label}
        for label in sorted(set(self._label_pause_started_at) - labels):
            start = self._label_pause_started_at.pop(label)
            end = max(start, now)
            self._label_pause_intervals.setdefault(label, []).append((start, end))
            self._label_last_seen_at[label] = now

        for label in sorted(labels - set(self._label_pause_started_at)):
            self._label_pause_started_at[label] = now
            self._label_last_seen_at[label] = now

        for label in labels:
            self._label_last_seen_at[label] = now
        self.prune_label_pause_history(now)

    def note_live_action_labels(self, labels: set[str], now: float) -> None:
        self._live_action_labels = {label for label in labels if label}
        for label in self._live_action_labels & self.paused_duration_labels():
            self._label_last_seen_at[label] = now
        self.prune_label_pause_history(now)

    def note_display_label_seen(self, label: str, now: float) -> None:
        if label:
            self._label_last_seen_at[label] = now
        self.prune_label_pause_history(now)

    def paused_duration_labels(self) -> set[str]:
        return set(self._label_pause_intervals) | set(self._label_pause_started_at)

    def prune_label_pause_history(self, now: float) -> None:
        tracked = self.paused_duration_labels()
        if not tracked:
            return

        protected = set(self._label_pause_started_at) | self._live_action_labels
        forget_before = now - DISPLAY_PAUSE_LABEL_GRACE_SECONDS
        forget_labels = [
            label
            for label in tracked
            if label not in protected
            and self._label_last_seen_at.get(label, 0.0) < forget_before
        ]

        if len(tracked) - len(forget_labels) > DISPLAY_PAUSE_LABEL_HISTORY_LIMIT:
            candidates = [
                label
                for label in tracked
                if label not in protected and label not in forget_labels
            ]
            candidates.sort(key=lambda label: self._label_last_seen_at.get(label, 0.0))
            overflow = len(tracked) - len(forget_labels) - DISPLAY_PAUSE_LABEL_HISTORY_LIMIT
            forget_labels.extend(candidates[:overflow])

        for label in forget_labels:
            self._label_pause_intervals.pop(label, None)
            self._label_last_seen_at.pop(label, None)

    # Return how much of one wall-clock span was spent with actions paused.
    def _paused_overlap_seconds(self, start: float, end: float) -> float:
        if end <= start:
            return 0.0

        paused_seconds = 0.0
        for pause_start, pause_end in self._pause_intervals:
            overlap_start = max(start, pause_start)
            overlap_end = min(end, pause_end)
            if overlap_end > overlap_start:
                paused_seconds += overlap_end - overlap_start

        if self._pause_started_at is not None:
            overlap_start = max(start, self._pause_started_at)
            if end > overlap_start:
                paused_seconds += end - overlap_start

        return paused_seconds

    def _label_paused_overlap_seconds(self, label: str, start: float, end: float) -> float:
        if end <= start:
            return 0.0

        paused_seconds = 0.0
        for pause_start, pause_end in self._label_pause_intervals.get(label, []):
            overlap_start = max(start, pause_start)
            overlap_end = min(end, pause_end)
            if overlap_end > overlap_start:
                paused_seconds += overlap_end - overlap_start

        pause_start = self._label_pause_started_at.get(label)
        if pause_start is not None:
            overlap_start = max(start, pause_start)
            if end > overlap_start:
                paused_seconds += end - overlap_start

        return paused_seconds

    # Return wall-clock elapsed time with wrapper-induced paused time removed.
    def _active_elapsed_seconds(self, start: float, end: float) -> float:
        elapsed = end - start
        paused = self._paused_overlap_seconds(start, end)
        return max(0.0, elapsed - paused)

    def _active_elapsed_seconds_for_label(self, label: str, start: float, end: float) -> float:
        elapsed = end - start
        paused = self._label_paused_overlap_seconds(label, start, end)
        return max(0.0, elapsed - paused)

    # Return action durations aged by active time, optionally including a partial line.
    def _effective_durations(
        self,
        now: float | None = None,
        include_partial: bool = False,
    ) -> list[float]:
        durations = []
        for action in self.action_durations:
            end = now if now is not None else action.observed_at
            if end is not None and action.started_at is not None:
                durations.append(self._active_elapsed_seconds(action.started_at, end))
            else:
                durations.append(float(action.displayed_seconds))
        if include_partial and self._buffer:
            partial_duration = parse_duration_seconds(ANSI_RE.sub("", self._buffer))
            if partial_duration is not None:
                if now is not None and self._buffer_updated_at is not None:
                    partial_action_started_at = self._buffer_updated_at - partial_duration
                    durations.append(
                        self._active_elapsed_seconds(partial_action_started_at, now)
                    )
                else:
                    durations.append(float(partial_duration))
        return durations

    def all_reported_actions_over(self, limit_seconds: int, now: float | None = None) -> bool:
        durations = self._effective_durations(now, include_partial=True)

        if not durations:
            frame_has_stalled = (
                now is not None
                and self.current_frame_started_at is not None
                and self._active_elapsed_seconds(self.current_frame_started_at, now)
                > limit_seconds
            )
            return (
                self.running_count is not None
                and self.running_count > 0
                and bool(self._buffer)
                and frame_has_stalled
            )

        if self.running_count == 0:
            return False

        all_visible_actions_are_over_limit = all(
            duration > limit_seconds for duration in durations
        )

        if self.running_count is None:
            return all_visible_actions_are_over_limit

        if len(durations) < self.running_count:
            return all_visible_actions_are_over_limit

        reported_action_durations = durations[: self.running_count]
        return all(duration > limit_seconds for duration in reported_action_durations)

    def all_displayed_actions_over(self, limit_seconds: int, now: float | None = None) -> bool:
        durations = self._effective_durations(now, include_partial=True)
        if not durations:
            return False
        if self.running_count == 0:
            return False
        if self.running_count is None:
            return all(duration > limit_seconds for duration in durations)

        reported_action_durations = durations[: self.running_count]
        return all(duration > limit_seconds for duration in reported_action_durations)

    def completed_progress_recent(self, now: float, window_seconds: float) -> bool:
        return (
            self.completed_count_advanced_at is not None
            and now - self.completed_count_advanced_at <= window_seconds
        )

    def has_running_actions(self) -> bool:
        if self.running_count is not None:
            return self.running_count > 0
        return bool(self.action_durations)

    def current_action_durations(self, now: float | None = None) -> list[float]:
        durations = self._effective_durations(now, include_partial=False)
        if self.running_count is not None:
            return durations[: self.running_count]
        return durations

    def upscale_action_skip_reason(
        self,
        max_action_seconds: int,
        remaining_action_finish_threshold: int,
        now: float | None = None,
    ) -> str | None:
        if not self.meaningful_work_done:
            return "completed action count has not advanced in this Bazel attempt"
        if not self.has_running_actions():
            return "no actions are currently running; letting Bazel finish"
        have_progress_counts = (
            self.completed_count is not None
            and self.total_count is not None
        )
        remaining_count = None
        if have_progress_counts:
            remaining_count = max(0, self.total_count - self.completed_count)
            if remaining_count <= remaining_action_finish_threshold:
                return (
                    f"only {remaining_count} action(s) remain; "
                    f"need more than {remaining_action_finish_threshold} before upscale"
                )
            if self.running_count is not None and remaining_count == self.running_count:
                return (
                    f"only {remaining_count} action(s) remain and "
                    f"{self.running_count} action(s) are running; letting Bazel finish"
                )
        running_count_decrease_suggests_finish = self.running_count_decreased
        if (
            running_count_decrease_suggests_finish
            and remaining_count is not None
            and self.running_count is not None
            and remaining_count > max(self.running_count * 2, self.running_count + 8)
        ):
            running_count_decrease_suggests_finish = False
        if running_count_decrease_suggests_finish:
            return "running action count is decreasing; letting Bazel finish"
        durations = self.current_action_durations(now)
        if not durations:
            return "current running action durations are unavailable"
        oldest_action_seconds = max(durations)
        if oldest_action_seconds >= max_action_seconds:
            oldest_display_seconds = int(oldest_action_seconds)
            return (
                f"oldest current running action is {oldest_display_seconds}s; "
                f"need all current actions under {max_action_seconds}s before upscale"
            )
        return None

    def current_action_age_description(self, now: float | None = None) -> str:
        if not self.has_running_actions():
            return "no current running actions"
        durations = self.current_action_durations(now)
        if not durations:
            return "current action ages unavailable"
        return f"oldest current action {int(max(durations))}s"


# Read total and available memory from /proc/meminfo or a test override.
def read_meminfo(path: str | None = None) -> MemInfo:
    values: dict[str, int] = {}
    meminfo_path = path or os.environ.get(MEMINFO_ENV, DEFAULT_MEMINFO_PATH)
    with open(meminfo_path, encoding="utf-8") as meminfo:
        for line in meminfo:
            fields = line.split()
            if len(fields) >= 2 and fields[0].endswith(":"):
                try:
                    values[fields[0][:-1]] = int(fields[1])
                except ValueError:
                    continue
    return MemInfo(
        total_kb=values.get("MemTotal", 0),
        available_kb=values.get("MemAvailable", values.get("MemFree", 0)),
    )


def read_swap_io(path: str | None = None) -> SwapIo:
    values: dict[str, int] = {}
    vmstat_path = path or os.environ.get(VMSTAT_ENV, DEFAULT_VMSTAT_PATH)
    with open(vmstat_path, encoding="utf-8") as vmstat:
        for line in vmstat:
            fields = line.split()
            if len(fields) != 2:
                continue
            if fields[0] != "pswpin":
                continue
            try:
                values[fields[0]] = int(fields[1])
            except ValueError:
                continue
    return SwapIo(pages_in=values.get("pswpin", 0))


# Increase jobs by 1.5x, rounded up and capped at the initial maximum.
def upscale_jobs(jobs: int, max_jobs: int) -> int:
    return min(max_jobs, max(jobs + 1, (jobs * 3 + 1) // 2))


# Reduce jobs by half, rounded up so odd counts are not cut too sharply.
def downscale_jobs(jobs: int) -> int:
    return max(1, (jobs + 1) // 2)


# Read the memory polling interval, clamped away from a busy loop.
def memory_poll_interval() -> float:
    value = os.environ.get(MEMORY_POLL_INTERVAL_ENV)
    if value is None:
        return DEFAULT_MEMORY_POLL_INTERVAL_SECONDS
    try:
        return max(MIN_MEMORY_POLL_INTERVAL_SECONDS, float(value))
    except ValueError:
        return DEFAULT_MEMORY_POLL_INTERVAL_SECONDS


# Limit repeated same-job retries for action failures that happen with healthy memory.
def same_job_retry_limit() -> int:
    value = os.environ.get(SAME_JOB_RETRY_LIMIT_ENV)
    if value is None:
        return DEFAULT_SAME_JOB_RETRY_LIMIT
    parsed = positive_int(value)
    if parsed is None:
        return DEFAULT_SAME_JOB_RETRY_LIMIT
    return parsed


# Read the short settling delay used before every Bazel restart.
def restart_settle_delay() -> float:
    value = os.environ.get(RESTART_SETTLE_DELAY_ENV)
    if value is None:
        return DEFAULT_RESTART_SETTLE_DELAY_SECONDS
    try:
        return max(0.0, float(value))
    except ValueError:
        return DEFAULT_RESTART_SETTLE_DELAY_SECONDS


# Read the nice increment inherited by Bazel's long-running build process tree.
def bazel_nice_increment() -> int:
    value = os.environ.get(BAZEL_NICE_ENV)
    if value is None:
        return DEFAULT_BAZEL_NICE
    try:
        parsed = int(value, 10)
    except ValueError:
        return DEFAULT_BAZEL_NICE
    return min(MAX_BAZEL_NICE, max(MIN_BAZEL_NICE, parsed))


# Put Bazel in its own process group and lower only Bazel's scheduling priority.
def prepare_bazel_child() -> None:
    os.setpgrp()
    nice_increment = bazel_nice_increment()
    if nice_increment == 0:
        return
    try:
        os.nice(nice_increment)
    except OSError:
        pass


# Maintain the rolling memory window used by retry and upscale decisions.
class MemoryPressureMonitor:
    def __init__(self, poll_interval: float | None = None) -> None:
        self.poll_interval = poll_interval if poll_interval is not None else memory_poll_interval()
        self.next_poll = 0.0
        self.last: MemInfo | None = None
        self.last_low_at: float | None = None
        self.last_low: MemInfo | None = None
        self.samples: list[tuple[float, MemInfo]] = []

    def sample(self, now: float, force: bool = False) -> MemInfo | None:
        if not force and now < self.next_poll:
            return self.last
        self.next_poll = now + self.poll_interval
        try:
            meminfo = read_meminfo()
        except OSError as error:
            diag(f"could not read memory information: {error}")
            return self.last
        self.last = meminfo
        self.samples.append((now, meminfo))
        self.samples = [
            (sampled_at, sample)
            for sampled_at, sample in self.samples
            if now - sampled_at <= MEMORY_REPORT_SECONDS
        ]
        if meminfo.available_kb < low_memory_threshold_kb():
            self.last_low_at = now
            self.last_low = meminfo
        return meminfo

    def recent_samples(self, now: float) -> list[MemInfo]:
        recent = []
        for sampled_at, sample in self.samples:
            if now - sampled_at <= MEMORY_REPORT_SECONDS:
                recent.append(sample)
        return recent

    def recent_average_available_kb(self, now: float) -> int | None:
        recent_samples = self.recent_samples(now)
        if not recent_samples:
            return None
        return sum(sample.available_kb for sample in recent_samples) // len(recent_samples)

    def recent_min_available_kb(self, now: float) -> int | None:
        recent_samples = self.recent_samples(now)
        if not recent_samples:
            return None
        return min(sample.available_kb for sample in recent_samples)

    def recent_total_kb(self, now: float) -> int:
        recent_samples = self.recent_samples(now)
        if recent_samples:
            return recent_samples[-1].total_kb
        if self.last is not None:
            return self.last.total_kb
        return 0

    def upscale_skip_reason(
        self,
        now: float,
        running_actions_seconds: float | None,
        required_running_actions_seconds: float,
    ) -> str | None:
        average_available_kb = self.recent_average_available_kb(now)
        total_kb = self.recent_total_kb(now)
        if average_available_kb is None or total_kb <= 0:
            return "memory data is unavailable"
        recent_min_available_kb = self.recent_min_available_kb(now)
        threshold_mb = low_memory_threshold_kb() // 1024
        if (
            recent_min_available_kb is not None
            and recent_min_available_kb < low_memory_threshold_kb()
        ):
            return (
                f"memory dipped below low-memory threshold in last "
                f"{int(MEMORY_REPORT_SECONDS)}s: min "
                f"{recent_min_available_kb // 1024} MiB < {threshold_mb} MiB"
            )
        if running_actions_seconds is None:
            return (
                "running Bazel actions have not been observed yet; need "
                f"{int(required_running_actions_seconds)}s before upscale"
            )
        if running_actions_seconds < required_running_actions_seconds:
            return (
                f"running Bazel actions observed for {int(running_actions_seconds)}s; "
                f"need {int(required_running_actions_seconds)}s before upscale"
            )
        if total_kb > 0 and average_available_kb * 2 > total_kb:
            return None
        return (
            "average available memory over last "
            f"{int(MEMORY_REPORT_SECONDS)}s is {average_available_kb // 1024} MiB "
            f"of {total_kb // 1024} MiB; need more than {total_kb // 2048} MiB"
        )

    def upscale_ready_description(self, now: float, running_actions_seconds: float | None) -> str:
        average_available_kb = self.recent_average_available_kb(now) or 0
        recent_min_available_kb = self.recent_min_available_kb(now) or 0
        total_kb = self.recent_total_kb(now)
        latest_available_kb = self.last.available_kb if self.last is not None else 0
        running_seconds = int(running_actions_seconds or 0)
        return (
            f"memory latest {latest_available_kb // 1024}/{total_kb // 1024} MiB; "
            f"{int(MEMORY_REPORT_SECONDS)}s average {average_available_kb // 1024} MiB; "
            f"min {recent_min_available_kb // 1024} MiB; "
            f"running actions observed for {running_seconds}s"
        )

    def retry_same_jobs_after_failure(self, now: float) -> bool:
        average_available_kb = self.recent_average_available_kb(now)
        total_kb = self.recent_total_kb(now)
        return (
            average_available_kb is not None
            and total_kb > 0
            and average_available_kb * 2 > total_kb
        )

    def failure_average_description(self, now: float) -> str:
        average_available_kb = self.recent_average_available_kb(now) or 0
        total_kb = self.recent_total_kb(now)
        return (
            f"{int(MEMORY_REPORT_SECONDS)}s average memory "
            f"{average_available_kb // 1024}/{total_kb // 1024} MiB"
        )

    def recent_low_memory(self, now: float) -> bool:
        return (
            self.last_low_at is not None
            and now - self.last_low_at <= RECENT_MEMORY_PRESSURE_SECONDS
        )

    def recent_low_memory_description(self) -> str:
        if self.last_low is None:
            return "recent low memory"
        return f"{self.last_low.available_kb // 1024} MiB available"

    def failure_report(self, now: float) -> str:
        if self.last is None:
            return "memory pressure: unavailable"

        recent_samples = self.recent_samples(now)
        recent_min = min(recent_samples, key=lambda sample: sample.available_kb, default=self.last)
        recent_average = self.recent_average_available_kb(now) or self.last.available_kb
        recent_low = "yes" if self.recent_low_memory(now) else "no"
        threshold_mb = low_memory_threshold_kb() // 1024
        return (
            "memory pressure: "
            f"latest {self.last.available_kb // 1024}/{self.last.total_kb // 1024} MiB; "
            f"{int(MEMORY_REPORT_SECONDS)}s average {recent_average // 1024} MiB; "
            f"min {recent_min.available_kb // 1024} MiB; "
            f"less than low-memory threshold {threshold_mb} MiB: {recent_low}"
        )


# Temporarily hand the foreground terminal to Bazel for natural Ctrl-C handling.
class TerminalForeground:
    def __init__(self) -> None:
        self.enabled = False
        self.fd = -1
        self.wrapper_pgid = os.getpgrp()
        self._given = False

        try:
            fd = sys.stdin.fileno()
        except (AttributeError, OSError):
            return
        if os.isatty(fd):
            self.enabled = True
            self.fd = fd

    def give_to(self, pgid: int) -> None:
        if not self.enabled:
            return
        self._set_foreground(pgid)
        self._given = True

    def restore(self) -> None:
        if not self.enabled or not self._given:
            return
        self._set_foreground(self.wrapper_pgid)
        self._given = False

    def _set_foreground(self, pgid: int) -> None:
        old_handler = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        try:
            os.tcsetpgrp(self.fd, pgid)
        except OSError:
            pass
        finally:
            signal.signal(signal.SIGTTOU, old_handler)


# Parse boolean environment flags used for PTY behavior.
def env_flag(name: str) -> bool:
    return os.environ.get(name, DEFAULT_ENV_FLAG_VALUE).lower() in {"1", "true", "yes", "on"}


# Convert signal-style negative subprocess return codes to shell exit codes.
def normalize_returncode(returncode: int) -> int:
    if returncode < 0:
        return 128 + abs(returncode)
    return returncode


# Rewrite displayed Bazel action counts to include wrapper-paused action groups.
def rewrite_action_duration_display(
    text: str,
    parser: ProgressFrameParser,
    now: float,
    paused_count: int,
    paused_labels: set[str] | None = None,
) -> str:
    rewritten_count = 0
    current_labels = paused_labels or set()
    labels = parser.paused_duration_labels() | current_labels
    if paused_count <= 0 and not labels:
        return text

    def line_for_match(match: re.Match) -> str:
        line_start = text.rfind("\n", 0, match.start()) + 1
        carriage_start = text.rfind("\r", 0, match.start()) + 1
        line_start = max(line_start, carriage_start)
        line_end_candidates = [
            index
            for index in (
                text.find("\n", match.end()),
                text.find("\r", match.end()),
            )
            if index != -1
        ]
        line_end = min(line_end_candidates) if line_end_candidates else len(text)
        return text[line_start:line_end]

    def matching_label(match: re.Match) -> str | None:
        if not labels:
            return None
        line = ANSI_RE.sub("", line_for_match(match)).replace("\\", "/")
        for label in sorted(labels, key=len, reverse=True):
            if label in line:
                return label
        return None

    def replace(match: re.Match) -> str:
        nonlocal rewritten_count
        duration = parse_duration_seconds(match.group(0))
        if duration is None:
            return match.group(0)
        started_at = now - duration

        label = matching_label(match)
        if label is not None:
            parser.note_display_label_seen(label, now)
            if label in parser.paused_duration_labels():
                active_duration = int(
                    parser._active_elapsed_seconds_for_label(label, started_at, now)
                )
            else:
                active_duration = int(parser._active_elapsed_seconds(started_at, now))
        else:
            if paused_count <= 0 or labels or rewritten_count >= paused_count:
                return match.group(0)
            active_duration = int(parser._active_elapsed_seconds(started_at, now))

        rewritten_count += 1
        return f"; {max(0, active_duration)}s"

    return ACTION_DURATION_RE.sub(replace, text)


def rewrite_action_summary_display(text: str, paused_count: int) -> str:
    if paused_count <= 0:
        return text

    def split_actions(actions: int, running: int, parenthesized: bool) -> str:
        paused = min(paused_count, running)
        active_running = running - paused
        action_word = "action" if actions == 1 else "actions"
        rewritten = f"{actions} {action_word}, {paused} paused, {active_running} running"
        if parenthesized:
            return f"({rewritten})"
        return rewritten

    def replace(match: re.Match) -> str:
        running_text = match.group("running")
        if running_text is not None:
            return split_actions(int(match.group("actions")), int(running_text), True)

        bare_running_text = match.group("bare_running")
        if bare_running_text is not None:
            return split_actions(
                int(match.group("bare_actions")),
                int(bare_running_text),
                False,
            )

        parenthesized_only_running = match.group("parenthesized_only_running")
        only_running_text = parenthesized_only_running or match.group("only_running")
        return split_actions(
            int(only_running_text),
            int(only_running_text),
            parenthesized_only_running is not None,
        )

    return ACTION_SUMMARY_DISPLAY_RE.sub(replace, text)


# Remember where a selected stream should be forwarded and how to close it.
class StreamTarget:
    def __init__(self, output, close_on_eof=None) -> None:
        self.output = output
        self.close_on_eof = close_on_eof

    def close(self) -> None:
        if self.close_on_eof is None:
            return
        try:
            self.close_on_eof()
        except OSError:
            pass


# Choose PTY or pipe output wiring and register it with the selector.
class BazelOutput:
    def __init__(self) -> None:
        self.master_fd: int | None = None
        self.slave_fd: int | None = None
        self.use_pty = False

        if env_flag(DISABLE_PTY_ENV):
            return

        stdout_fd = None
        stderr_fd = None
        try:
            stdout_fd = sys.stdout.fileno()
            stderr_fd = sys.stderr.fileno()
        except (AttributeError, OSError):
            pass

        has_terminal = (
            stdout_fd is not None
            and stderr_fd is not None
            and os.isatty(stdout_fd)
            and os.isatty(stderr_fd)
        )
        if has_terminal or env_flag(FORCE_PTY_ENV):
            self.master_fd, self.slave_fd = pty.openpty()
            rows = positive_int(os.environ.get(PTY_ROWS_ENV, DEFAULT_PTY_ROWS))
            columns = positive_int(os.environ.get(PTY_COLUMNS_ENV, DEFAULT_PTY_COLUMNS))
            if rows is None or columns is None:
                fd_rows = fd_columns = 0
                if stdout_fd is not None:
                    try:
                        # Prefer the real terminal size so Bazel progress frames are not truncated.
                        data = fcntl.ioctl(
                            stdout_fd,
                            termios.TIOCGWINSZ,
                            struct.pack("HHHH", 0, 0, 0, 0),
                        )
                        fd_rows, fd_columns, _, _ = struct.unpack("HHHH", data)
                    except OSError:
                        pass
                if fd_rows <= 0 or fd_columns <= 0:
                    fallback = shutil.get_terminal_size(
                        fallback=(DEFAULT_TERMINAL_COLUMNS, DEFAULT_TERMINAL_ROWS)
                    )
                    fd_rows, fd_columns = fallback.lines, fallback.columns
                rows = rows or fd_rows
                columns = columns or fd_columns
            try:
                # Apply the chosen PTY size before Bazel starts writing progress frames.
                window_size = struct.pack("HHHH", rows, columns, 0, 0)
                fcntl.ioctl(self.slave_fd, termios.TIOCSWINSZ, window_size)
            except OSError:
                pass
            self.use_pty = True

    def popen_kwargs(self) -> dict:
        if self.use_pty:
            return {"stdout": self.slave_fd, "stderr": self.slave_fd}
        return {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE}

    def parent_after_spawn(self) -> None:
        if self.use_pty and self.slave_fd is not None:
            os.close(self.slave_fd)
            self.slave_fd = None

    def register(self, selector: selectors.DefaultSelector, process: subprocess.Popen) -> None:
        if self.use_pty and self.master_fd is not None:
            selector.register(
                self.master_fd,
                selectors.EVENT_READ,
                StreamTarget(sys.stdout.buffer, self.close_master),
            )
            return
        if process.stdout is not None:
            selector.register(process.stdout, selectors.EVENT_READ, StreamTarget(sys.stdout.buffer))
        if process.stderr is not None:
            selector.register(process.stderr, selectors.EVENT_READ, StreamTarget(sys.stderr.buffer))

    def close(self) -> None:
        if self.slave_fd is not None:
            try:
                os.close(self.slave_fd)
            except OSError:
                pass
            self.slave_fd = None
        self.close_master()

    def close_master(self) -> None:
        if self.master_fd is None:
            return
        try:
            os.close(self.master_fd)
        except OSError:
            pass
        self.master_fd = None


# Drain ready Bazel output streams while forwarding bytes and parsing a copy.
def drain_ready_streams(
    selector: selectors.DefaultSelector,
    parser: ProgressFrameParser,
    timeout: float,
    paused_count=None,
    paused_labels=None,
) -> None:
    for key, _ in selector.select(timeout):
        fd = key.fileobj if isinstance(key.fileobj, int) else key.fileobj.fileno()
        try:
            # Read what is available without blocking; PTY EIO means EOF.
            data = os.read(fd, 65536)
        except BlockingIOError:
            data = b""
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            data = None
        if data:
            target = key.data
            # Forward bytes immediately so partial lines never wait for CR/LF.
            text = data.decode("utf-8", errors="ignore")
            now = time.monotonic()
            current_paused_count = paused_count() if paused_count is not None else 0
            displayed = rewrite_action_duration_display(
                text,
                parser,
                now,
                current_paused_count,
                paused_labels() if paused_labels is not None else None,
            )
            displayed = rewrite_action_summary_display(displayed, current_paused_count)
            target.output.write(displayed.encode("utf-8"))
            target.output.flush()
            parser.feed(text, now)
            continue
        try:
            selector.unregister(key.fileobj)
        except KeyError:
            pass
        if not isinstance(key.fileobj, int):
            key.fileobj.close()
        key.data.close()


# Drain any buffered Bazel output after the process exits.
def drain_remaining_streams(
    selector: selectors.DefaultSelector,
    parser: ProgressFrameParser,
    paused_count=None,
    paused_labels=None,
) -> None:
    while selector.get_map():
        before = len(selector.get_map())
        drain_ready_streams(selector, parser, 0, paused_count, paused_labels)
        after = len(selector.get_map())
        if before == after:
            break


# Read process command line and cwd from /proc, tolerating races with exit.
def process_info(pid: int) -> ProcessInfo | None:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as cmdline:
            command = cmdline.read().replace(b"\0", b" ").decode("utf-8", errors="ignore")
    except OSError:
        return None
    nice: int | None = None
    started_at_ticks: int | None = None
    ppid: int | None = None
    state: str | None = None
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as stat:
            fields = stat.read().rsplit(")", 1)[1].strip().split()
            state = fields[0]
            ppid = int(fields[1])
            nice = int(fields[16])
            started_at_ticks = int(fields[19])
    except (OSError, IndexError, ValueError):
        ppid = None
        state = None
        nice = None
        started_at_ticks = None
    try:
        cwd = os.path.realpath(os.readlink(f"/proc/{pid}/cwd"))
    except OSError:
        cwd = None
    cgroups = process_cgroups(pid)
    return ProcessInfo(
        pid=pid,
        cmdline=command,
        cwd=cwd,
        nice=nice,
        started_at_ticks=started_at_ticks,
        ppid=ppid,
        state=state,
        cgroups=cgroups,
    )


def process_cgroups(pid: int) -> tuple[tuple[str, str], ...]:
    try:
        with open(f"/proc/{pid}/cgroup", encoding="utf-8") as cgroup_file:
            entries = []
            for line in cgroup_file:
                fields = line.rstrip("\n").split(":", 2)
                if len(fields) == 3:
                    entries.append((fields[1], fields[2]))
            return tuple(sorted(entries))
    except OSError:
        return ()


def useful_cgroup_paths(cgroups: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    return tuple((controllers, path) for controllers, path in cgroups if path not in {"", "/"})


def same_process_domain(
    owner_cgroups: tuple[tuple[str, str], ...],
    candidate_cgroups: tuple[tuple[str, str], ...],
) -> bool:
    owner_paths = useful_cgroup_paths(owner_cgroups)
    if not owner_paths:
        return True
    if not candidate_cgroups:
        return False

    candidate_by_controller = dict(candidate_cgroups)
    for controllers, owner_path in owner_paths:
        candidate_path = candidate_by_controller.get(controllers)
        if candidate_path is None:
            continue
        if candidate_path == owner_path or candidate_path.startswith(owner_path.rstrip("/") + "/"):
            return True
    return False


def process_swap_kb(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as status:
            for line in status:
                if line.startswith("VmSwap:"):
                    fields = line.split()
                    if len(fields) >= 2:
                        return int(fields[1])
                    return 0
    except (OSError, ValueError):
        return 0
    return 0


# List current Linux process ids from /proc.
def proc_pids() -> list[int]:
    pids: list[int] = []
    for name in os.listdir("/proc"):
        if name.isdigit():
            pids.append(int(name))
    return pids


# Check whether a candidate process is still alive.
def pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


# Track workspace, process domain, and Bazel output bases for cleanup.
class BuildContext:
    def __init__(
        self,
        workspace: str,
        cgroups: tuple[tuple[str, str], ...] | None = None,
    ) -> None:
        self.workspace = os.path.realpath(workspace)
        self.cgroups = cgroups if cgroups is not None else process_cgroups(os.getpid())
        self.output_bases: set[str] = set()

    def add_output_base(self, output_base: str | None) -> None:
        if output_base:
            self.output_bases.add(os.path.realpath(output_base))

    def add_output_bases(self, output_bases: set[str]) -> None:
        for output_base in output_bases:
            self.add_output_base(output_base)

    def owns_process(self, info: ProcessInfo) -> bool:
        return same_process_domain(self.cgroups, info.cgroups)

    def refresh_from_bazel_servers(self) -> None:
        for server in bazel_servers_for_workspace(self.workspace, self.cgroups):
            self.add_output_base(server.output_base)


# Find Bazel server processes that belong to this workspace.
def bazel_servers_for_workspace(
    workspace: str,
    owner_cgroups: tuple[tuple[str, str], ...] = (),
) -> list[BazelServer]:
    candidates = {workspace, os.path.realpath(workspace)}
    servers: list[BazelServer] = []
    for pid in proc_pids():
        info = process_info(pid)
        if info is None:
            continue
        if not same_process_domain(owner_cgroups, info.cgroups):
            continue
        if "A-server.jar" not in info.cmdline and "bazel(" not in info.cmdline:
            continue
        if any(f"--workspace_directory={candidate}" in info.cmdline for candidate in candidates):
            output_base = None
            for field in info.cmdline.split():
                if field.startswith("--output_base="):
                    # Capture Bazel's output base so cleanup can find sandbox children.
                    output_base = os.path.realpath(field.split("=", 1)[1])
                    break
            servers.append(BazelServer(pid=pid, output_base=output_base))
    return servers


# Find leftover Bazel sandbox/build processes tied to this workspace.
def dangling_build_processes(context: BuildContext) -> list[ProcessInfo]:
    context.refresh_from_bazel_servers()
    if not context.output_bases:
        return []

    own_pid = os.getpid()
    candidates: dict[int, ProcessInfo] = {}
    for pid in proc_pids():
        if pid == own_pid:
            continue
        info = process_info(pid)
        if info is None or not info.cmdline:
            continue
        if not context.owns_process(info):
            continue
        if (
            "A-server.jar" in info.cmdline
            or "bazel(" in info.cmdline
            or os.path.basename(info.cmdline.split(" ", 1)[0] or "") == "bazel"
        ):
            continue
        candidates[pid] = info

    matched_pids: set[int] = set()
    for info in candidates.values():
        for output_base in context.output_bases:
            try:
                # Match processes whose cwd or command ties them to this Bazel output base.
                cwd_under_output_base = (
                    info.cwd is not None
                    and os.path.commonpath(
                        [os.path.realpath(info.cwd), os.path.realpath(output_base)]
                    )
                    == os.path.realpath(output_base)
                )
            except ValueError:
                cwd_under_output_base = False
            if cwd_under_output_base or output_base in info.cmdline:
                matched_pids.add(info.pid)
                break

    children_by_parent: dict[int, list[int]] = {}
    for info in candidates.values():
        if info.ppid is not None:
            children_by_parent.setdefault(info.ppid, []).append(info.pid)

    processes: list[ProcessInfo] = []
    seen: set[int] = set()
    stack = list(sorted(matched_pids))
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        info = candidates.get(pid)
        if info is None:
            continue
        processes.append(info)
        stack.extend(children_by_parent.get(pid, []))
    return processes


def source_labels_from_process(info: ProcessInfo, context: BuildContext) -> set[str]:
    labels: set[str] = set()
    for raw_token in info.cmdline.split():
        token = raw_token.strip("'\"")
        if not SOURCE_FILE_RE.search(token):
            continue
        normalized = token.replace("\\", "/")
        labels.add(normalized)
        try:
            real_token = os.path.realpath(token)
            if os.path.isabs(token) and os.path.commonpath(
                [real_token, context.workspace]
            ) == context.workspace:
                labels.add(os.path.relpath(real_token, context.workspace).replace("\\", "/"))
        except (OSError, ValueError):
            pass

        execroot_marker = "/execroot/"
        if execroot_marker in normalized:
            after_execroot = normalized.split(execroot_marker, 1)[1]
            parts = after_execroot.split("/", 1)
            if len(parts) == 2:
                execroot_relative = parts[1]
                labels.add(execroot_relative)
                external_parts = execroot_relative.split("/", 2)
                if (
                    len(external_parts) == 3
                    and external_parts[0] == "external"
                ):
                    labels.add(external_parts[2])

    return {label for label in labels if "/" in label or label.startswith("//")}


# Group build processes by Bazel sandbox action directory when possible.
def build_process_groups(context: BuildContext) -> list[ActionProcessGroup]:
    processes = dangling_build_processes(context)
    processes_by_pid = {process.pid: process for process in processes}

    def sandbox_key(info: ProcessInfo) -> str | None:
        for text in (info.cwd or "", info.cmdline):
            match = SANDBOX_ACTION_RE.search(text)
            if match:
                return match.group("sandbox_key")
        return None

    direct_keys = {
        process.pid: key
        for process in processes
        if (key := sandbox_key(process)) is not None
    }

    def inherited_key(info: ProcessInfo) -> str:
        seen: set[int] = set()
        current: ProcessInfo | None = info
        while current is not None and current.pid not in seen:
            seen.add(current.pid)
            key = direct_keys.get(current.pid)
            if key is not None:
                return key
            if current.ppid is None:
                break
            current = processes_by_pid.get(current.ppid)
        return f"pid:{info.pid}"

    grouped: dict[str, list[ProcessInfo]] = {}
    for info in processes:
        grouped.setdefault(inherited_key(info), []).append(info)

    groups: list[ActionProcessGroup] = []
    for key, processes in grouped.items():
        starts = [
            process.started_at_ticks
            for process in processes
            if process.started_at_ticks is not None
        ]
        action_labels: set[str] = set()
        for process in processes:
            action_labels.update(source_labels_from_process(process, context))
        states = {process.state for process in processes if process.state is not None}
        groups.append(
            ActionProcessGroup(
                key=key,
                pids=sorted(process.pid for process in processes),
                started_at_ticks=min(starts) if starts else None,
                action_labels=action_labels,
                states=states,
            )
        )
    return groups


# Pause and resume Bazel action process groups to reduce memory pressure.
class ActionThrottler:
    def __init__(self, context: BuildContext) -> None:
        self.context = context
        self.paused_keys: set[str] = set()
        self.paused_pids: dict[str, set[int]] = {}
        self.paused_action_labels: dict[str, set[str]] = {}
        self.paused_started_at: dict[str, float] = {}
        self.paused_total_seconds: dict[str, float] = {}
        self.current_action_labels: set[str] = set()
        self.base_threshold_kb = low_memory_threshold_kb()
        self.effective_threshold_kb = self.base_threshold_kb
        self.max_threshold_kb = self.base_threshold_kb * 2
        self.threshold_step_kb = ADAPTIVE_THRESHOLD_STEP_MB * 1024
        self.next_threshold_raise_at = 0.0
        self.next_threshold_lower_at = 0.0
        self.max_observed_action_groups = 0
        self.io_stall_floor_seconds = io_stall_floor_seconds()
        self.io_stall_swap_rate_kb_per_second = io_stall_swap_rate_kb_per_second()
        self.resume_swap_in_grace_seconds = resume_swap_in_grace_seconds()
        self.io_stall_started_at: float | None = None
        self.io_stall_observations: list[tuple[float, bool]] = []
        self.current_io_stall_observed = False
        self.io_stall_floor_groups: int | None = None
        self.next_io_stall_floor_drop_at: float | None = None
        self.last_running_io_stall_at: float | None = None
        self.last_resume_at: float | None = None
        self.last_swap_io_sample: tuple[float, SwapIo] | None = None
        self.last_swap_io_rate_kb_per_second = 0.0
        self.next_normal_resume_at = 0.0

    def paused_count(self) -> int:
        return len(self.paused_keys)

    def paused_labels(self) -> set[str]:
        labels: set[str] = set()
        for key in self.paused_keys:
            labels.update(self.paused_action_labels.get(key, set()))
        return labels

    def group_is_physically_stopped(self, group: ActionProcessGroup) -> bool:
        return bool(group.states) and group.states <= {"T"}

    def group_is_paused(self, group: ActionProcessGroup) -> bool:
        return group.key in self.paused_keys or self.group_is_physically_stopped(group)

    def group_is_action(self, group: ActionProcessGroup) -> bool:
        return not group.key.startswith("pid:")

    def running_action_groups(
        self,
        groups: list[ActionProcessGroup],
    ) -> list[ActionProcessGroup]:
        return [
            group
            for group in groups
            if self.group_is_action(group) and not self.group_is_paused(group)
        ]

    def stalled_running_groups(
        self,
        groups: list[ActionProcessGroup],
    ) -> list[ActionProcessGroup]:
        return [group for group in self.running_action_groups(groups) if "D" in group.states]

    def swap_io_is_heavy(self, now: float) -> bool:
        try:
            current = read_swap_io()
        except OSError:
            return False

        previous = self.last_swap_io_sample
        self.last_swap_io_sample = (now, current)
        if previous is None:
            return False

        previous_at, previous_sample = previous
        elapsed = now - previous_at
        if elapsed <= 0:
            return False

        pages_in = max(0, current.pages_in - previous_sample.pages_in)
        self.last_swap_io_rate_kb_per_second = pages_in * PAGE_SIZE_KB / elapsed
        return self.last_swap_io_rate_kb_per_second >= self.io_stall_swap_rate_kb_per_second

    def io_stall_reason(self, stalled_running: list[ActionProcessGroup]) -> str:
        if stalled_running:
            return (
                f"{len(stalled_running)} running action group(s) "
                "in uninterruptible I/O"
            )
        return (
            "swap-in at "
            f"{int(self.last_swap_io_rate_kb_per_second // 1024)} MiB/s"
        )

    def resume_swap_in_grace_active(self, now: float, meminfo: MemInfo) -> bool:
        return (
            self.last_resume_at is not None
            and now - self.last_resume_at <= self.resume_swap_in_grace_seconds
            and meminfo.available_kb > self.low_memory_threshold_kb()
        )

    def record_io_stall_observation(self, now: float, stalled: bool) -> None:
        self.current_io_stall_observed = stalled
        self.io_stall_observations.append((now, stalled))
        cutoff = now - self.io_stall_floor_seconds * 2
        self.io_stall_observations = [
            observation
            for observation in self.io_stall_observations
            if observation[0] >= cutoff
        ]
        if stalled:
            self.last_running_io_stall_at = now
            if self.io_stall_started_at is None:
                self.io_stall_started_at = now
        elif not self.recent_io_stall_observed(now):
            self.io_stall_started_at = None

    def recent_io_stall_observed(self, now: float) -> bool:
        return (
            self.last_running_io_stall_at is not None
            and now - self.last_running_io_stall_at <= IO_STALL_RECENT_OBSERVATION_SECONDS
        )

    def sustained_io_stall_observed(self, now: float) -> bool:
        if self.io_stall_started_at is None:
            return False
        if now - self.io_stall_started_at < self.io_stall_floor_seconds:
            return False
        if not self.current_io_stall_observed:
            return False
        stalled_observations = sum(
            1 for _observed_at, stalled in self.io_stall_observations if stalled
        )
        return stalled_observations >= IO_STALL_MIN_OBSERVATIONS

    def group_active_elapsed_seconds(
        self,
        group: ActionProcessGroup,
        now: float,
    ) -> float | None:
        if group.started_at_ticks is None:
            return None
        started_at = group.started_at_ticks / CLOCK_TICKS_PER_SECOND
        paused_seconds = self.paused_total_seconds.get(group.key, 0.0)
        pause_started_at = self.paused_started_at.get(group.key)
        if pause_started_at is not None and now > pause_started_at:
            paused_seconds += now - pause_started_at
        return max(0.0, now - started_at - paused_seconds)

    def all_running_action_groups_over(self, limit_seconds: int, now: float) -> bool | None:
        groups = self.refresh_paused_groups(build_process_groups(self.context))
        running_groups = self.running_action_groups(groups)
        if not running_groups:
            return None
        durations: list[float] = []
        for group in running_groups:
            duration = self.group_active_elapsed_seconds(group, now)
            if duration is None:
                return None
            durations.append(duration)
        return all(duration > limit_seconds for duration in durations)

    def update(self, meminfo: MemInfo | None) -> None:
        if meminfo is None:
            return
        if self.paused_count() > 0 and meminfo.available_kb > self.low_memory_threshold_kb():
            if not self.resume_if_needed(meminfo):
                self.pause_if_needed(meminfo)
        else:
            self.pause_if_needed(meminfo)

    def low_memory_threshold_kb(self) -> int:
        return self.effective_threshold_kb

    def pause_watch_threshold_kb(self) -> int:
        return self.low_memory_threshold_kb() * 2

    def downscale_memory_threshold_kb(self) -> int:
        if self.paused_count() > 0:
            return self.pause_watch_threshold_kb()
        return self.low_memory_threshold_kb()

    def maybe_adapt_threshold(self, groups: list[ActionProcessGroup], meminfo: MemInfo) -> None:
        now = time.monotonic()
        stalled_running = self.stalled_running_groups(groups)
        swap_io_stalled = self.swap_io_is_heavy(now)
        if swap_io_stalled and self.resume_swap_in_grace_active(now, meminfo):
            swap_io_stalled = False
        io_stalled = bool(stalled_running) or swap_io_stalled
        self.record_io_stall_observation(now, io_stalled)
        if io_stalled:
            self.maybe_lower_io_stall_floor(groups, now)
            if (
                self.effective_threshold_kb < self.max_threshold_kb
                and now >= self.next_threshold_raise_at
            ):
                old_mb = self.effective_threshold_kb // 1024
                self.effective_threshold_kb = min(
                    self.max_threshold_kb,
                    self.effective_threshold_kb + self.threshold_step_kb,
                )
                self.next_threshold_raise_at = (
                    now + ADAPTIVE_THRESHOLD_RAISE_COOLDOWN_SECONDS
                )
                self.next_threshold_lower_at = (
                    now + ADAPTIVE_THRESHOLD_LOWER_COOLDOWN_SECONDS
                )
                diag(
                    "raising low-memory threshold from "
                    f"{old_mb} to {self.effective_threshold_kb // 1024} MiB "
                    "after observing "
                    f"{self.io_stall_reason(stalled_running)}"
                )
            return

        if (
            not self.sustained_io_stall_observed(now)
            and self.io_stall_floor_groups is not None
        ):
            self.io_stall_floor_groups = None
            self.next_io_stall_floor_drop_at = None
            diag(
                "uninterruptible I/O cleared; restoring normal pause floor of "
                f"{self.minimum_running_groups(len(groups))} running action group(s)"
            )

        if self.effective_threshold_kb <= self.base_threshold_kb:
            return
        if self.paused_count() > 0:
            return
        if meminfo.available_kb <= self.pause_watch_threshold_kb():
            return
        if now < self.next_threshold_lower_at:
            return

        old_mb = self.effective_threshold_kb // 1024
        self.effective_threshold_kb = max(
            self.base_threshold_kb,
            self.effective_threshold_kb - self.threshold_step_kb,
        )
        self.next_threshold_lower_at = now + ADAPTIVE_THRESHOLD_LOWER_COOLDOWN_SECONDS
        diag(
            "lowering low-memory threshold from "
            f"{old_mb} to {self.effective_threshold_kb // 1024} MiB "
            "after running actions avoided I/O stalls"
        )

    def normal_minimum_running_groups(self, current_group_count: int) -> int:
        if current_group_count <= 0:
            return 0
        observed = max(self.max_observed_action_groups, current_group_count)
        floor = max(1, (observed + 1) // 2)
        return min(current_group_count, floor)

    def maybe_lower_io_stall_floor(
        self,
        groups: list[ActionProcessGroup],
        now: float,
    ) -> None:
        if not self.sustained_io_stall_observed(now):
            return
        if (
            self.next_io_stall_floor_drop_at is not None
            and now < self.next_io_stall_floor_drop_at
        ):
            return

        old_floor = self.minimum_running_groups(len(groups))
        new_floor = max(1, (old_floor + 1) // 2)
        self.io_stall_floor_groups = new_floor
        self.next_io_stall_floor_drop_at = now + self.io_stall_floor_seconds
        if new_floor < old_floor:
            diag(
                "sustained uninterruptible I/O observed for "
                f"{self.io_stall_floor_seconds}s; lowering pause floor from "
                f"{old_floor} to {new_floor} running action group(s)"
            )

    def refresh_paused_groups(
        self,
        groups: list[ActionProcessGroup],
    ) -> list[ActionProcessGroup]:
        action_groups = [group for group in groups if self.group_is_action(group)]
        self.max_observed_action_groups = max(
            self.max_observed_action_groups, len(action_groups)
        )
        groups_by_key = {group.key: group for group in action_groups}
        self.paused_keys.intersection_update(groups_by_key.keys())
        self.paused_pids = {
            key: pids for key, pids in self.paused_pids.items() if key in self.paused_keys
        }
        self.paused_action_labels = {
            key: labels
            for key, labels in self.paused_action_labels.items()
            if key in self.paused_keys
        }
        self.paused_started_at = {
            key: started_at
            for key, started_at in self.paused_started_at.items()
            if key in self.paused_keys
        }
        self.paused_total_seconds = {
            key: paused_seconds
            for key, paused_seconds in self.paused_total_seconds.items()
            if key in groups_by_key
        }
        self.current_action_labels = set()
        for group in action_groups:
            self.current_action_labels.update(group.action_labels)
        return action_groups

    def minimum_running_groups(self, current_group_count: int) -> int:
        floor = self.normal_minimum_running_groups(current_group_count)
        if self.io_stall_floor_groups is not None:
            floor = min(floor, self.io_stall_floor_groups)
        return min(current_group_count, floor)

    def running_io_stall_recently_cleared(self, now: float) -> bool:
        return (
            self.last_running_io_stall_at is not None
            and now - self.last_running_io_stall_at < RESUME_IO_STALL_CLEAR_SECONDS
        )

    def memory_is_tight_for_resume(self, meminfo: MemInfo) -> bool:
        return meminfo.available_kb <= self.pause_watch_threshold_kb()

    def resume_memory_is_settling(self, now: float) -> bool:
        return now < self.next_normal_resume_at

    def remember_paused_group(self, group: ActionProcessGroup, now: float) -> None:
        self.paused_keys.add(group.key)
        self.paused_pids[group.key] = set(group.pids)
        self.paused_action_labels[group.key] = set(group.action_labels)
        self.paused_started_at.setdefault(group.key, now)

    def forget_paused_group(self, key: str, now: float) -> None:
        pause_started_at = self.paused_started_at.pop(key, None)
        if pause_started_at is not None and now > pause_started_at:
            self.paused_total_seconds[key] = (
                self.paused_total_seconds.get(key, 0.0) + now - pause_started_at
            )
        self.paused_keys.discard(key)
        self.paused_pids.pop(key, None)
        self.paused_action_labels.pop(key, None)

    def ensure_one_action_group_running(
        self,
        groups: list[ActionProcessGroup],
    ) -> bool:
        if not groups:
            return False

        action_groups = [group for group in groups if self.group_is_action(group)]
        running = [group for group in action_groups if not self.group_is_paused(group)]
        if running:
            return False

        paused = [group for group in action_groups if self.group_is_paused(group)]
        if not paused:
            return False

        selected = min(paused, key=self.group_sort_key)
        now = time.monotonic()
        self.signal_group(selected, signal.SIGCONT)
        self.forget_paused_group(selected.key, now)
        self.last_resume_at = now
        diag(
            "resumed oldest paused Bazel action group "
            f"{selected.key} to keep at least one action group running"
        )
        return True

    # Return the staggered memory threshold for the next pause number.
    def pause_threshold_kb(self, total_groups: int, pause_number: int) -> int:
        threshold_kb = self.low_memory_threshold_kb()
        pausable_count = max(1, total_groups - 1)
        capped_pause_number = min(pausable_count, pause_number)
        if pausable_count == 1:
            return threshold_kb * 2
        return (
            threshold_kb * 2
            - threshold_kb * (capped_pause_number - 1) // (pausable_count - 1)
        )

    def pause_if_needed(self, meminfo: MemInfo | None) -> None:
        if meminfo is None:
            return
        threshold_kb = self.low_memory_threshold_kb()
        if meminfo.available_kb > threshold_kb * 2:
            return

        groups = self.refresh_paused_groups(build_process_groups(self.context))
        if self.ensure_one_action_group_running(groups):
            return
        self.maybe_adapt_threshold(groups, meminfo)

        running = [group for group in groups if not self.group_is_paused(group)]
        if len(running) <= 1:
            return
        if len(running) <= self.minimum_running_groups(len(groups)):
            return

        next_pause_number = len(self.paused_keys) + 1
        now = time.monotonic()
        stall_floor_active = (
            self.io_stall_floor_groups is not None
            and self.sustained_io_stall_observed(now)
        )
        if (
            not stall_floor_active
            and meminfo.available_kb > self.pause_threshold_kb(len(groups), next_pause_number)
        ):
            return

        selected = max(running, key=self.group_sort_key)
        self.signal_group(selected, signal.SIGSTOP)
        self.remember_paused_group(selected, now)

    def resume_if_needed(self, meminfo: MemInfo | None) -> bool:
        if meminfo is None:
            return False

        groups = self.refresh_paused_groups(build_process_groups(self.context))
        if self.ensure_one_action_group_running(groups):
            return True
        if meminfo.available_kb <= self.low_memory_threshold_kb():
            return False
        self.maybe_adapt_threshold(groups, meminfo)
        now = time.monotonic()
        memory_is_tight = self.memory_is_tight_for_resume(meminfo)
        if (
            self.resume_memory_is_settling(now)
            or (
                memory_is_tight
                and (
                    self.stalled_running_groups(groups)
                    or self.running_io_stall_recently_cleared(now)
                )
            )
        ):
            return False

        paused = [group for group in groups if self.group_is_paused(group)]
        if not paused:
            return False

        selected = min(paused, key=self.group_sort_key)
        resume_threshold_kb = max(
            self.pause_threshold_kb(len(groups), len(self.paused_keys)),
            self.low_memory_threshold_kb() + self.resume_memory_kb(selected),
        )
        if meminfo.available_kb <= resume_threshold_kb:
            return False

        self.signal_group(selected, signal.SIGCONT)
        self.forget_paused_group(selected.key, now)
        self.last_resume_at = now
        self.next_normal_resume_at = now + RESUME_MEMORY_SETTLE_SECONDS
        return True

    def resume_memory_kb(self, group: ActionProcessGroup) -> int:
        return sum(process_swap_kb(pid) for pid in group.pids)

    def resume_all(self, reason: str | None = None) -> int:
        resumed_groups = 0
        now = time.monotonic()
        groups_by_key = {group.key: group for group in build_process_groups(self.context)}
        for key in list(self.paused_keys):
            group = groups_by_key.get(key)
            if group is not None:
                self.signal_group(group, signal.SIGCONT)
                resumed_groups += 1
            else:
                remembered_pids = self.paused_pids.get(key, set())
                for pid in sorted(remembered_pids):
                    try:
                        os.kill(pid, signal.SIGCONT)
                    except ProcessLookupError:
                        pass
                    except PermissionError:
                        pass
                if remembered_pids:
                    resumed_groups += 1
            self.forget_paused_group(key, now)
        if resumed_groups > 0 and reason is not None:
            diag(f"resumed {resumed_groups} paused Bazel action group(s) {reason}")
        return resumed_groups

    def group_sort_key(self, group: ActionProcessGroup) -> tuple[int, str]:
        if group.started_at_ticks is None:
            return (-1, group.key)
        return (group.started_at_ticks, group.key)

    def signal_group(self, group: ActionProcessGroup, sig: int) -> None:
        for pid in group.pids:
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
            except PermissionError:
                pass


def action_timeout_evidence(
    parser: ProgressFrameParser,
    action_throttler: ActionThrottler,
    limit_seconds: int,
    now: float,
) -> tuple[bool, str]:
    running_groups_over_timeout_fn = getattr(
        action_throttler,
        "all_running_action_groups_over",
        None,
    )
    running_groups_over_timeout = (
        running_groups_over_timeout_fn(limit_seconds, now)
        if running_groups_over_timeout_fn is not None
        else None
    )
    if running_groups_over_timeout:
        return True, "all active Bazel action groups"
    if parser.all_reported_actions_over(limit_seconds, now):
        return True, "all reported running actions"
    return False, "action-age evidence"


def timeout_downscale_defer_reason(
    parser: ProgressFrameParser,
    action_throttler: ActionThrottler,
    limit_seconds: int,
    now: float,
) -> str | None:
    if not parser.completed_progress_recent(now, limit_seconds):
        return None
    if action_throttler.recent_io_stall_observed(now):
        return None
    if action_throttler.current_io_stall_observed:
        return None
    return (
        "completed action count advanced recently and no running action "
        "I/O stall is currently observed"
    )


# Lower scheduler priority for Bazel action children that the server launches.
def renice_build_processes(context: BuildContext) -> None:
    target_nice = bazel_nice_increment()
    if target_nice <= 0:
        return

    for info in dangling_build_processes(context):
        if info.nice is not None and info.nice >= target_nice:
            continue
        try:
            os.setpriority(os.PRIO_PROCESS, info.pid, target_nice)
        except (OSError, PermissionError):
            pass


# Wait briefly for leftover Bazel build processes to exit before retrying.
def wait_for_no_dangling_build_processes(context: BuildContext, wait_seconds: float) -> bool:
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if not dangling_build_processes(context):
            return True
        time.sleep(0.1)
    return not dangling_build_processes(context)


# Run "bazel shutdown" and report whether the command itself succeeded.
def run_bazel_shutdown(bazel_path: str, timeout_seconds: int) -> None:
    try:
        # Ask the server to stop before escalating to process-group killing.
        completed = subprocess.run(
            [bazel_path, "shutdown"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=min(
                max(timeout_seconds, BAZEL_SHUTDOWN_MIN_TIMEOUT_SECONDS),
                BAZEL_SHUTDOWN_MAX_TIMEOUT_SECONDS,
            ),
            check=False,
            preexec_fn=os.setpgrp,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        diag(f"bazel shutdown did not complete cleanly: {error}")
        return
    diag(f"bazel shutdown completed with exit code {completed.returncode}")


# Shared restart gate: optionally stop the Bazel server, then wait and pause.
def settle_before_restart(
    context: BuildContext,
    restart_description: str,
    bazel_path: str | None = None,
    shutdown_timeout: int | None = None,
) -> None:
    if bazel_path is not None:
        diag(
            "asking Bazel server to shut down before "
            f"{restart_description} because the previous retry made no "
            "meaningful progress"
        )
        run_bazel_shutdown(bazel_path, shutdown_timeout or 1)

    delay = restart_settle_delay()
    if delay <= 0:
        return
    diag(
        f"waiting up to {delay:g}s for Bazel build processes to exit "
        f"before {restart_description}"
    )
    if wait_for_no_dangling_build_processes(context, delay):
        diag("Bazel build processes are gone")
    else:
        diag(f"Bazel build processes are still present after {delay:g}s")
    diag(f"settling for {delay:g}s before {restart_description}")
    time.sleep(delay)


# Signal a process tree by walking /proc parent relationships.
def kill_process_tree(pid: int, sig: int, context: BuildContext | None = None) -> None:
    # Build a parent map from /proc so children are signaled before their parent.
    parents: dict[int, int] = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        proc_pid = int(name)
        try:
            with open(f"/proc/{proc_pid}/stat", encoding="utf-8") as stat:
                content = stat.read()
        except OSError:
            continue
        try:
            after_name = content.rsplit(")", 1)[1].strip().split()
            parents[proc_pid] = int(after_name[1])
        except (IndexError, ValueError):
            continue

    children_by_parent: dict[int, list[int]] = {}
    for child, parent in parents.items():
        children_by_parent.setdefault(parent, []).append(child)

    descendants: list[int] = []
    stack = list(children_by_parent.get(pid, []))
    while stack:
        child = stack.pop()
        descendants.append(child)
        stack.extend(children_by_parent.get(child, []))
    for child in reversed(descendants):
        if context is not None:
            info = process_info(child)
            if info is None or not context.owns_process(info):
                continue
        try:
            os.kill(child, sig)
        except ProcessLookupError:
            pass
        except PermissionError:
            pass
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        pass
    except PermissionError:
        pass


# Terminate leftover Bazel sandbox/build processes tied to this workspace.
def cleanup_dangling_build_processes(context: BuildContext) -> CleanupResult:
    # Poll process liveness with a small sleep so cleanup waits without spinning.
    def wait_for_exit(processes: list[ProcessInfo], wait_seconds: float) -> bool:
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            if not any(pid_exists(info.pid) for info in processes):
                return True
            time.sleep(0.1)
        return not any(pid_exists(info.pid) for info in processes)

    processes = dangling_build_processes(context)
    if not processes:
        return CleanupResult(count=0)

    diag(f"found {len(processes)} dangling Bazel build process(es); terminating")

    for info in processes:
        kill_process_tree(info.pid, signal.SIGTERM, context)
    if wait_for_exit(processes, DANGLING_PROCESS_TERM_WAIT_SECONDS):
        return CleanupResult(count=len(processes))

    survivors = [info for info in processes if pid_exists(info.pid)]
    if not survivors:
        return CleanupResult(count=len(processes))
    diag(f"{len(survivors)} dangling Bazel build process(es) survived SIGTERM; killing")
    for info in survivors:
        kill_process_tree(info.pid, signal.SIGKILL, context)
    if wait_for_exit(survivors, DANGLING_PROCESS_KILL_WAIT_SECONDS):
        return CleanupResult(count=len(processes))

    remaining = [info for info in survivors if pid_exists(info.pid)]
    if remaining:
        diag(f"{len(remaining)} dangling Bazel build process(es) still running after SIGKILL")
        for info in remaining:
            command = info.cmdline.strip() or "<unknown>"
            if len(command) > 140:
                command = command[:137] + "..."
            cwd = f" cwd={info.cwd}" if info.cwd else ""
            # Only verbose-print process details when cleanup could not kill them.
            diag(f"dangling build process: pid={info.pid}{cwd} cmd={command}")
    return CleanupResult(count=len(processes))


# Interrupt Bazel's process group and explain why.
def graceful_stop(
    process: subprocess.Popen,
    reason: str,
    action: str = "interrupting Bazel",
) -> None:
    diag(f"{reason}; {action}")
    try:
        os.killpg(process.pid, signal.SIGINT)
    except ProcessLookupError:
        pass


# Run one Bazel attempt and classify whether the wrapper should retry.
def run_once(
    bazel_path: str,
    parsed: ParsedArgs,
    jobs: int,
    max_jobs: int,
    context: BuildContext,
) -> RunResult:
    global ACTIVE_PROCESS

    # Rewrite or insert --jobs directly before launching this Bazel attempt.
    bazel_args = bazel_args_with_jobs(parsed, jobs)
    command = [bazel_path, *bazel_args]
    parser = ProgressFrameParser()
    selector = selectors.DefaultSelector()
    terminal = TerminalForeground()
    output = BazelOutput()
    memory_monitor = MemoryPressureMonitor()
    action_throttler = ActionThrottler(context)
    now = time.monotonic()
    memory_monitor.sample(now, force=True)
    # Tests can shorten the upscale warm-up interval with an environment override.
    try:
        configured_upscale_interval = float(
            os.environ.get(
                UPSCALE_CHECK_INTERVAL_ENV,
                str(DEFAULT_UPSCALE_CHECK_INTERVAL_SECONDS),
            )
        )
    except ValueError:
        configured_upscale_interval = DEFAULT_UPSCALE_CHECK_INTERVAL_SECONDS
    if configured_upscale_interval <= 0:
        configured_upscale_interval = DEFAULT_UPSCALE_CHECK_INTERVAL_SECONDS
    next_upscale_check_interval = max(memory_poll_interval(), configured_upscale_interval)
    next_upscale_check: float | None = None
    required_running_actions_seconds = next_upscale_check_interval
    running_actions_since: float | None = None
    last_stall_at: float | None = None
    stop_reason: str | None = None
    stop_deadline = 0.0
    last_upscale_skip_reason: str | None = None
    upscale_skip_count = 0
    upscale_reevaluation_count = 0
    upscale_memory_skip_count = 0
    upscale_job_runtime_skip_count = 0
    upscale_description: str | None = None
    pending_upscale_next_jobs: int | None = None
    next_renice_check = now
    next_pause_check = now
    next_resume_check = now
    next_downscale_defer_report = now
    memory_tightness_observed = False
    memory_kill_resume_done = False
    user_termination_resume_done = False

    # Package this attempt's result with the latest monitoring context.
    def result(
        exit_code: int,
        restart: str | None = None,
        retry_after_dangling_processes: bool = True,
    ) -> RunResult:
        return RunResult(
            exit_code=exit_code,
            restart=restart,
            upscale_skip_reason=last_upscale_skip_reason,
            upscale_skip_count=upscale_skip_count,
            upscale_reevaluation_count=upscale_reevaluation_count,
            upscale_memory_skip_count=upscale_memory_skip_count,
            upscale_job_runtime_skip_count=upscale_job_runtime_skip_count,
            upscale_description=upscale_description,
            failure_retry_same=memory_monitor.retry_same_jobs_after_failure(now),
            failure_average_description=memory_monitor.failure_average_description(now),
            retry_after_dangling_processes=retry_after_dangling_processes,
            internal_interrupted_crash=(
                parser.saw_internal_crash
                and parser.saw_java_interrupted
                and stop_reason is None
                and not parser.saw_user_interrupt
            ),
            retryable_action_failure=parser.saw_memory_kill and stop_reason is None,
            meaningful_work_done=parser.meaningful_work_done,
            user_interrupted=parser.saw_user_interrupt and stop_reason is None,
        )

    # Once Bazel owns the terminal, hold wrapper diagnostics until Bazel stops.
    def finish_interactive_bazel_output() -> None:
        terminal.restore()
        stop_interactive_diag_buffering()
        flush_interactive_diag_buffer()

    diag(f"starting Bazel with --jobs={jobs}")
    process = subprocess.Popen(
        command,
        stdin=None,
        bufsize=0,
        preexec_fn=prepare_bazel_child,
        **output.popen_kwargs(),
    )
    output.parent_after_spawn()
    ACTIVE_PROCESS = process
    output.register(selector, process)
    context.refresh_from_bazel_servers()
    terminal.give_to(process.pid)
    start_interactive_diag_buffering(output.use_pty)

    # Attribute each skipped upscale evaluation to memory or job-runtime state.
    def upscale_skip_category(reason: str, from_memory_gate: bool = False) -> str:
        if not from_memory_gate:
            return SKIP_JOB_RUNTIME
        if reason.startswith("running Bazel actions"):
            return SKIP_JOB_RUNTIME
        return SKIP_MEMORY

    # Classify whether upscale should run now, stay pending, or be blocked.
    def evaluate_upscale(
        running_actions_seconds: float | None,
        keep_pending_on_memory_skip: bool = False,
    ) -> UpscaleEvaluation:
        memory_monitor.sample(now, force=True)
        memory_skip = memory_monitor.upscale_skip_reason(
            now,
            running_actions_seconds,
            required_running_actions_seconds,
        )
        if memory_skip is not None:
            if keep_pending_on_memory_skip:
                skip_category = upscale_skip_category(memory_skip, from_memory_gate=True)
                return UpscaleEvaluation(UPSCALE_PENDING, memory_skip, skip_category)

            skip_category = upscale_skip_category(memory_skip, from_memory_gate=True)
            return UpscaleEvaluation(UPSCALE_BLOCKED, memory_skip, skip_category)
        paused_count = action_throttler.paused_count()
        if paused_count > 0:
            return UpscaleEvaluation(
                UPSCALE_PENDING,
                f"{paused_count} action group(s) are paused",
                SKIP_JOB_RUNTIME,
            )
        remaining_action_finish_threshold = jobs * UPSCALE_REMAINING_ACTION_FINISH_JOBS_MULTIPLIER
        action_skip = parser.upscale_action_skip_reason(
            UPSCALE_MAX_ACTION_SECONDS,
            remaining_action_finish_threshold,
            now,
        )
        if action_skip is not None:
            return UpscaleEvaluation(UPSCALE_PENDING, action_skip, SKIP_JOB_RUNTIME)
        return UpscaleEvaluation(UPSCALE_READY, None, None)

    # Count why an upscale evaluation could not proceed.
    def record_upscale_skip(category: str | None) -> None:
        nonlocal upscale_memory_skip_count, upscale_job_runtime_skip_count
        if category == SKIP_MEMORY:
            upscale_memory_skip_count += 1
        elif category == SKIP_JOB_RUNTIME:
            upscale_job_runtime_skip_count += 1

    # Keep action-age accounting aligned with wrapper-induced SIGSTOP intervals.
    def update_pause_accounting(previous_paused_count: int) -> None:
        paused_count = action_throttler.paused_count()
        if previous_paused_count == 0 and paused_count > 0:
            parser.note_actions_paused(now)
        elif previous_paused_count > 0 and paused_count == 0:
            parser.note_actions_resumed(now)
        parser.note_live_action_labels(
            getattr(action_throttler, "current_action_labels", set()),
            now,
        )
        parser.note_paused_labels(action_throttler.paused_labels(), now)

    # Stop Bazel at a cheap point so the next attempt can use more jobs.
    def begin_upscale(next_jobs: int, running_actions_seconds: float | None) -> None:
        nonlocal stop_reason, stop_deadline, upscale_description
        upscale_description = memory_monitor.upscale_ready_description(
            now,
            running_actions_seconds,
        )
        upscale_description += f"; {parser.current_action_age_description(now)}"
        finish_interactive_bazel_output()
        paused_count = action_throttler.paused_count()
        action_throttler.resume_all("before stopping Bazel for upscale")
        update_pause_accounting(paused_count)
        reason = (
            f"upscale: {upscale_description}; "
            f"stopping Bazel at --jobs={jobs} so the wrapper can "
            f"restart at --jobs={next_jobs}"
        )
        graceful_stop(
            process,
            reason,
            "interrupting Bazel at a cheap upscale point",
        )
        stop_reason = "up"
        stop_deadline = now + parsed.action_timeout

    try:
        while True:
            drain_timeout = 0.2
            if stop_reason is None and not parser.saw_memory_kill:
                drain_timeout = min(
                    drain_timeout,
                    max(0.0, next_pause_check - time.monotonic()),
                    max(0.0, next_resume_check - time.monotonic()),
                )
            drain_ready_streams(
                selector,
                parser,
                drain_timeout,
                action_throttler.paused_count,
                action_throttler.paused_labels,
            )
            now = time.monotonic()
            meminfo = memory_monitor.sample(now)
            if (
                (USER_TERMINATING or (parser.saw_user_interrupt and stop_reason is None))
                and not user_termination_resume_done
            ):
                paused_count = action_throttler.paused_count()
                if USER_TERMINATING:
                    reason = "because the wrapper received a user signal"
                else:
                    reason = "because Bazel reported a user interrupt"
                action_throttler.resume_all(reason)
                update_pause_accounting(paused_count)
                user_termination_resume_done = True
            if parser.saw_memory_kill and not memory_kill_resume_done:
                paused_count = action_throttler.paused_count()
                action_throttler.resume_all(
                    "because Bazel reported a killed or terminated action"
                )
                update_pause_accounting(paused_count)
                memory_kill_resume_done = True
            if (
                stop_reason is None
                and not parser.saw_memory_kill
                and not parser.saw_user_interrupt
            ):
                if now >= next_pause_check:
                    pause_meminfo = memory_monitor.sample(now, force=True)
                    pause_watch_threshold_kb = getattr(
                        action_throttler,
                        "pause_watch_threshold_kb",
                        lambda: low_memory_threshold_kb() * 2,
                    )()
                    if (
                        pause_meminfo is not None
                        and pause_meminfo.available_kb
                        <= pause_watch_threshold_kb
                    ):
                        if not memory_tightness_observed:
                            memory_tightness_observed = True
                            next_renice_check = now
                        paused_count = action_throttler.paused_count()
                        action_throttler.pause_if_needed(pause_meminfo)
                        update_pause_accounting(paused_count)
                        pause_check_delay = (
                            THROTTLE_PAUSE_CHECK_SECONDS
                            if action_throttler.paused_count() != paused_count
                            else THROTTLE_IDLE_PAUSE_CHECK_SECONDS
                        )
                    else:
                        pause_check_delay = THROTTLE_IDLE_PAUSE_CHECK_SECONDS
                    next_pause_check = now + pause_check_delay
                if now >= next_resume_check:
                    resume_meminfo = memory_monitor.sample(now, force=True)
                    resume_threshold_kb = getattr(
                        action_throttler,
                        "low_memory_threshold_kb",
                        low_memory_threshold_kb,
                    )()
                    if (
                        resume_meminfo is not None
                        and resume_meminfo.available_kb
                        > resume_threshold_kb
                    ):
                        paused_count = action_throttler.paused_count()
                        action_throttler.resume_if_needed(resume_meminfo)
                        update_pause_accounting(paused_count)
                    next_resume_check = now + THROTTLE_RESUME_CHECK_SECONDS
                if memory_tightness_observed and now >= next_renice_check:
                    renice_build_processes(context)
                    next_renice_check = now + RENICE_BUILD_CHILDREN_SECONDS
            if parser.has_running_actions():
                if running_actions_since is None:
                    running_actions_since = now
                    next_upscale_check = now + next_upscale_check_interval
            if running_actions_since is None:
                running_actions_seconds = None
            else:
                running_actions_seconds = now - running_actions_since
            if parser.all_displayed_actions_over(parsed.action_timeout, now):
                last_stall_at = now
            returncode = process.poll()
            if returncode is not None:
                drain_remaining_streams(
                    selector,
                    parser,
                    action_throttler.paused_count,
                    action_throttler.paused_labels,
                )
                finish_interactive_bazel_output()
                if parser.all_displayed_actions_over(parsed.action_timeout, now):
                    last_stall_at = now
                context.add_output_bases(parser.output_bases)
                context.refresh_from_bazel_servers()
                normalized_returncode = normalize_returncode(returncode)
                if normalized_returncode != 0 and stop_reason is None:
                    diag(memory_monitor.failure_report(now))
                if (
                    normalized_returncode != 0
                    and parser.saw_user_interrupt
                    and stop_reason is None
                ):
                    return result(130)
                if (
                    normalized_returncode != 0
                    and parser.saw_memory_kill
                    and stop_reason is None
                    and jobs > 1
                ):
                    if memory_monitor.retry_same_jobs_after_failure(now):
                        diag(
                            "Bazel reported a killed or terminated action, but "
                            f"{memory_monitor.failure_average_description(now)}; "
                            f"retrying with same --jobs={jobs}"
                        )
                        return result(normalized_returncode, "same")
                    diag("Bazel reported a killed or terminated action; retrying with fewer jobs")
                    return result(normalized_returncode, "down")
                recent_stall = (
                    last_stall_at is not None and now - last_stall_at <= RECENT_STALL_SECONDS
                )
                if (
                    normalized_returncode != 0
                    and parser.saw_server_abrupt
                    and jobs > 1
                ):
                    evidence = []
                    if memory_monitor.recent_low_memory(now):
                        evidence.append(
                            "recent memory pressure "
                            f"({memory_monitor.recent_low_memory_description()})"
                        )
                    if recent_stall:
                        evidence.append(
                            f"recent visible action stall over {parsed.action_timeout}s"
                        )
                    if not evidence:
                        evidence.append("server failure")
                    evidence_description = " and ".join(evidence)
                    if memory_monitor.retry_same_jobs_after_failure(now):
                        diag(
                            "Bazel server terminated abruptly after "
                            f"{evidence_description}, but "
                            f"{memory_monitor.failure_average_description(now)}; "
                            f"retrying with same --jobs={jobs}"
                        )
                        return result(normalized_returncode, "same")
                    diag(
                        "Bazel server terminated abruptly after "
                        f"{evidence_description}; "
                        "retrying with fewer jobs"
                    )
                    return result(normalized_returncode, "down")
                if (
                    normalized_returncode != 0
                    and stop_reason == "up"
                    and parser.saw_build_failure
                ):
                    diag(
                        "upscale cancelled because Bazel reported a build failure "
                        "while stopping for upscale"
                    )
                    return result(
                        normalized_returncode,
                        retry_after_dangling_processes=False,
                    )
                return result(normalized_returncode, stop_reason)

            if USER_TERMINATING:
                continue

            if stop_reason is not None:
                if now >= stop_deadline:
                    finish_interactive_bazel_output()
                    context.add_output_bases(parser.output_bases)
                    context.refresh_from_bazel_servers()
                    diag("graceful stop timed out; asking Bazel server to shut down")
                    run_bazel_shutdown(bazel_path, parsed.action_timeout)

                    if process.poll() is None:
                        diag("Bazel client is still running; killing its process group")
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass

                    for server in bazel_servers_for_workspace(os.getcwd(), context.cgroups):
                        server_pid = server.pid
                        if server_pid in {os.getpid(), process.pid}:
                            continue
                        diag(f"Bazel server pid {server_pid} is still running; killing it")
                        kill_process_tree(server_pid, signal.SIGKILL, context)
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass
                    returncode = process.poll()
                    if returncode is not None:
                        drain_remaining_streams(
                            selector,
                            parser,
                            action_throttler.paused_count,
                            action_throttler.paused_labels,
                        )
                        return result(normalize_returncode(returncode), stop_reason)
                continue

            downscale_memory_threshold_fn = getattr(
                action_throttler,
                "downscale_memory_threshold_kb",
                None,
            )
            downscale_memory_threshold_kb = (
                downscale_memory_threshold_fn()
                if downscale_memory_threshold_fn is not None
                else low_memory_threshold_kb()
            )
            if (
                jobs > 1
                and meminfo is not None
                and meminfo.available_kb < downscale_memory_threshold_kb
            ):
                running_actions_over_timeout, timeout_subject = action_timeout_evidence(
                    parser,
                    action_throttler,
                    parsed.action_timeout,
                    now,
                )
                if running_actions_over_timeout:
                    defer_reason = timeout_downscale_defer_reason(
                        parser,
                        action_throttler,
                        parsed.action_timeout,
                        now,
                    )
                    if defer_reason is not None:
                        if now >= next_downscale_defer_report:
                            diag(
                                "downscale deferred despite old action-age evidence: "
                                f"{defer_reason}"
                            )
                            next_downscale_defer_report = (
                                now + TIMEOUT_DOWNSCALE_DEFER_REPORT_SECONDS
                            )
                    else:
                        finish_interactive_bazel_output()
                        paused_count = action_throttler.paused_count()
                        action_throttler.resume_all("before stopping Bazel for downscale")
                        update_pause_accounting(paused_count)
                        reason = (
                            f"{timeout_subject} are over {parsed.action_timeout}s "
                            "and memory is low "
                            f"({meminfo.available_kb // 1024} MiB available; "
                            f"threshold {downscale_memory_threshold_kb // 1024} MiB)"
                        )
                        graceful_stop(process, reason)
                        stop_reason = "down"
                        stop_deadline = now + parsed.action_timeout
                        diag(
                            "downscale decision used "
                            f"{timeout_subject}; {paused_count} action group(s) were paused"
                        )
                        diag(
                            "action timeout and low memory detected; "
                            "retrying with fewer jobs"
                        )
                        continue

            if pending_upscale_next_jobs is not None:
                upscale_reevaluation_count += 1
                evaluation = evaluate_upscale(
                    running_actions_seconds,
                    keep_pending_on_memory_skip=True,
                )
                record_upscale_skip(evaluation.skip_category)
                if evaluation.status == UPSCALE_READY:
                    begin_upscale(pending_upscale_next_jobs, running_actions_seconds)
                    pending_upscale_next_jobs = None
                    continue
                if evaluation.status == UPSCALE_BLOCKED:
                    pending_upscale_next_jobs = None
                    upscale_skip_count += 1
                    last_upscale_skip_reason = evaluation.reason
                    next_upscale_check = now + next_upscale_check_interval
                elif evaluation.reason is not None:
                    last_upscale_skip_reason = evaluation.reason

            if (
                pending_upscale_next_jobs is None
                and next_upscale_check is not None
                and now >= next_upscale_check
            ):
                next_upscale_check = now + next_upscale_check_interval
                if jobs < max_jobs:
                    next_jobs = upscale_jobs(jobs, max_jobs)
                    evaluation = evaluate_upscale(
                        running_actions_seconds,
                        keep_pending_on_memory_skip=True,
                    )
                    if evaluation.status == UPSCALE_READY:
                        last_upscale_skip_reason = None
                        begin_upscale(next_jobs, running_actions_seconds)
                    elif evaluation.status == UPSCALE_PENDING:
                        pending_upscale_next_jobs = next_jobs
                        upscale_skip_count += 1
                        record_upscale_skip(evaluation.skip_category)
                        last_upscale_skip_reason = evaluation.reason
                        diag(
                            f"upscale watch active: {evaluation.reason}; "
                            f"will restart with --jobs={next_jobs} when memory "
                            "and current action ages allow"
                        )
                    else:
                        upscale_skip_count += 1
                        record_upscale_skip(evaluation.skip_category)
                        last_upscale_skip_reason = evaluation.reason
    finally:
        now = time.monotonic()
        finish_interactive_bazel_output()
        paused_count = action_throttler.paused_count()
        action_throttler.resume_all()
        update_pause_accounting(paused_count)
        ACTIVE_PROCESS = None
        selector.close()
        output.close()


# Retry Bazel attempts while adapting the current jobs value.
def run_adaptive(bazel_path: str, parsed: ParsedArgs) -> int:
    if not parsed.supports_jobs:
        os.execvpe(bazel_path, [bazel_path, *parsed.original_args], os.environ)

    jobs = parsed.initial_jobs
    max_jobs = parsed.initial_jobs
    context = BuildContext(os.getcwd())
    internal_interrupted_crash_retries = 0
    same_job_action_failure_retries: dict[int, int] = {}
    clean_server_before_same_retry = False

    try:
        while True:
            result = run_once(bazel_path, parsed, jobs, max_jobs, context)
            cleanup = cleanup_dangling_build_processes(context)
            if USER_TERMINATING or result.user_interrupted:
                return result.exit_code
            if (
                result.exit_code != 0
                and result.restart is None
                and result.internal_interrupted_crash
            ):
                if internal_interrupted_crash_retries >= 1:
                    diag(
                        "Bazel crashed internally after java.lang.InterruptedException "
                        "again; not retrying"
                    )
                    return result.exit_code
                internal_interrupted_crash_retries += 1
                diag(
                    "Bazel crashed internally after java.lang.InterruptedException; "
                    f"retrying with same --jobs={jobs}"
                )
                result.restart = "same"
            if (
                result.restart != "up"
                and result.upscale_skip_count > 0
                and result.upscale_skip_reason is not None
            ):
                attempt_word = "attempt" if result.upscale_skip_count == 1 else "attempts"
                reevaluation_word = (
                    "reevaluation"
                    if result.upscale_reevaluation_count == 1
                    else "reevaluations"
                )
                diag(
                    "upscale watch skipped after "
                    f"{result.upscale_skip_count} scheduled {attempt_word} and "
                    f"{result.upscale_reevaluation_count} {reevaluation_word} "
                    f"(memory skips: {result.upscale_memory_skip_count}; "
                    f"job-runtime skips: {result.upscale_job_runtime_skip_count}): "
                    f"{result.upscale_skip_reason}"
                )
            if (
                result.exit_code != 0
                and result.restart is None
                and cleanup.count > 0
                and jobs > 1
                and result.retry_after_dangling_processes
            ):
                if result.failure_retry_same:
                    diag(
                        "Bazel exited while build processes were still running, but "
                        f"{result.failure_average_description}; retrying with same --jobs={jobs}"
                    )
                    result.restart = "same"
                else:
                    diag(
                        "Bazel exited while build processes were still running; "
                        "retrying with fewer jobs"
                    )
                    result.restart = "down"
            if result.restart == "same" and result.retryable_action_failure:
                prior_same_retries = same_job_action_failure_retries.get(jobs, 0)
                clean_server_before_same_retry = (
                    prior_same_retries > 0 and not result.meaningful_work_done
                )
                retry_count = prior_same_retries + 1
                if retry_count > same_job_retry_limit():
                    diag(
                        "Bazel kept reporting killed or terminated actions at "
                        f"--jobs={jobs} after {prior_same_retries} same-job "
                        "retry attempt(s); not retrying"
                    )
                    return result.exit_code
                same_job_action_failure_retries[jobs] = retry_count
            if result.restart == "down":
                if jobs <= 1:
                    diag("already at --jobs=1; not retrying")
                    return result.exit_code
                while True:
                    try:
                        # Wait for memory to recover before starting the smaller retry.
                        meminfo = read_meminfo()
                    except OSError as error:
                        diag(
                            "could not read memory information while waiting "
                            f"for recovery: {error}"
                        )
                        break
                    if meminfo.total_kb > 0 and meminfo.available_kb * 2 >= meminfo.total_kb:
                        break
                    diag(
                        "waiting for memory recovery "
                        f"({meminfo.available_kb // 1024} MiB available "
                        f"of {meminfo.total_kb // 1024} MiB)"
                    )
                    time.sleep(memory_poll_interval())
                jobs = downscale_jobs(jobs)
                settle_before_restart(context, f"restarting with --jobs={jobs}")
                continue
            if result.restart == "same":
                diag(f"retrying Bazel with same --jobs={jobs}")
                if clean_server_before_same_retry:
                    settle_before_restart(
                        context,
                        f"retrying with same --jobs={jobs}",
                        bazel_path,
                        parsed.action_timeout,
                    )
                    clean_server_before_same_retry = False
                else:
                    settle_before_restart(context, f"retrying with same --jobs={jobs}")
                continue
            if result.restart == "up":
                next_jobs = upscale_jobs(jobs, max_jobs)
                upscale_context = (
                    f"; {result.upscale_description}" if result.upscale_description else ""
                )
                diag(
                    f"upscale: Bazel stopped at --jobs={jobs}; "
                    f"restarting with --jobs={next_jobs}{upscale_context}"
                )
                jobs = next_jobs
                settle_before_restart(context, f"restarting with --jobs={jobs}")
                continue
            return result.exit_code
    finally:
        cleanup_dangling_build_processes(context)


# CLI entry point for resolving Bazel, parsing args, and starting adaptation.
def main(argv: list[str]) -> int:
    wrapper_path = os.path.realpath(__file__)
    # Prefer BAZEL unless it points back at this wrapper, then search PATH.
    bazel_path = os.environ.get(BAZEL_ENV)
    if bazel_path and os.path.realpath(bazel_path) == wrapper_path:
        bazel_path = None
    if not bazel_path:
        for directory in os.environ.get(PATH_ENV, DEFAULT_PATH).split(os.pathsep):
            candidate = os.path.join(directory or os.curdir, "bazel")
            if os.access(candidate, os.X_OK) and os.path.realpath(candidate) != wrapper_path:
                bazel_path = candidate
                break
        if not bazel_path:
            candidate = shutil.which("bazel")
            if candidate and os.path.realpath(candidate) != wrapper_path:
                bazel_path = candidate
    if bazel_path is None:
        print(f"{diag_prefix()} could not find real bazel on PATH", file=sys.stderr)
        return 127

    if not argv:
        exit_code = subprocess.run([bazel_path], check=False).returncode
        print(
            f"{diag_prefix()} Set {BUILD_TIMEOUT_ENV}=<seconds> to control adaptive "
            f"build timeout; set {LOW_MEMORY_THRESHOLD_ENV}=<MiB> to control "
            f"low-memory detection; defaults are {DEFAULT_ACTION_TIMEOUT_SECONDS}s "
            f"and {DEFAULT_LOW_MEMORY_THRESHOLD_MB} MiB.",
            file=sys.stderr,
            flush=True,
        )
        return normalize_returncode(exit_code)

    if not bazel_command_supports_jobs(argv):
        os.execvpe(bazel_path, [bazel_path, *argv], os.environ)

    try:
        action_timeout = build_timeout_from_env()
        low_memory_threshold_kb()
    except ValueError as error:
        print(f"{diag_prefix()} {error}", file=sys.stderr)
        return 2

    parsed = parse_bazel_args(argv, action_timeout)

    # Forward user termination signals to the active Bazel process group.
    def forward_signal(signum: int, _frame) -> None:
        global USER_TERMINATING
        USER_TERMINATING = True
        process = ACTIVE_PROCESS
        if process is None or process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            pass

    signal.signal(signal.SIGINT, forward_signal)
    signal.signal(signal.SIGTERM, forward_signal)
    return run_adaptive(bazel_path, parsed)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
