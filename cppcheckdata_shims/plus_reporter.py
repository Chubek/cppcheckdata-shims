#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
plus_reporter.py — Rich diagnostic reporter for cppcheckdata_shims.

Generates Rust-style colourful terminal diagnostics while remaining
compatible with Cppcheck's standard report format.  Optionally emits
SARIF 2.1.0 JSON and/or HTML reports controlled by environment variables.

Environment variables
---------------------
REPORT_GENERATE_SARIF
    If set to a file path, a SARIF 2.1.0 log is written there on
    ``Reporter.finish()`` (or context-manager exit).

REPORT_GENERATE_HTML
    If set to a file path, an HTML report is rendered there on
    ``Reporter.finish()``.

REPORT_HTML_TEMPLATE
    Path to a custom Jinja2 HTML template.  Falls back to
    ``$CPPCHECKDATA_SHIMS_RESOURCE_HOME/report-template.html``.

CPPCHECKDATA_SHIMS_RESOURCE_HOME
    Base directory for bundled resources (templates, etc.).

Copyright (c) 2024-2026  cppcheckdata_shims contributors.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import json
import os
import re
import sys
import textwrap
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
)

# ---------------------------------------------------------------------------
# termcolor import (bundled with cppcheckdata_shims)
# ---------------------------------------------------------------------------
try:
    from termcolor import colored, cprint, can_colorize
except ImportError:
    # Graceful degradation: no colour if termcolor is absent
    # type: ignore[misc]
    def colored(text: object, *_args: Any, **_kw: Any) -> str:
        return str(text)

    # type: ignore[misc]
    def cprint(text: object, *_args: Any, **_kw: Any) -> None:
        print(str(text))

    def can_colorize(**_kw: Any) -> bool:  # type: ignore[misc]
        return False

# ---------------------------------------------------------------------------
# Jinja2 — optional, needed only for HTML generation
# ---------------------------------------------------------------------------
_jinja2_available = False
try:
    import jinja2

    _jinja2_available = True
except ImportError:
    jinja2 = None  # type: ignore[assignment]

# ===================================================================
#  Constants & helpers
# ===================================================================

_RESOURCE_HOME: Optional[str] = os.environ.get(
    "CPPCHECKDATA_SHIMS_RESOURCE_HOME")
_DEFAULT_TEMPLATE_NAME = "report-template.html"

# Cppcheck severities (canonical order)
_CPPCHECK_SEVERITIES = ("error", "warning", "style", "performance",
                        "portability", "information", "debug")


def _severity_rank(sev: str) -> int:
    """Lower rank = more severe."""
    try:
        return _CPPCHECK_SEVERITIES.index(sev)
    except ValueError:
        return 99


def _now_iso() -> str:
    return datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _read_file_lines(path: str) -> List[str]:
    """Read a source file and return its lines (1-indexed list, index 0 is empty)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        # Prepend a dummy so that lines[1] is the first real line
        return [""] + [ln.rstrip("\n\r") for ln in lines]
    except OSError:
        return [""]


# ===================================================================
#  Severity enum
# ===================================================================

class Severity(Enum):
    """Diagnostic severity levels (matches Cppcheck)."""
    ERROR = "error"
    WARNING = "warning"
    STYLE = "style"
    PERFORMANCE = "performance"
    PORTABILITY = "portability"
    INFORMATION = "information"
    DEBUG = "debug"

    # Convenience aliases for builder methods
    NOTE = "note"       # displayed but not a Cppcheck severity
    HELP = "help"       # displayed but not a Cppcheck severity

    @property
    def cppcheck_name(self) -> str:
        if self in (Severity.NOTE, Severity.HELP):
            return "information"
        return self.value

    @property
    def color(self) -> str:
        """Terminal colour for this severity."""
        return {
            Severity.ERROR: "red",
            Severity.WARNING: "yellow",
            Severity.STYLE: "cyan",
            Severity.PERFORMANCE: "magenta",
            Severity.PORTABILITY: "blue",
            Severity.INFORMATION: "green",
            Severity.DEBUG: "dark_grey",
            Severity.NOTE: "cyan",
            Severity.HELP: "green",
        }.get(self, "white")

    @property
    def attrs(self) -> List[str]:
        if self in (Severity.ERROR, Severity.WARNING):
            return ["bold"]
        return []

    @property
    def sarif_level(self) -> str:
        return {
            Severity.ERROR: "error",
            Severity.WARNING: "warning",
            Severity.STYLE: "note",
            Severity.PERFORMANCE: "note",
            Severity.PORTABILITY: "note",
            Severity.INFORMATION: "note",
            Severity.DEBUG: "none",
            Severity.NOTE: "note",
            Severity.HELP: "none",
        }.get(self, "note")


def _parse_severity(s: Union[str, Severity]) -> Severity:
    if isinstance(s, Severity):
        return s
    s_lower = s.lower().strip()
    for member in Severity:
        if member.value == s_lower:
            return member
    return Severity.INFORMATION


# ===================================================================
#  Span / Location data structures
# ===================================================================

@dataclass(frozen=True)
class SourceLocation:
    """A precise point in a source file."""
    file: str = ""
    line: int = 0
    column: int = 0
    end_line: int = 0
    end_column: int = 0

    @property
    def has_range(self) -> bool:
        return self.end_line > 0 and self.end_column > 0

    def cppcheck_str(self) -> str:
        """``[file:line]`` or ``[file:line:col]``."""
        if self.column > 0:
            return f"[{self.file}:{self.line}:{self.column}]"
        return f"[{self.file}:{self.line}]"

    def short(self) -> str:
        if self.column > 0:
            return f"{self.file}:{self.line}:{self.column}"
        return f"{self.file}:{self.line}"


@dataclass
class SpanAnnotation:
    """
    An underline annotation beneath a code span.

    *col_start* and *col_end* are 1-based column indices into the
    source line referenced by the parent location.
    """
    col_start: int
    col_end: int
    label: str = ""
    style: str = "error"   # "error" | "warning" | "info" | "help" | "note"

    @property
    def color(self) -> str:
        return {
            "error": "red",
            "warning": "yellow",
            "info": "cyan",
            "help": "green",
            "note": "blue",
        }.get(self.style, "white")

    @property
    def char(self) -> str:
        """The underline character."""
        if self.style in ("error", "warning"):
            return "^"
        return "~"

    @property
    def attrs(self) -> List[str]:
        if self.style in ("error", "warning"):
            return ["bold"]
        return []


# ===================================================================
#  DiagnosticPart — one piece of a Diagnostic
# ===================================================================

@dataclass
class DiagnosticPart:
    """A single sub-message (note, help, label, etc.) inside a Diagnostic."""
    kind: str                          # "primary" | "note" | "help" | "label"
    severity: Severity = Severity.NOTE
    message: str = ""
    location: Optional[SourceLocation] = None
    spans: List[SpanAnnotation] = field(default_factory=list)
    suggestion: str = ""               # replacement text for "help" parts


# ===================================================================
#  Diagnostic — the complete diagnostic unit
# ===================================================================

@dataclass
class Diagnostic:
    """
    A complete diagnostic message, built incrementally.

    A ``Diagnostic`` comprises:

    - A **primary** part (severity + errorId + message + primary location + spans).
    - Zero or more **secondary** parts (notes, labels, help messages,
      each optionally with their own location and spans).

    The builder methods (``at``, ``span``, ``note``, ``help``, etc.)
    return ``self`` so they can be chained.
    """
    error_id: str = ""
    message: str = ""
    severity: Severity = Severity.ERROR
    parts: List[DiagnosticPart] = field(default_factory=list)
    cwe: Optional[int] = None
    tool: str = "cppcheckdata_shims"
    _reporter: Optional["Reporter"] = field(default=None, repr=False)
    _current_part_index: int = field(default=-1, repr=False)

    # ---- primary location shortcuts ----

    @property
    def primary(self) -> Optional[DiagnosticPart]:
        for p in self.parts:
            if p.kind == "primary":
                return p
        return None

    @property
    def location(self) -> Optional[SourceLocation]:
        p = self.primary
        return p.location if p else None

    # ---- builder interface (chained) ----

    def at(self, file: str, line: int, column: int = 0,
           end_line: int = 0, end_column: int = 0) -> "Diagnostic":
        """Set the location for the *current* part (primary or last added)."""
        loc = SourceLocation(file=file, line=line, column=column,
                             end_line=end_line or line,
                             end_column=end_column)
        part = self._current_part()
        part.location = loc
        return self

    def span(self, col_start: int, col_end: int, label: str = "",
             *, style: str = "") -> "Diagnostic":
        """
        Add a span annotation to the *current* part.

        The span underlines columns *col_start* .. *col_end* (inclusive,
        1-based) on the line of the current part's location.
        """
        if not style:
            cur = self._current_part()
            style = cur.severity.value if cur.severity in (
                Severity.ERROR, Severity.WARNING) else "info"
        self._current_part().spans.append(
            SpanAnnotation(col_start=col_start, col_end=col_end,
                           label=label, style=style))
        return self

    def note(self, file: str = "", line: int = 0, column: int = 0,
             message: str = "") -> "Diagnostic":
        """Add a note sub-diagnostic."""
        loc = SourceLocation(file=file, line=line, column=column,
                             end_line=line) if file else None
        part = DiagnosticPart(kind="note", severity=Severity.NOTE,
                              message=message, location=loc)
        self.parts.append(part)
        self._current_part_index = len(self.parts) - 1
        return self

    def label(self, file: str = "", line: int = 0, column: int = 0,
              message: str = "") -> "Diagnostic":
        """Add a secondary label (like a note but with a different rendering)."""
        loc = SourceLocation(file=file, line=line, column=column,
                             end_line=line) if file else None
        part = DiagnosticPart(kind="label", severity=Severity.NOTE,
                              message=message, location=loc)
        self.parts.append(part)
        self._current_part_index = len(self.parts) - 1
        return self

    def help(self, message: str = "", suggestion: str = "") -> "Diagnostic":
        """Add a help message (displayed with ``= help:`` prefix)."""
        part = DiagnosticPart(kind="help", severity=Severity.HELP,
                              message=message, suggestion=suggestion)
        self.parts.append(part)
        self._current_part_index = len(self.parts) - 1
        return self

    def with_cwe(self, cwe_id: int) -> "Diagnostic":
        """Attach a CWE identifier."""
        self.cwe = cwe_id
        return self

    def emit(self) -> "Diagnostic":
        """
        Finalise and emit this diagnostic.

        Prints it to stderr and records it in the parent ``Reporter``
        for later SARIF / HTML generation.
        """
        if self._reporter is not None:
            self._reporter._emit_diagnostic(self)
        else:
            # Stand-alone usage: just print
            _TerminalRenderer().render(self, file=sys.stderr)
        return self

    # ---- internal ----

    def _current_part(self) -> DiagnosticPart:
        if self._current_part_index < 0 or self._current_part_index >= len(self.parts):
            # Auto-create primary part
            part = DiagnosticPart(kind="primary", severity=self.severity)
            self.parts.append(part)
            self._current_part_index = len(self.parts) - 1
        return self.parts[self._current_part_index]

    def _ensure_primary(self) -> DiagnosticPart:
        for i, p in enumerate(self.parts):
            if p.kind == "primary":
                return p
        part = DiagnosticPart(kind="primary", severity=self.severity)
        self.parts.insert(0, part)
        self._current_part_index = 0
        return part


# ===================================================================
#  Terminal Renderer
# ===================================================================

class _TerminalRenderer:
    """
    Renders a ``Diagnostic`` to the terminal in Rust-style format,
    followed by the Cppcheck-compatible one-liner.
    """

    GUTTER_COLOR = "blue"
    GUTTER_ATTRS: List[str] = ["bold"]

    def render(self, diag: Diagnostic, *, file: Any = None,
               cppcheck_line: bool = True) -> str:
        """Render *diag* and write to *file* (default stderr).  Returns the full text."""
        if file is None:
            file = sys.stderr
        lines: List[str] = []

        # ── header ──────────────────────────────────────────────
        sev = diag.severity
        sev_text = colored(f"{sev.value}", sev.color, attrs=sev.attrs)
        eid = colored(f"[{diag.error_id}]", sev.color,
                      attrs=sev.attrs) if diag.error_id else ""
        header = f"{sev_text}{eid}: {diag.message}"
        lines.append(header)

        # ── parts ───────────────────────────────────────────────
        for part in diag.parts:
            plines = self._render_part(part, diag)
            lines.extend(plines)

        # ── Cppcheck-format one-liner ──────────────────────────
        if cppcheck_line:
            lines.append("")
            lines.append(self._cppcheck_oneliner(diag))

        text = "\n".join(lines) + "\n"
        file.write(text)
        return text

    # ---- part rendering ----

    def _render_part(self, part: DiagnosticPart,
                     diag: Diagnostic) -> List[str]:
        lines: List[str] = []
        loc = part.location

        if part.kind == "help":
            prefix = self._gutter("") + colored(" = ",
                                                self.GUTTER_COLOR, attrs=self.GUTTER_ATTRS)
            help_label = colored("help", "green", attrs=["bold"])
            msg = part.message or part.suggestion
            lines.append(f"{prefix}{help_label}: {msg}")
            return lines

        # Sub-diagnostic header (note / label)
        if part.kind in ("note", "label") and part.message:
            kind_text = colored(part.kind, part.severity.color,
                                attrs=part.severity.attrs)
            lines.append(f"{kind_text}: {part.message}")

        if loc is None:
            return lines

        # ``--> file:line:col``
        arrow = colored("-->", self.GUTTER_COLOR, attrs=self.GUTTER_ATTRS)
        lines.append(f"  {arrow} {loc.short()}")

        # Source line + annotations
        src_lines = _read_file_lines(loc.file)
        line_no = loc.line
        if 0 < line_no < len(src_lines):
            src_line = src_lines[line_no]
            gutter_w = len(str(line_no))

            # Blank gutter line before
            lines.append(self._gutter_line("", gutter_w))

            # Source line
            annotated_src = self._highlight_spans(src_line, part.spans)
            num_gutter = self._gutter(str(line_no).rjust(gutter_w))
            lines.append(
                f"{num_gutter} {colored('|', self.GUTTER_COLOR, attrs=self.GUTTER_ATTRS)} {annotated_src}")

            # Span underlines
            for sp in part.spans:
                underline = self._build_underline(sp, gutter_w, src_line)
                lines.append(underline)

            # Blank gutter line after
            lines.append(self._gutter_line("", gutter_w))

        return lines

    # ---- span / underline helpers ----

    def _highlight_spans(self, src_line: str, spans: List[SpanAnnotation]) -> str:
        """Return the source line with span regions coloured."""
        if not spans:
            return src_line
        # Sort by col_start so we can walk left-to-right
        sorted_spans = sorted(spans, key=lambda s: s.col_start)
        parts: List[str] = []
        prev_end = 0  # 0-based index of next unprocessed char
        for sp in sorted_spans:
            cs = max(sp.col_start - 1, 0)  # to 0-based
            # col_end is inclusive, but as 0-based end
            ce = min(sp.col_end, len(src_line))
            if cs > prev_end:
                parts.append(src_line[prev_end:cs])
            highlighted = colored(src_line[cs:ce], sp.color, attrs=sp.attrs)
            parts.append(highlighted)
            prev_end = ce
        if prev_end < len(src_line):
            parts.append(src_line[prev_end:])
        return "".join(parts)

    def _build_underline(self, sp: SpanAnnotation, gutter_w: int,
                         src_line: str) -> str:
        """Build the ^^^^ / ~~~~ underline line with optional label."""
        cs = max(sp.col_start - 1, 0)
        ce = min(sp.col_end, len(src_line))
        span_len = max(ce - cs, 1)
        padding = " " * cs
        underline_chars = sp.char * span_len
        underline = colored(underline_chars, sp.color, attrs=sp.attrs)
        label_part = ""
        if sp.label:
            label_part = " " + colored(sp.label, sp.color, attrs=sp.attrs)
        gutter = self._gutter(" " * gutter_w)
        pipe = colored("|", self.GUTTER_COLOR, attrs=self.GUTTER_ATTRS)
        return f"{gutter} {pipe} {padding}{underline}{label_part}"

    # ---- gutter helpers ----

    def _gutter(self, text: str) -> str:
        return colored(text, self.GUTTER_COLOR, attrs=self.GUTTER_ATTRS)

    def _gutter_line(self, text: str, width: int) -> str:
        padded = text.rjust(width) if text else " " * width
        gutter = self._gutter(padded)
        pipe = colored("|", self.GUTTER_COLOR, attrs=self.GUTTER_ATTRS)
        return f"{gutter} {pipe}"

    # ---- Cppcheck format ----

    def _cppcheck_oneliner(self, diag: Diagnostic) -> str:
        """
        Build the standard Cppcheck one-liner::

            [file:line]: (severity) message [errorId]

        Or multi-location arrow format for notes::

            [file:line] -> [file2:line2]: (severity) message [errorId]
        """
        locations: List[SourceLocation] = []
        for part in diag.parts:
            if part.location is not None:
                locations.append(part.location)

        sev_name = diag.severity.cppcheck_name
        eid = diag.error_id or "unknownError"
        msg = diag.message

        if not locations:
            return f"[nofile:0]: ({sev_name}) {msg} [{eid}]"

        if len(locations) == 1:
            loc = locations[0]
            return f"{loc.cppcheck_str()}: ({sev_name}) {msg} [{eid}]"

        # Multi-location arrow chain
        parts = [locations[0].cppcheck_str()]
        for loc in locations[1:]:
            parts.append(loc.cppcheck_str())
        arrow_chain = " -> ".join(parts)
        return f"{arrow_chain}: ({sev_name}) {msg} [{eid}]"


# ===================================================================
#  Plain-text renderer (for non-TTY / log files)
# ===================================================================

class _PlainRenderer:
    """Like _TerminalRenderer but strips all colour."""

    def render(self, diag: Diagnostic, *, file: Any = None,
               cppcheck_line: bool = True) -> str:
        """Render without colour.  Used for log files / piped output."""
        inner = _TerminalRenderer()
        # Temporarily force no colour
        text = inner.render(diag, file=open(os.devnull, "w"),
                            cppcheck_line=cppcheck_line)
        # Strip ANSI escapes
        ansi_escape = re.compile(r'\033\[[0-9;]*m')
        clean = ansi_escape.sub("", text)
        if file is None:
            file = sys.stderr
        file.write(clean)
        return clean


# ===================================================================
#  SARIF 2.1.0 Builder
# ===================================================================

class _SarifBuilder:
    """
    Accumulates diagnostics and serialises them as a SARIF 2.1.0 log.
    """

    def __init__(self, tool_name: str = "cppcheckdata_shims",
                 tool_version: str = "1.0.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version
        self._results: List[Dict[str, Any]] = []
        self._rules: OrderedDict[str, Dict[str, Any]] = OrderedDict()

    def add(self, diag: Diagnostic) -> None:
        rule_id = diag.error_id or "generic"
        if rule_id not in self._rules:
            rule_desc: Dict[str, Any] = {
                "id": rule_id,
                "shortDescription": {"text": diag.message},
            }
            if diag.cwe is not None:
                rule_desc["properties"] = {
                    "cwe": f"CWE-{diag.cwe}"
                }
            self._rules[rule_id] = rule_desc

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": diag.severity.sarif_level,
            "message": {"text": diag.message},
        }

        # Locations
        locations: List[Dict[str, Any]] = []
        related: List[Dict[str, Any]] = []

        for i, part in enumerate(diag.parts):
            if part.location is None:
                continue
            loc_obj = self._make_location(part.location)
            if part.kind == "primary":
                # Augment with region from spans if available
                if part.spans:
                    sp = part.spans[0]
                    loc_obj["physicalLocation"]["region"] = {
                        "startLine": part.location.line,
                        "startColumn": sp.col_start,
                        "endColumn": sp.col_end,
                    }
                locations.append(loc_obj)
            else:
                rel: Dict[str, Any] = {
                    "id": i,
                    "message": {"text": part.message or ""},
                    "location": loc_obj,
                }
                related.append(rel)

        if locations:
            result["locations"] = locations
        if related:
            result["relatedLocations"] = related

        # Code flows (ordered path through locations)
        if len(diag.parts) > 1:
            thread_flow_locs: List[Dict[str, Any]] = []
            for part in diag.parts:
                if part.location is None:
                    continue
                tfl: Dict[str, Any] = {
                    "location": {
                        "message": {"text": part.message or ""},
                        **self._make_location(part.location),
                    }
                }
                thread_flow_locs.append(tfl)
            if thread_flow_locs:
                result["codeFlows"] = [{
                    "threadFlows": [{
                        "locations": thread_flow_locs,
                    }]
                }]

        self._results.append(result)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.tool_name,
                        "version": self.tool_version,
                        "rules": list(self._rules.values()),
                    }
                },
                "results": self._results,
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": _now_iso(),
                }],
            }],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def write(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())

    @staticmethod
    def _make_location(loc: SourceLocation) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": loc.file,
                },
                "region": {
                    "startLine": loc.line,
                },
            }
        }
        if loc.column > 0:
            result["physicalLocation"]["region"]["startColumn"] = loc.column
        if loc.end_line > 0:
            result["physicalLocation"]["region"]["endLine"] = loc.end_line
        if loc.end_column > 0:
            result["physicalLocation"]["region"]["endColumn"] = loc.end_column
        return result


# ===================================================================
#  HTML Builder
# ===================================================================

_BUILTIN_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{{ title }}</title>
<style>
/* ---- Reset & base ---- */
*,*::before,*::after{box-sizing:border-box}
body{margin:0;font-family:'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
     background:#1e1e2e;color:#cdd6f4;line-height:1.6}
a{color:#89b4fa;text-decoration:none}
a:hover{text-decoration:underline}
/* ---- Layout ---- */
.container{max-width:1200px;margin:0 auto;padding:1rem 2rem}
header{background:#181825;padding:1.2rem 2rem;border-bottom:2px solid #313244}
header h1{margin:0;font-size:1.5rem;color:#cba6f7}
header .meta{font-size:.85rem;color:#6c7086;margin-top:.3rem}
/* ---- Summary ---- */
.summary{display:flex;gap:1.5rem;flex-wrap:wrap;margin:1.5rem 0}
.summary .badge{padding:.5rem 1.2rem;border-radius:8px;font-weight:600;font-size:1.1rem}
.badge.error{background:#45293a;color:#f38ba8}
.badge.warning{background:#45392a;color:#fab387}
.badge.style{background:#1e3a4a;color:#89dceb}
.badge.perf{background:#302040;color:#cba6f7}
.badge.info{background:#1e3a2e;color:#a6e3a1}
/* ---- Diagnostics list ---- */
.diag{background:#181825;border:1px solid #313244;border-radius:8px;
      margin-bottom:1rem;overflow:hidden}
.diag-header{padding:.7rem 1rem;display:flex;align-items:center;gap:.6rem;
             cursor:pointer;user-select:none}
.diag-header:hover{background:#1e1e30}
.diag-header .sev{font-weight:700;text-transform:uppercase;font-size:.85rem}
.sev.error{color:#f38ba8}.sev.warning{color:#fab387}
.sev.style{color:#89dceb}.sev.performance{color:#cba6f7}
.sev.information{color:#a6e3a1}.sev.debug{color:#6c7086}
.sev.note{color:#89dceb}.sev.help{color:#a6e3a1}
.diag-header .eid{color:#6c7086;font-family:monospace}
.diag-header .msg{flex:1;color:#cdd6f4}
.diag-body{padding:0 1rem 1rem 1rem;display:none}
.diag.open .diag-body{display:block}
/* ---- Code block ---- */
.code-block{background:#11111b;border-radius:6px;padding:.8rem 1rem;
            font-family:'Fira Code','Cascadia Code',Consolas,monospace;
            font-size:.85rem;overflow-x:auto;margin:.5rem 0;line-height:1.7}
.code-block .ln{color:#585b70;min-width:3ch;display:inline-block;
                text-align:right;margin-right:1rem;user-select:none}
.code-block .span-error{color:#f38ba8;font-weight:700}
.code-block .span-warning{color:#fab387;font-weight:700}
.code-block .span-info{color:#89dceb}
.code-block .span-help{color:#a6e3a1}
.code-block .span-note{color:#89b4fa}
.underline-row{color:#585b70}
.underline-row .caret-error{color:#f38ba8;font-weight:700}
.underline-row .caret-warning{color:#fab387;font-weight:700}
.underline-row .caret-info{color:#89dceb}
.underline-row .caret-help{color:#a6e3a1}
.underline-row .caret-note{color:#89b4fa}
.underline-row .label{margin-left:.5ch}
/* ---- Part ---- */
.part{margin-top:.6rem}
.part .part-head{font-size:.8rem;color:#a6adc8}
.part .part-head .kind{font-weight:600}
.part .location{font-size:.8rem;color:#6c7086;font-family:monospace}
/* ---- Help ---- */
.help-msg{color:#a6e3a1;font-size:.85rem;padding:.3rem 0 .3rem 2rem}
.help-msg::before{content:'= help: ';font-weight:600}
/* ---- Cppcheck line ---- */
.cppcheck-line{font-family:monospace;font-size:.78rem;color:#585b70;
               padding:.3rem 1rem;border-top:1px solid #313244}
/* ---- Footer ---- */
footer{text-align:center;padding:2rem;font-size:.75rem;color:#585b70}
</style>
</head>
<body>
<header>
 <h1>{{ title }}</h1>
 <div class="meta">Generated {{ timestamp }} &mdash; {{ total }} diagnostic{{ 's' if total != 1 else '' }}</div>
</header>
<div class="container">

<div class="summary">
 {% for sev, count in severity_counts.items() %}
 <div class="badge {{ sev }}">{{ sev }}: {{ count }}</div>
 {% endfor %}
</div>

{% for diag in diagnostics %}
<div class="diag" id="diag-{{ loop.index }}">
 <div class="diag-header" onclick="this.parentElement.classList.toggle('open')">
  <span class="sev {{ diag.severity }}">{{ diag.severity }}</span>
  <span class="eid">[{{ diag.error_id }}]</span>
  <span class="msg">{{ diag.message }}</span>
 </div>
 <div class="diag-body">
  {% for part in diag.parts %}
  <div class="part">
   {% if part.kind not in ('primary', 'help') and part.message %}
   <div class="part-head"><span class="kind">{{ part.kind }}</span>: {{ part.message }}</div>
   {% endif %}
   {% if part.location %}
   <div class="location">&rarr; {{ part.location.file }}:{{ part.location.line }}{% if part.location.column %}:{{ part.location.column }}{% endif %}</div>
   {% endif %}
   {% if part.source_line %}
   <div class="code-block">
    <span class="ln">{{ part.location.line }}</span>{{ part.highlighted_html | safe }}
    {% for sp in part.spans %}
    <br/><span class="ln"></span><span class="underline-row">{{ sp.padding_html | safe }}<span class="caret-{{ sp.style }}">{{ sp.underline_chars }}</span>{% if sp.label %}<span class="label caret-{{ sp.style }}">{{ sp.label }}</span>{% endif %}</span>
    {% endfor %}
   </div>
   {% endif %}
   {% if part.kind == 'help' %}
   <div class="help-msg">{{ part.message }}</div>
   {% endif %}
  </div>
  {% endfor %}
  <div class="cppcheck-line">{{ diag.cppcheck_line }}</div>
 </div>
</div>
{% endfor %}

</div>
<footer>plus_reporter &mdash; cppcheckdata_shims</footer>
<script>
// Expand first diagnostic by default
document.addEventListener('DOMContentLoaded', () => {
  const first = document.querySelector('.diag');
  if (first) first.classList.add('open');
});
</script>
</body>
</html>
"""


class _HtmlBuilder:
    """
    Accumulates diagnostics and renders them into an HTML report
    using Jinja2 templates.
    """

    def __init__(self, title: str = "Static Analysis Report"):
        self.title = title
        self._diagnostics: List[Dict[str, Any]] = []

    def add(self, diag: Diagnostic) -> None:
        d: Dict[str, Any] = {
            "severity": diag.severity.cppcheck_name,
            "error_id": diag.error_id,
            "message": diag.message,
            "parts": [],
            "cppcheck_line": _TerminalRenderer()._cppcheck_oneliner(diag),
        }
        # Remove ANSI from cppcheck_line
        ansi_re = re.compile(r'\033\[[0-9;]*m')
        d["cppcheck_line"] = ansi_re.sub("", d["cppcheck_line"])

        for part in diag.parts:
            pd: Dict[str, Any] = {
                "kind": part.kind,
                "message": part.message,
                "location": None,
                "source_line": "",
                "highlighted_html": "",
                "spans": [],
            }
            if part.location:
                pd["location"] = {
                    "file": part.location.file,
                    "line": part.location.line,
                    "column": part.location.column,
                }
                # Read source
                src_lines = _read_file_lines(part.location.file)
                ln = part.location.line
                if 0 < ln < len(src_lines):
                    src = src_lines[ln]
                    pd["source_line"] = src
                    pd["highlighted_html"] = self._highlight_html(
                        src, part.spans)
                    for sp in part.spans:
                        cs = max(sp.col_start - 1, 0)
                        pd["spans"].append({
                            "style": sp.style,
                            "padding_html": "&nbsp;" * cs,
                            "underline_chars": sp.char * max(sp.col_end - cs, 1),
                            "label": sp.label,
                        })
            d["parts"].append(pd)
        self._diagnostics.append(d)

    def render(self, template_path: Optional[str] = None) -> str:
        """Render to HTML string."""
        if not _jinja2_available:
            return self._fallback_html()

        tmpl_str = self._load_template(template_path)
        env = jinja2.Environment(
            autoescape=jinja2.select_autoescape(["html"]),
            undefined=jinja2.StrictUndefined,
        )
        # Register custom test so 'in' works in Jinja
        env.tests["in_collection"] = lambda val, col: val in col
        template = env.from_string(tmpl_str)

        severity_counts: OrderedDict[str, int] = OrderedDict()
        for diag in self._diagnostics:
            s = diag["severity"]
            severity_counts[s] = severity_counts.get(s, 0) + 1

        return template.render(
            title=self.title,
            timestamp=_now_iso(),
            total=len(self._diagnostics),
            severity_counts=severity_counts,
            diagnostics=self._diagnostics,
        )

    def write(self, path: str, template_path: Optional[str] = None) -> None:
        html = self.render(template_path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)

    def _load_template(self, custom_path: Optional[str] = None) -> str:
        # 1. Explicit custom path
        if custom_path and os.path.isfile(custom_path):
            with open(custom_path, "r", encoding="utf-8") as fh:
                return fh.read()
        # 2. Environment variable
        env_path = os.environ.get("REPORT_HTML_TEMPLATE")
        if env_path and os.path.isfile(env_path):
            with open(env_path, "r", encoding="utf-8") as fh:
                return fh.read()
        # 3. Resource home
        if _RESOURCE_HOME:
            default_path = os.path.join(_RESOURCE_HOME, _DEFAULT_TEMPLATE_NAME)
            if os.path.isfile(default_path):
                with open(default_path, "r", encoding="utf-8") as fh:
                    return fh.read()
        # 4. Built-in template
        return _BUILTIN_TEMPLATE

    def _highlight_html(self, src: str, spans: List[SpanAnnotation]) -> str:
        """Insert <span> tags around annotated regions."""
        if not spans:
            return _html_escape(src)
        sorted_spans = sorted(spans, key=lambda s: s.col_start)
        parts: List[str] = []
        prev = 0
        for sp in sorted_spans:
            cs = max(sp.col_start - 1, 0)
            ce = min(sp.col_end, len(src))
            if cs > prev:
                parts.append(_html_escape(src[prev:cs]))
            cls = f"span-{sp.style}"
            parts.append(
                f'<span class="{cls}">{_html_escape(src[cs:ce])}</span>')
            prev = ce
        if prev < len(src):
            parts.append(_html_escape(src[prev:]))
        return "".join(parts)

    def _fallback_html(self) -> str:
        """Minimal HTML when Jinja2 is unavailable."""
        lines = [
            "<!DOCTYPE html><html><head><meta charset='utf-8'/>",
            f"<title>{_html_escape(self.title)}</title></head><body>",
            f"<h1>{_html_escape(self.title)}</h1>",
            f"<p>Generated {_now_iso()} — {len(self._diagnostics)} diagnostics</p>",
            "<pre>",
        ]
        for d in self._diagnostics:
            lines.append(_html_escape(d["cppcheck_line"]))
        lines.append("</pre></body></html>")
        return "\n".join(lines)


def _html_escape(text: str) -> str:
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))


# ===================================================================
#  Statistics Tracker
# ===================================================================

@dataclass
class ReporterStats:
    """Aggregate statistics for all emitted diagnostics."""
    total: int = 0
    by_severity: Dict[str, int] = field(default_factory=lambda: {
        s: 0 for s in _CPPCHECK_SEVERITIES
    })
    by_file: Dict[str, int] = field(default_factory=dict)
    by_error_id: Dict[str, int] = field(default_factory=dict)

    def record(self, diag: Diagnostic) -> None:
        self.total += 1
        sev = diag.severity.cppcheck_name
        self.by_severity[sev] = self.by_severity.get(sev, 0) + 1
        eid = diag.error_id or "unknown"
        self.by_error_id[eid] = self.by_error_id.get(eid, 0) + 1
        loc = diag.location
        if loc and loc.file:
            self.by_file[loc.file] = self.by_file.get(loc.file, 0) + 1


# ===================================================================
#  Reporter — Main public API
# ===================================================================

class Reporter:
    """
    Incremental diagnostic reporter for ``cppcheckdata_shims`` addons.

    Usage::

        with Reporter(tool="MyAddon") as rep:
            rep.error("use-after-free", "dangling pointer dereference") \\
               .at("main.c", 42, 10) \\
               .span(10, 23, "freed here", style="error") \\
               .note("main.c", 38, message="allocated here") \\
               .span(5, 18, "in this call", style="info") \\
               .help("use a smart pointer") \\
               .emit()

        # On exit, SARIF / HTML are written if env vars are set.
    """

    def __init__(self, *,
                 tool: str = "cppcheckdata_shims",
                 tool_version: str = "1.0.0",
                 output: Any = None,
                 html_title: str = "Static Analysis Report",
                 force_color: Optional[bool] = None,
                 no_color: Optional[bool] = None):
        """
        Parameters
        ----------
        tool : str
            Tool name for SARIF and report headers.
        tool_version : str
            Tool version string.
        output : file-like or None
            Where to print terminal diagnostics.  Defaults to ``sys.stderr``.
        html_title : str
            Title for the HTML report.
        force_color / no_color : bool or None
            Override colour detection.
        """
        self.tool = tool
        self.tool_version = tool_version
        self.output = output or sys.stderr
        self.html_title = html_title
        self.force_color = force_color
        self.no_color = no_color

        self._diagnostics: List[Diagnostic] = []
        self._renderer = _TerminalRenderer()
        self._stats = ReporterStats()

        # SARIF builder (always active so we can write on finish)
        self._sarif = _SarifBuilder(tool_name=tool,
                                    tool_version=tool_version)
        # HTML builder
        self._html = _HtmlBuilder(title=html_title)

    # ---- Context manager ----

    def __enter__(self) -> "Reporter":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.finish()

    # ---- Diagnostic constructors (builder entry points) ----

    def _make_diag(self, severity: Severity, error_id: str,
                   message: str) -> Diagnostic:
        diag = Diagnostic(
            error_id=error_id,
            message=message,
            severity=severity,
            _reporter=self,
        )
        # Ensure a primary part exists
        diag._ensure_primary()
        diag.parts[0].severity = severity
        diag._current_part_index = 0
        return diag

    def error(self, error_id: str, message: str) -> Diagnostic:
        """Start building an **error** diagnostic."""
        return self._make_diag(Severity.ERROR, error_id, message)

    def warning(self, error_id: str, message: str) -> Diagnostic:
        """Start building a **warning** diagnostic."""
        return self._make_diag(Severity.WARNING, error_id, message)

    def style(self, error_id: str, message: str) -> Diagnostic:
        """Start building a **style** diagnostic."""
        return self._make_diag(Severity.STYLE, error_id, message)

    def performance(self, error_id: str, message: str) -> Diagnostic:
        """Start building a **performance** diagnostic."""
        return self._make_diag(Severity.PERFORMANCE, error_id, message)

    def portability(self, error_id: str, message: str) -> Diagnostic:
        """Start building a **portability** diagnostic."""
        return self._make_diag(Severity.PORTABILITY, error_id, message)

    def information(self, error_id: str, message: str) -> Diagnostic:
        """Start building an **information** diagnostic."""
        return self._make_diag(Severity.INFORMATION, error_id, message)

    def debug(self, error_id: str, message: str) -> Diagnostic:
        """Start building a **debug** diagnostic."""
        return self._make_diag(Severity.DEBUG, error_id, message)

    def diagnostic(self, severity: Union[str, Severity],
                   error_id: str, message: str) -> Diagnostic:
        """Start building a diagnostic with an arbitrary severity."""
        return self._make_diag(_parse_severity(severity), error_id, message)

    # ---- Quick one-shot emitters ----

    def quick_error(self, error_id: str, message: str,
                    file: str = "", line: int = 0, column: int = 0) -> None:
        """Emit a simple error diagnostic in one call."""
        d = self.error(error_id, message)
        if file:
            d.at(file, line, column)
        d.emit()

    def quick_warning(self, error_id: str, message: str,
                      file: str = "", line: int = 0, column: int = 0) -> None:
        d = self.warning(error_id, message)
        if file:
            d.at(file, line, column)
        d.emit()

    # ---- Emission (called by Diagnostic.emit()) ----

    def _emit_diagnostic(self, diag: Diagnostic) -> None:
        """Record and render a finalised diagnostic."""
        self._diagnostics.append(diag)
        self._stats.record(diag)
        self._sarif.add(diag)
        self._html.add(diag)

        # Terminal rendering
        self._renderer.render(diag, file=self.output, cppcheck_line=True)

    # ---- Accessors ----

    @property
    def diagnostics(self) -> List[Diagnostic]:
        """All emitted diagnostics (in order)."""
        return list(self._diagnostics)

    @property
    def stats(self) -> ReporterStats:
        return self._stats

    def has_errors(self) -> bool:
        return self._stats.by_severity.get("error", 0) > 0

    def error_count(self) -> int:
        return self._stats.by_severity.get("error", 0)

    def warning_count(self) -> int:
        return self._stats.by_severity.get("warning", 0)

    def total_count(self) -> int:
        return self._stats.total

    # ---- Summary ----

    def print_summary(self, *, file: Any = None) -> None:
        """Print a coloured summary line."""
        if file is None:
            file = self.output
        total = self._stats.total
        errs = self._stats.by_severity.get("error", 0)
        warns = self._stats.by_severity.get("warning", 0)

        if errs > 0:
            status = colored("FAILED", "red", attrs=["bold"])
        elif warns > 0:
            status = colored("PASSED WITH WARNINGS", "yellow", attrs=["bold"])
        else:
            status = colored("PASSED", "green", attrs=["bold"])

        parts = [f"Analysis {status}:"]
        if errs:
            parts.append(colored(f"{errs} error{'s' if errs != 1 else ''}",
                                 "red", attrs=["bold"]))
        if warns:
            parts.append(colored(f"{warns} warning{'s' if warns != 1 else ''}",
                                 "yellow", attrs=["bold"]))
        other = total - errs - warns
        if other > 0:
            parts.append(f"{other} other")
        if total == 0:
            parts.append(colored("no issues found", "green"))

        file.write("  " + ", ".join(parts) + "\n")

    # ---- Finish / flush ----

    def finish(self) -> None:
        """
        Finalise the reporter:

        1. Print summary to terminal.
        2. Write SARIF if ``$REPORT_GENERATE_SARIF`` is set.
        3. Write HTML if ``$REPORT_GENERATE_HTML`` is set.
        """
        self.print_summary()

        sarif_path = os.environ.get("REPORT_GENERATE_SARIF")
        if sarif_path:
            self._sarif.write(sarif_path)
            note = colored(f"  SARIF report written to {sarif_path}",
                           "green", attrs=["bold"])
            self.output.write(note + "\n")

        html_path = os.environ.get("REPORT_GENERATE_HTML")
        if html_path:
            template_path = os.environ.get("REPORT_HTML_TEMPLATE")
            self._html.write(html_path, template_path)
            note = colored(f"  HTML report written to {html_path}",
                           "green", attrs=["bold"])
            self.output.write(note + "\n")

    # ---- SARIF / HTML direct access ----

    def sarif_dict(self) -> Dict[str, Any]:
        """Return the SARIF log as a Python dict."""
        return self._sarif.to_dict()

    def sarif_json(self, indent: int = 2) -> str:
        """Return the SARIF log as a JSON string."""
        return self._sarif.to_json(indent)

    def write_sarif(self, path: str) -> None:
        """Manually write SARIF to *path*."""
        self._sarif.write(path)

    def html_string(self, template_path: Optional[str] = None) -> str:
        """Render the HTML report to a string."""
        return self._html.render(template_path)

    def write_html(self, path: str,
                   template_path: Optional[str] = None) -> None:
        """Manually write HTML to *path*."""
        self._html.write(path, template_path)

    # ---- Cppcheck-format batch output ----

    def cppcheck_lines(self) -> List[str]:
        """Return all diagnostics as Cppcheck-format one-liners."""
        result: List[str] = []
        ansi_re = re.compile(r'\033\[[0-9;]*m')
        for diag in self._diagnostics:
            raw = self._renderer._cppcheck_oneliner(diag)
            result.append(ansi_re.sub("", raw))
        return result

    def write_cppcheck_log(self, path: str) -> None:
        """Write a plain-text log in Cppcheck format."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            for line in self.cppcheck_lines():
                fh.write(line + "\n")


# ===================================================================
#  Module-level convenience — singleton Reporter
# ===================================================================

_default_reporter: Optional[Reporter] = None


def get_reporter(**kwargs: Any) -> Reporter:
    """
    Get or create the module-level default Reporter singleton.

    Keyword arguments are forwarded to the ``Reporter`` constructor
    only on first call.
    """
    global _default_reporter
    if _default_reporter is None:
        _default_reporter = Reporter(**kwargs)
    return _default_reporter


def reset_reporter() -> None:
    """Discard the default reporter singleton."""
    global _default_reporter
    _default_reporter = None
