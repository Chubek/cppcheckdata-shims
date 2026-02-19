#!/usr/bin/env python3
"""
cppcheckdata_shims/plus_reporter.py
════════════════════════════════════

Rust-style colourful diagnostic reporter for cppcheck addons.

Output formats
──────────────
  • Terminal : colourful Rust-style rendering (default)
  • SARIF    : if $REPORT_GENERATE_SARIF is set to a file path
  • HTML     : if $REPORT_GENERATE_HTML is set to a file path

Cppcheck compatibility
──────────────────────
Every diagnostic also emits a classic one-liner:
    [filename:line]: (severity) message [errorId]

Usage
─────
    from plus_reporter import Reporter, Severity

    with Reporter() as rep:
        (rep.diagnostic(Severity.WARNING, "unusedVariable",
                        "variable 'x' is assigned but never used")
            .at("demo.c", 14, 5)
            .span(14, 5, 14, 6, label="declared here")
            .note("consider removing or prefixing with '_'")
            .with_cwe(563)
            .emit())
"""

from __future__ import annotations

import enum
import io
import json
import os
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Sequence,
    TextIO,
    Tuple,
    Union,
)

# ── optional dependency: termcolor (bundled shim) ────────────────────
try:
    from cppcheckdata_shims.termcolor import colored, cprint
except ImportError:
    try:
        from termcolor import colored, cprint  # type: ignore[import-untyped]
    except ImportError:
        # ultimate fallback — no colour
        def colored(text: str, color: Optional[str] = None, on_color: Optional[str] = None,
                    attrs: Optional[list] = None) -> str:
            return text

        def cprint(text: str, color: Optional[str] = None, on_color: Optional[str] = None,
                   attrs: Optional[list] = None, **kwargs: Any) -> None:
            print(text, **kwargs)

# ── optional dependency: jinja2 (for HTML) ───────────────────────────
try:
    import jinja2

    _HAS_JINJA2 = True
except ImportError:
    _HAS_JINJA2 = False


# ═════════════════════════════════════════════════════════════════════════
#  SEVERITY ENUM
# ═════════════════════════════════════════════════════════════════════════

class Severity(enum.Enum):
    """
    Diagnostic severity levels.

    Each carries:
      • cppcheck_name — the string cppcheck uses in its output
      • color         — termcolor colour name
      • sarif_level   — SARIF 2.1.0 ``level`` string
    """

    ERROR = ("error", "red", "error")
    WARNING = ("warning", "yellow", "warning")
    STYLE = ("style", "cyan", "note")
    PERFORMANCE = ("performance", "magenta", "warning")
    PORTABILITY = ("portability", "blue", "warning")
    INFORMATION = ("information", "white", "note")

    def __init__(self, cppcheck_name: str, color: str, sarif_level: str) -> None:
        self.cppcheck_name = cppcheck_name
        self.color = color
        self.sarif_level = sarif_level

    @classmethod
    def from_string(cls, s: str) -> Severity:
        """Parse a severity from its cppcheck name (case-insensitive)."""
        s_low = s.strip().lower()
        for member in cls:
            if member.cppcheck_name == s_low:
                return member
        return cls.WARNING  # safe default


# ═════════════════════════════════════════════════════════════════════════
#  DATA STRUCTURES
# ═════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class SourceLocation:
    """A point in a source file."""
    file: str = ""
    line: int = 0
    column: int = 0

    def __str__(self) -> str:
        if self.column:
            return f"{self.file}:{self.line}:{self.column}"
        return f"{self.file}:{self.line}"


@dataclass(frozen=True)
class SpanAnnotation:
    """
    An underlined span of source text with an optional label.

    Coordinates are 1-based.  ``end_column`` is exclusive (points one
    past the last highlighted character).
    """
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    label: str = ""
    style: str = "^"  # '^' for primary, '~' for secondary


@dataclass
class DiagnosticPart:
    """
    A sub-part of a diagnostic (the main message, a note, or a help hint).
    """
    kind: str  # "primary", "note", "help"
    message: str = ""
    location: Optional[SourceLocation] = None
    spans: List[SpanAnnotation] = field(default_factory=list)


@dataclass
class ReporterStats:
    """Aggregate counts per severity."""
    error: int = 0
    warning: int = 0
    style: int = 0
    performance: int = 0
    portability: int = 0
    information: int = 0

    # FIX: add a method to increment the right counter from a Severity
    def record(self, severity: Severity) -> None:
        """Increment the counter that corresponds to *severity*."""
        attr = severity.cppcheck_name        # e.g. "warning"
        setattr(self, attr, getattr(self, attr) + 1)

    @property
    def total(self) -> int:
        return (
            self.error
            + self.warning
            + self.style
            + self.performance
            + self.portability
            + self.information
        )

    def summary_line(self) -> str:
        parts: List[str] = []
        if self.error:
            parts.append(f"{self.error} error{'s' if self.error != 1 else ''}")
        if self.warning:
            parts.append(f"{self.warning} warning{'s' if self.warning != 1 else ''}")
        if self.style:
            parts.append(f"{self.style} style")
        if self.performance:
            parts.append(f"{self.performance} performance")
        if self.portability:
            parts.append(f"{self.portability} portability")
        if self.information:
            parts.append(f"{self.information} info")
        if not parts:
            return "no diagnostics emitted"
        return "; ".join(parts) + f" ({self.total} total)"


# ═════════════════════════════════════════════════════════════════════════
#  DIAGNOSTIC (builder pattern)
# ═════════════════════════════════════════════════════════════════════════

class Diagnostic:
    """
    Incrementally constructed diagnostic.

    Usage::

        (reporter.diagnostic(Severity.WARNING, "unusedVar", "…")
            .at("file.c", 10, 1)
            .span(10, 1, 10, 4, label="this variable")
            .note("consider removing it")
            .help("prefix unused variables with '_'")
            .with_cwe(563)
            .emit())
    """

    def __init__(
        self,
        reporter: Reporter,
        severity: Severity,
        error_id: str,
        message: str,
    ) -> None:
        self._reporter = reporter
        self.severity = severity
        self.error_id = error_id
        self.message = message
        self.cwe: Optional[int] = None
        self.primary = DiagnosticPart(kind="primary", message=message)
        self.notes: List[DiagnosticPart] = []
        self.helps: List[DiagnosticPart] = []

    # ── builder methods (all return self for chaining) ───────────────

    def at(self, file: str, line: int, column: int = 0) -> Diagnostic:
        """Set the primary source location."""
        self.primary.location = SourceLocation(file, line, column)
        return self

    def span(
        self,
        start_line: int,
        start_col: int,
        end_line: int,
        end_col: int,
        label: str = "",
        style: str = "^",
    ) -> Diagnostic:
        """Add an underline span to the primary location."""
        self.primary.spans.append(
            SpanAnnotation(start_line, start_col, end_line, end_col, label, style)
        )
        return self

    def note(self, message: str, file: str = "", line: int = 0, column: int = 0) -> Diagnostic:
        """Append a note sub-diagnostic."""
        loc = SourceLocation(file, line, column) if file else None
        self.notes.append(DiagnosticPart(kind="note", message=message, location=loc))
        return self

    def help(self, message: str) -> Diagnostic:
        """Append a help hint."""
        self.helps.append(DiagnosticPart(kind="help", message=message))
        return self

    def with_cwe(self, cwe_id: int) -> Diagnostic:
        """Tag this diagnostic with a MITRE CWE number."""
        self.cwe = cwe_id
        return self

    def emit(self) -> None:
        """
        Finalise and send the diagnostic to the reporter.

        After this call the builder should not be reused.
        """
        self._reporter._accept(self)  # noqa: SLF001

    # ── convenience ──────────────────────────────────────────────────

    @property
    def location(self) -> Optional[SourceLocation]:
        return self.primary.location

    def cppcheck_line(self) -> str:
        """Classic one-liner: ``[file:line]: (severity) message [id]``."""
        loc = self.primary.location
        fname = loc.file if loc else ""
        lineno = loc.line if loc else 0
        sev = self.severity.cppcheck_name
        return f"[{fname}:{lineno}]: ({sev}) {self.message} [{self.error_id}]"


# ═════════════════════════════════════════════════════════════════════════
#  TERMINAL RENDERER  (Rust-style colourful output)
# ═════════════════════════════════════════════════════════════════════════

class _TerminalRenderer:
    """Render diagnostics to a terminal with colours."""

    def __init__(self, stream: TextIO = sys.stderr) -> None:
        self._stream = stream

    # ── public API ───────────────────────────────────────────────────

    def render(self, diag: Diagnostic) -> None:
        lines: List[str] = []

        # ── header: severity[errorId]: message ───────────────────────
        sev_str = colored(
            f"{diag.severity.cppcheck_name}[{diag.error_id}]",
            diag.severity.color,
            attrs=["bold"],
        )
        lines.append(f"{sev_str}: {colored(diag.message, 'white', attrs=['bold'])}")

        # ── primary location ─────────────────────────────────────────
        loc = diag.primary.location
        if loc:
            arrow = colored("-->", "blue", attrs=["bold"])
            lines.append(f"  {arrow} {loc}")

        # ── span annotations ─────────────────────────────────────────
        if loc and diag.primary.spans:
            lines.extend(self._render_spans(loc, diag.primary.spans, diag.severity))

        # ── notes ────────────────────────────────────────────────────
        for note in diag.notes:
            prefix = colored("note", "cyan", attrs=["bold"])
            lines.append(f"  = {prefix}: {note.message}")
            if note.location:
                arrow = colored("-->", "blue", attrs=["bold"])
                lines.append(f"    {arrow} {note.location}")

        # ── helps ────────────────────────────────────────────────────
        for hlp in diag.helps:
            prefix = colored("help", "green", attrs=["bold"])
            lines.append(f"  = {prefix}: {hlp.message}")

        # ── CWE tag ──────────────────────────────────────────────────
        if diag.cwe is not None:
            cwe_str = colored(f"CWE-{diag.cwe}", "blue", attrs=["underline"])
            lines.append(f"  = {cwe_str}: https://cwe.mitre.org/data/definitions/{diag.cwe}.html")

        # ── cppcheck compat line ─────────────────────────────────────
        lines.append(colored(diag.cppcheck_line(), attrs=["dark"]))

        lines.append("")  # blank separator
        self._stream.write("\n".join(lines) + "\n")
        self._stream.flush()

    # ── span rendering helpers ───────────────────────────────────────

    def _render_spans(
        self,
        loc: SourceLocation,
        spans: List[SpanAnnotation],
        severity: Severity,
    ) -> List[str]:
        """
        Build the Rust-style annotated source view.

        Since we may not have the actual source file, we render a
        schematic view using line numbers and caret annotations.
        """
        result: List[str] = []
        gutter_w = max(len(str(s.start_line)) for s in spans) + 1
        pipe = colored("|", "blue", attrs=["bold"])

        # Try to read source lines
        source_lines = self._read_source(loc.file, spans)

        for sp in spans:
            line_num = str(sp.start_line).rjust(gutter_w)
            line_prefix = colored(line_num, "blue", attrs=["bold"])

            # Source text
            src_text = source_lines.get(sp.start_line, "")
            result.append(f" {line_prefix} {pipe} {src_text}")

            # Caret / tilde line
            pad = " " * (sp.start_col - 1) if sp.start_col > 0 else ""
            span_len = max(sp.end_col - sp.start_col, 1)
            marker_char = sp.style if sp.style else "^"
            marker = marker_char * span_len
            label_str = f" {sp.label}" if sp.label else ""

            marker_colored = colored(marker + label_str, severity.color, attrs=["bold"])
            blank_gutter = " " * (gutter_w + 1)
            result.append(f" {blank_gutter} {pipe} {pad}{marker_colored}")

        return result

    @staticmethod
    def _read_source(
        filepath: str, spans: Sequence[SpanAnnotation]
    ) -> Dict[int, str]:
        """Attempt to read relevant source lines; return {} on failure."""
        if not filepath:
            return {}
        try:
            needed = {s.start_line for s in spans}
            result: Dict[int, str] = {}
            with open(filepath, "r", errors="replace") as fh:
                for idx, line in enumerate(fh, 1):
                    if idx in needed:
                        result[idx] = line.rstrip("\n\r")
                    if idx > max(needed):
                        break
            return result
        except OSError:
            return {}


# ═════════════════════════════════════════════════════════════════════════
#  PLAIN RENDERER  (for log files / non-TTY)
# ═════════════════════════════════════════════════════════════════════════

class _PlainRenderer:
    """Non-coloured renderer — one cppcheck-compatible line per diagnostic."""

    def __init__(self, stream: TextIO = sys.stderr) -> None:
        self._stream = stream

    def render(self, diag: Diagnostic) -> None:
        self._stream.write(diag.cppcheck_line() + "\n")
        for note in diag.notes:
            loc_str = f" [{note.location}]" if note.location else ""
            self._stream.write(f"  note{loc_str}: {note.message}\n")
        self._stream.flush()


# ═════════════════════════════════════════════════════════════════════════
#  SARIF 2.1.0 BUILDER
# ═════════════════════════════════════════════════════════════════════════

class _SarifBuilder:
    """Accumulates diagnostics and writes a SARIF 2.1.0 JSON file."""

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = (
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
        "Schemata/sarif-schema-2.1.0.json"
    )

    def __init__(self) -> None:
        self._results: List[Dict[str, Any]] = []
        self._rules: Dict[str, Dict[str, Any]] = {}  # errorId → rule obj

    def add(self, diag: Diagnostic) -> None:
        # ── rule ─────────────────────────────────────────────────────
        if diag.error_id not in self._rules:
            rule: Dict[str, Any] = {
                "id": diag.error_id,
                "shortDescription": {"text": diag.message},
            }
            if diag.cwe is not None:
                rule["relationships"] = [
                    {
                        "target": {
                            "id": str(diag.cwe),
                            "guid": "",
                            "toolComponent": {"name": "CWE", "guid": ""},
                        },
                        "kinds": ["superset"],
                    }
                ]
            self._rules[diag.error_id] = rule

        # ── result ───────────────────────────────────────────────────
        loc = diag.primary.location
        result: Dict[str, Any] = {
            "ruleId": diag.error_id,
            "level": diag.severity.sarif_level,
            "message": {"text": diag.message},
        }
        if loc:
            phys: Dict[str, Any] = {
                "artifactLocation": {"uri": loc.file},
                "region": {"startLine": loc.line},
            }
            if loc.column:
                phys["region"]["startColumn"] = loc.column
            result["locations"] = [{"physicalLocation": phys}]

        # ── related locations (notes) ────────────────────────────────
        related: List[Dict[str, Any]] = []
        for idx, note in enumerate(diag.notes):
            entry: Dict[str, Any] = {
                "id": idx,
                "message": {"text": note.message},
            }
            if note.location:
                entry["physicalLocation"] = {
                    "artifactLocation": {"uri": note.location.file},
                    "region": {"startLine": note.location.line},
                }
            related.append(entry)
        if related:
            result["relatedLocations"] = related

        # ── CWE property ────────────────────────────────────────────
        if diag.cwe is not None:
            result.setdefault("properties", {})["cwe"] = diag.cwe

        self._results.append(result)

    def to_json(self, tool_name: str = "cppcheckdata-shims", version: str = "1.0.0") -> str:
        sarif: Dict[str, Any] = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "version": version,
                            "rules": list(self._rules.values()),
                        }
                    },
                    "results": self._results,
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def write(self, path: str, tool_name: str = "cppcheckdata-shims", version: str = "1.0.0") -> None:
        content = self.to_json(tool_name, version)
        Path(path).write_text(content, encoding="utf-8")


# ═════════════════════════════════════════════════════════════════════════
#  HTML BUILDER
# ═════════════════════════════════════════════════════════════════════════

class _HtmlBuilder:
    """Accumulates diagnostics and renders to an HTML file via Jinja2."""

    def __init__(self) -> None:
        self._diagnostics: List[Dict[str, Any]] = []

    def add(self, diag: Diagnostic) -> None:
        loc = diag.primary.location
        entry: Dict[str, Any] = {
            "severity": diag.severity.cppcheck_name,
            "severity_color": diag.severity.color,
            "error_id": diag.error_id,
            "message": diag.message,
            "file": loc.file if loc else "",
            "line": loc.line if loc else 0,
            "column": loc.column if loc else 0,
            "cwe": diag.cwe,
            "notes": [
                {
                    "message": n.message,
                    "file": n.location.file if n.location else "",
                    "line": n.location.line if n.location else 0,
                }
                for n in diag.notes
            ],
            "helps": [h.message for h in diag.helps],
            "spans": [
                {
                    "start_line": s.start_line,
                    "start_col": s.start_col,
                    "end_line": s.end_line,
                    "end_col": s.end_col,
                    "label": s.label,
                    "style": s.style,
                }
                for s in diag.primary.spans
            ],
        }
        self._diagnostics.append(entry)

    def write(self, path: str, template_path: Optional[str] = None) -> None:
        if not _HAS_JINJA2:
            # Fallback: write a minimal HTML without Jinja2
            self._write_minimal(path)
            return

        template_str = self._load_template(template_path)
        env = jinja2.Environment(autoescape=True)
        tmpl = env.from_string(template_str)
        html = tmpl.render(diagnostics=self._diagnostics, total=len(self._diagnostics))
        Path(path).write_text(html, encoding="utf-8")

    def _load_template(self, template_path: Optional[str]) -> str:
        """Resolve the HTML template, using env vars and fallback."""
        # 1. explicit argument
        if template_path:
            return Path(template_path).read_text(encoding="utf-8")

        # 2. $REPORT_HTML_TEMPLATE
        env_tmpl = os.environ.get("REPORT_HTML_TEMPLATE", "")
        if env_tmpl and Path(env_tmpl).is_file():
            return Path(env_tmpl).read_text(encoding="utf-8")

        # 3. $CPPCHECKDATA_SHIMS_RESOURCE_HOME/report-template.html
        res_home = os.environ.get("CPPCHECKDATA_SHIMS_RESOURCE_HOME", "")
        if res_home:
            candidate = Path(res_home) / "report-template.html"
            if candidate.is_file():
                return candidate.read_text(encoding="utf-8")

        # 4. built-in default
        return _DEFAULT_HTML_TEMPLATE

    def _write_minimal(self, path: str) -> None:
        """Fallback HTML writer without Jinja2."""
        buf = io.StringIO()
        buf.write("<!DOCTYPE html><html><head><meta charset='utf-8'>")
        buf.write("<title>Diagnostic Report</title></head><body>")
        buf.write(f"<h1>Diagnostic Report ({len(self._diagnostics)} issues)</h1>")
        buf.write("<table border='1' cellpadding='4'><tr>")
        buf.write("<th>#</th><th>Severity</th><th>ID</th><th>File</th>")
        buf.write("<th>Line</th><th>Message</th><th>CWE</th></tr>")
        for idx, d in enumerate(self._diagnostics, 1):
            cwe_cell = f"CWE-{d['cwe']}" if d["cwe"] else ""
            buf.write(
                f"<tr><td>{idx}</td><td>{d['severity']}</td>"
                f"<td>{d['error_id']}</td><td>{d['file']}</td>"
                f"<td>{d['line']}</td><td>{d['message']}</td>"
                f"<td>{cwe_cell}</td></tr>"
            )
        buf.write("</table></body></html>")
        Path(path).write_text(buf.getvalue(), encoding="utf-8")


# ═════════════════════════════════════════════════════════════════════════
#  REPORTER  (main entry point)
# ═════════════════════════════════════════════════════════════════════════

class Reporter:
    """
    Central diagnostic dispatcher.

    Use as a context manager::

        with Reporter() as rep:
            rep.diagnostic(Severity.WARNING, "id", "msg").at(...).emit()
        # finish() is called automatically

    Or manually::

        rep = Reporter()
        rep.diagnostic(Severity.WARNING, "id", "msg").at(...).emit()
        rep.finish()
    """

    def __init__(
        self,
        stream: TextIO = sys.stderr,
        colour: Optional[bool] = None,
        tool_name: str = "cppcheckdata-shims",
        tool_version: str = "1.0.0",
    ) -> None:
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.stats = ReporterStats()
        self._diagnostics: List[Diagnostic] = []

        # ── choose renderer ──────────────────────────────────────────
        use_colour = colour if colour is not None else hasattr(stream, "isatty") and stream.isatty()
        if use_colour:
            self._renderer: Union[_TerminalRenderer, _PlainRenderer] = _TerminalRenderer(stream)
        else:
            self._renderer = _PlainRenderer(stream)

        # ── optional writers (driven by env vars) ────────────────────
        self._sarif: Optional[_SarifBuilder] = None
        sarif_path = os.environ.get("REPORT_GENERATE_SARIF", "")
        if sarif_path:
            self._sarif = _SarifBuilder()
            self._sarif_path = sarif_path

        self._html: Optional[_HtmlBuilder] = None
        html_path = os.environ.get("REPORT_GENERATE_HTML", "")
        if html_path:
            self._html = _HtmlBuilder()
            self._html_path = html_path

    # ── context manager ──────────────────────────────────────────────

    def __enter__(self) -> Reporter:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.finish()

    # ── builder entry point ──────────────────────────────────────────

    def diagnostic(
        self,
        severity: Severity,
        error_id: str,
        message: str,
    ) -> Diagnostic:
        """Create a new :class:`Diagnostic` builder bound to this reporter."""
        return Diagnostic(self, severity, error_id, message)

    # ── internal accept ──────────────────────────────────────────────

    def _accept(self, diag: Diagnostic) -> None:
        """
        Called by :meth:`Diagnostic.emit`.

        Routes the diagnostic to all active outputs AND increments stats.
        """
        # FIX: ──────────────────────────────────────────────────────
        # This is the *critical* fix: record the severity in stats
        # BEFORE doing anything else, so that finish() sees the real
        # counts even if a renderer raises.
        # ──────────────────────────────────────────────────────────────
        self.stats.record(diag.severity)

        self._diagnostics.append(diag)
        self._renderer.render(diag)

        if self._sarif is not None:
            self._sarif.add(diag)

        if self._html is not None:
            self._html.add(diag)

    # ── finalisation ─────────────────────────────────────────────────

    def finish(self) -> ReporterStats:
        """
        Print the summary line and write SARIF / HTML if configured.

        Returns the final :class:`ReporterStats`.
        """
        # ── summary ──────────────────────────────────────────────────
        summary = self.stats.summary_line()
        if isinstance(self._renderer, _TerminalRenderer):
            if self.stats.error:
                cprint(f"  ╰─ {summary}", "red", attrs=["bold"], file=sys.stderr)
            elif self.stats.total:
                cprint(f"  ╰─ {summary}", "yellow", attrs=["bold"], file=sys.stderr)
            else:
                cprint(f"  ╰─ {summary}", "green", attrs=["bold"], file=sys.stderr)
        else:
            print(f"  {summary}", file=sys.stderr)

        # ── SARIF ────────────────────────────────────────────────────
        if self._sarif is not None:
            try:
                self._sarif.write(
                    self._sarif_path,
                    tool_name=self.tool_name,
                    tool_version=self.tool_version,
                )
            except OSError as exc:
                print(f"plus_reporter: failed to write SARIF: {exc}", file=sys.stderr)

        # ── HTML ─────────────────────────────────────────────────────
        if self._html is not None:
            try:
                self._html.write(self._html_path)
            except OSError as exc:
                print(f"plus_reporter: failed to write HTML: {exc}", file=sys.stderr)

        return self.stats


# ═════════════════════════════════════════════════════════════════════════
#  DEFAULT HTML TEMPLATE
# ═════════════════════════════════════════════════════════════════════════

_DEFAULT_HTML_TEMPLATE = textwrap.dedent("""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Diagnostic Report</title>
  <style>
    :root { --bg: #1e1e2e; --fg: #cdd6f4; --surface: #313244;
            --red: #f38ba8; --yellow: #f9e2af; --cyan: #89dceb;
            --green: #a6e3a1; --blue: #89b4fa; --magenta: #cba6f7;
            --border: #45475a; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Fira Code', 'Cascadia Code', monospace;
           background: var(--bg); color: var(--fg); padding: 2rem; }
    h1 { margin-bottom: 1rem; }
    .card { background: var(--surface); border: 1px solid var(--border);
            border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
    .sev-error   { border-left: 4px solid var(--red); }
    .sev-warning { border-left: 4px solid var(--yellow); }
    .sev-style   { border-left: 4px solid var(--cyan); }
    .sev-performance { border-left: 4px solid var(--magenta); }
    .sev-portability { border-left: 4px solid var(--blue); }
    .sev-information { border-left: 4px solid var(--fg); }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
             font-size: 0.85em; font-weight: bold; }
    .badge-error   { background: var(--red); color: var(--bg); }
    .badge-warning { background: var(--yellow); color: var(--bg); }
    .badge-style   { background: var(--cyan); color: var(--bg); }
    .badge-performance { background: var(--magenta); color: var(--bg); }
    .badge-portability { background: var(--blue); color: var(--bg); }
    .badge-information { background: var(--fg); color: var(--bg); }
    .loc { color: var(--blue); font-size: 0.9em; }
    .msg { margin-top: 0.4rem; }
    .note { color: var(--cyan); margin-top: 0.3rem; font-size: 0.9em; }
    .help { color: var(--green); margin-top: 0.3rem; font-size: 0.9em; }
    .cwe  { color: var(--magenta); margin-top: 0.3rem; font-size: 0.9em; }
    .summary { margin-top: 2rem; padding: 1rem; background: var(--surface);
               border-radius: 8px; text-align: center; font-size: 1.1em; }
  </style>
</head>
<body>
  <h1>Diagnostic Report</h1>
  {% for d in diagnostics %}
  <div class="card sev-{{ d.severity }}">
    <span class="badge badge-{{ d.severity }}">{{ d.severity }}</span>
    <code>[{{ d.error_id }}]</code>
    {% if d.file %}
      <span class="loc">{{ d.file }}:{{ d.line }}{% if d.column %}:{{ d.column }}{% endif %}</span>
    {% endif %}
    <div class="msg">{{ d.message }}</div>
    {% for n in d.notes %}
      <div class="note">note: {{ n.message }}{% if n.file %} ({{ n.file }}:{{ n.line }}){% endif %}</div>
    {% endfor %}
    {% for h in d.helps %}
      <div class="help">help: {{ h }}</div>
    {% endfor %}
    {% if d.cwe %}
      <div class="cwe">CWE-{{ d.cwe }}: <a href="https://cwe.mitre.org/data/definitions/{{ d.cwe }}.html" style="color:inherit;">details</a></div>
    {% endif %}
  </div>
  {% endfor %}
  <div class="summary">{{ total }} diagnostic{{ 's' if total != 1 else '' }} emitted.</div>
</body>
</html>
""")


# ═════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ═════════════════════════════════════════════════════════════════════════

__all__ = [
    "Severity",
    "SourceLocation",
    "SpanAnnotation",
    "DiagnosticPart",
    "Diagnostic",
    "Reporter",
    "ReporterStats",
]
