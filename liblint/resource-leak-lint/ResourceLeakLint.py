"""
ResourceLeakLint.py — Cppcheck addon
======================================
Detects unclosed POSIX/C resource handles: file streams, file descriptors,
memory maps, directory handles, dlopen handles, and heap allocations.

Checkers
--------
RLL-01  unclosed_file_stream      FILE* from fopen/fdopen/popen not closed
RLL-02  unclosed_posix_fd         int fd from open/socket/accept not closed
RLL-03  unmapped_mmap             void* from mmap not munmapped
RLL-04  unclosed_dir_handle       DIR* from opendir not closedir'd
RLL-05  undlclosed_dl_handle      void* from dlopen not dlclose'd
RLL-06  double_close              handle released twice
RLL-07  use_after_close           handle used after release
RLL-08  leak_on_reassignment      handle overwritten while still ACQUIRED

CWE mapping
-----------
RLL-01..05, RLL-08  →  CWE-772  (Missing Release of Resource after Effective Lifetime)
RLL-06              →  CWE-415  (Double Free)
RLL-07              →  CWE-416  (Use After Free / Use After Close)

Shim contract
-------------
Variable IDs accessed ONLY via _safe_vid() / _safe_vid_tok().
All .variable, .valueType, .astParent, .astOperand1/2 accesses guarded for None.
"""

import sys
import re
from collections import defaultdict

# ---------------------------------------------------------------------------
# cppcheckdata import with offline stub
# ---------------------------------------------------------------------------
try:
    import cppcheckdata
except ImportError:          # pragma: no cover
    cppcheckdata = None      # type: ignore


# ===========================================================================
# §1  Shim contract — variable-ID accessors
# ===========================================================================

def _safe_vid(var):
    """Return var.Id as a string key, or None if var is None / Id missing."""
    if var is None:
        return None
    try:
        vid = var.Id
        return str(vid) if vid is not None else None
    except AttributeError:
        return None


def _safe_vid_tok(tok):
    """Return the variable-Id of tok.variable, or None."""
    if tok is None:
        return None
    try:
        var = tok.variable
    except AttributeError:
        return None
    return _safe_vid(var)


# ===========================================================================
# §2  Safe token field accessors
# ===========================================================================

def _tok_str(tok):
    """Return tok.str, or '' if unavailable."""
    if tok is None:
        return ''
    try:
        return tok.str or ''
    except AttributeError:
        return ''


def _ast_op1(tok):
    if tok is None:
        return None
    try:
        return tok.astOperand1
    except AttributeError:
        return None


def _ast_op2(tok):
    if tok is None:
        return None
    try:
        return tok.astOperand2
    except AttributeError:
        return None


def _ast_parent(tok):
    if tok is None:
        return None
    try:
        return tok.astParent
    except AttributeError:
        return None


def _tok_linenr(tok):
    if tok is None:
        return 0
    try:
        return int(tok.linenr) if tok.linenr is not None else 0
    except (AttributeError, TypeError, ValueError):
        return 0


def _tok_file(tok):
    if tok is None:
        return ''
    try:
        return tok.file or ''
    except AttributeError:
        return ''


def _tok_scope(tok):
    if tok is None:
        return None
    try:
        return tok.scope
    except AttributeError:
        return None


def _scope_type(scope):
    if scope is None:
        return ''
    try:
        return scope.type or ''
    except AttributeError:
        return ''


def _is_expanded_macro(tok):
    if tok is None:
        return False
    try:
        return bool(tok.isExpandedMacro)
    except AttributeError:
        return False


def _tok_is_number(tok):
    if tok is None:
        return False
    try:
        return bool(tok.isNumber)
    except AttributeError:
        return False


def _var_is_local(tok):
    """Return True if tok.variable.isLocal is True."""
    if tok is None:
        return False
    try:
        v = tok.variable
        if v is None:
            return False
        return bool(v.isLocal)
    except AttributeError:
        return False


# ===========================================================================
# §3  Resource family definitions
# ===========================================================================

class ResourceFamily:
    """Describes a class of resources with matching acquire/release sets."""
    __slots__ = ('name', 'acquire', 'release', 'cwe_leak',
                 'cwe_double', 'cwe_uaf', 'checker_leak')

    def __init__(self, name, acquire, release,
                 cwe_leak, cwe_double, cwe_uaf, checker_leak):
        self.name         = name
        self.acquire      = frozenset(acquire)
        self.release      = frozenset(release)
        self.cwe_leak     = cwe_leak
        self.cwe_double   = cwe_double
        self.cwe_uaf      = cwe_uaf
        self.checker_leak = checker_leak   # 'RLL-0X' string


# Ordered list — matched in order for acquire/release look-up.
# IMPORTANT: more-specific families (dlopen) must come BEFORE
# generic void* families (mmap) so name-based disambiguation works.

_FAMILIES = [
    ResourceFamily(
        name='FILE_STREAM',
        acquire={'fopen', 'fdopen', 'tmpfile', 'tmpfile64',
                 'freopen', 'popen'},
        release={'fclose', 'pclose'},
        cwe_leak=772, cwe_double=415, cwe_uaf=416,
        checker_leak='RLL-01',
    ),
    ResourceFamily(
        name='POSIX_FD',
        acquire={'open', 'open64', 'openat', 'openat64',
                 'creat', 'creat64',
                 'dup', 'dup2', 'dup3',
                 'socket', 'accept', 'accept4',
                 'eventfd', 'timerfd_create',
                 'inotify_init', 'inotify_init1',
                 'signalfd', 'memfd_create',
                 'epoll_create', 'epoll_create1'},
        release={'close'},
        cwe_leak=772, cwe_double=415, cwe_uaf=416,
        checker_leak='RLL-02',
    ),
    ResourceFamily(
        name='MMAP',
        acquire={'mmap', 'mmap64'},
        release={'munmap'},
        cwe_leak=772, cwe_double=415, cwe_uaf=416,
        checker_leak='RLL-03',
    ),
    ResourceFamily(
        name='DIR_HANDLE',
        acquire={'opendir', 'fdopendir'},
        release={'closedir'},
        cwe_leak=772, cwe_double=415, cwe_uaf=416,
        checker_leak='RLL-04',
    ),
    ResourceFamily(
        name='DL_HANDLE',
        acquire={'dlopen'},
        release={'dlclose'},
        cwe_leak=772, cwe_double=415, cwe_uaf=416,
        checker_leak='RLL-05',
    ),
    ResourceFamily(
        name='HEAP',
        acquire={'malloc', 'calloc', 'realloc',
                 'strdup', 'strndup',
                 'realpath',
                 'getcwd'},
        release={'free'},
        cwe_leak=772, cwe_double=415, cwe_uaf=416,
        checker_leak='RLL-01',   # reuse error code; distinct message
    ),
]

# Fast lookup tables built from the family list
_ACQUIRE_MAP: dict = {}   # func_name → ResourceFamily
_RELEASE_MAP: dict = {}   # func_name → ResourceFamily

for _fam in _FAMILIES:
    for _fn in _fam.acquire:
        _ACQUIRE_MAP[_fn] = _fam
    for _fn in _fam.release:
        _RELEASE_MAP[_fn] = _fam

# Functions that "use" a resource handle (for RLL-07)
_FILE_USE_FUNCS = frozenset({
    'fread', 'fwrite', 'fgets', 'fputs', 'fgetc', 'fputc',
    'fprintf', 'fscanf', 'fflush', 'fseek', 'ftell',
    'feof', 'ferror', 'rewind', 'ftruncate',
    'fileno', 'clearerr',
})

_FD_USE_FUNCS = frozenset({
    'read', 'write', 'recv', 'send',
    'recvfrom', 'sendto', 'recvmsg', 'sendmsg',
    'ioctl', 'fcntl', 'getsockopt', 'setsockopt',
    'bind', 'connect', 'listen', 'shutdown',
    'fstat', 'lseek', 'select', 'poll',
})

_USE_FUNCS = _FILE_USE_FUNCS | _FD_USE_FUNCS


# ===========================================================================
# §4  Handle state constants
# ===========================================================================

STATE_ACQUIRED  = 'ACQUIRED'
STATE_RELEASED  = 'RELEASED'
STATE_ESCAPED   = 'ESCAPED'    # returned or passed to unknown function
STATE_MAYBE     = 'MAYBE'      # conditionally acquired (NULL possible)


# ===========================================================================
# §5  Call-site parsing helpers
# ===========================================================================

def _call_name_from_tok(tok):
    """
    Given a token (anywhere near a call site), attempt to resolve the
    function name.  Most reliable when tok.str == '(' and the previous
    token is the function name.
    """
    if tok is None:
        return None

    s = _tok_str(tok)

    # If tok IS the '(' of a call, the function name is in astOperand1
    if s == '(':
        op1 = _ast_op1(tok)
        if op1 is not None:
            name = _tok_str(op1)
            if name and (name.isidentifier() or name.replace('_', '').isalnum()):
                return name
        # Fallback: previous token
        try:
            prev = tok.previous
            if prev is not None:
                name = _tok_str(prev)
                if name and name[0].isalpha() or (name and name[0] == '_'):
                    return name
        except AttributeError:
            pass

    return None


def _collect_call_args(call_paren_tok):
    """
    Given the '(' token of a function call, return a list of the AST
    root nodes for each argument (best-effort).

    In cppcheckdata, argument lists are represented as a chain of ','
    nodes.  The top-level argument sub-tree is in astOperand2 of '(',
    and each subsequent argument is the right operand of ','.
    """
    args = []
    if call_paren_tok is None:
        return args

    # The argument list root is op2 of the '(' node
    arg_root = _ast_op2(call_paren_tok)
    if arg_root is None:
        return args

    # Walk the comma chain
    node = arg_root
    while node is not None:
        s = _tok_str(node)
        if s == ',':
            # left side of ',' is one argument
            left = _ast_op1(node)
            if left is not None:
                args.append(left)
            node = _ast_op2(node)
        else:
            # Last (or only) argument
            args.append(node)
            break

    return args


def _vid_of_arg(arg_tok):
    """
    Return the variable-ID of an argument token, following simple
    aliases one level deep (e.g., if the argument is itself a name token
    referring to a variable).
    """
    if arg_tok is None:
        return None
    # Direct variable reference
    vid = _safe_vid_tok(arg_tok)
    if vid is not None:
        return vid
    # Unary & address-of: &var — skip, we don't track pointer targets
    return None


# ===========================================================================
# §6  HandleTable — per-function resource state tracker
# ===========================================================================

class HandleRecord:
    """Tracks one acquired handle within a function scope."""
    __slots__ = ('vid', 'var_name', 'family', 'state',
                 'acquire_tok', 'release_tok')

    def __init__(self, vid, var_name, family, acquire_tok):
        self.vid         = vid
        self.var_name    = var_name
        self.family      = family
        self.state       = STATE_ACQUIRED
        self.acquire_tok = acquire_tok
        self.release_tok = None


class HandleTable:
    """
    Manages a mapping of variable-ID → HandleRecord for one function body.
    Multiple records can exist for the same vid if it is re-acquired.
    We keep only the most-recent acquisition per vid to keep memory bounded.
    """

    def __init__(self):
        # vid → HandleRecord
        self._table: dict = {}

    def acquire(self, vid, var_name, family, tok):
        """Record a new acquisition for vid."""
        self._table[vid] = HandleRecord(vid, var_name, family, tok)

    def release(self, vid, tok):
        """Mark vid as released.  Return the HandleRecord, or None."""
        rec = self._table.get(vid)
        if rec is None:
            return None
        rec.release_tok = tok
        rec.state = STATE_RELEASED
        return rec

    def escape(self, vid):
        """Mark vid as escaped (returned or passed to unknown function)."""
        rec = self._table.get(vid)
        if rec is not None:
            rec.state = STATE_ESCAPED

    def get(self, vid):
        return self._table.get(vid)

    def all_records(self):
        return list(self._table.values())

    def acquired_records(self):
        return [r for r in self._table.values()
                if r.state == STATE_ACQUIRED]


# ===========================================================================
# §7  Per-function scan engine
# ===========================================================================

def _scan_function_tokens(func_tokens):
    """
    Scan the flat token list for one function body.
    Returns a list of raw error dictionaries.
    """
    errors  = []
    htable  = HandleTable()

    for tok in func_tokens:
        s = _tok_str(tok)

        # ----------------------------------------------------------------
        # A)  Assignment:  lhs = rhs_call(...)
        #     We look for '=' tokens whose RHS is a function call.
        # ----------------------------------------------------------------
        if s == '=' and _is_assignment_op(tok):
            lhs = _ast_op1(tok)
            rhs = _ast_op2(tok)

            if lhs is not None and rhs is not None:
                rhs_name = _resolve_call_name_from_expr(rhs)

                if rhs_name and rhs_name in _ACQUIRE_MAP:
                    fam   = _ACQUIRE_MAP[rhs_name]
                    vid   = _safe_vid_tok(lhs)
                    vname = _tok_str(lhs)

                    if vid is not None:
                        # RLL-08: overwriting an existing ACQUIRED handle
                        existing = htable.get(vid)
                        if existing is not None and existing.state == STATE_ACQUIRED:
                            errors.append(_mk_error(
                                'RLL-08', tok,
                                f"leak_on_reassignment: "
                                f"variable '{vname}' holds an acquired "
                                f"{existing.family.name} handle "
                                f"(opened at line "
                                f"{_tok_linenr(existing.acquire_tok)}) "
                                f"that is overwritten without being released. "
                                f"[CWE-{existing.family.cwe_leak}]",
                                'warning',
                            ))

                        htable.acquire(vid, vname, fam, tok)

                # Release call on the RHS of an assignment is unusual but
                # check for  int r = close(fd)  patterns
                elif rhs_name and rhs_name in _RELEASE_MAP:
                    # The argument to the release call is the handle
                    _process_release_call(rhs, htable, errors)

        # ----------------------------------------------------------------
        # B)  Standalone function call (tok is the '(' of the call)
        #     Covers: close(fd), fclose(f), munmap(ptr, len), etc.
        # ----------------------------------------------------------------
        if s == '(':
            call_name = _call_name_from_tok(tok)
            if call_name is None:
                continue

            # Release call
            if call_name in _RELEASE_MAP:
                _process_release_call(tok, htable, errors)

            # Use call (for RLL-07 use-after-close detection)
            elif call_name in _USE_FUNCS:
                _process_use_call(tok, htable, errors)

        # ----------------------------------------------------------------
        # C)  return statement — any ACQUIRED handle that is returned
        #     counts as ESCAPED (ownership transferred to caller).
        # ----------------------------------------------------------------
        if s == 'return':
            ret_val = _ast_op1(tok)
            if ret_val is not None:
                vid = _safe_vid_tok(ret_val)
                if vid is not None:
                    htable.escape(vid)

    # At function end, everything still ACQUIRED is leaked
    for rec in htable.acquired_records():
        errors.append(_mk_error(
            rec.family.checker_leak,
            rec.acquire_tok,
            f"{_leak_checker_name(rec.family.checker_leak)}: "
            f"variable '{rec.var_name}' acquires a "
            f"{rec.family.name} resource "
            f"but is never released before the function returns. "
            f"[CWE-{rec.family.cwe_leak}]",
            'error',
        ))

    return errors


# ===========================================================================
# §8  Call-processing sub-routines
# ===========================================================================

def _is_assignment_op(tok):
    """Return True if tok is a simple '=' assignment operator."""
    try:
        return bool(tok.isAssignmentOp)
    except AttributeError:
        return _tok_str(tok) == '='


def _resolve_call_name_from_expr(tok):
    """
    Given the AST node that is the RHS of an assignment, try to extract
    the top-level function name if the expression is a call.

    Handles:
      - direct calls:        fopen(...)    tok.str == '(' and op1.str == 'fopen'
      - nested:              (FILE*)fopen  cast wrapping a call
    """
    if tok is None:
        return None

    s = _tok_str(tok)

    # Direct function-call node:  the '(' is the AST operator
    if s == '(':
        return _call_name_from_tok(tok)

    # Cast node wrapping a call:  look at op1 / op2
    op1 = _ast_op1(tok)
    op2 = _ast_op2(tok)

    if op1 is not None and _tok_str(op1) == '(':
        return _call_name_from_tok(op1)
    if op2 is not None and _tok_str(op2) == '(':
        return _call_name_from_tok(op2)

    return None


def _process_release_call(call_tok, htable, errors):
    """
    Process a release function call.
    call_tok is either:
      - the '(' token of the standalone call, or
      - the expression root of the call on the RHS of an assignment.

    Extracts the first argument, looks up its vid, and updates the
    HandleTable.  Emits RLL-06 on double-release.
    """
    # Normalise: we need the '(' token to collect arguments
    paren = _find_call_paren(call_tok)
    if paren is None:
        return

    call_name = _call_name_from_tok(paren)
    if call_name is None:
        return

    fam = _RELEASE_MAP.get(call_name)
    if fam is None:
        return

    args = _collect_call_args(paren)
    if not args:
        return

    # First argument is the handle for all release functions
    handle_arg = args[0]
    vid = _vid_of_arg(handle_arg)
    if vid is None:
        return

    existing = htable.get(vid)
    if existing is None:
        # Handle not tracked — could be a global or parameter; skip
        return

    if existing.state == STATE_RELEASED:
        # RLL-06: double close
        vname = existing.var_name
        errors.append(_mk_error(
            'RLL-06', paren,
            f"double_close: "
            f"variable '{vname}' ({existing.family.name}) "
            f"is released a second time. "
            f"It was already released at line "
            f"{_tok_linenr(existing.release_tok)}. "
            f"[CWE-{existing.family.cwe_double}]",
            'error',
        ))
        return

    if existing.state == STATE_ACQUIRED:
        htable.release(vid, paren)


def _process_use_call(call_tok, htable, errors):
    """
    Process a use function call (read, fread, etc.).
    Scans all arguments for variables in RELEASED state and emits RLL-07.
    """
    paren = _find_call_paren(call_tok)
    if paren is None:
        return

    call_name = _call_name_from_tok(paren)
    args = _collect_call_args(paren)

    for arg in args:
        vid = _vid_of_arg(arg)
        if vid is None:
            continue
        rec = htable.get(vid)
        if rec is None:
            continue
        if rec.state == STATE_RELEASED:
            errors.append(_mk_error(
                'RLL-07', paren,
                f"use_after_close: "
                f"variable '{rec.var_name}' ({rec.family.name}) "
                f"was released at line {_tok_linenr(rec.release_tok)} "
                f"but is passed to '{call_name}' here. "
                f"[CWE-{rec.family.cwe_uaf}]",
                'error',
            ))


def _find_call_paren(tok):
    """
    Given either a '(' token or an expression-root token that is or
    contains a call, return the '(' token, or None.
    """
    if tok is None:
        return None
    if _tok_str(tok) == '(':
        return tok
    # Walk operands
    op1 = _ast_op1(tok)
    if op1 is not None and _tok_str(op1) == '(':
        return op1
    op2 = _ast_op2(tok)
    if op2 is not None and _tok_str(op2) == '(':
        return op2
    return None


# ===========================================================================
# §9  Error construction helpers
# ===========================================================================

def _leak_checker_name(checker_id):
    """Map checker ID to a human-readable prefix for the message."""
    _names = {
        'RLL-01': 'unclosed_file_stream',
        'RLL-02': 'unclosed_posix_fd',
        'RLL-03': 'unmapped_mmap',
        'RLL-04': 'unclosed_dir_handle',
        'RLL-05': 'undlclosed_dl_handle',
        'RLL-06': 'double_close',
        'RLL-07': 'use_after_close',
        'RLL-08': 'leak_on_reassignment',
    }
    return _names.get(checker_id, checker_id)


def _mk_error(checker_id, tok, msg, severity):
    return {
        'id':       checker_id,
        'tok':      tok,
        'msg':      msg,
        'severity': severity,
    }


# ===========================================================================
# §10  Function-body token partitioner
# ===========================================================================

def _partition_by_function(cfg):
    """
    Yield (func, token_list) for each function in cfg.
    token_list contains all tokens within that function's brace scope,
    in order.

    Strategy:
      1. Build a set of scope objects that correspond to function bodies.
      2. For each token, check tok.scope membership.
    """
    # Collect function scopes
    func_scopes = {}  # scope id → Function object
    for func in cfg.functions:
        try:
            fs = func.functionScope
            if fs is not None:
                func_scopes[id(fs)] = func
        except AttributeError:
            pass

    if not func_scopes:
        # Fallback: yield all tokens as one group
        yield (None, list(cfg.tokenlist))
        return

    # Partition tokens by scope
    buckets = defaultdict(list)
    for tok in cfg.tokenlist:
        sc = _tok_scope(tok)
        if sc is not None and id(sc) in func_scopes:
            buckets[id(sc)].append(tok)

    for scope_id, func in func_scopes.items():
        yield (func, buckets[scope_id])


# ===========================================================================
# §11  Top-level checker dispatcher
# ===========================================================================

def _run_all_checks(cfg):
    """Run all RLL checkers for one configuration.  Returns list of errors."""
    all_errors = []

    for func, tokens in _partition_by_function(cfg):
        if not tokens:
            continue
        errors = _scan_function_tokens(tokens)
        all_errors.extend(errors)

    return all_errors


# ===========================================================================
# §12  Error emission
# ===========================================================================

_SEVERITY_MAP = {
    'error':       'error',
    'warning':     'warning',
    'style':       'style',
    'performance': 'performance',
    'information': 'information',
}

_CWE_FROM_ID = {
    'RLL-01': 772,
    'RLL-02': 772,
    'RLL-03': 772,
    'RLL-04': 772,
    'RLL-05': 772,
    'RLL-06': 415,
    'RLL-07': 416,
    'RLL-08': 772,
}


def _emit(errors, filter_ids=None):
    """Emit errors via cppcheckdata.reportError or stderr fallback."""
    for e in errors:
        tok      = e['tok']
        msg      = e['msg']
        checker  = e['id']
        severity = _SEVERITY_MAP.get(e.get('severity', 'warning'), 'warning')

        if filter_ids and checker not in filter_ids:
            continue

        if cppcheckdata is not None:
            try:
                cppcheckdata.reportError(
                    tok, severity, msg, 'ResourceLeakLint', checker
                )
            except TypeError:
                try:
                    cppcheckdata.reportError(tok, severity, msg)
                except Exception:
                    pass
        else:
            loc = f"{_tok_file(tok)}:{_tok_linenr(tok)}"
            print(f"[{checker}] {loc}: {msg}", file=sys.stderr)


# ===========================================================================
# §13  Public entry point
# ===========================================================================

def analyse(filename, filter_ids=None):
    """Main entry point called by Cppcheck's addon runner."""
    if cppcheckdata is None:
        print("ERROR: cppcheckdata module not found.", file=sys.stderr)
        sys.exit(1)

    data = cppcheckdata.parsedump(filename)

    all_errors = []
    for cfg in data.configurations:
        all_errors.extend(_run_all_checks(cfg))

    _emit(all_errors, filter_ids)


# ---------------------------------------------------------------------------
# Cppcheck addon protocol — direct invocation
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(
            "Usage: python3 ResourceLeakLint.py <file.c.dump>",
            file=sys.stderr,
        )
        sys.exit(1)

    analyse(sys.argv[1])
