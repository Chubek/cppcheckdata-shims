# tests/test_parser.py
"""
Tests for the CASL parser: source text → AST nodes.
"""

import pytest

from casl.parser import parse
from casl.errors import CASLParseError
from casl.ast_nodes import (
    Program, AddonDecl, CheckerDecl, FnDecl, ConstDecl,
    ImportStmt, TypeAliasDecl,
    LetStmt, IfStmt, ForStmt, WhileStmt, ReturnStmt, EmitStmt,
    BreakStmt, ContinueStmt, ExprStmt, AssignStmt,
    Identifier, IntLiteral, FloatLiteral, StringLiteral, BoolLiteral,
    NullLiteral, ListLiteral, SetLiteral,
    BinaryExpr, UnaryExpr, TernaryExpr, CallExpr, IndexExpr,
    MemberExpr, MethodCallExpr, MatchExpr,
    BinOp, UnaryOp, Severity, Confidence, OnEvent, AssignOp,
    TokenPattern, ScopePattern, WildcardPattern, DerefPattern,
    PatternDecl, PatternClauseMatch, PatternClauseWhere,
    QueryDecl, OnBlock, SuppressDecl,
    TypeName, TypeGeneric, Param,
)
from tests.conftest import (
    MINIMAL_CASL, ADDON_ONLY_CASL, CONST_CASL, FN_CASL,
    CHECKER_MINIMAL_CASL, CHECKER_FULL_CASL, PATTERN_CASL,
    IMPORT_CASL, IF_ELIF_ELSE_CASL, FOR_LOOP_CASL,
    WHILE_LOOP_CASL, SUPPRESS_CASL, DOCSTRING_CASL,
    QUERY_CASL, LIST_LITERAL_CASL, BINARY_EXPR_CASL,
    TERNARY_CASL,
)


class TestParseEmpty:

    def test_empty_string(self):
        prog = parse("")
        assert isinstance(prog, Program)
        assert prog.addon is None
        assert prog.items == []

    def test_whitespace_only(self):
        prog = parse("   \n\n\t  ")
        assert prog.items == []

    def test_comment_only(self):
        prog = parse("// just a comment\n/* block */")
        assert prog.items == []


class TestParseAddon:

    def test_addon_with_description(self):
        prog = parse(ADDON_ONLY_CASL)
        assert prog.addon is not None
        assert prog.addon.name == "TestAddon"
        assert prog.addon.description == "A test addon"

    def test_addon_fields(self):
        prog = parse(ADDON_ONLY_CASL)
        assert len(prog.addon.fields) == 1
        assert prog.addon.fields[0].key == "severity"

    def test_addon_multiple_fields(self):
        src = '''
            addon Multi {
                cwe = 100;
                severity = "error";
                version = "1.0";
            }
        '''
        prog = parse(src)
        assert len(prog.addon.fields) == 3


class TestParseConst:

    def test_integer_const(self):
        prog = parse(CONST_CASL)
        assert len(prog.items) == 1
        c = prog.items[0]
        assert isinstance(c, ConstDecl)
        assert c.name == "MAX_VAL"
        assert isinstance(c.value, IntLiteral)
        assert c.value.value == 42

    def test_string_const(self):
        prog = parse('const NAME = "hello";')
        c = prog.items[0]
        assert isinstance(c.value, StringLiteral)
        assert c.value.value == "hello"

    def test_list_const(self):
        prog = parse(LIST_LITERAL_CASL)
        c = prog.items[0]
        assert isinstance(c.value, ListLiteral)
        assert len(c.value.elements) == 3

    def test_hex_const(self):
        prog = parse("const MASK = 0xFF;")
        assert prog.items[0].value.value == 255

    def test_binary_const(self):
        prog = parse("const FLAGS = 0b1010;")
        assert prog.items[0].value.value == 10


class TestParseFn:

    def test_simple_fn(self):
        prog = parse(FN_CASL)
        fn = prog.items[0]
        assert isinstance(fn, FnDecl)
        assert fn.name == "helper"
        assert len(fn.params) == 2
        assert fn.params[0].name == "x"

    def test_fn_with_return_type(self):
        src = 'fn typed(x: Int) -> Bool { return true; }'
        prog = parse(src)
        fn = prog.items[0]
        assert fn.params[0].type_annotation is not None
        assert fn.return_type is not None

    def test_fn_empty_body(self):
        prog = parse("fn noop() { }")
        fn = prog.items[0]
        assert fn.body == []


class TestParseImport:

    def test_simple_import(self):
        prog = parse("import foo;")
        imp = prog.items[0]
        assert isinstance(imp, ImportStmt)
        assert imp.path == ["foo"]

    def test_dotted_import(self):
        prog = parse(IMPORT_CASL)
        imp = prog.items[0]
        assert isinstance(imp, ImportStmt)
        assert imp.path == ["utils", "helpers"]


class TestParseChecker:

    def test_minimal_checker(self):
        prog = parse(CHECKER_MINIMAL_CASL)
        ch = prog.items[0]
        assert isinstance(ch, CheckerDecl)
        assert ch.name == "minimal"
        assert ch.error_id == "minErr"
        assert ch.severity == Severity.WARNING

    def test_full_checker(self):
        prog = parse(CHECKER_FULL_CASL)
        # Find the checker
        checkers = [i for i in prog.items if isinstance(i, CheckerDecl)]
        assert len(checkers) == 1
        ch = checkers[0]
        assert ch.name == "full_check"
        assert ch.cwe == 476
        assert ch.confidence == Confidence.PROBABLE
        assert len(ch.on_blocks) >= 2  # init, token, finish

    def test_checker_on_events(self):
        prog = parse(CHECKER_FULL_CASL)
        ch = [i for i in prog.items if isinstance(i, CheckerDecl)][0]
        events = {ob.event for ob in ch.on_blocks}
        assert OnEvent.INIT in events
        assert OnEvent.TOKEN in events
        assert OnEvent.FINISH in events

    def test_checker_let(self):
        prog = parse(CHECKER_FULL_CASL)
        ch = [i for i in prog.items if isinstance(i, CheckerDecl)][0]
        assert len(ch.lets) == 1
        assert ch.lets[0].name == "counter"
        assert ch.lets[0].mutable is True


class TestParsePattern:

    def test_pattern_with_match_and_where(self):
        prog = parse(PATTERN_CASL)
        ch = prog.items[0]
        assert len(ch.patterns) == 1
        pat = ch.patterns[0]
        assert pat.name == "deref_op"
        assert len(pat.clauses) == 2
        assert isinstance(pat.clauses[0], PatternClauseMatch)
        assert isinstance(pat.clauses[0].pattern, TokenPattern)
        assert isinstance(pat.clauses[1], PatternClauseWhere)

    def test_token_pattern_constraints(self):
        prog = parse(PATTERN_CASL)
        pat = prog.items[0].patterns[0]
        tp = pat.clauses[0].pattern
        assert isinstance(tp, TokenPattern)
        assert "str" in tp.constraints
        assert "isOp" in tp.constraints


class TestParseQuery:

    def test_query_declaration(self):
        prog = parse(QUERY_CASL)
        ch = prog.items[0]
        assert len(ch.queries) == 1
        q = ch.queries[0]
        assert q.name == "find_stuff"
        assert isinstance(q.return_type, (TypeName, TypeGeneric))


class TestParseSuppress:

    def test_suppress_with_glob(self):
        prog = parse(SUPPRESS_CASL)
        ch = prog.items[0]
        assert len(ch.suppressions) == 1
        s = ch.suppressions[0]
        assert s.error_id == "suppErr"
        assert s.file_glob == "test/*.c"


class TestParseDocstring:

    def test_docstring_on_checker(self):
        prog = parse(DOCSTRING_CASL)
        ch = prog.items[0]
        assert ch.docstring == "A documented checker"


class TestParseStatements:

    def test_if_elif_else(self):
        prog = parse(IF_ELIF_ELSE_CASL)
        fn = prog.items[0]
        stmt = fn.body[0]
        assert isinstance(stmt, IfStmt)
        assert len(stmt.elif_clauses) == 1
        assert stmt.else_body is not None

    def test_for_loop(self):
        prog = parse(FOR_LOOP_CASL)
        fn = prog.items[0]
        stmt = fn.body[0]
        assert isinstance(stmt, ForStmt)
        assert stmt.var == "item"

    def test_while_loop(self):
        prog = parse(WHILE_LOOP_CASL)
        fn = prog.items[0]
        # let mut i = 0; while ... ; return i;
        assert any(isinstance(s, WhileStmt) for s in fn.body)


class TestParseExpressions:

    def test_binary_precedence(self):
        prog = parse(BINARY_EXPR_CASL)
        fn = prog.items[0]
        let = fn.body[0]
        assert isinstance(let, LetStmt)
        assert isinstance(let.value, BinaryExpr)
        assert let.value.op == BinOp.ADD

    def test_ternary(self):
        prog = parse(TERNARY_CASL)
        fn = prog.items[0]
        let = fn.body[0]
        assert isinstance(let.value, TernaryExpr)

    def test_call_expr(self):
        prog = parse('fn test() { let x = foo(1, 2); }')
        fn = prog.items[0]
        let = fn.body[0]
        assert isinstance(let.value, CallExpr)

    def test_member_access(self):
        prog = parse('fn test() { let x = obj.field; }')
        fn = prog.items[0]
        let = fn.body[0]
        assert isinstance(let.value, MemberExpr)

    def test_index_access(self):
        prog = parse('fn test() { let x = arr[0]; }')
        fn = prog.items[0]
        let = fn.body[0]
        assert isinstance(let.value, IndexExpr)

    def test_unary_not(self):
        prog = parse('fn test() { let x = !y; }')
        fn = prog.items[0]
        let = fn.body[0]
        assert isinstance(let.value, UnaryExpr)
        assert let.value.op == UnaryOp.NOT

    def test_nested_member_and_call(self):
        prog = parse('fn test() { let x = a.b.c; }')
        fn = prog.items[0]
        let = fn.body[0]
        # a.b.c → MemberExpr(MemberExpr(a, b), c)
        assert isinstance(let.value, MemberExpr)


class TestParseErrors:

    def test_unterminated_string(self):
        with pytest.raises(CASLParseError):
            parse('const x = "unterminated;')

    def test_missing_semicolon(self):
        with pytest.raises(CASLParseError):
            parse("const x = 1")

    def test_invalid_checker_syntax(self):
        with pytest.raises(CASLParseError):
            parse("checker { broken }")

    def test_error_has_location(self):
        try:
            parse("const x = ;")
            assert False, "Should have raised"
        except CASLParseError as e:
            assert "1" in str(e.line) or e.line >= 1


class TestParseLocations:

    def test_loc_on_program(self):
        prog = parse("const x = 1;")
        assert prog.loc.line >= 1

    def test_loc_on_const(self):
        prog = parse("const x = 1;")
        c = prog.items[0]
        assert c.loc.line == 1
