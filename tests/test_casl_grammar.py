# tests/test_grammar.py
"""
Tests that the CASL PEG grammar is well-formed and parses fundamental
constructs at the grammar level (before visitor transformation).
"""

import pytest
from parsimonious.grammar import Grammar
from parsimonious.exceptions import ParseError, IncompleteParseError

from casl.grammar import CASL_GRAMMAR


@pytest.fixture(scope="module")
def grammar():
    """Compile the grammar once per module."""
    return Grammar(CASL_GRAMMAR)


class TestGrammarWellFormed:
    """The grammar string itself must compile without errors."""

    def test_grammar_compiles(self, grammar):
        assert grammar is not None
        assert "program" in grammar

    def test_all_rules_reachable(self, grammar):
        # Parsimonious lazily resolves; ensure key rules exist
        for rule in ("program", "checker_decl", "fn_decl", "expr",
                     "stmt", "pattern_decl", "on_block", "import_stmt",
                     "const_decl", "type_alias"):
            assert rule in grammar, f"Rule {rule!r} missing"


class TestGrammarParseAtoms:
    """Test that atomic constructs parse at the grammar level."""

    def test_empty_input(self, grammar):
        tree = grammar.parse("")
        assert tree is not None

    def test_integer_literals(self, grammar):
        for lit in ("0", "42", "0xFF", "0b1010", "0o77"):
            tree = grammar["integer"].parse(lit)
            assert tree.text == lit

    def test_string_literals(self, grammar):
        for lit in ('"hello"', "'world'", r'"escaped\"quote"'):
            tree = grammar["string_literal"].parse(lit)
            assert tree is not None

    def test_bool_literals(self, grammar):
        grammar["bool_lit"].parse("true")
        grammar["bool_lit"].parse("false")

    def test_null_literal(self, grammar):
        grammar["null_lit"].parse("null")

    def test_identifier_simple(self, grammar):
        for name in ("x", "foo_bar", "_priv", "camelCase", "ALL_CAPS"):
            tree = grammar["identifier"].parse(name)
            assert tree.text == name

    def test_identifier_rejects_keywords(self, grammar):
        for kw in ("if", "else", "for", "while", "return", "let", "fn",
                    "checker", "addon", "import", "true", "false", "null"):
            with pytest.raises((ParseError, IncompleteParseError)):
                grammar["identifier"].parse(kw)

    def test_float_literal(self, grammar):
        for lit in ("3.14", "0.5", "1.0e10", "2.5E-3"):
            tree = grammar["float_lit"].parse(lit)
            assert tree is not None


class TestGrammarStatements:

    def test_let_statement(self, grammar):
        grammar["let_stmt"].parse("let x = 42;")

    def test_let_mut(self, grammar):
        grammar["let_stmt"].parse("let mut count = 0;")

    def test_return_with_value(self, grammar):
        grammar["return_stmt"].parse("return x;")

    def test_return_bare(self, grammar):
        grammar["return_stmt"].parse("return;")

    def test_break_continue(self, grammar):
        grammar["break_stmt"].parse("break;")
        grammar["continue_stmt"].parse("continue;")

    def test_emit_stmt(self, grammar):
        grammar["emit_stmt"].parse('emit myErr("message", file, 1, 0);')

    def test_for_stmt(self, grammar):
        grammar["for_stmt"].parse("for x in items { let y = x; }")

    def test_while_stmt(self, grammar):
        grammar["while_stmt"].parse("while x > 0 { x = x - 1; }")


class TestGrammarDeclarations:

    def test_const_decl(self, grammar):
        grammar["const_decl"].parse("const MAX = 100;")

    def test_fn_decl_empty(self, grammar):
        grammar["fn_decl"].parse("fn noop() { }")

    def test_fn_decl_params(self, grammar):
        grammar["fn_decl"].parse("fn add(a, b) { return a; }")

    def test_import_simple(self, grammar):
        grammar["import_stmt"].parse("import foo;")

    def test_import_dotted(self, grammar):
        grammar["import_stmt"].parse("import foo.bar.baz;")

    def test_addon_decl(self, grammar):
        grammar["addon_decl"].parse(
            'addon MyAddon "desc" { severity = "error"; }'
        )

    def test_checker_decl_minimal(self, grammar):
        grammar["checker_decl"].parse(
            'checker foo { error_id = "fooErr"; severity = error; '
            'on token { let x = 1; } }'
        )


class TestGrammarExpressions:

    def test_binary_add(self, grammar):
        grammar["expr"].parse("a + b")

    def test_binary_precedence(self, grammar):
        grammar["expr"].parse("a + b * c")

    def test_comparison(self, grammar):
        grammar["expr"].parse("x > 0")

    def test_logical(self, grammar):
        grammar["expr"].parse("a && b || c")

    def test_ternary(self, grammar):
        grammar["expr"].parse("x ? a : b")

    def test_call_expr(self, grammar):
        grammar["expr"].parse("foo(1, 2)")

    def test_member_access(self, grammar):
        grammar["expr"].parse("obj.field")

    def test_index_access(self, grammar):
        grammar["expr"].parse("arr[0]")

    def test_list_literal(self, grammar):
        grammar["expr"].parse("[1, 2, 3]")

    def test_unary_not(self, grammar):
        grammar["expr"].parse("!x")

    def test_unary_neg(self, grammar):
        grammar["expr"].parse("-x")

    def test_grouped(self, grammar):
        grammar["expr"].parse("(a + b)")


class TestGrammarComments:

    def test_line_comment(self, grammar):
        grammar.parse("// a comment\n")

    def test_block_comment(self, grammar):
        grammar.parse("/* block */")

    def test_comment_in_fn(self, grammar):
        grammar.parse("""
            fn foo() {
                // comment
                let x = 1; /* inline */
            }
        """)


class TestGrammarPatterns:

    def test_token_pattern(self, grammar):
        grammar["token_pattern"].parse('token(str = "+", isOp = true)')

    def test_scope_pattern(self, grammar):
        grammar["scope_pattern"].parse("scope(functionScope)")

    def test_deref_pattern(self, grammar):
        grammar["deref_pattern"].parse("deref(token())")

    def test_wildcard(self, grammar):
        grammar["wildcard_pattern"].parse("_")
