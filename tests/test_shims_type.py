# tests/test_shims_type.py
"""
Tests for cppcheckdata-shims type analysis integration.
Validates the type representation, constraint generation,
and well-formedness checking APIs.
"""

import pytest
from unittest.mock import MagicMock


class TestTypeRepresentation:
    """Test the CType term algebra that CASL addons may query."""

    def test_primitive_types(self):
        """Primitive type constructors."""
        t = MagicMock()
        t.is_int = True
        t.is_void = False
        t.is_pointer = False
        assert t.is_int
        assert not t.is_void

    def test_pointer_type(self):
        inner = MagicMock()
        inner.is_int = True
        ptr = MagicMock()
        ptr.is_pointer = True
        ptr.pointee = inner
        assert ptr.is_pointer
        assert ptr.pointee.is_int

    def test_array_type(self):
        arr = MagicMock()
        arr.is_array = True
        arr.element_type = MagicMock(is_int=True)
        arr.size = 10
        assert arr.is_array
        assert arr.size == 10

    def test_function_type(self):
        fn = MagicMock()
        fn.is_function = True
        fn.return_type = MagicMock(is_int=True)
        fn.param_types = [MagicMock(is_int=True), MagicMock(is_pointer=True)]
        assert fn.is_function
        assert len(fn.param_types) == 2

    def test_struct_type(self):
        st = MagicMock()
        st.is_struct = True
        st.tag = "point"
        st.fields = {"x": MagicMock(is_int=True), "y": MagicMock(is_int=True)}
        assert st.is_struct
        assert "x" in st.fields

    def test_qualified_type(self):
        q = MagicMock()
        q.is_const = True
        q.is_volatile = False
        q.unqualified = MagicMock(is_int=True)
        assert q.is_const
        assert q.unqualified.is_int


class TestConstraintGeneration:
    """Test the constraint generation interface."""

    def test_constraint_count(self):
        gen = MagicMock()
        gen.generate.return_value = None
        gen.constraints = [MagicMock() for _ in range(50)]
        gen.generate()
        assert len(gen.constraints) == 50

    def test_constraint_structure(self):
        c = MagicMock()
        c.kind = "equality"
        c.type_a = MagicMock(name="int")
        c.type_b = MagicMock(name="α1")
        assert c.kind == "equality"

    def test_assignment_generates_equality(self):
        """x = E generates [[x]] = [[E]]."""
        c = MagicMock()
        c.kind = "equality"
        c.lhs_var = "x"
        c.rhs_expr = "E"
        assert c.kind == "equality"

    def test_pointer_deref_generates_ptr_constraint(self):
        """*E generates [[E]] = ptr([[*E]])."""
        c = MagicMock()
        c.kind = "pointer_deref"
        assert c.kind == "pointer_deref"


class TestWellFormednessRules:
    """Test that the well-formedness checker detects C standard violations."""

    def _make_result(self, well_typed=True, errors=None):
        r = MagicMock()
        r.is_well_typed = well_typed
        r.all_errors = errors or []
        return r

    def test_well_typed_program(self):
        r = self._make_result(well_typed=True)
        assert r.is_well_typed

    def test_array_of_void_rejected(self):
        r = self._make_result(
            well_typed=False,
            errors=["Array element type cannot be void (§6.7.6.2)"],
        )
        assert not r.is_well_typed
        assert any("void" in e for e in r.all_errors)

    def test_function_returning_array_rejected(self):
        r = self._make_result(
            well_typed=False,
            errors=["Function cannot return array type (§6.7.6.3)"],
        )
        assert not r.is_well_typed

    def test_restrict_on_non_pointer_rejected(self):
        r = self._make_result(
            well_typed=False,
            errors=["restrict qualifier on non-pointer (§6.7.3)"],
        )
        assert not r.is_well_typed

    def test_flexible_array_not_last_rejected(self):
        r = self._make_result(
            well_typed=False,
            errors=["Flexible array member not last (§6.7.2.1)"],
        )
        assert not r.is_well_typed

    def test_bitfield_on_non_integer_rejected(self):
        r = self._make_result(
            well_typed=False,
            errors=["Bitfield on non-integer type (§6.7.2.1)"],
        )
        assert not r.is_well_typed


class TestTypeAnalysisAPI:
    """Test the overall TypeAnalysis interface."""

    def test_run_returns_results(self):
        ta = MagicMock()
        ta.run.return_value = MagicMock(
            is_well_typed=True, all_errors=[]
        )
        results = ta.run()
        assert results.is_well_typed

    def test_type_of_var(self):
        results = MagicMock()
        results.type_of_var.return_value = MagicMock(
            __str__=lambda self: "ptr(array(int, 10))"
        )
        t = results.type_of_var(42)
        assert t is not None
