"""
casl/csql_compiler.py - Compiles CSQL queries to executable Python code.

This module implements the CSQL-to-Python compiler, which transforms CSQL query
AST nodes into executable Python code that can run against cppcheckdata entities
(Token, Scope, Function, Variable).

Design follows patterns from:
- PQL paper (state machines, bindings, unification) [sca-pql-prog-query-lang.pdf p6]
- cppcheckdata-shims (AbsExecEvent, EventMatch) [cppcheckdata-shims-source-code.md:3187-3195]

The generated Python code:
1. Iterates over entities from CppcheckData
2. Evaluates predicates against entity attributes
3. Manages variable bindings during matching
4. Yields QueryMatch results with bindings and source locations
"""

from __future__ import annotations

import re
import textwrap
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

if TYPE_CHECKING:
    from .semantic import SymbolTable

# =============================================================================
# AST Node Types (mirrors casl/parser.py structure from conversation summary)
# =============================================================================
# These are forward declarations / type stubs for the AST nodes that parser.py
# produces. The actual classes are defined in casl/ast.py or casl/parser.py.


class CsqlNode(ABC):
    """Base class for all CSQL AST nodes."""
    pass


@dataclass
class CsqlQuery(CsqlNode):
    """Top-level CSQL query: (query <name> <source> <predicate>)"""
    name: str
    source: str  # Entity type: "token", "function", "variable", "scope"
    predicate: CsqlPredicate
    location: Optional[Tuple[int, int]] = None


@dataclass
class CsqlPredicate(CsqlNode, ABC):
    """Base class for CSQL predicates."""
    pass


@dataclass
class CsqlAnd(CsqlPredicate):
    """Conjunction: (and <pred1> <pred2> ...)"""
    children: List[CsqlPredicate]


@dataclass
class CsqlOr(CsqlPredicate):
    """Disjunction: (or <pred1> <pred2> ...)"""
    children: List[CsqlPredicate]


@dataclass
class CsqlNot(CsqlPredicate):
    """Negation: (not <pred>)"""
    child: CsqlPredicate


@dataclass
class CsqlHasAttr(CsqlPredicate):
    """Attribute existence check: (has-attr <attr-name>)"""
    attr_name: str


@dataclass
class CsqlAttrEq(CsqlPredicate):
    """Attribute equality: (attr-eq <attr-name> <value>)"""
    attr_name: str
    value: Any


@dataclass
class CsqlAttrMatch(CsqlPredicate):
    """Attribute regex match: (attr-match <attr-name> <pattern>)"""
    attr_name: str
    pattern: str


@dataclass
class CsqlAttrIn(CsqlPredicate):
    """Attribute set membership: (attr-in <attr-name> <value1> <value2> ...)"""
    attr_name: str
    values: List[Any]


@dataclass
class CsqlAttrCmp(CsqlPredicate):
    """Attribute comparison: (attr-cmp <attr-name> <op> <value>)"""
    attr_name: str
    op: str  # "<", "<=", ">", ">=", "==", "!="
    value: Any


@dataclass
class CsqlBind(CsqlPredicate):
    """Variable binding: (bind <var-name> <attr-name>)"""
    var_name: str
    attr_name: str


@dataclass
class CsqlRef(CsqlPredicate):
    """Variable reference equality: (ref <var-name> <attr-name>)"""
    var_name: str
    attr_name: str


@dataclass
class CsqlExists(CsqlPredicate):
    """Existential subquery: (exists <source> <predicate>)"""
    source: str
    predicate: CsqlPredicate


@dataclass
class CsqlForall(CsqlPredicate):
    """Universal subquery: (forall <source> <predicate>)"""
    source: str
    predicate: CsqlPredicate


@dataclass
class CsqlFollows(CsqlPredicate):
    """Sequence constraint: (follows <pred1> <pred2>)"""
    first: CsqlPredicate
    second: CsqlPredicate


@dataclass
class CsqlTrue(CsqlPredicate):
    """Always true predicate: (true)"""
    pass


@dataclass
class CsqlFalse(CsqlPredicate):
    """Always false predicate: (false)"""
    pass


# =============================================================================
# Query Result Types
# =============================================================================


@dataclass
class QueryMatch:
    """
    Represents a single query match result.
    
    Following the EventMatch pattern from cppcheckdata-shims [3141-3196]:
    - bindings: Variable name → matched value
    - entity: The matched cppcheckdata entity
    - location: Source location (file, line, column)
    - confidence: Match confidence score (1.0 for exact matches)
    - metadata: Additional match information
    """
    entity: Any
    bindings: Dict[str, Any] = field(default_factory=dict)
    location: Optional[Tuple[str, int, int]] = None  # (file, line, column)
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CompiledQuery:
    """
    A compiled CSQL query ready for execution.
    
    Contains:
    - name: Query identifier
    - source_code: Generated Python source code
    - executor: Compiled Python function
    - source_type: Entity type being queried
    """
    name: str
    source_code: str
    executor: Callable[[Any], Iterator[QueryMatch]]
    source_type: str


# =============================================================================
# Entity Schema - Attribute Definitions from cppcheckdata.py
# =============================================================================
# These schemas define valid attributes for each entity type, enabling
# compile-time validation of attribute references in predicates.
# Source: cppcheckdata.py [223-282, 548-625, 627-700, 705-794]


class EntitySchema:
    """
    Schema definitions for cppcheckdata entities.
    
    Defines valid attributes and their types for compile-time checking.
    """
    
    # Token attributes [cppcheckdata.py:223-282]
    TOKEN_ATTRS: Dict[str, type] = {
        # Lexical
        'str': str,
        'type': str,  # "name", "op", "number", "string"
        'isName': bool,
        'isNumber': bool,
        'isString': bool,
        'isOp': bool,
        'isInt': bool,
        'isFloat': bool,
        'isBoolean': bool,
        'isLong': bool,
        'isUnsigned': bool,
        'isSigned': bool,
        'isExpandedMacro': bool,
        'isSplittedVarDeclComma': bool,
        'isSplittedVarDeclEq': bool,
        'isImplicitInt': bool,
        'isComplex': bool,
        'isTemplateArg': bool,
        'isRemovedVoidParameter': bool,
        'isAttributeExport': bool,
        # Links
        'next': object,
        'previous': object,
        'link': object,
        'scope': object,  # Scope
        'variable': object,  # Variable
        'function': object,  # Function
        # IDs
        'varId': int,
        'exprId': int,
        'Id': str,
        # AST links
        'astParent': object,
        'astOperand1': object,
        'astOperand2': object,
        # Type info
        'valueType': object,
        'typeScope': object,
        'values': object,
        # Location
        'file': str,
        'linenr': int,
        'column': int,
    }
    
    # Scope attributes [cppcheckdata.py:548-625]
    SCOPE_ATTRS: Dict[str, type] = {
        'Id': str,
        'bodyStart': object,  # Token
        'bodyEnd': object,  # Token
        'className': str,
        'function': object,  # Function
        'functions': list,  # List[Function]
        'nestedIn': object,  # Scope
        'nestedList': list,  # List[Scope]
        'type': str,  # Function/If/Else/For/While/Switch/Global/Enum/Struct/Namespace/Class/Constructor/Destructor
        'isExecutable': bool,
        'definedType': str,
        'varlist': list,  # List[Variable]
    }
    
    # Function attributes [cppcheckdata.py:627-700]
    FUNCTION_ATTRS: Dict[str, type] = {
        'Id': str,
        'argument': dict,  # Dict[int, Variable]
        'token': object,  # Token (implementation)
        'tokenDef': object,  # Token (definition)
        'name': str,
        'type': str,  # Constructor/Destructor/Function/Lambda/CopyConstructor/MoveConstructor/OperatorEqual
        'hasVirtualSpecifier': bool,
        'isImplicitlyVirtual': bool,
        'access': str,  # Public/Protected/Private
        'isInlineKeyword': bool,
        'isStatic': bool,
        'isAttributeNoreturn': bool,
        'overriddenFunction': object,  # Function
        'nestedIn': object,  # Scope
    }
    
    # Variable attributes [cppcheckdata.py:705-794]
    VARIABLE_ATTRS: Dict[str, type] = {
        'Id': str,
        'nameToken': object,  # Token
        'typeStartToken': object,  # Token
        'typeEndToken': object,  # Token
        'access': str,  # Global/Local/Namespace/Public/Protected/Private/Argument/Unknown
        'scope': object,  # Scope
        'constness': int,
        'isArgument': bool,
        'isGlobal': bool,
        'isLocal': bool,
        'isArray': bool,
        'isClass': bool,
        'isConst': bool,
        'isExtern': bool,
        'isPointer': bool,
        'isReference': bool,
        'isStatic': bool,
        'isVolatile': bool,
    }
    
    @classmethod
    def get_schema(cls, source_type: str) -> Dict[str, type]:
        """Get attribute schema for an entity type."""
        schemas = {
            'token': cls.TOKEN_ATTRS,
            'scope': cls.SCOPE_ATTRS,
            'function': cls.FUNCTION_ATTRS,
            'variable': cls.VARIABLE_ATTRS,
        }
        return schemas.get(source_type.lower(), {})
    
    @classmethod
    def validate_attr(cls, source_type: str, attr_name: str) -> bool:
        """Check if an attribute is valid for an entity type."""
        schema = cls.get_schema(source_type)
        return attr_name in schema


# =============================================================================
# Code Generation Helpers
# =============================================================================


class CodeBuilder:
    """
    Helper for building Python source code with proper indentation.
    
    Following the emission pattern from cppcheckdata-shims compile_cfg()
    [cppcheckdata-shims-source-code.md:9890-10015], but targeting Python
    source code instead of bytecode.
    """
    
    def __init__(self, indent_size: int = 4):
        self._lines: List[str] = []
        self._indent_level: int = 0
        self._indent_size: int = indent_size
    
    @property
    def indent(self) -> str:
        """Current indentation string."""
        return ' ' * (self._indent_level * self._indent_size)
    
    def line(self, code: str = '') -> 'CodeBuilder':
        """Add a line of code at current indentation."""
        if code:
            self._lines.append(f'{self.indent}{code}')
        else:
            self._lines.append('')
        return self
    
    def lines(self, *codes: str) -> 'CodeBuilder':
        """Add multiple lines of code."""
        for code in codes:
            self.line(code)
        return self
    
    def block(self, header: str) -> 'CodeBuilder':
        """Start a new block (if/for/def/etc.) with header."""
        self.line(header)
        self._indent_level += 1
        return self
    
    def end_block(self) -> 'CodeBuilder':
        """End the current block."""
        self._indent_level = max(0, self._indent_level - 1)
        return self
    
    def blank(self) -> 'CodeBuilder':
        """Add a blank line."""
        self._lines.append('')
        return self
    
    def comment(self, text: str) -> 'CodeBuilder':
        """Add a comment."""
        self.line(f'# {text}')
        return self
    
    def docstring(self, text: str) -> 'CodeBuilder':
        """Add a docstring."""
        self.line(f'"""{text}"""')
        return self
    
    def raw(self, code: str) -> 'CodeBuilder':
        """Add raw code without indentation processing."""
        self._lines.append(code)
        return self
   
   def build(self) -> str:
        """Build the final source code string."""
        parts = []
        
        # Module docstring if first line is a docstring
        # (handled by user adding it explicitly)
        
        # Imports section
        import_lines = self._build_imports()
        if import_lines:
            parts.extend(import_lines)
            parts.append("")
            parts.append("")
        
        # Main code
        parts.extend(self._lines)
        
        # Ensure trailing newline
        result = "\n".join(parts)
        if not result.endswith("\n"):
            result += "\n"
        
        return result


# =============================================================================
# Entity Schema (extracted from cppcheckdata.py)
# =============================================================================

class EntitySchema:
    """
    Schema information for cppcheckdata entities.
    
    Based on cppcheckdata.py class definitions:
    - Token (lines 223-282): lexical/semantic token info
    - Scope (lines 548-625): function/class scopes
    - Function (lines 627-700): function definitions
    - Variable (lines 705-794): variable declarations
    
    Reference: cppcheckdata.py entity classes
    """
    
    SCHEMAS: Dict[str, Dict[str, str]] = {
        "Token": {
            # Core identification
            "Id": "str",
            "str": "str",
            
            # Location info
            "file": "str",
            "linenr": "int",
            "column": "int",
            
            # Token classification
            "isName": "bool",
            "isNumber": "bool",
            "isInt": "bool",
            "isFloat": "bool",
            "isString": "bool",
            "isChar": "bool",
            "isOp": "bool",
            "isArithmeticalOp": "bool",
            "isComparisonOp": "bool",
            "isAssignmentOp": "bool",
            "isLogicalOp": "bool",
            "isCast": "bool",
            "isExpandedMacro": "bool",
            "isSplittedVarDeclComma": "bool",
            "isSplittedVarDeclEq": "bool",
            "isImplicitInt": "bool",
            "isComplex": "bool",
            "isTemplateArg": "bool",
            "isRemovedVoidParameter": "bool",
            
            # Semantic links (optional, may be None)
            "scope": "Optional[Scope]",
            "function": "Optional[Function]",
            "variable": "Optional[Variable]",
            "type": "Optional[Type]",
            "astParent": "Optional[Token]",
            "astOperand1": "Optional[Token]",
            "astOperand2": "Optional[Token]",
            "link": "Optional[Token]",
            "previous": "Optional[Token]",
            "next": "Optional[Token]",
            
            # Value tracking
            "values": "Optional[List[ValueFlow.Value]]",
            "valueType": "Optional[ValueType]",
            "typeScope": "Optional[Scope]",
        },
        
        "Scope": {
            "Id": "str",
            "type": "str",  # "Global", "Function", "Class", "Namespace", etc.
            "className": "str",
            "bodyStart": "Optional[Token]",
            "bodyEnd": "Optional[Token]",
            "nestedIn": "Optional[Scope]",
            "function": "Optional[Function]",
            "functionList": "List[Function]",
            "varlist": "List[Variable]",
            
            # Execution flags
            "isExecutable": "bool",
        },
        
        "Function": {
            "Id": "str",
            "name": "str",
            "tokenDef": "Optional[Token]",
            "token": "Optional[Token]",
            "argument": "Dict[int, Variable]",  # 1-indexed argument map
            "argumentId": "Dict[int, str]",
            
            # Type info
            "retType": "str",
            "retDef": "Optional[Token]",
            
            # Modifiers
            "isVirtual": "bool",
            "isPure": "bool",
            "isConst": "bool",
            "isStatic": "bool",
            "isStaticLocal": "bool",
            "isExtern": "bool",
            "isExplicit": "bool",
            "isDefault": "bool",
            "isDelete": "bool",
            "isNoExcept": "bool",
            "isThrow": "bool",
            "isOperator": "bool",
            "isVariadic": "bool",
            "isVolatile": "bool",
            "hasVirtualSpecifier": "bool",
            "isFinal": "bool",
            "isOverride": "bool",
            "isInline": "bool",
            "isInlineKeyword": "bool",
            "hasTrailingReturnType": "bool",
            "nestedIn": "Optional[Scope]",
        },
        
        "Variable": {
            "Id": "str",
            "nameToken": "Optional[Token]",
            "typeStartToken": "Optional[Token]",
            "typeEndToken": "Optional[Token]",
            "access": "str",  # "Public", "Protected", "Private", "Global", "Local", "Argument"
            
            # Flags
            "isArgument": "bool",
            "isArray": "bool",
            "isClass": "bool",
            "isConst": "bool",
            "isExtern": "bool",
            "isGlobal": "bool",
            "isLocal": "bool",
            "isMutable": "bool",
            "isPointer": "bool",
            "isReference": "bool",
            "isStatic": "bool",
            "isVolatile": "bool",
            
            "constness": "int",  # bitfield for nested const levels
            "dimensions": "List[Dimension]",
        },
        
        "Configuration": {
            "name": "str",
            "tokenlist": "List[Token]",
            "scopes": "List[Scope]",
            "functions": "List[Function]",
            "variables": "List[Variable]",
            "valueflows": "List[ValueFlow]",
            "standards": "Standards",
        },
        
        "CppcheckData": {
            "filename": "str",
            "configurations": "List[Configuration]",
        },
    }
    
    # Collection accessor mapping: entity -> (container, path from CppcheckData)
    ENTITY_SOURCES: Dict[str, Tuple[str, str]] = {
        "Token": ("Configuration", "tokenlist"),
        "Scope": ("Configuration", "scopes"),
        "Function": ("Configuration", "functions"),
        "Variable": ("Configuration", "variables"),
    }
    
    @classmethod
    def get_attrs(cls, entity: str) -> Dict[str, str]:
        """Get attribute schema for an entity type."""
        return cls.SCHEMAS.get(entity, {})
    
    @classmethod
    def has_attr(cls, entity: str, attr: str) -> bool:
        """Check if entity type has a given attribute."""
        return attr in cls.SCHEMAS.get(entity, {})
    
    @classmethod
    def get_attr_type(cls, entity: str, attr: str) -> Optional[str]:
        """Get the type of an attribute."""
        return cls.SCHEMAS.get(entity, {}).get(attr)
    
    @classmethod
    def is_optional(cls, entity: str, attr: str) -> bool:
        """Check if an attribute is optional (may be None)."""
        attr_type = cls.get_attr_type(entity, attr)
        if attr_type is None:
            return True
        return attr_type.startswith("Optional[")
    
    @classmethod
    def get_source_path(cls, entity: str) -> Optional[Tuple[str, str]]:
        """Get the collection source for an entity type."""
        return cls.ENTITY_SOURCES.get(entity)


# =============================================================================
# Built-in Predicate Functions
# =============================================================================

class BuiltinPredicates:
    """
    Registry of built-in predicate functions for CSQL.
    
    These predicates are compiled to inline Python expressions or
    helper function calls in the generated code.
    """
    
    # Predicate signature: (arg_types, return_type, python_expr_template)
    PREDICATES: Dict[str, Tuple[Tuple[str, ...], str, str]] = {
        # Token predicates
        "isPointer": (("Token",), "bool", "({0}.valueType and {0}.valueType.pointer > 0)"),
        "isReference": (("Token",), "bool", "({0}.valueType and {0}.valueType.reference)"),
        "isConst": (("Token",), "bool", "({0}.valueType and {0}.valueType.constness > 0)"),
        "isIntegral": (("Token",), "bool", "({0}.valueType and {0}.valueType.isIntegral())"),
        "isFloat": (("Token",), "bool", "({0}.valueType and {0}.valueType.isFloat())"),
        "isSigned": (("Token",), "bool", "({0}.valueType and {0}.valueType.sign == 'signed')"),
        "isUnsigned": (("Token",), "bool", "({0}.valueType and {0}.valueType.sign == 'unsigned')"),
        "isArithmetic": (("Token",), "bool", "({0}.isArithmeticalOp)"),
        "isComparison": (("Token",), "bool", "({0}.isComparisonOp)"),
        "isAssignment": (("Token",), "bool", "({0}.isAssignmentOp)"),
        "isLogical": (("Token",), "bool", "({0}.isLogicalOp)"),
        
        # Variable predicates  
        "isLocalVar": (("Variable",), "bool", "({0}.isLocal)"),
        "isGlobalVar": (("Variable",), "bool", "({0}.isGlobal)"),
        "isArgVar": (("Variable",), "bool", "({0}.isArgument)"),
        "isPointerVar": (("Variable",), "bool", "({0}.isPointer)"),
        "isArrayVar": (("Variable",), "bool", "({0}.isArray)"),
        "isConstVar": (("Variable",), "bool", "({0}.isConst)"),
        "isStaticVar": (("Variable",), "bool", "({0}.isStatic)"),
        
        # Function predicates
        "isVirtualFunc": (("Function",), "bool", "({0}.isVirtual)"),
        "isStaticFunc": (("Function",), "bool", "({0}.isStatic)"),
        "isConstFunc": (("Function",), "bool", "({0}.isConst)"),
        "isInlineFunc": (("Function",), "bool", "({0}.isInline)"),
        "isVariadicFunc": (("Function",), "bool", "({0}.isVariadic)"),
        "hasArgs": (("Function",), "bool", "(len({0}.argument) > 0)"),
        "argCount": (("Function",), "int", "(len({0}.argument))"),
        
        # Scope predicates
        "isGlobalScope": (("Scope",), "bool", "({0}.type == 'Global')"),
        "isFunctionScope": (("Scope",), "bool", "({0}.type == 'Function')"),
        "isClassScope": (("Scope",), "bool", "({0}.type == 'Class')"),
        "isNamespaceScope": (("Scope",), "bool", "({0}.type == 'Namespace')"),
        
        # Value flow predicates
        "hasKnownValue": (("Token",), "bool", "({0}.values and any(v.valueKind == 'known' for v in {0}.values))"),
        "hasPossibleValue": (("Token",), "bool", "({0}.values and any(v.valueKind == 'possible' for v in {0}.values))"),
        "mayBeNull": (("Token",), "bool", "({0}.values and any(v.isNull() for v in {0}.values))"),
        "isDefinitelyNull": (("Token",), "bool", "({0}.values and all(v.isNull() for v in {0}.values if v.valueKind == 'known'))"),
        
        # String helpers
        "startsWith": (("str", "str"), "bool", "({0}.startswith({1}))"),
        "endsWith": (("str", "str"), "bool", "({0}.endswith({1}))"),
        "contains": (("str", "str"), "bool", "({1} in {0})"),
        "matches": (("str", "str"), "bool", "(re.match({1}, {0}) is not None)"),
    }
    
    @classmethod
    def get(cls, name: str) -> Optional[Tuple[Tuple[str, ...], str, str]]:
        """Get predicate info by name."""
        return cls.PREDICATES.get(name)
    
    @classmethod
    def exists(cls, name: str) -> bool:
        """Check if a builtin predicate exists."""
        return name in cls.PREDICATES
    
    @classmethod
    def compile_call(cls, name: str, args: List[str]) -> str:
        """Compile a predicate call to Python expression."""
        info = cls.PREDICATES.get(name)
        if info is None:
            raise ValueError(f"Unknown builtin predicate: {name}")
        
        _, _, template = info
        return template.format(*args)


# =============================================================================
# CSQL Code Generator (Visitor Implementation)
# =============================================================================

class CSQLCodeGenerator(CsqlVisitor):
    """
    Visitor that generates Python code from CSQL AST.
    
    The generated code follows patterns from cppcheckdata-shims:
    - Generator-based iteration for memory efficiency
    - QueryMatch result objects with bindings
    - Integration hooks for EventSequenceMatcher
    
    Reference: cppcheckdata-shims-source-code.md lines 4072-4084 (EventSequenceMatcher),
               lines 3398-3426 (EventMatch/bindings pattern)
    """
    
    def __init__(self, query_name: Optional[str] = None):
        self.query_name = query_name
        self._var_counter = 0
        self._subquery_counter = 0
        self._temp_vars: List[str] = []
        self._context_stack: List[str] = []  # current binding context
        self._needs_re = False
    
    def _fresh_var(self, prefix: str = "_v") -> str:
        """Generate a fresh variable name."""
        self._var_counter += 1
        name = f"{prefix}{self._var_counter}"
        self._temp_vars.append(name)
        return name
    
        Returns executable Python source -> str:
        """Generate a fresh subquery function name."""
        self._subquery_counter += 1
        return f"_subquery_{self._subquery_counter}"
    
    def generate(self, query: CsqlQuery) -> str:
        """
        Generate complete Python module for a CSQL query.
        
        Returns executable Python source code that defines a query function.
        """
        builder = CodeBuilder()
        
        # Module docstring
        builder.line('"""')
        builder.line(f"Auto-generated CSQL query: {self.query_name or 'anonymous'}")
        builder.line("")
        builder.line("Generated by csql_compiler.py")
        builder.line('"""')
        builder.blank()
        
        # Imports
        builder.add_from_import("typing", "Any", "Dict", "Iterator", "List", "Optional", "Tuple")
        builder.add_from_import("dataclasses", "dataclass", "field")
        if self._needs_re:
            builder.add_import("re")
        
        # Generate QueryMatch class inline (or import from csql_runtime)
        self._emit_query_match_class(builder)
        
        # Generate the main query function
        self._emit_query_function(builder, query)
        
        # Generate convenience wrapper
        self._emit_convenience_wrapper(builder, query)
        
        return builder.build()
    
    def _emit_query_match_class(self, builder: CodeBuilder) -> None:
        """Emit QueryMatch dataclass definition."""
        builder.blank()
        builder.line("@dataclass")
        builder.block("class QueryMatch:")
        builder.docstring("Result of a single query match with bindings and projections.")
        builder.line("bindings: Dict[str, Any]")
        builder.line("projections: Dict[str, Any]")
        builder.line("source_loc: Optional[Tuple[str, int, int]] = None")
        builder.line("confidence: float = 1.0")
        builder.line("metadata: Dict[str, Any] = field(default_factory=dict)")
        builder.blank()
        builder.block("def __getitem__(self, key: str) -> Any:")
        builder.line("return self.projections[key]")
        builder.end_block()
        builder.blank()
        builder.block("def get(self, key: str, default: Any = None) -> Any:")
        builder.line("return self.projections.get(key, default)")
        builder.end_block()
        builder.end_block()
        builder.blank(2)
    
    def _emit_query_function(self, builder: CodeBuilder, query: CsqlQuery) -> None:
        """Emit the main query generator function."""
        func_name = self.query_name or "execute_query"
        entity = query.entity
        binding_var = query.binding_var
        
        # Function signature
        builder.block(f"def {func_name}_iter(data, config_name: Optional[str] = None) -> Iterator[QueryMatch]:")
        builder.docstring(f"Execute CSQL query over {entity} entities.\n\nYields QueryMatch for each matching {entity}.")
        builder.blank()
        
        # Get configurations to process
        builder.comment("Determine which configurations to process")
        builder.block("if hasattr(data, 'configurations'):")
        builder.block("if config_name:")
        builder.line("configs = [c for c in data.configurations if c.name == config_name]")
        builder.end_block()
        builder.block("else:")
        builder.line("configs = data.configurations")
        builder.end_block()
        builder.end_block()
        builder.block("else:")
        builder.comment("Assume data is already a configuration")
        builder.line("configs = [data]")
        builder.end_block()
        builder.blank()
        
        # Main iteration loop
        builder.block("for _cfg in configs:")
        
        # Get entity collection
        source_info = EntitySchema.get_source_path(entity)
        if source_info:
            _, collection_attr = source_info
            builder.line(f"_collection = getattr(_cfg, '{collection_attr}', [])")
        else:
            builder.comment(f"Unknown entity type: {entity}, assuming direct iteration")
            builder.line(f"_collection = _cfg")
        builder.blank()
        
        # Entity iteration
        builder.block(f"for {binding_var} in _collection:")
        
        # Generate predicate check
        if query.predicate is not None:
            self._context_stack.append(binding_var)
            predicate_code = query.predicate.accept(self)
            self._context_stack.pop()
            
            builder.comment("Apply WHERE predicate")
            builder.block(f"if not ({predicate_code}):")
            builder.line("continue")
            builder.end_block()
            builder.blank()
        
        # Generate projections
        builder.comment("Build projections")
        builder.line("_projections = {}")
        
        self._context_stack.append(binding_var)
        for proj in query.projections:
            alias = proj.alias or self._infer_projection_alias(proj.expr)
            expr_code = proj.expr.accept(self)
            builder.line(f"_projections[{repr(alias)}] = {expr_code}")
        self._context_stack.pop()
        builder.blank()
        
        # Generate source location
        builder.comment("Extract source location if available")
        builder.line(f"_loc = None")
        builder.block(f"if hasattr({binding_var}, 'file') and hasattr({binding_var}, 'linenr'):")
        builder.line(f"_loc = ({binding_var}.file, {binding_var}.linenr, getattr({binding_var}, 'column', 0))")
        builder.end_block()
        builder.block(f"elif hasattr({binding_var}, 'nameToken') and {binding_var}.nameToken:")
        builder.line(f"_t = {binding_var}.nameToken")
        builder.line(f"_loc = (_t.file, _t.linenr, getattr(_t, 'column', 0))")
        builder.end_block()
        builder.blank()
        
        # Yield match
        builder.comment("Yield match result")
        builder.block("yield QueryMatch(")
        builder.line(f"bindings={{'{binding_var}': {binding_var}}},")
        builder.line("projections=_projections,")
        builder.line("source_loc=_loc,")
        builder.line("confidence=1.0,")
        builder.line("metadata={'config': _cfg.name if hasattr(_cfg, 'name') else None},")
        builder.end_block().line(")")
        
        builder.end_block()  # for entity
        builder.end_block()  # for config
        builder.end_block()  # function
        builder.blank(2)
    
    def _emit_convenience_wrapper(self, builder: CodeBuilder, query: CsqlQuery) -> None:
        """Emit convenience function that returns a list."""
        func_name = self.query_name or "execute_query"
        
        builder.block(f"def {func_name}(data, config_name: Optional[str] = None, limit: Optional[int] = None) -> List[QueryMatch]:")
        builder.docstring(f"Execute CSQL query and return results as a list.\n\nArgs:\n    data: CppcheckData or Configuration object\n    config_name: Optional configuration name filter\n    limit: Maximum results to return")
        builder.line("results = []")
        builder.block(f"for match in {func_name}_iter(data, config_name):")
        builder.line("results.append(match)")
        builder.block("if limit and len(results) >= limit:")
        builder.line("break")
        builder.end_block()
        builder.line("return results")
        builder.end_block()
        builder.blank(2)

    # =========================================================================
    # Visitor implementations (expression + predicate lowering)
    # =========================================================================

    def visit_query(self, node: CsqlQuery) -> str:
        raise RuntimeError("Query node should not be visited directly")

    def visit_projection(self, node: CsqlProjection) -> str:
        return node.expr.accept(self)

    def visit_order_by(self, node: CsqlOrderBy) -> str:
        expr = node.key_expr.accept(self)
        return f"(lambda _m: {expr})"

    # -------------------------------------------------------------------------
    # Predicate visitors
    # -------------------------------------------------------------------------

    def visit_and(self, node: CsqlAnd) -> str:
        left = node.left.accept(self)
        right = node.right.accept(self)
        return f"(({left}) and ({right}))"

    def visit_or(self, node: CsqlOr) -> str:
        left = node.left.accept(self)
        right = node.right.accept(self)
        return f"(({left}) or ({right}))"

    def visit_not(self, node: CsqlNot) -> str:
        operand = node.operand.accept(self)
        return f"(not ({operand}))"

    def visit_has_attr(self, node: CsqlHasAttr) -> str:
        return f"(hasattr({node.var}, {node.attr!r}) and {node.var}.{node.attr} is not None)"

    def visit_comparison(self, node: CsqlComparison) -> str:
        left = node.left.accept(self)
        right = node.right.accept(self)

        if node.op in {"is", "is not"}:
            return f"({left} {node.op} {right})"

        if node.op in {"in", "not in"}:
            return f"({left} {node.op} {right})"

        return f"({left} {node.op} {right})"

    def visit_matches(self, node: CsqlMatches) -> str:
        self._needs_re = True
        expr = node.expr.accept(self)
        return f"(re.search({node.pattern!r}, {expr}) is not None)"

    def visit_in(self, node: CsqlIn) -> str:
        expr = node.expr.accept(self)
        values = ", ".join(repr(v) for v in node.values)
        return f"({expr} in ({values},))"

    def visit_exists(self, node: CsqlExists) -> str:
        fn = self._fresh_subquery()
        subgen = CSQLCodeGenerator(fn)
        code = subgen.generate(node.subquery)

        # Inject subquery function
        return f"(any({fn}_iter(data)))"

    def visit_forall(self, node: CsqlForAll) -> str:
        coll = node.collection_expr.accept(self)
        self._context_stack.append(node.var)
        pred = node.predicate.accept(self)
        self._context_stack.pop()
        return f"(all(({pred}) for {node.var} in {coll}))"

    def visit_call_predicate(self, node: CsqlCallPredicate) -> str:
        args = [arg.accept(self) for arg in node.args]

        if BuiltinPredicates.exists(node.name):
            return BuiltinPredicates.compile_call(node.name, args)

        arglist = ", ".join(args)
        return f"{node.name}({arglist})"

    # -------------------------------------------------------------------------
    # Expression visitors
    # -------------------------------------------------------------------------

    def visit_attr_access(self, node: CsqlAttrAccess) -> str:
        base = (
            node.base
            if isinstance(node.base, str)
            else node.base.accept(self)
        )
        return f"getattr({base}, {node.attr!r}, None)"

    def visit_var_ref(self, node: CsqlVarRef) -> str:
        return node.name

    def visit_literal(self, node: CsqlLiteral) -> str:
        return repr(node.value)

    def visit_list_expr(self, node: CsqlListExpr) -> str:
        elems = ", ".join(elem.accept(self) for elem in node.elements)
        return f"[{elems}]"

    def visit_call_expr(self, node: CsqlCallExpr) -> str:
        args = ", ".join(arg.accept(self) for arg in node.args)
        return f"{node.func}({args})"

    def visit_binary_expr(self, node: CsqlBinaryExpr) -> str:
        left = node.left.accept(self)
        right = node.right.accept(self)
        return f"({left} {node.op} {right})"

    def visit_conditional_expr(self, node: CsqlConditionalExpr) -> str:
        cond = node.condition.accept(self)
        then = node.then_expr.accept(self)
        els = node.else_expr.accept(self)
        return f"({then} if {cond} else {els})"

    # =========================================================================
    # Helpers
    # =========================================================================

    def _infer_projection_alias(self, expr: CsqlExpr) -> str:
        if isinstance(expr, CsqlAttrAccess):
            return expr.attr
        if isinstance(expr, CsqlVarRef):
            return expr.name
        return f"expr_{id(expr)}"

    def _fresh_subquery(self) -> str:
        self._subquery_counter += 1
        return f"_subquery_{self._subquery_counter}"

