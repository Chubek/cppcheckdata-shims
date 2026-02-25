# The Home of `cppcheckdata-shims`, CASL and LibLINT

This is the official repository for the `cppcheckdata-shims` library. A "shim", by definition, is an API that adds new features to another, often extremely bare-bones library. In `cppcheckdata.py`, the Cppcheck API module for building plugins, we exactly have such thing.

`cppcheckdata.py` is solely responsible for parsing the XML 'dumpfile' that Cppcheck outputs for each *Translation Unit*, so its plugins to run wild. It parses the XML file into several `Configuration` objects, a 'configuration' being a single "semantically operational" form of the program --- and in fact, the term 'configuration' here is on lend from operational semantics.

Each `Configuration` holds with it:
- The processed token stream, `Token` (as opposed to the 'raw' token stream, also available);
- The functions of the Translation Unit, `Function`;
- The variables of the Translation Unit, `Variable`;
- The scopes of the Translation Unit, `Scope`;
- The value flow and values, `ValueFlow`;

This representation is extremely *concrete*. Although the `Token` object represnts, for expressions, an abstract syntax tree, it is neither intraprocedural, nor interporcedural, it is merely a representation of a single expression.

## The Solution: `cppcheckdata-shims`

This library, housed in the `cppcheckdata_shims` library, is the main life force of this project. This plugin is a 'shim API' for `cppcheckdata.py`. It has over 20 modules (as of now) that add build on top of `cppcheckdata.py`. These modules provide intermediate representation, analysis tools, and tools for abstraction interpretation, symbolic execution, control flow analysis, data flow analysis, and so on. We also provide tools for reporting errors, scoring the code, etc.

Take a gander at `MODULES.md` to understand what each module does. `cppcheckdata-shims` is a fully-fledged static analysis library, with Cppcheck as its mere provenance.

### Building the Documentation

The documentation is easily buildable using the following sequence of commands:

```sh
$ cd docs
$ make
```

There's a *manual* in `docs/vade-mecum`. The manual is written by myself and teaches the user how to utilize the shims library. The 'documentation' is just extracted docstrings.

An HTML version of these documentation is available [here](https://chubak.nekoweb.org/cppcheck-shimslib-docs.html).

You can use the `docs/build_docs.py` to generate documentation in other formats, e.g.:

```sh
$ python3 docs/build_docs.py --format rst
$ python3 docs/build_docs.py --format json
```

## LibLINT 

LibLINT is a *massive* collection of addons for Cppcheck, all using the shims library. This library is growing and growing.

## CASL

CASL stands for "Cppcheck Addon Specification Language". It is a S-Expression-based *declarative constraint-based domain-specific language*, used for specification of Cppcheck addons. A CASL file compiles directly to a Python program that uses the shims library.
