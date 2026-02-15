========
Pipeline
========

The CASL compilation pipeline transforms a ``.casl`` specification through
several phases, each of which is documented by its module-level docstring.

.. code-block:: text

   .casl source
       │
       ▼
   ┌──────────┐
   │  Parser   │   sexpdata → CASL AST
   └────┬─────┘
        │
        ▼
   ┌──────────────┐
   │  Semantic     │   Multi-pass validation
   │  Analyzer     │   (symbols, types, soundness)
   └────┬─────────┘
        │
        ▼
   ┌──────────────┐
   │  Code         │   AST → Python source
   │  Generator    │   (standalone Cppcheck addon)
   └────┬─────────┘
        │
        ▼
   generated_addon.py

Each phase is a pure function of its input, making the pipeline easy to
test, debug, and extend.
