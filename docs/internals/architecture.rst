============
Architecture
============

Package Layout
--------------

.. graphviz::

   digraph architecture {
       rankdir=TB;
       node [shape=box, style=filled, fillcolor="#e8f0fe", fontname="monospace"];

       subgraph cluster_casl {
           label="casl/";
           style=dashed;
           casl_main  [label="__main__.py\n(CLI entry point)"];
           casl_parser [label="parser.py\n(S-expr → AST)"];
           casl_sem   [label="semantic.py\n(validation)"];
           casl_codegen [label="codegen.py\n(AST → Python)"];
           casl_runtime [label="runtime.py\n(execution)"];
           casl_ast   [label="ast.py\n(node types)"];
           casl_errors [label="errors.py\n(diagnostics)"];
       }

       subgraph cluster_shims {
           label="cppcheckdata_shims/";
           style=dashed;
           shims_core [label="core.py\n(base abstractions)"];
           shims_cfg  [label="cfg.py\n(control-flow)"];
           shims_df   [label="dataflow.py\n(data-flow)"];
           shims_dom  [label="domains.py\n(abstract domains)"];
           shims_pat  [label="patterns.py\n(AST patterns)"];
       }

       casl_main -> casl_parser -> casl_sem -> casl_codegen;
       casl_main -> casl_runtime;
       casl_codegen -> shims_core;
       casl_runtime -> shims_core;
       shims_core -> shims_cfg;
       shims_core -> shims_df;
       shims_df -> shims_dom;
       shims_core -> shims_pat;
   }
