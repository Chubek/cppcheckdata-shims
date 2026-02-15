==========
Quickstart
==========

CASL is a domain-specific language for writing Cppcheck addons declaratively.

Basic Workflow
--------------

1. Write a ``.casl`` specification
2. Compile it to a standalone Python addon
3. Run it against Cppcheck dump files

.. code-block:: bash

   # Compile a specification
   casl compile my-checker.casl -o my_checker.py

   # Generate a dump file with Cppcheck
   cppcheck --dump source.c

   # Run the addon
   python my_checker.py source.c.dump

Generate a Skeleton
-------------------

.. code-block:: bash

   casl init --name my-checker --author "Your Name" -o my-checker.casl
