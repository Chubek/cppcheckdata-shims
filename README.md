# Cppcheck Addon API Shims & the Lint Library Based Upon it

This is home to `cppcheckdata-shims` library, and the `liblint` substrate.

The Cppcheck addon API, shipped alongside the analyzer in `addons/cppcheckdata.py`, leave *a lot* to be desired in terms of carrying the addon from its provenance to reporting the errors. This API is designed for lightweight checks, such as confirming to a coding standard such as MISRA and compliance with a certain naming style.

The `cppcheckdata-shims` library does away with that. It offers the user several facilities for creating addons that do *actual* analysis work, such as:

- Control flow analysis
- Data flow analysis
- Taint analysis
- Type checking
- Symbolic execution
- Abstract interpretation

And so on. The usage of this library has been documented in `docs/SHIMS_VADE_MECUM.md` --- *vade mecum* being a very pretentious way to say "manual". But that is not the only facet of this project. Basically, in this project, we have three substrates:

- The shims substrate
- The CASL substrate
- The liblint substrate

The CASL substrate is still heavily WIP. CASL stands for "Cppcheck Addon Specification Language" and it is a S-Expression-based domain-specific language (DSL) used to 'describe' an addon in a declarative manner, and it will generate a Python script that carries out the specified analyses using the shims library.

But `liblint` is a collection of linters and analyzers that utilize the shims library. To use `liblint`:

1. Create a new Python virtual environment:
```sh
$ python3 -m venv env
```

2. Activate the virtual environment:
```sh
$ source env/bin/activate.sh
```

The extension of `activate` script version you should use, is variant based on your shell. For example, I run the Fish shell, so I must source `env/bin/activate.fish`. If you use a POSIX-based shell like Bash, `activate.sh` is your poistion -- and so on.

3. Install the shims library:

```sh
$ python3 setup.y install
```

Now you can run `liblint` analyzers. Imagine we wish to run `Buflint` on a file called `foo.c`:

```sh
$ cppcheck --dump foo.c
$ PYTHONPATH="$PYTHONPATH:deps" liblinb/buflint/Buflint.py foo.c.dump
```

You must `cd(1)` to the root directory of the project, the directory this very file is at. You need to add `deps/` directory to `$PYTHONPATH`, this is non-negotiable.

If you have any problems running liblint, or the shims library, contact me at `behrang.nevi.93@gmail.com`.
