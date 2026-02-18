# Cppcheck Addon API Shims

The default API provided by Cppcheck for writing addons, `cppcheckdata.py`, leaves a lot to be desired. It is merely a parser for the XML 'dump files' that the program generates with the `--dump` flag. This library creates a very rich abstraction layer on top of this API, what is colliqually referred to as a "shim" library. Do not mistake a "shim" with a "polyfill". A polyfill creates a *compatiblity layer* on top of an API or a language, whereas a shim provides *features* that do not exist by default in that API or language.

I recommend installing this library in a virtual environment:

```sh
$ python3 -m venv env
$ source env/bin/activate.<shell> # choose the script based on your shell, e.g. POSIX shell, Bash, or Fish
$ python3 setup.py install
```

After having had installed the library, you can run one of the examples in the `examples` directory against one of the faulty codes in `erroneous-code` directory.

As of right now, the features provided by the `cppcheckdata-shims` library are:

- Contorl flow analysis
- Data flow analysis
- Abstract interpretation
- Symbolic extection
- Taint analysis
- Type checking

This library comes with several *canonical examples*, all located under the `examples/` directory. These addons detect errors that Cppcheck itself does not detect! If you do not believe me, be my guest, test it out.

This library comes with a substrate called "CASL" or *Cppcheck Addon Specification Language*. CASL is a S-Expression-based language for quick and easy authorship of Cppcheck addons. You *specify* your addon in CASL, call the `casl` utility on it, and it will generate the addon as a Python script --- an addon that utilizes the shims library.

This library is currently at version 0.1.0. The documentation leaves *a lot* to be desired. I am working on documentation, please be patient. I will also make a manpage for `casl`.

I recommend generating addons with an LLM, e.g. Opus 4.6. It is my intention to provide the user with means to provide LLMs with a context to generate plugins with.

This library is the intellectual property of Poyan Afzar. It is released under the MIT license. A good porition of the library is AI-generated, so this addon belongs to everyone who wishes to use it.
