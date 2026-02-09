# Shims for Cppcheck Addon API

The Cppcheck static analyzer allows for creation of addons through its XML-based 'dump files'. These 'dump files' are parsed using `cppcheckdata.py`, but the representation offered by this script is extremely 'concrete', and high-level. This thwarts us from doing any sort of analysis based on control flow, abstract domains, or symbolic execution.

However, what we *could* do is to create several 'shims' for `cppcheckdata.Configuration` that enables analysis of control flow, and provide abstract domains for other aspects of our program.

This project does just that. It does not provide a separate parser for 'dump files', you need to still use `cppcheckdata.py` to parse dump files into `Configuration` objects. However, this project provides shims that take one `Configuration` object, and provide better tools for analysis of the program.



