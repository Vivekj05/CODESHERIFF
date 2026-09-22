"""Test package for `semantic_agent`.

Present so `test_corpus_semantic.py` can do `from .cassettes import ...`. The cassette helpers are
shared between the tests and `tools/record_cassettes.py`, so they live in their own module rather
than in `conftest.py`, and a relative import needs the directory to be a package.
"""
