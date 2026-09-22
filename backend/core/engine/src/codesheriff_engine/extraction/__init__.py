"""ChangeUnit extraction: fetched file blobs in, one unit per changed function out.

Pure. No HTTP client, no GitHub client, no database session — the caller fetches the blobs and
hands them over. `apps/worker` is the only caller in production; Chapter 14 is the other one, and
it runs this over corpus cases with no credentials at all.

Everything about the shape of a unit is decided here and nowhere else, because two places deciding
it is how the engine and the agents came to disagree about what a finding was (`AUDIT.md` 1.1).
"""

from codesheriff_engine.extraction.diffing import changed_line_numbers
from codesheriff_engine.extraction.python import PythonFile, PythonSymbol, parse_python_file
from codesheriff_engine.extraction.units import (
    PYTHON_SUFFIXES,
    ExtractionResult,
    FetchedFile,
    SkippedFile,
    SkipReason,
    extract_units,
    is_analysable_path,
    is_test_path,
    qualified,
    unit_id_for,
)

__all__ = [
    "PYTHON_SUFFIXES",
    "ExtractionResult",
    "FetchedFile",
    "PythonFile",
    "PythonSymbol",
    "SkipReason",
    "SkippedFile",
    "changed_line_numbers",
    "extract_units",
    "is_analysable_path",
    "is_test_path",
    "parse_python_file",
    "qualified",
    "unit_id_for",
]
