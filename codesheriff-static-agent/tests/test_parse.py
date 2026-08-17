"""Tests for Tree-sitter CodeParser and symbols extraction."""

from static_agent.taint.parse import CodeParser
from static_agent.taint.symbols import extract_symbols, enclosing_symbol


def test_code_parser_python() -> None:
    code = "def hello():\n    return 'world'\n"
    parser = CodeParser()
    node_view = parser.parse(code, "python")
    assert node_view is not None
    assert node_view.text == code


def test_symbol_extraction() -> None:
    code = "def get_user(uid):\n    return uid\n"
    parser = CodeParser()
    node_view = parser.parse(code, "python")
    symbols = extract_symbols(node_view)
    assert len(symbols) > 0
    assert symbols[0].name == "get_user"
    assert enclosing_symbol(1, symbols) == "get_user"
