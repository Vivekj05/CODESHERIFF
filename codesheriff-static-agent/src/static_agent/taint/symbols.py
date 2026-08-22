"""Symbol extraction and range resolution."""

import re
from typing import List, Optional
from pydantic import BaseModel
from static_agent.taint.parse import ASTNodeView


class SymbolInfo(BaseModel):
    name: str
    kind: str
    start_line: int
    end_line: int
    text: str


def extract_symbols(root: ASTNodeView) -> List[SymbolInfo]:
    """Extract top-level and nested function/method symbols from AST."""
    symbols: List[SymbolInfo] = []

    def _walk(node: ASTNodeView) -> None:
        if node.kind in ("function_definition", "function_declaration", "method_definition", "arrow_function"):
            name = "anonymous"
            for child in node.children:
                if child.kind in ("identifier", "property_identifier", "name"):
                    name = child.text
                    break
            symbols.append(
                SymbolInfo(
                    name=name,
                    kind=node.kind,
                    start_line=node.start_point[0],
                    end_line=node.end_point[0],
                    text=node.text,
                )
            )

        for child in node.children:
            _walk(child)

    _walk(root)

    if not symbols:
        # Regex fallback for function extraction if AST didn't capture symbols
        lines = root.text.splitlines()
        for i, line in enumerate(lines, start=1):
            m = re.match(r"^\s*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", line) or re.match(r"^\s*function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", line)
            if m:
                symbols.append(
                    SymbolInfo(
                        name=m.group(1),
                        kind="function_definition",
                        start_line=i,
                        end_line=len(lines),
                        text=line,
                    )
                )

    return symbols


def enclosing_symbol(line: int, symbols: List[SymbolInfo]) -> Optional[str]:
    """Find the symbol name enclosing the specified line number."""
    matched = [s for s in symbols if s.start_line <= line <= s.end_line]
    if not matched:
        return None
    # Pick the smallest enclosing scope (most specific symbol)
    matched.sort(key=lambda s: s.end_line - s.start_line)
    return matched[0].name
