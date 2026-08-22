"""Tree-sitter AST parser wrapper and node representation."""

from typing import Any, List, Optional
from pydantic import BaseModel


class ASTNodeView(BaseModel):
    """Normalized AST node view."""
    kind: str
    start_byte: int
    end_byte: int
    start_point: tuple[int, int]  # (line, col) 1-based line
    end_point: tuple[int, int]
    text: str
    children: List["ASTNodeView"] = []


ASTNodeView.model_rebuild()


class CodeParser:
    """Tree-sitter AST parser wrapper."""

    def __init__(self) -> None:
        self._parsers: dict[str, Any] = {}

    def get_parser(self, language: str) -> Optional[Any]:
        lang = language.lower()
        if lang in ("python", "py"):
            lang_key = "python"
        elif lang in ("javascript", "js", "typescript", "ts"):
            lang_key = "javascript"
        else:
            return None

        if lang_key in self._parsers:
            return self._parsers[lang_key]

        try:
            import tree_sitter_language_pack as tslp
            parser = tslp.get_parser(lang_key)
            self._parsers[lang_key] = parser
            return parser
        except Exception:
            return None

    def parse(self, source_code: str, language: str) -> Optional[ASTNodeView]:
        """Parse source code into ASTNodeView tree."""
        parser = self.get_parser(language)
        if not parser:
            return self._fallback_parse(source_code)

        try:
            tree = parser.parse(bytes(source_code, "utf-8"))
            return self._build_node_view(tree.root_node, source_code)
        except Exception:
            return self._fallback_parse(source_code)

    def _build_node_view(self, node: Any, source_code: str) -> ASTNodeView:
        children = [self._build_node_view(child, source_code) for child in node.children]
        text_bytes = bytes(source_code, "utf-8")[node.start_byte:node.end_byte]
        text = text_bytes.decode("utf-8", errors="replace")
        return ASTNodeView(
            kind=node.type,
            start_byte=node.start_byte,
            end_byte=node.end_byte,
            start_point=(node.start_point[0] + 1, node.start_point[1]),
            end_point=(node.end_point[0] + 1, node.end_point[1]),
            text=text,
            children=children,
        )

    def _fallback_parse(self, source_code: str) -> ASTNodeView:
        """Lightweight fallback AST node for unparsed text."""
        lines = source_code.splitlines()
        line_count = len(lines) or 1
        return ASTNodeView(
            kind="module",
            start_byte=0,
            end_byte=len(source_code),
            start_point=(1, 0),
            end_point=(line_count, len(lines[-1]) if lines else 0),
            text=source_code,
            children=[],
        )
