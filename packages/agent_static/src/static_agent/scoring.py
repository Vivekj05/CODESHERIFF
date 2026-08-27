"""Scoring module for evidence raw_score computation."""

def clamp(val: float, min_val: float = 0.0, max_val: float = 1.0) -> float:
    return max(min_val, min(max_val, val))


def calculate_raw_score(
    danger: str = "medium",
    partial_sanitizer: bool = False,
    path_length: int = 2,
    network_facing: bool = True,
    is_test_file: bool = False,
) -> float:
    """Compute explicit, deterministic evidence score."""
    base = 0.45
    if danger.lower() == "critical":
        base += 0.20
    elif danger.lower() == "high":
        base += 0.10

    if partial_sanitizer:
        base -= 0.25

    length_penalty = 0.05 * min(max(0, path_length - 2), 4) / 4.0
    base -= length_penalty

    if network_facing:
        base += 0.15

    if is_test_file:
        base -= 0.20

    return round(clamp(base, 0.0, 1.0), 3)
