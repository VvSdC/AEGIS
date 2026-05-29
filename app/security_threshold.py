"""Security threshold presets for output code-vulnerability review."""

from typing import Literal

SecurityThresholdPreset = Literal["strict", "balanced", "quiet"]

SECURITY_THRESHOLD_PRESETS: dict[str, float] = {
    "strict": 0.95,
    "balanced": 0.90,
    "quiet": 0.85,
}

PRESET_LABELS: dict[str, str] = {
    "strict": "Strict (0.95)",
    "balanced": "Balanced (0.90)",
    "quiet": "Quiet (0.85)",
}


def resolve_security_threshold(preset: str) -> float:
    return SECURITY_THRESHOLD_PRESETS.get(preset, SECURITY_THRESHOLD_PRESETS["balanced"])
