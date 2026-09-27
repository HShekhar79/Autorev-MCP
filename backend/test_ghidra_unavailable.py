from unittest.mock import patch

from engines.ghidra_engine.ghidra_engine import run_ghidra_analysis


def test_ghidra_unavailable_returns_none():
    with patch(
        "engines.ghidra_engine.ghidra_engine._resolve_headless",
        return_value=None,
    ):
        result = run_ghidra_analysis("dummy_binary.exe")

    assert result is None


def test_ghidra_unavailable_does_not_raise():
    with patch(
        "engines.ghidra_engine.ghidra_engine._resolve_headless",
        return_value=None,
    ):
        try:
            result = run_ghidra_analysis("dummy_binary.exe")
        except Exception as exc:
            raise AssertionError(
                f"Ghidra unavailable leaked an exception: {exc}"
            )

    assert result is None


if __name__ == "__main__":
    print("Ghidra unavailable regression tests")