import tempfile
from unittest.mock import patch

from engines.extractor_engine.radare_extractor import (
    extract_functions,
    extract_imports,
    extract_strings,
    extract_file_info,
    extract_sections,
    extract_all_calls,
)


def make_temp_file():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"VALID_TEMP_FILE_FOR_R2_FAILURE_TEST")
        return f.name


def test_r2_open_failure_returns_empty_functions():
    path = make_temp_file()

    with patch(
        "engines.extractor_engine.radare_extractor.r2pipe.open",
        side_effect=RuntimeError("Simulated Radare2 open failure"),
    ):
        result = extract_functions(path)

    assert result == []


def test_r2_open_failure_returns_empty_imports():
    path = make_temp_file()

    with patch(
        "engines.extractor_engine.radare_extractor.r2pipe.open",
        side_effect=RuntimeError("Simulated Radare2 open failure"),
    ):
        result = extract_imports(path)

    assert result == []


def test_r2_open_failure_returns_empty_strings():
    path = make_temp_file()

    with patch(
        "engines.extractor_engine.radare_extractor.r2pipe.open",
        side_effect=RuntimeError("Simulated Radare2 open failure"),
    ):
        result = extract_strings(path)

    assert result == []


def test_r2_open_failure_returns_empty_file_info():
    path = make_temp_file()

    with patch(
        "engines.extractor_engine.radare_extractor.r2pipe.open",
        side_effect=RuntimeError("Simulated Radare2 open failure"),
    ):
        result = extract_file_info(path)

    assert result == {}


def test_r2_open_failure_returns_empty_sections():
    path = make_temp_file()

    with patch(
        "engines.extractor_engine.radare_extractor.r2pipe.open",
        side_effect=RuntimeError("Simulated Radare2 open failure"),
    ):
        result = extract_sections(path)

    assert result == []


def test_r2_open_failure_returns_empty_calls():
    path = make_temp_file()

    with patch(
        "engines.extractor_engine.radare_extractor.r2pipe.open",
        side_effect=RuntimeError("Simulated Radare2 open failure"),
    ):
        result = extract_all_calls(path)

    assert result == []


if __name__ == "__main__":
    print("Running Radare2 failure regression tests...")