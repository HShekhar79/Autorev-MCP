"""
test_malformed_inputs.py

Regression tests for malformed, unsupported, and missing input handling.

Run with:
    python test_malformed_inputs.py
"""

import os
import tempfile

from engines.file_type_router.file_type_router import (
    detect_file_type,
    route_and_extract,
)


def test_missing_file():
    print("\n" + "=" * 80)
    print("TEST 1: Missing File")
    print("=" * 80)

    path = os.path.join(
        tempfile.gettempdir(),
        "autorev_definitely_missing_file_12345.bin",
    )

    if os.path.exists(path):
        os.remove(path)

    result = route_and_extract(path)

    assert isinstance(result, dict)
    assert result["_meta"]["reason"] == "file_not_found"
    assert result["_meta"]["extraction_engine"] == "none"

    print("PASS: Missing file handled safely")
    print(f"   Reason: {result['_meta']['reason']}")


def test_unknown_binary():
    print("\n" + "=" * 80)
    print("TEST 2: Unknown Binary")
    print("=" * 80)

    with tempfile.NamedTemporaryFile(
        suffix=".unknownbin",
        delete=False,
    ) as tmp:
        tmp.write(
            b"\xff\xfe\xfd\xfc"
            b"\x01\x02\x03\x04"
            b"UNKNOWN_BINARY_TEST"
        )
        path = tmp.name

    try:
        type_group, subtype = detect_file_type(path)

        assert type_group == "unknown"
        assert subtype == "unknownbin"

        result = route_and_extract(path)

        assert isinstance(result, dict)
        assert result["_meta"]["file_type"] == "UNKNOWN"
        assert result["_meta"]["extraction_engine"] == "raw_strings"

        assert "UNKNOWN_BINARY_TEST" in result["strings"]

        print("PASS: Unknown binary safely falls back to raw strings")
        print(f"   Type: {type_group}")
        print(f"   Subtype: {subtype}")
        print(f"   Strings: {len(result['strings'])}")

    finally:
        os.remove(path)


def test_malformed_pe_header():
    print("\n" + "=" * 80)
    print("TEST 3: Malformed PE Header")
    print("=" * 80)

    with tempfile.NamedTemporaryFile(
        suffix=".exe",
        delete=False,
    ) as tmp:
        # Valid DOS magic but intentionally incomplete PE content.
        tmp.write(
            b"MZ"
            + b"\x00" * 100
        )
        path = tmp.name

    try:
        type_group, subtype = detect_file_type(path)

        assert type_group == "pe"
        assert subtype == "pe"

        result = route_and_extract(path)

        assert isinstance(result, dict)
        assert result.get("_route_to_radare") is True
        assert result.get("file_type") == "PE"

        print(
            "PASS: Malformed PE is safely routed to the PE analysis path"
        )
        print(
            "   Note: PE integrity validation belongs to the downstream "
            "analysis engine, not this router."
        )

    finally:
        os.remove(path)


def test_malformed_zip():
    print("\n" + "=" * 80)
    print("TEST 4: Malformed ZIP")
    print("=" * 80)

    with tempfile.NamedTemporaryFile(
        suffix=".zip",
        delete=False,
    ) as tmp:
        # ZIP local-file signature followed by intentionally invalid data.
        tmp.write(
            b"PK\x03\x04"
            b"\x00\x00\x00\x00"
            b"INVALID_AUTOREV_ZIP_DATA"
        )
        path = tmp.name

    try:
        type_group, subtype = detect_file_type(path)

        assert type_group == "zip_based"
        assert subtype == "zip"

        result = route_and_extract(path)

        assert isinstance(result, dict)
        assert "functions" in result
        assert "imports" in result
        assert "strings" in result
        assert "behaviours" in result
        assert "_meta" in result

        print("PASS: Malformed ZIP handled without crashing")
        print(f"   Type: {type_group}")
        print(f"   Subtype: {subtype}")

    finally:
        os.remove(path)


def test_plaintext_unknown_extension():
    print("\n" + "=" * 80)
    print("TEST 5: Plaintext With Unknown Extension")
    print("=" * 80)

    with tempfile.NamedTemporaryFile(
        suffix=".autorev_unknown",
        mode="wb",
        delete=False,
    ) as tmp:
        tmp.write(
            b"This is a plaintext AutoRev regression test.\n"
            b"https://example.com/test\n"
        )
        path = tmp.name

    try:
        type_group, subtype = detect_file_type(path)

        assert type_group == "text"
        assert subtype == "plaintext"

        result = route_and_extract(path)

        assert isinstance(result, dict)
        assert result["_meta"]["extraction_engine"] == "text_static"
        assert "network_activity" in result["behaviours"]

        print("PASS: UTF-8 plaintext fallback handled correctly")
        print(f"   Type: {type_group}")
        print(f"   Subtype: {subtype}")
        print(f"   Behaviours: {result['behaviours']}")

    finally:
        os.remove(path)


def test_all_results_are_dicts():
    print("\n" + "=" * 80)
    print("TEST 6: Result Contract")
    print("=" * 80)

    with tempfile.NamedTemporaryFile(
        suffix=".bin",
        delete=False,
    ) as tmp:
        tmp.write(b"\x00\x01\x02AUTOREV")
        path = tmp.name

    try:
        result = route_and_extract(path)

        assert isinstance(result, dict)

        required_keys = {
            "functions",
            "imports",
            "strings",
            "calls",
            "behaviours",
            "capabilities",
            "mitre",
            "_meta",
            "hashes",
        }

        missing = required_keys - set(result.keys())

        assert not missing, (
            f"Router result missing required keys: {missing}"
        )

        print("PASS: Router result contract preserved")

    finally:
        os.remove(path)


def run_all_tests():
    print("\n" + "#" * 80)
    print("# MALFORMED / UNSUPPORTED INPUT REGRESSION SUITE")
    print("#" * 80)

    tests = [
        ("Missing File", test_missing_file),
        ("Unknown Binary", test_unknown_binary),
        ("Malformed PE", test_malformed_pe_header),
        ("Malformed ZIP", test_malformed_zip),
        ("Plaintext Fallback", test_plaintext_unknown_extension),
        ("Result Contract", test_all_results_are_dicts),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as exc:
            failed += 1
            print(f"\nFAIL: {name}")
            print(f"   Error: {exc}")

            import traceback
            traceback.print_exc()

    print("\n" + "#" * 80)
    print(
        f"# TEST RESULTS: {passed} passed, {failed} failed"
    )
    print("#" * 80)

    if failed == 0:
        print("\nALL MALFORMED / UNSUPPORTED INPUT TESTS PASSED")
        return True

    print("\nMALFORMED / UNSUPPORTED INPUT REGRESSION FAILED")
    return False


if __name__ == "__main__":
    success = run_all_tests()
    raise SystemExit(0 if success else 1)