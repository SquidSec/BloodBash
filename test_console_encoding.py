#!/usr/bin/env python3
"""Console encoding guards.

The release binary crashed on a Windows runner before this fix: a cp1252
console cannot encode the check mark printed when a collection finishes
loading, and the resulting UnicodeEncodeError killed the run before any
analysis happened.

Two layers keep that from recurring:
  * stdout/stderr are reconfigured to UTF-8 when the current encoding cannot
    represent the glyphs the tool prints;
  * the console print guard falls back to plain ASCII if an encode error still
    escapes, so output never aborts an analysis.
"""
from __future__ import annotations

import io
import unittest
from unittest.mock import patch

from rich.console import Console

import BloodBash as bb

GLYPH = "\u2713"


class _Cp1252Stream(io.TextIOBase):
    """Stream that encodes like a legacy Windows console."""

    encoding = "cp1252"

    def __init__(self):
        self.written = []
        self.reconfigured = None

    def reconfigure(self, encoding=None, errors=None):
        # Mirrors TextIOWrapper.reconfigure, which real consoles provide.
        self.reconfigured = encoding
        self.encoding = encoding

    def write(self, text):
        text.encode("cp1252")  # raises UnicodeEncodeError for the check mark
        self.written.append(text)
        return len(text)

    def flush(self):
        pass

    def isatty(self):
        return False


class TestEncodingSupported(unittest.TestCase):
    def test_utf8_supports_the_glyph(self):
        self.assertTrue(bb.encoding_supports_glyphs("utf-8"))

    def test_cp1252_does_not_support_the_glyph(self):
        self.assertFalse(bb.encoding_supports_glyphs("cp1252"))

    def test_unknown_encoding_is_treated_as_unsupported(self):
        self.assertFalse(bb.encoding_supports_glyphs("not-a-codec"))

    def test_none_encoding_is_treated_as_unsupported(self):
        self.assertFalse(bb.encoding_supports_glyphs(None))


class TestAsciiFallback(unittest.TestCase):
    def test_glyph_is_replaced(self):
        text = bb.ascii_safe_text(f"{GLYPH} Loaded 10 objects")
        self.assertNotIn(GLYPH, text)
        self.assertIn("Loaded 10 objects", text)

    def test_plain_ascii_passes_through(self):
        self.assertEqual(bb.ascii_safe_text("Loaded 10 objects"), "Loaded 10 objects")

    def test_box_drawing_characters_are_replaced(self):
        self.assertNotIn("\u2500", bb.ascii_safe_text("a\u2500b"))

    def test_emoji_are_removed(self):
        self.assertNotIn("\U0001f600", bb.ascii_safe_text("x\U0001f600y"))


class TestPrintGuardSurvivesEncodeErrors(unittest.TestCase):
    def test_guard_falls_back_instead_of_raising(self):
        con = Console(file=io.StringIO(), width=120, force_terminal=False, legacy_windows=False)
        bb._install_markup_guard(con)
        calls = {"n": 0}
        real_print = con.print

        def flaky(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise UnicodeEncodeError("cp1252", GLYPH, 0, 1, "charmap")
            return None

        con.print = flaky
        bb._install_markup_guard(con)
        # No exception escapes
        con.print(f"[green]{GLYPH} Loaded[/green]")
        self.assertGreaterEqual(calls["n"], 1)

    def test_guard_retries_without_markup(self):
        con = Console(file=io.StringIO(), width=120, force_terminal=False, legacy_windows=False)
        seen = []
        real_print = con.print

        def fake(*args, **kwargs):
            seen.append(kwargs.get("markup"))
            if len(seen) == 1:
                raise UnicodeEncodeError("cp1252", GLYPH, 0, 1, "charmap")
            return real_print(*args, **kwargs)

        con.print = fake
        bb._install_markup_guard(con)
        con.print(f"{GLYPH} Loaded")
        self.assertEqual(seen[-1], False)


class TestGlyphSafeStream(unittest.TestCase):
    def test_transliterates_the_check_mark(self):
        stream = _Cp1252Stream()
        proxy = bb.GlyphSafeStream(stream)
        proxy.write(f"{GLYPH} Loaded 10 objects\n")
        self.assertIn("[+] Loaded 10 objects", stream.written[-1])

    def test_passes_ascii_through_unchanged(self):
        stream = _Cp1252Stream()
        proxy = bb.GlyphSafeStream(stream)
        proxy.write("Loaded 10 objects\n")
        self.assertEqual(stream.written[-1], "Loaded 10 objects\n")

    def test_reports_utf8_so_rich_does_not_downgrade(self):
        self.assertEqual(bb.GlyphSafeStream(_Cp1252Stream()).encoding, "utf-8")

    def test_console_print_survives_a_legacy_stream(self):
        con = Console(file=io.StringIO(), width=120, force_terminal=False, legacy_windows=False)
        legacy = _Cp1252Stream()
        con.file = legacy
        bb.ensure_console_encoding(con)
        bb._install_markup_guard(con)
        con.print(f"[green]{GLYPH} Loaded 10 objects[/green]")
        self.assertTrue(any("Loaded 10 objects" in line for line in legacy.written))

    def test_wrapped_stream_exposes_other_attributes(self):
        stream = _Cp1252Stream()
        proxy = bb.GlyphSafeStream(stream)
        self.assertEqual(proxy.written, [])


class TestReconfigureConsoleEncoding(unittest.TestCase):
    def test_reconfigures_a_cp1252_stream(self):
        stream = _Cp1252Stream()
        changed = bb.reconfigure_stream_encoding(stream)
        self.assertTrue(changed)
        self.assertEqual(stream.encoding.lower().replace("-", ""), "utf8")

    def test_leaves_a_utf8_stream_alone(self):
        stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        self.assertFalse(bb.reconfigure_stream_encoding(stream))

    def test_missing_reconfigure_is_not_fatal(self):
        class Bare:
            encoding = "cp1252"

        self.assertFalse(bb.reconfigure_stream_encoding(Bare()))

    def test_readme_example_glyphs_are_covered(self):
        # The glyphs the loader actually prints.
        for text in (f"{GLYPH} Loaded 10 objects", f"{GLYPH} Graph built: 1 nodes"):
            self.assertNotIn(GLYPH, bb.ascii_safe_text(text))


if __name__ == "__main__":
    unittest.main()
