#!/usr/bin/env python3

import os
from pathlib import Path
import tempfile
import unittest

import check_locale_parity


DEFAULT_XML = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="greeting">Hello</string>
    <string name="detail">Detail: %1$s</string>
    <string name="language_option_hebrew" translatable="false">עברית</string>
    <plurals name="blocked">
        <item quantity="one">%1$d app is blocked</item>
        <item quantity="other">%1$d apps are blocked</item>
    </plurals>
</resources>
"""

HEBREW_XML = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="greeting">שלום</string>
    <string name="detail">פרט: %1$s</string>
    <plurals name="blocked">
        <item quantity="one">נחסמה אפליקציה אחת</item>
        <item quantity="two">נחסמו שתי אפליקציות</item>
        <item quantity="other">נחסמו %1$d אפליקציות</item>
    </plurals>
</resources>
"""


class LocaleParityFixtureTest(unittest.TestCase):
    """Each case mutates one valid pair of files and asserts the check notices."""

    def check(self, default=DEFAULT_XML, hebrew=HEBREW_XML):
        with tempfile.TemporaryDirectory() as tmp:
            for folder, content in (("values", default), ("values-iw", hebrew)):
                directory = Path(tmp) / folder
                directory.mkdir()
                (directory / "strings.xml").write_text(content, encoding="utf-8")
            _, _, problems = check_locale_parity.check_res_dir(tmp)
            return problems

    def test_matching_locales_report_no_problems(self) -> None:
        self.assertEqual([], self.check())

    def test_missing_translation_is_reported(self) -> None:
        hebrew = HEBREW_XML.replace('<string name="greeting">שלום</string>', "")
        self.assertIn("values-iw: string/greeting is missing", self.check(hebrew=hebrew))

    def test_extra_translation_is_reported(self) -> None:
        hebrew = HEBREW_XML.replace(
            "</resources>", '    <string name="stray">מחרוזת</string>\n</resources>'
        )
        self.assertIn(
            "values-iw: string/stray is not in the default locale", self.check(hebrew=hebrew)
        )

    def test_translating_an_untranslatable_string_is_reported(self) -> None:
        hebrew = HEBREW_XML.replace(
            "</resources>",
            '    <string name="language_option_hebrew">עברית</string>\n</resources>',
        )
        problems = self.check(hebrew=hebrew)
        self.assertTrue(
            any("must not be translated" in problem for problem in problems), problems
        )

    def test_dropped_format_placeholder_is_reported(self) -> None:
        hebrew = HEBREW_XML.replace("פרט: %1$s", "פרט")
        problems = self.check(hebrew=hebrew)
        self.assertTrue(
            any("string/detail placeholders" in problem for problem in problems), problems
        )

    def test_missing_hebrew_dual_form_is_reported(self) -> None:
        hebrew = HEBREW_XML.replace(
            '        <item quantity="two">נחסמו שתי אפליקציות</item>\n', ""
        )
        problems = self.check(hebrew=hebrew)
        self.assertTrue(any("plurals/blocked declares" in problem for problem in problems), problems)

    def test_english_dual_form_is_reported(self) -> None:
        default = DEFAULT_XML.replace(
            '        <item quantity="other">',
            '        <item quantity="two">%1$d apps are blocked</item>\n        <item quantity="other">',
        )
        problems = self.check(default=default)
        self.assertTrue(any("plurals/blocked declares" in problem for problem in problems), problems)

    def test_other_quantity_that_cannot_show_every_argument_is_reported(self) -> None:
        # Both locales gain the same second argument in a non-fallback branch, so
        # the cross-locale union still matches and only the `other` rule can fire.
        default = DEFAULT_XML.replace(
            "%1$d app is blocked", "%1$d app is blocked out of %2$d"
        )
        hebrew = HEBREW_XML.replace("נחסמו שתי אפליקציות", "נחסמו שתי אפליקציות מתוך %2$d")
        problems = self.check(default=default, hebrew=hebrew)
        self.assertIn(
            "values: plurals/blocked quantity=other cannot show ['%2$d'], which another "
            "quantity uses; other is the fallback branch",
            problems,
        )
        self.assertTrue(
            any(problem.startswith("values-iw: plurals/blocked quantity=other") for problem in problems),
            problems,
        )

    def test_hebrew_left_in_the_default_locale_is_reported(self) -> None:
        default = DEFAULT_XML.replace(
            '<string name="greeting">Hello</string>', '<string name="greeting">שלום</string>'
        )
        problems = self.check(default=default)
        self.assertTrue(
            any("the default locale is English" in problem for problem in problems), problems
        )

    def test_untranslated_value_in_the_hebrew_locale_is_reported(self) -> None:
        hebrew = HEBREW_XML.replace(
            '<string name="greeting">שלום</string>', '<string name="greeting">Hello</string>'
        )
        problems = self.check(hebrew=hebrew)
        self.assertTrue(
            any("was probably never translated" in problem for problem in problems), problems
        )

    def test_a_value_holding_no_word_is_not_reported_as_untranslated(self) -> None:
        # A separator assembled only from placeholders and punctuation -- the kiosk
        # profile/state summary -- is identical in both locales because there is
        # nothing in it to translate.
        separator = '    <string name="summary">%1$s · %2$s</string>\n</resources>'
        self.assertEqual(
            [],
            self.check(
                default=DEFAULT_XML.replace("</resources>", separator),
                hebrew=HEBREW_XML.replace("</resources>", separator),
            ),
        )

    def test_a_value_that_still_holds_a_word_is_reported(self) -> None:
        # The exemption is narrow: one letter outside a placeholder makes the
        # value translatable again.
        sentence = '    <string name="summary">%1$s and %2$s</string>\n</resources>'
        problems = self.check(
            default=DEFAULT_XML.replace("</resources>", sentence),
            hebrew=HEBREW_XML.replace("</resources>", sentence),
        )
        self.assertTrue(
            any("was probably never translated" in problem for problem in problems), problems
        )

    def test_blank_value_is_reported(self) -> None:
        hebrew = HEBREW_XML.replace("<string name=\"greeting\">שלום</string>", '<string name="greeting"> </string>')
        problems = self.check(hebrew=hebrew)
        self.assertTrue(any("is blank" in problem for problem in problems), problems)


class ShippedResourcesTest(unittest.TestCase):
    def test_the_resources_in_this_repository_are_in_parity(self) -> None:
        res_dir = check_locale_parity.default_res_dir()
        self.assertTrue(os.path.isdir(res_dir), res_dir)
        default, translations, problems = check_locale_parity.check_res_dir(res_dir)
        self.assertEqual([], problems)
        self.assertTrue(default.translatable)
        self.assertTrue(default.plurals)
        self.assertEqual(["values-iw"], [t.folder for t in translations])


if __name__ == "__main__":
    unittest.main()
