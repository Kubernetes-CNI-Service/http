"""Direct contract of tools/hostname_ranges.py: merged device lists and the --devices selector (v3.1.1 M4).

Expectations are written from the requirement texts, not from the module:
- R-002 rules 1-8 (owner 2026-10-26) and the owner's example (需求文档 R-002: input described at :62,
  the expected six lines at :74-79); O1 point 9 (owner 2026-11-07): lines come back without "- ";
- R-003 (owner 2026-10-26) and its acceptance list (需求文档 :132-135); O1 points 1-4 (owner 2026-11-07):
  a pattern with "." is compared with the CSV value, without "." with the display short name; a comma
  list; "all" only with allow_all; an item matching nothing is an argument error;
- v3.1.1 guide 14.3: the range is part of the matching, not a check after a greedy match
  (`*leaf[01-05]*` must select `leaf03leaf99`).
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import hostname_ranges as HR  # noqa: E402

FORMS = ("ew-leaf*", "[001-039]", "[a-d]")   # the three supported forms the error must name (R-003)


class CompressTests(unittest.TestCase):
    def test_owner_example_of_r002(self):
        # 需求文档 R-002 :62: ew-leaf001..112 without 034, ew-spine001..072 without 013, 032, 069,
        # all with the suffix .site.example.test.  The text says "共 182 台" but these ranges hold
        # 111 + 69 = 180 names; the expected six lines (:74-79) cover exactly these 180.
        leaf = [f"ew-leaf{n:03d}.site.example.test" for n in range(1, 113) if n != 34]
        spine = [f"ew-spine{n:03d}.site.example.test" for n in range(1, 73) if n not in (13, 32, 69)]
        names = list(reversed(spine)) + leaf[1::2] + leaf[0::2]   # input order must not matter
        self.assertEqual(180, len(names))
        self.assertEqual(
            [
                "ew-leaf[001-033].site.example.test",
                "ew-leaf[035-112].site.example.test",
                "ew-spine[001-012].site.example.test",
                "ew-spine[014-031].site.example.test",
                "ew-spine[033-068].site.example.test",
                "ew-spine[070-072].site.example.test",
            ],
            HR.compress(names),
        )

    def test_only_numbers_of_the_same_width_merge(self):
        # Rule 2 (Q1 B, Q2 A) with the owner's two examples.
        self.assertEqual(
            ["ib-leaf[1-9]", "ib-leaf[10-12]"],
            HR.compress([f"ib-leaf{n}" for n in range(12, 0, -1)]),
        )
        self.assertEqual(
            ["ew-leaf[009-010]", "ew-leaf9"],
            HR.compress(["ew-leaf9", "ew-leaf010", "ew-leaf009"]),
        )

    def test_a_gap_starts_a_new_line_and_a_single_name_has_no_brackets(self):
        # Rules 3 and 5.
        self.assertEqual(["leaf[01-02]", "leaf04"], HR.compress(["leaf04", "leaf01", "leaf02"]))
        self.assertEqual(["ew-leaf001", "ew-leaf003"], HR.compress(["ew-leaf003", "ew-leaf001"]))
        self.assertEqual(["ew-leaf001.site.example.test"], HR.compress(["ew-leaf001.site.example.test"]))

    def test_empty_input(self):
        self.assertEqual([], HR.compress([]))

    def test_groups_follow_the_natural_order_of_names(self):
        # Rule 4: groups in the natural order of the names (2 before 10).
        self.assertEqual(["leaf2", "leaf10"], HR.compress(["leaf10", "leaf2"]))
        self.assertEqual(
            ["ew-leaf[001-002]", "ew-spine001"],
            HR.compress(["ew-spine001", "ew-leaf002", "ew-leaf001"]),
        )

    def test_letters_merge_one_letter_at_a_time(self):
        # Rule 8: the owner's example.
        self.assertEqual(
            ["ib-pod[a-c]-leaf01"],
            HR.compress(["ib-podc-leaf01", "ib-poda-leaf01", "ib-podb-leaf01"]),
        )

    def test_a_and_upper_a_are_not_adjacent(self):
        # Rule 8: letters are case-sensitive, a and A are not neighbours.
        self.assertEqual(
            {"ib-poda-leaf01", "ib-podA-leaf01"},
            set(HR.compress(["ib-poda-leaf01", "ib-podA-leaf01"])),
        )
        self.assertEqual(
            {"ib-poda-leaf01", "ib-podB-leaf01"},
            set(HR.compress(["ib-poda-leaf01", "ib-podB-leaf01"])),
        )
        self.assertEqual(
            {"ib-pod[a-b]-leaf01", "ib-pod[A-B]-leaf01"},
            set(HR.compress(["ib-poda-leaf01", "ib-podB-leaf01", "ib-podA-leaf01", "ib-podb-leaf01"])),
        )
        # 推断 from rules 6-8: a letter of the other case is no neighbour, so it does not keep a name
        # from merging on another segment (ib-su1-leafa still joins ib-su2-leafa).
        self.assertEqual(
            ["ib-su[1-2]-leafa", "ib-su1-leafB"],
            HR.compress(["ib-su1-leafB", "ib-su2-leafa", "ib-su1-leafa"]),
        )

    def test_only_the_rightmost_changing_segment_merges(self):
        # Rule 7: pod a-d x leaf 01-12 gives four lines; with only pods a and d, two lines.
        names = [f"ib-pod{pod}-leaf{n:02d}" for pod in "dcba" for n in range(12, 0, -1)]
        self.assertEqual(
            ["ib-poda-leaf[01-12]", "ib-podb-leaf[01-12]", "ib-podc-leaf[01-12]", "ib-podd-leaf[01-12]"],
            HR.compress(names),
        )
        names = [f"ib-pod{pod}-leaf{n:02d}" for pod in "ad" for n in range(1, 13)]
        self.assertEqual(["ib-poda-leaf[01-12]", "ib-podd-leaf[01-12]"], HR.compress(names))

    def test_several_number_segments(self):
        # R-002 acceptance "多段数字", read with rule 7 (推断: the other segments group, the rightmost
        # changing one merges; a name whose own rightmost number has no neighbour merges on the next).
        self.assertEqual(
            ["ib-su1-leaf[01-02]", "ib-su2-leaf[01-02]"],
            HR.compress(["ib-su2-leaf02", "ib-su1-leaf01", "ib-su2-leaf01", "ib-su1-leaf02"]),
        )
        self.assertEqual(
            ["ib-su[1-3]-leaf01"],
            HR.compress(["ib-su3-leaf01", "ib-su1-leaf01", "ib-su2-leaf01"]),
        )
        self.assertEqual(
            ["ib-poda-leaf[01-02]", "ib-podb-leaf01"],
            HR.compress(["ib-podb-leaf01", "ib-poda-leaf02", "ib-poda-leaf01"]),
        )

    def test_mixed_suffixes_form_separate_groups(self):
        # Rule 1: prefix and suffix must both be the same.
        self.assertEqual(
            ["ew-leaf[001-002].site.example.test", "ew-leaf003.other.example.test", "ew-leaf004"],
            HR.compress([
                "ew-leaf004", "ew-leaf003.other.example.test",
                "ew-leaf002.site.example.test", "ew-leaf001.site.example.test",
            ]),
        )

    def test_output_keeps_the_original_spelling(self):
        # Rule 6: prefix and suffix compare without case, the output keeps the written case.
        self.assertEqual(["EW-Leaf[001-002].Site.Example.Test"],
                         HR.compress(["EW-Leaf002.Site.Example.Test", "EW-Leaf001.Site.Example.Test"]))


HOSTS = [
    "ew-leaf001.site.example.test",
    "ew-leaf002.site.example.test",
    "ew-leaf003.site.example.test",
    "ew-leaf033.site.example.test",
    "ew-leaf035.site.example.test",
    "ew-leaf039.site.example.test",
    "ew-leaf040.site.example.test",
    "ew-leaf112.site.example.test",
    "ew-leaf0010.site.example.test",
    "ew-leaf0399.site.example.test",
    "ew-leaf1.site.example.test",
    "ew-spine001.site.example.test",
    "ib-poda-leaf01.site.example.test",
    "ib-podb-leaf01.site.example.test",
    "ib-podc-leaf12.site.example.test",
    "ib-podd-leaf01.site.example.test",
    "ib-pode-leaf01.site.example.test",
    "ib-podA-leaf02.site.example.test",
    "ib-podD-leaf03.site.example.test",
    "core-leaf007-x.site.example.test",
]


def chosen(text, hosts=HOSTS, **options):
    return set(HR.select(HR.parse_selector(text, **options), hosts))


def full(*shorts):
    return {f"{short}.site.example.test" for short in shorts}


class SelectorTests(unittest.TestCase):
    def test_literal_and_star(self):
        self.assertEqual(
            full("ew-leaf001", "ew-leaf002", "ew-leaf003", "ew-leaf033", "ew-leaf035", "ew-leaf039",
                 "ew-leaf040", "ew-leaf112", "ew-leaf0010", "ew-leaf0399", "ew-leaf1"),
            chosen("ew-leaf*"),
        )
        self.assertEqual(full("ew-spine001"), chosen("*spine*"))

    def test_digit_range_with_star_takes_extra_digits(self):
        # R-003 Q4 B: the range takes as many digits as its ends, the rest goes to "*";
        # ew-leaf1 has one digit and does not match [001-039]; 040 and 112 are outside.
        self.assertEqual(
            full("ew-leaf001", "ew-leaf002", "ew-leaf003", "ew-leaf033", "ew-leaf035", "ew-leaf039",
                 "ew-leaf0010", "ew-leaf0399"),
            chosen("ew-leaf[001-039]*"),
        )

    def test_digit_range_without_star_and_with_a_fixed_suffix(self):
        self.assertEqual(
            full("ew-leaf001", "ew-leaf002", "ew-leaf003", "ew-leaf033", "ew-leaf035", "ew-leaf039"),
            chosen("ew-leaf[001-039]"),
        )
        self.assertEqual(
            full("ew-leaf001", "ew-leaf002", "ew-leaf003", "ew-leaf033"),
            chosen("ew-leaf[001-033].site.example.test"),
        )

    def test_missing_numbers_inside_a_range_are_fine(self):
        self.assertEqual(full("ew-leaf033", "ew-leaf035"), chosen("ew-leaf[033-035]"))

    def test_letter_ranges_are_case_sensitive_and_the_rest_is_not(self):
        self.assertEqual(full("ib-poda-leaf01", "ib-podb-leaf01", "ib-podc-leaf12", "ib-podd-leaf01"),
                         chosen("ib-pod[a-d]*"))
        self.assertEqual(full("ib-podA-leaf02", "ib-podD-leaf03"), chosen("ib-pod[A-D]*"))
        self.assertEqual(full("ib-poda-leaf01", "ib-podb-leaf01"), chosen("IB-POD[a-b]-LEAF01"))
        self.assertEqual(full("ew-leaf001", "ew-leaf002"), chosen("EW-LEAF[001-002]"))

    def test_several_ranges_in_one_pattern(self):
        self.assertEqual(full("ib-poda-leaf01", "ib-podb-leaf01", "ib-podc-leaf12", "ib-podd-leaf01"),
                         chosen("ib-pod[a-d]-leaf[01-12]"))
        self.assertEqual(full("ib-poda-leaf01", "ib-podb-leaf01", "ib-podc-leaf12", "ib-podd-leaf01"),
                         chosen("ib-pod[a-d]-leaf*"))
        self.assertEqual(full("ib-poda-leaf01", "ib-podb-leaf01", "ib-podd-leaf01"),
                         chosen("ib-pod[a-d]-leaf[01-01]"))

    def test_star_on_both_sides_of_a_range(self):
        self.assertEqual(
            full("ew-leaf001", "ew-leaf002", "ew-leaf003", "ew-leaf0010", "core-leaf007-x"),
            chosen("*leaf[001-010]*"),
        )

    def test_range_is_matched_in_place_not_checked_after_a_greedy_match(self):
        # v3.1.1 guide 14.3: a greedy "*" first aligns with leaf99; the other alignment (leaf03) matches.
        self.assertEqual({"leaf03leaf99"}, chosen("*leaf[01-05]*", hosts=["leaf03leaf99", "leaf99leaf98"]))
        self.assertEqual({"leaf99leaf03"}, chosen("*leaf[01-05]", hosts=["leaf99leaf03", "leaf03leaf99"]))

    def test_pattern_with_a_dot_compares_the_csv_value_otherwise_the_short_name(self):
        # O1 point 1 (option A).
        self.assertEqual(full("ew-leaf001"), chosen("ew-leaf001"))
        self.assertEqual(full("ew-leaf001"), chosen("ew-leaf001.site.example.test"))
        self.assertEqual(full("ew-leaf001"), chosen("ew-leaf001.*"))
        self.assertEqual({"ew-leaf001.site.example.test"}, chosen("EW-LEAF001.SITE.EXAMPLE.TEST"))
        with self.assertRaises(HR.SelectorError):
            chosen("ew-leaf001.other.example.test")
        # The short name keeps its case for the letter range (P3b design point).
        self.assertEqual({"IB-PodA-leaf01"}, chosen("ib-pod[A-B]-leaf01", hosts=["IB-PodA-leaf01", "ib-poda-leaf02"]))

    def test_comma_list(self):
        # O1 point 2: comma list in one argument, blanks around items ignored.
        self.assertEqual(full("ew-leaf001", "ew-spine001"), chosen(" ew-leaf001 , ew-spine001 "))
        selected = HR.select(HR.parse_selector("ew-leaf00[1-2],ew-leaf*,ew-leaf001"), HOSTS)
        self.assertEqual(len(selected), len(set(selected)))   # every host once
        self.assertEqual([h for h in HOSTS if h in set(selected)], selected)   # in inventory order

    def test_empty_items_are_argument_errors(self):
        for text in ("", " ", "ew-leaf001,,ew-spine001", "ew-leaf001,", ",ew-leaf001"):
            with self.subTest(text=text):
                with self.assertRaises(HR.SelectorError) as caught:
                    HR.parse_selector(text)
                self.assertIn("--devices", str(caught.exception))

    def test_items_matching_nothing_are_listed_in_one_error(self):
        # O1 point 4.
        selector = HR.parse_selector("ew-leaf001,nosuch*,ew-leaf[200-210]")
        with self.assertRaises(HR.SelectorError) as caught:
            HR.select(selector, HOSTS)
        message = str(caught.exception)
        self.assertIn("--devices", message)
        self.assertIn("nosuch*", message)
        self.assertIn("ew-leaf[200-210]", message)
        self.assertIsInstance(caught.exception, ValueError)

    def test_all_only_when_allowed(self):
        # O1 point 3: "all" is for --direct-access only (allow_all=True); otherwise it is a plain name.
        self.assertEqual(HOSTS, HR.select(HR.parse_selector("all", option="--direct-access", allow_all=True), HOSTS))
        with self.assertRaises(HR.SelectorError):
            HR.select(HR.parse_selector("all"), HOSTS)

    def test_invalid_patterns_name_the_option_the_item_and_the_three_forms(self):
        # R-003: invalid ranges and the retired glob forms (Q5 B) are argument errors with a hint.
        for item in (
            "ib-pod[a-D]*",       # mixed case letter range
            "ib-pod[a-9]*",       # letter and digit
            "ib-pod[aa-ad]*",     # more than one letter
            "ib-leaf[1-12]",      # ends of different width
            "ew-leaf[039-001]",   # start after end
            "ib-pod[d-a]*",       # start after end
            "ew-leaf[0a-12]",     # not a digit
            "ew-leaf[001-",       # incomplete
            "ew-leaf[001]",       # no range
            "ew-leaf[]",
            "ew-leaf]",
            "ew-leaf[1-2-3]",
            "ew-leaf00?",         # retired: ?
            "ew-leaf[abc]",       # retired: character set
            "ew-leaf[!a-c]",      # retired: negation
            "ew leaf",
        ):
            with self.subTest(item=item):
                with self.assertRaises(HR.SelectorError) as caught:
                    HR.parse_selector(f"ew-leaf001,{item}")
                message = str(caught.exception)
                self.assertIn("--devices", message)
                self.assertIn(item, message)
                for form in FORMS:
                    self.assertIn(form, message)
        with self.assertRaises(HR.SelectorError) as caught:
            HR.parse_selector("ufm?", option="--node")
        self.assertIn("--node", str(caught.exception))

    def test_ranges_with_equal_ends_are_valid(self):
        self.assertEqual(full("ew-leaf033"), chosen("ew-leaf[033-033]"))
        self.assertEqual(full("ib-podb-leaf01"), chosen("ib-pod[b-b]-leaf01"))


if __name__ == "__main__":
    unittest.main()
