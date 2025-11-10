"""
Tests for diff formatting fixes:
- Word-level diffing (minimal spans)
- Two-stage diff with stable anchors
- Apostrophe normalization
- Jaccard similarity to prevent paragraph-wide changes
- No phantom formatting changes
"""

from __future__ import annotations

from dashboard.app import (
    _compute_char_diff,
    _compute_line_diff,
    _jaccard_similarity,
    _normalize_style_value,
    _normalize_text_for_diff,
    _tokenize_text,
)


def test_word_level_diff_minimal_spans():
    """
    Test that word-level diffing produces minimal spans.
    When a single word is added/removed, only that word should be marked, not the entire paragraph.
    """
    # test case: single word added in a paragraph
    old_line = "This is a test paragraph with some text."
    new_line = "This is a test paragraph with some new text."

    old_parts, new_parts = _compute_char_diff(old_line, new_line, word_level=True)

    # count how many parts are marked as changed
    new_changed = [p for p in new_parts if p.get("type") != "equal"]

    # should only have one changed part (the word "new")
    assert len(new_changed) == 1, f"Expected 1 changed part, got {len(new_changed)}: {new_changed}"
    assert new_changed[0].get("type") == "added"
    assert "new" in new_changed[0].get("text", "").lower()

    # test case: single word removed
    old_line2 = "This is a test paragraph with some text."
    new_line2 = "This is a test paragraph with text."

    old_parts2, new_parts2 = _compute_char_diff(old_line2, new_line2, word_level=True)

    old_changed2 = [p for p in old_parts2 if p.get("type") != "equal"]

    # should only have one changed part (the word "some" removed)
    assert (
        len(old_changed2) == 1
    ), f"Expected 1 changed part, got {len(old_changed2)}: {old_changed2}"
    assert old_changed2[0].get("type") == "removed"
    assert "some" in old_changed2[0].get("text", "").lower()


def test_apostrophe_normalization():
    """
    Test that apostrophe normalization works correctly.
    Curly apostrophes (U+2019) should be normalized to straight apostrophes.
    """
    # test curly apostrophe normalization
    text_with_curly = "what's"
    text_with_straight = "what's"

    normalized_curly = _normalize_text_for_diff(
        text_with_curly.replace("'", "\u2019")
    )  # replace with curly
    normalized_straight = _normalize_text_for_diff(text_with_straight)

    # all should normalize to similar forms (after normalization, apostrophes are stripped for comparison)
    # the key is that "what's" and "whats" should be treated as similar
    assert (
        normalized_curly.lower() == normalized_straight.lower()
    ), "Curly and straight apostrophes should normalize to same form"

    # test that normalization handles Unicode quotes
    text_with_quotes = 'He said "hello"'
    normalized_quotes = _normalize_text_for_diff(
        text_with_quotes.replace('"', "\u201C").replace('"', "\u201D")
    )
    normalized_straight_quotes = _normalize_text_for_diff(text_with_quotes)

    assert (
        normalized_quotes == normalized_straight_quotes
    ), "Curly and straight quotes should normalize to same form"


def test_style_value_normalization():
    """
    Test that style value normalization works correctly to prevent phantom formatting changes.
    """
    # test color normalization
    assert _normalize_style_value("color", "#A02B93") == "A02B93"
    assert _normalize_style_value("color", "A02B93") == "A02B93"
    assert _normalize_style_value("color", "#a02b93") == "A02B93"
    assert _normalize_style_value("color", "#ABC") == "AABBCC"  # 3-digit to 6-digit

    # test boolean normalization
    assert _normalize_style_value("bold", "true") == "true"
    assert _normalize_style_value("bold", "1") == "true"
    assert _normalize_style_value("bold", "yes") == "true"
    assert _normalize_style_value("bold", "false") == ""
    assert _normalize_style_value("bold", "0") == ""

    # test strikethrough normalization
    assert _normalize_style_value("strikethrough", "true") == "true"
    assert _normalize_style_value("strikethrough", "double") == "double"
    assert _normalize_style_value("strikethrough", "false") == ""


def test_tokenize_text():
    """
    Test that tokenization works correctly for word-level diffing.
    """
    text = "This is a test."
    tokens = _tokenize_text(text)

    # should tokenize into words
    assert len(tokens) > 0, "Should tokenize text into tokens"

    # check that tokens have correct format (token, start, end)
    for token, start, end in tokens:
        assert isinstance(token, str)
        assert isinstance(start, int)
        assert isinstance(end, int)
        assert start < end
        assert text[start:end] == token


def test_line_anchor_hello_insertion():
    """
    Acceptance test: Line anchor + word diff test (hello insertion)
    Arrange: baseline lines ["add", QUOTE_LINE]; current ["add", "hello", QUOTE_LINE].
    Expect: one line-level insertion for hello only. No changes on QUOTE_LINE.
    """
    QUOTE_LINE = "This is a long quotation paragraph with many words that should remain unchanged."

    baseline_lines = ["add", QUOTE_LINE]
    current_lines = ["add", "hello", QUOTE_LINE]

    diff_segments = _compute_line_diff(baseline_lines, current_lines)

    # find segments
    equal_segments = [s for s in diff_segments if s.get("type") == "equal"]
    added_segments = [s for s in diff_segments if s.get("type") == "added"]
    modified_segments = [s for s in diff_segments if s.get("type") == "modified"]

    # should have equal segments for "add" and QUOTE_LINE
    assert (
        len(equal_segments) >= 2
    ), f"Expected at least 2 equal segments, got {len(equal_segments)}"

    # should have exactly one added segment for "hello"
    assert len(added_segments) == 1, f"Expected 1 added segment, got {len(added_segments)}"
    assert added_segments[0].get("new_lines") == [
        "hello"
    ], f"Expected added segment to contain 'hello', got {added_segments[0].get('new_lines')}"

    # QUOTE_LINE should be in an equal segment, not modified
    quote_in_equal = any(QUOTE_LINE in (s.get("old_lines") or []) for s in equal_segments)
    quote_in_modified = any(QUOTE_LINE in (s.get("old_lines") or []) for s in modified_segments)

    assert quote_in_equal, "QUOTE_LINE should be in an equal segment"
    assert not quote_in_modified, "QUOTE_LINE should not be in a modified segment"


def test_single_word_removal_within_stable_paragraph():
    """
    Acceptance test: Single-word removal within stable paragraph
    Arrange: same QUOTE_LINE, remove exactly one word (whats / what's).
    Expect: one word-level deletion span, not a full-line deletion/insertion.
    """
    QUOTE_LINE_BASELINE = (
        "This is a long quotation paragraph with whats many words that should remain unchanged."
    )
    QUOTE_LINE_CURRENT = (
        "This is a long quotation paragraph with many words that should remain unchanged."
    )

    baseline_lines = [QUOTE_LINE_BASELINE]
    current_lines = [QUOTE_LINE_CURRENT]

    diff_segments = _compute_line_diff(baseline_lines, current_lines)

    # should have one modified segment (not removed + added)
    modified_segments = [s for s in diff_segments if s.get("type") == "modified"]
    removed_segments = [s for s in diff_segments if s.get("type") == "removed"]
    added_segments = [s for s in diff_segments if s.get("type") == "added"]

    # should have exactly one modified segment, not a removed + added pair
    assert (
        len(modified_segments) == 1
    ), f"Expected 1 modified segment, got {len(modified_segments)}. Removed: {len(removed_segments)}, Added: {len(added_segments)}"
    assert len(removed_segments) == 0, f"Expected 0 removed segments, got {len(removed_segments)}"
    assert len(added_segments) == 0, f"Expected 0 added segments, got {len(added_segments)}"

    # check that the modified segment has word-level diffs
    modified_seg = modified_segments[0]
    old_char_diffs = modified_seg.get("old_char_diffs", [])
    new_char_diffs = modified_seg.get("new_char_diffs", [])

    assert len(old_char_diffs) > 0, "Modified segment should have old_char_diffs"
    assert len(new_char_diffs) > 0, "Modified segment should have new_char_diffs"

    # check that only "whats" is marked as removed
    removed_parts = []
    for diff_list in old_char_diffs:
        for part in diff_list:
            if part.get("type") == "removed":
                removed_parts.append(part.get("text", ""))

    # should have exactly one removed part containing "whats"
    assert (
        len(removed_parts) == 1
    ), f"Expected 1 removed part, got {len(removed_parts)}: {removed_parts}"
    assert (
        "whats" in removed_parts[0].lower()
    ), f"Expected removed part to contain 'whats', got '{removed_parts[0]}'"


def test_apostrophe_normalization_in_diff():
    """
    Acceptance test: Apostrophe normalization
    Arrange: baseline has what's (curly U+2019), current has whats or vice versa.
    Expect: treat apostrophe variants as normalized tokens to avoid false paragraph churn.
    """
    # test case 1: baseline has curly apostrophe, current has straight
    baseline_line = "This is what\u2019s happening."  # curly apostrophe
    current_line = "This is what's happening."  # straight apostrophe

    diff_segments = _compute_line_diff([baseline_line], [current_line])

    # should be treated as equal (after normalization)
    equal_segments = [s for s in diff_segments if s.get("type") == "equal"]
    modified_segments = [s for s in diff_segments if s.get("type") == "modified"]

    # after normalization, they should be equal
    assert (
        len(equal_segments) == 1 or len(modified_segments) == 1
    ), f"Expected either equal or minimal modified segment, got {len(equal_segments)} equal, {len(modified_segments)} modified"

    # if modified, check that it's minimal (not full replacement)
    if len(modified_segments) == 1:
        modified_seg = modified_segments[0]
        old_char_diffs = modified_seg.get("old_char_diffs", [[]])[0]
        new_char_diffs = modified_seg.get("new_char_diffs", [[]])[0]

        # should have mostly equal parts
        equal_parts_old = [p for p in old_char_diffs if p.get("type") == "equal"]
        equal_parts_new = [p for p in new_char_diffs if p.get("type") == "equal"]

        assert (
            len(equal_parts_old) > 0 and len(equal_parts_new) > 0
        ), "Should have equal parts even with apostrophe variant"

    # test case 2: baseline has straight apostrophe, current has no apostrophe
    baseline_line2 = "This is what's happening."
    current_line2 = "This is whats happening."

    diff_segments2 = _compute_line_diff([baseline_line2], [current_line2])

    # should detect minimal change (just the apostrophe difference)
    modified_segments2 = [s for s in diff_segments2 if s.get("type") == "modified"]

    assert (
        len(modified_segments2) == 1
    ), f"Expected 1 modified segment, got {len(modified_segments2)}"

    # check that it's a minimal change, not full replacement
    modified_seg2 = modified_segments2[0]
    old_char_diffs2 = modified_seg2.get("old_char_diffs", [[]])[0]

    # should have equal parts (most of the line is unchanged)
    equal_parts = [p for p in old_char_diffs2 if p.get("type") == "equal"]
    assert len(equal_parts) > 0, "Should have equal parts even when apostrophe is removed"


def test_jaccard_similarity():
    """
    Test that Jaccard similarity calculation works correctly.
    """
    # identical sets
    tokens1 = {"this", "is", "a", "test"}
    tokens2 = {"this", "is", "a", "test"}
    similarity = _jaccard_similarity(tokens1, tokens2)
    assert similarity == 1.0, f"Expected similarity 1.0 for identical sets, got {similarity}"

    # sets with high overlap
    tokens3 = {"this", "is", "a", "test", "paragraph"}
    tokens4 = {"this", "is", "a", "test", "with"}
    similarity2 = _jaccard_similarity(tokens3, tokens4)
    assert similarity2 >= 0.6, f"Expected similarity >= 0.6 for high overlap, got {similarity2}"

    # sets with low overlap
    tokens5 = {"this", "is", "a", "test"}
    tokens6 = {"completely", "different", "words"}
    similarity3 = _jaccard_similarity(tokens5, tokens6)
    assert similarity3 == 0.0, f"Expected similarity 0.0 for no overlap, got {similarity3}"


def test_word_level_diff_preserves_unchanged_text():
    """
    Test that word-level diffing preserves unchanged text correctly.
    When only one word changes, the rest of the text should be marked as equal.
    """
    old_line = "This is a test paragraph with some text."
    new_line = "This is a test paragraph with some new text."

    old_parts, new_parts = _compute_char_diff(old_line, new_line, word_level=True)

    # count equal parts
    old_equal = [p for p in old_parts if p.get("type") == "equal"]
    new_equal = [p for p in new_parts if p.get("type") == "equal"]

    # should have equal parts for unchanged text
    assert len(old_equal) > 0, "Should have equal parts for unchanged text"
    assert len(new_equal) > 0, "Should have equal parts for unchanged text"

    # verify that equal parts contain the unchanged text
    old_equal_text = "".join(p.get("text", "") for p in old_equal)
    new_equal_text = "".join(p.get("text", "") for p in new_equal)

    # the equal text should be the same (normalized)
    assert (
        old_equal_text.lower().strip() == new_equal_text.lower().strip()
    ), "Equal parts should contain the same text"
