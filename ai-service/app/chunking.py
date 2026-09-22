"""
chunking.py

Extracts a bounded code window around a Semgrep finding for the
DistilRoBERTa false-positive filter, which has a hard 512-token ceiling.

Two-tiered strategy:
  Tier 1 (standard): a line-count window of ±`context` lines around the
    vulnerable line. This is sufficient for ordinary source files and
    comfortably fits under the token limit.
  Tier 2 (fallback): minified/bundled code can put an entire file's logic
    on a single line thousands of characters long — a line-count window
    doesn't help there, since "the line" IS the whole blob. In that case,
    fall back to a character-radius crop centered on Semgrep's exact
    match column, which bounds the window regardless of how the source
    is formatted.

Naively feeding whole files to the tokenizer either crashes it or
silently truncates context immediately before the vulnerable line —
both failure modes lose the exact signal the classifier needs.
"""

from typing import List, Tuple


def extract_window(
    file_lines: List[str],
    start_line: int,
    end_line: int,
    start_col: int = 0,
    context: int = 15,
    max_chars: int = 1800,
) -> Tuple[str, bool]:
    """
    Args:
        file_lines: the source file, split into individual lines (1-indexed
            line numbers are assumed for start_line/end_line, matching
            Semgrep's own reporting convention).
        start_line: the 1-indexed line number where the finding begins.
        end_line: the 1-indexed line number where the finding ends.
        start_col: the 0-indexed column of the exact match, used only by
            the Tier 2 fallback to center the character crop.
        context: number of lines of context to include above/below the
            finding in the Tier 1 window.
        max_chars: the character budget for the returned snippet. 1800
            characters of ordinary source comfortably resolves to well
            under DistilRoBERTa's 512-token ceiling; this is also the
            threshold that decides whether Tier 2 fires.

    Returns:
        (snippet, truncation_flag) — truncation_flag is True only when
        the Tier 2 character-radius fallback was used, so callers can
        surface "this verdict was computed on a cropped view" rather
        than hiding it.
    """
    if not file_lines:
        return "", False

    # --- Tier 1: line-count window ------------------------------------
    lo = max(0, start_line - context - 1)
    hi = min(len(file_lines), end_line + context)
    window = "\n".join(file_lines[lo:hi])

    if len(window) <= max_chars:
        return window, False  # normal case — the line-window already fits

    # --- Tier 2: character-radius fallback -----------------------------
    # A single line can be tens of thousands of characters long in
    # minified/bundled code — no amount of *line*-count windowing bounds
    # that, since the finding's own line is the entire oversized blob.
    # Crop by CHARACTER instead, centered on Semgrep's exact match column
    # so the vulnerable call site is preserved inside the window.
    target_line_index = max(0, min(start_line - 1, len(file_lines) - 1))
    target_line = file_lines[target_line_index]

    center = min(start_col, len(target_line))
    half = max_chars // 2

    cropped = target_line[max(0, center - half): min(len(target_line), center + half)]

    return cropped, True
