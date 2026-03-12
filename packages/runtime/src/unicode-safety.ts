/**
 * Unicode normalization utilities for security-critical input processing.
 *
 * All security-sensitive string comparisons (paths, commands, patterns)
 * must normalize input to NFKC form before regex matching or comparison.
 * This prevents bypass via fullwidth characters (U+FF04 ＄ → $),
 * homoglyphs, zero-width characters, and bidi overrides.
 */

/**
 * Characters that should never appear in security-critical input.
 * Includes zero-width characters, bidi overrides, and other invisible
 * Unicode control characters that can be used for obfuscation.
 *
 * Two forms: non-global for .test() (avoids lastIndex state bugs),
 * global for .replace() (strips ALL occurrences, not just the first).
 */
const DANGEROUS_UNICODE_DETECT = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/;
const DANGEROUS_UNICODE_STRIP = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/g;

/**
 * Normalize a string to NFKC form and strip dangerous invisible characters.
 *
 * NFKC (Compatibility Decomposition followed by Canonical Composition):
 * - Fullwidth ＄ (U+FF04) → $ (U+0024)
 * - Fullwidth ；(U+FF1B) → ; (U+003B)
 * - Fullwidth ／(U+FF0F) → / (U+002F)
 * - Compatibility ligatures, superscripts, subscripts → base forms
 *
 * Additionally strips:
 * - Zero-width spaces (U+200B)
 * - Zero-width joiners/non-joiners (U+200C, U+200D)
 * - Bidi overrides (U+202A-U+202E)
 * - Word joiners (U+2060)
 * - BOM (U+FEFF)
 * - Soft hyphens (U+00AD)
 */
export function normalizeInput(input: string): string {
	return input.normalize("NFKC").replace(DANGEROUS_UNICODE_STRIP, "");
}

/**
 * Check if input contains dangerous invisible Unicode characters.
 * Returns true if the input contains characters that could be used
 * for obfuscation attacks (zero-width, bidi overrides, etc.).
 */
export function containsDangerousUnicode(input: string): boolean {
	return DANGEROUS_UNICODE_DETECT.test(input);
}
