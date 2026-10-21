"""Neutralize untrusted document values for terminal and report output."""
import unicodedata


def safe_text(value, limit=300, keep=''):
    """Replace control, format and other non-printing characters (except those
    in `keep`) with spaces and cap the length."""
    text = ''.join(c if c in keep or not unicodedata.category(c).startswith('C') else ' '
                   for c in str(value))
    return text if len(text) <= limit else text[:limit-3] + '...'
