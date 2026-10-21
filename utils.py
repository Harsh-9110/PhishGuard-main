"""Compatibility URL validation; dataset loading belongs exclusively in train.py."""
from feature_extraction import normalize_url,InvalidURL


def is_valid_url(value):
    try:
        normalize_url(value)
        return True
    except InvalidURL:
        return False


def sanitize_url(value):
    return normalize_url(value)
