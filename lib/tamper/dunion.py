#!/usr/bin/env python

"""
Copyright (c) 2006-2020 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""
import re

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces instances of <int> UNION with <int>DUNION

    Requirement:
        * Oracle

    Notes:
        * Reference: https://media.blackhat.com/us-13/US-13-Salgado-SQLi-Optimization-and-Obfuscation-Techniques-Slides.pdf

    >>> tamper('1 UNION ALL SELECT')
    '1DUNION ALL SELECT'
    """

    return re.sub(r"(\d+)\s+(UNION )", r"\g<1>D\g<2>", payload, re.I) if payload else payload
