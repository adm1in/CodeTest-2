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
    HTML encode (using code points) all non-alphanumeric characters (e.g. ' -> &#39;)

    >>> tamper("1' AND SLEEP(5)#")
    '1&#39;&#32;AND&#32;SLEEP&#40;5&#41;&#35;'
    """

    return re.sub(r"[^\w]", lambda match: "&#%d;" % ord(match.group(0)), payload) if payload else payload
