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
    Replaces (MySQL) instances like 'LIMIT M, N' with 'LIMIT N OFFSET M' counterpart

    Requirement:
        * MySQL

    Tested against:
        * MySQL 5.0 and 5.5

    >>> tamper('LIMIT 2, 3')
    'LIMIT 3 OFFSET 2'
    """

    retVal = payload

    match = re.search(r"(?i)LIMIT\s*(\d+),\s*(\d+)", payload or "")
    if match:
        retVal = retVal.replace(match.group(0), "LIMIT %s OFFSET %s" % (match.group(2), match.group(1)))

    return retVal
