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
    Prepends (inline) comment before parentheses (e.g. ( -> /**/()

    Tested against:
        * Microsoft SQL Server
        * MySQL
        * Oracle
        * PostgreSQL

    Notes:
        * Useful to bypass web application firewalls that block usage
          of function calls

    >>> tamper('SELECT ABS(1)')
    'SELECT ABS/**/(1)'
    """

    retVal = payload

    if payload:
        retVal = re.sub(r"\b(\w+)\(", r"\g<1>/**/(", retVal)

    return retVal
