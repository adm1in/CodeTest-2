#!/usr/bin/env python

"""
Copyright (c) 2006-2020 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""
def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces (MySQL) instances like 'CONCAT(A, B)' with 'CONCAT_WS(MID(CHAR(0), 0, 0), A, B)' counterpart

    Requirement:
        * MySQL

    Tested against:
        * MySQL 5.0

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that filter the CONCAT() function

    >>> tamper('CONCAT(1,2)')
    'CONCAT_WS(MID(CHAR(0),0,0),1,2)'
    """

    if payload:
        payload = payload.replace("CONCAT(", "CONCAT_WS(MID(CHAR(0),0,0),")

    return payload
