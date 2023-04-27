#!/usr/bin/env python

"""
Copyright (c) 2006-2020 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""
def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Slash escape single and double quotes (e.g. ' -> \')

    >>> tamper('1" AND SLEEP(5)#')
    '1\\\\" AND SLEEP(5)#'
    """

    return payload.replace("'", "\\'").replace('"', '\\"')
