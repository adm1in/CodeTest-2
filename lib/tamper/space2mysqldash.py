#!/usr/bin/env python

"""
Copyright (c) 2006-2020 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""
xrange = range
def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces space character (' ') with a dash comment ('--') followed by a new line ('\n')

    Requirement:
        * MySQL
        * MSSQL

    Notes:
        * Useful to bypass several web application firewalls.

    >>> tamper('1 AND 9227=9227')
    '1--%0AAND--%0A9227=9227'
    """

    retVal = ""

    if payload:
        for i in xrange(len(payload)):
            if payload[i].isspace():
                retVal += "--%0A"
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                retVal += payload[i:]
                break
            else:
                retVal += payload[i]

    return retVal
