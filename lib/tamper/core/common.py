import string
import random
import re
xrange = range
def randomInt(length=4, seed=None):
    """
    Returns random integer value with provided number of digits

    >>> random.seed(0)
    >>> randomInt(6)
    963638
    """
    choice = random.choice
    return int("".join(choice(string.digits if _ != 0 else string.digits.replace('0', '')) for _ in xrange(0, length)))

def zeroDepthSearch(expression, value):
    """
    Searches occurrences of value inside expression at 0-depth level
    regarding the parentheses

    >>> _ = "SELECT (SELECT id FROM users WHERE 2>1) AS result FROM DUAL"; _[zeroDepthSearch(_, "FROM")[0]:]
    'FROM DUAL'
    >>> _ = "a(b; c),d;e"; _[zeroDepthSearch(_, "[;, ]")[0]:]
    ',d;e'
    """

    retVal = []

    depth = 0
    for index in xrange(len(expression)):
        if expression[index] == '(':
            depth += 1
        elif expression[index] == ')':
            depth -= 1
        elif depth == 0:
            if value.startswith('[') and value.endswith(']'):
                if re.search(value, expression[index:index + 1]):
                    retVal.append(index)
            elif expression[index:index + len(value)] == value:
                retVal.append(index)

    return retVal

def randomRange(start=0, stop=1000, seed=None):
    """
    Returns random integer value in given range

    >>> random.seed(0)
    >>> randomRange(1, 500)
    152
    """

    # if seed is not None:
    #     _ = getCurrentThreadData().random
    #     _.seed(seed)
    #     randint = _.randint
    # else:
    randint = random.randint

    return int(randint(start, stop))