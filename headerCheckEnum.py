from enum import Enum

class HeaderVals(Enum):
    MISSING = 1
    PASS = 2
    WEAK = 3
    MISCONFIGURED = 4
    INAPPLICABLE = 5