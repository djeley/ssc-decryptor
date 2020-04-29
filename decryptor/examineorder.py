from enum import Enum, auto

class ExamineOrder(Enum):
    LONGEST_TO_SHORTEST = auto()
    FEWEST_TO_MOST_MATCHES = auto()
    MATCHES_DIVIDED_BY_LENGTH = auto()
    