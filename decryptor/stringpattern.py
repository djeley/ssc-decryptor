import numpy as np

class StringPattern:
    def __init__(self, string):
        self.string_pattern = self.__string_to_pattern(string)

    @staticmethod
    def __string_to_pattern(string):
        """Returns a patterns representation of any string"""
        pattern = str()
        unique_chars_base_repr = dict()

        for char in string:
            if char not in unique_chars_base_repr:
                unique_chars_base_repr[char] = np.base_repr(len(unique_chars_base_repr) + 1, base=26)
            pattern += unique_chars_base_repr[char]
        return str(len(string)) + '-' + pattern

    def get_pattern(self):
        return self.string_pattern
