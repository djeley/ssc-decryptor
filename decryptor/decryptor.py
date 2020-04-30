import argparse
import codecs
import importlib
import itertools
import logging
import os
import pprint
import re
import string
import sys
import time
from collections import OrderedDict

import numpy as np
import tableformatter
from unidecode import unidecode

import decryptor.wordpatterns as wordpatterns
from decryptor.examineorder import ExamineOrder
from decryptor.stringpattern import StringPattern

logging.basicConfig(format="%(message)s", stream=sys.stdout)
logger = logging.getLogger("decryptor")

class SscDecryptor:

    def __init__(self, log_level: int):
        logger.setLevel(log_level)

    def deduce_ciphertext_alphabet(self, encrypted_message: str, examine_word_order: ExamineOrder) -> dict:
        """
        Each encrypted word from an encrypted message will have zero or more matching plaintext words that share the same 
        word pattern. This function attempts to decipher encrypted messages by reducing the number of plaintext matches 
        for each encrypted word to one (ideally).
        """
        # Get the normalised encrypted words from the encrypted message text.
        encrypted_words = self.__get_normalised_encrypted_words(encrypted_message)
        logger.info(f"Normalised encrypted words: {encrypted_words}\n")

        # This is how many unique alphabetic characters we need to decipher.
        unique_encrypted_characters = self.__unique_alpha_chars_in_string(''.join(encrypted_words))
        logger.info(f"Unique alphabetic characters: {unique_encrypted_characters}\n")

        # Get a map of encrypted words (keys) and plaintext matches (values) in the desired key order.
        # The value for each key may be 'None' if the order doesn't require pre-fetching of the plaintext matches.
        encrypted_word_and_plaintext_matches = self.__get_ordered_encrypted_word_and_plaintext_matches(encrypted_words, examine_word_order)

        # Working list of examined encrypted words that resulted in a tuple match.
        matched_encrypted_words = list()

        # Working list of examined encrypted words that didn't result in a tuple match.
        unmatched_encrypted_words = list()

        # Working map of plaintext matches for each encrypted word, that will reduce as accuracy improves.
        deducted_plaintext_matches = dict()

        # Counter for the number of cartesian product tuples compared.
        total_tuples_compared = 0

        # Lookup map: Key = indexed word pattern, value = encrypted word.
        pattern_key_to_enc_word_map = dict()

        # For each encrypted word and its plaintext matches...
        for index, (encrypted_word, plaintext_matches) in enumerate(encrypted_word_and_plaintext_matches.items()):

            # Growing list of encrypted words being examined.
            matched_encrypted_words.append(encrypted_word)
            logger.info(f"\nExamining encrypted word: {encrypted_word}")

            # Create the indexed key.
            encrypted_word_pattern = StringPattern(encrypted_word).get_pattern()
            encrypted_word_pattern_key = self.__string_to_indexed_pattern(len(matched_encrypted_words), encrypted_word)
            pattern_key_to_enc_word_map[encrypted_word_pattern_key] = encrypted_word

            # Check if plaintext matches were pre-fetched or not.
            if plaintext_matches is None:
                plaintext_matches = self.__get_plaintext_matches_for_encrypted_word(encrypted_word)

            # If the encrypted word has no matches, continue.
            if plaintext_matches is None or len(plaintext_matches) == 0:
                matched_encrypted_words.remove(encrypted_word)
                unmatched_encrypted_words.append(encrypted_word)

                logger.info(f"No pattern matches. Removed: {encrypted_word}")
                continue

            # The cartesian product is created from a list of lists of matching words.
            deducted_plaintext_matches[encrypted_word_pattern_key] = plaintext_matches

            # At least two sets of matches are required to create a cartesian product.
            if not len(matched_encrypted_words) > 1:
                continue

            # New pattern for the encrypted words combined as a string.
            combined_encrypted_words_pattern = StringPattern(''.join(matched_encrypted_words)).get_pattern()

            logger.debug(f"\nBefore>deducted_plaintext_matches: {deducted_plaintext_matches}")
            
            logger.info(self.__bold_string("\nBefore deductions:"))
            self.__log_deducted_plaintext_match_counts(deducted_plaintext_matches, pattern_key_to_enc_word_map)

            # For each tuple of the cartesian product of the plaintext matches...
            tuple_plaintext_matches = dict()
            for plaintext_tuple in itertools.product(*deducted_plaintext_matches.values()):
                total_tuples_compared += 1

                # Create a combined pattern for the plaintext tuple.
                combined_plaintext_tuple_pattern = StringPattern(''.join(itertools.chain(*plaintext_tuple))).get_pattern()

                # Check if the patterns match.
                if combined_encrypted_words_pattern == combined_plaintext_tuple_pattern:
                    logger.info(f"\n{self.__bold_string('Tuple match:')} {' '.join(plaintext_tuple)}")

                    for tuple_word_pos, tuple_word in enumerate(plaintext_tuple, start=1):
                        tuple_word_key = self.__string_to_indexed_pattern(tuple_word_pos, tuple_word)

                        # Initialise keyed list.
                        if tuple_word_key not in tuple_plaintext_matches:
                            tuple_plaintext_matches[tuple_word_key] = list()

                        # Existing matches for the key.
                        tuple_word_key_words = tuple_plaintext_matches[tuple_word_key]

                        # Don't add duplicate matches.
                        if tuple_word not in tuple_word_key_words:
                            tuple_word_key_words.append(tuple_word)

                        # Latest matches.
                        tuple_plaintext_matches[tuple_word_key] = tuple_word_key_words

            if len(tuple_plaintext_matches) > 0:
                # Overwrite to achieve the deduction.
                deducted_plaintext_matches.update(tuple_plaintext_matches)

                logger.debug(f"\nAfter>deducted_plaintext_matches: {deducted_plaintext_matches}")
                
                logger.info(self.__bold_string("\nAfter deductions:"))
                self.__log_deducted_plaintext_match_counts(deducted_plaintext_matches, pattern_key_to_enc_word_map)
            else:
                # Adding this encrypted word to the product resulted in no matches. This doesn't necessarily mean
                # that this word is the problem. However, the best we can do at this stage is remove it and continue.
                deducted_plaintext_matches.pop(encrypted_word_pattern_key)
                matched_encrypted_words.remove(encrypted_word)
                unmatched_encrypted_words.append(encrypted_word)

                logger.info(self.__bold_string(f"\nNo tuple matches found for {encrypted_word}. Removed."))

            # Do we need to decrypt anymore words or do we have enough characters mapped to quit and build a cyphertext alphabet?
            all_characters_examined = self.__unique_alpha_chars_in_string(''.join(matched_encrypted_words)) == unique_encrypted_characters
            last_index = index == (len(encrypted_word_and_plaintext_matches) - 1)

            break_early = False
            if all_characters_examined and not last_index:
                logger.info("\nWe have examined all of the possible characters. Checking if we can break early...")

                break_early = True
                for matches in deducted_plaintext_matches:
                    if not len(deducted_plaintext_matches[matches]) == 1:
                        logger.info("\nNot breaking due to some words having more than one possible match.\n")
                        break_early = False
                        break

            if break_early:
                logger.info("\nBreaking early. We have all possible characters and one match for each currently examined word.\n")
                break

        # Get the plaintext and cyphertext alphabets.
        alphabets_map = self.__build_alphabets_map(matched_encrypted_words, unmatched_encrypted_words, deducted_plaintext_matches)

        # Pad with all ascii alphabet characters.
        alphabets_map = self.__pad_alphabets_map(alphabets_map)

        logger.info(f"\nTotal tuples examined: {total_tuples_compared}")

        return alphabets_map

    def decrypt_message(self, encrypted_message: str, alphabets_map: dict) -> str:
        """Decrypts an encrypted string using the given alphabets_map."""
        decrypted_message_list = list(encrypted_message)
        for index, symbol in enumerate(encrypted_message):

            if symbol.upper() in alphabets_map:
                replacement = alphabets_map[symbol.upper()]
                if len(replacement) > 1:
                    replacement = '[{0}]'.format(','.join(replacement))
                else:
                    replacement = replacement[0]

                if symbol.isupper():
                    replacement = replacement.upper()
                else:
                    replacement = replacement.lower()

                decrypted_message_list[index] = replacement

        decrypted_message = ''.join(decrypted_message_list)

        return decrypted_message

    def __string_to_indexed_pattern(self, index: int, encrypted_word: str) -> str:
        """
        Creates an indexed word pattern - rather than just the word pattern. This is to ensure that
        different words with the same pattern e.g. 'good' and 'food' will have their own entry in the map.
        """
        return str(index) + '-' + StringPattern(encrypted_word).get_pattern()

    def __get_plaintext_matches_for_encrypted_word(self, encrypted_word: str) -> list:
        encrypted_word_pattern = StringPattern(encrypted_word).get_pattern()
        if encrypted_word_pattern in wordpatterns.patterns:
            return wordpatterns.patterns[encrypted_word_pattern]

        return list()

    def __get_plaintext_matches_for_encrypted_words(self, encrypted_words: list) -> dict:
        """Returns a dict of encrypted words and a list of plaintest matches"""
        encrypted_words_and_plaintext_matches = dict()

        for encrypted_word in encrypted_words:
            if encrypted_word not in encrypted_words_and_plaintext_matches:
                encrypted_word_pattern = StringPattern(encrypted_word).get_pattern()
                if encrypted_word_pattern in wordpatterns.patterns:
                    encrypted_words_and_plaintext_matches[encrypted_word] = wordpatterns.patterns[encrypted_word_pattern]
                else:
                    encrypted_words_and_plaintext_matches[encrypted_word] = list()

        return encrypted_words_and_plaintext_matches

    def __get_ordered_encrypted_word_and_plaintext_matches(self, encrypted_words: list, examine_word_order: ExamineOrder) -> dict:
        """Returns an OrderedDict of encrypted words and a list of plaintest matches"""
        if examine_word_order == ExamineOrder.FEWEST_TO_MOST_MATCHES or examine_word_order == ExamineOrder.MATCHES_DIVIDED_BY_LENGTH:
            # Pre-fetch matches and re-order by number of fewest to most number of matches.
            encrypted_word_and_plaintext_matches = self.__get_plaintext_matches_for_encrypted_words(encrypted_words)

            if examine_word_order == ExamineOrder.FEWEST_TO_MOST_MATCHES:
                # Re-order by fewest to most plaintext matches for the encrypted word.
                return OrderedDict(sorted(encrypted_word_and_plaintext_matches.items(), key=lambda item: len(item[1]), reverse=False))

            if examine_word_order == ExamineOrder.MATCHES_DIVIDED_BY_LENGTH:
                # Re-order by number of plaintext matches divided by the encrypted word length.
                return OrderedDict(sorted(encrypted_word_and_plaintext_matches.items(), key=lambda item: len(item[1])/len(item[0]), reverse=False))
        else:
            # Default: ExamineOrder.LONGEST_TO_SHORTEST - Don't pre-fetch matches.
            sorted_encrypted_words = sorted(encrypted_words, key=lambda enc_word: len(enc_word), reverse=True)
            return OrderedDict([(key, None) for key in sorted_encrypted_words])

    @staticmethod
    def __unique_alpha_chars_in_string(string: str) -> int:
        return sum(map(str.isalpha, set(''.join(string.split()))))

    @staticmethod
    def __get_normalised_encrypted_words(encrypted_text: str) -> list:
        """Normalises the encrypted text and splits into a list of words."""
        # Convert unicode to ascii.
        normalised_encrypted_words = unidecode(encrypted_text)

        # Replace ascii hyphens and dashes with spaces.
        normalised_encrypted_words = normalised_encrypted_words.replace('-', ' ')

        # Remove remaining punctuation
        normalised_encrypted_words = normalised_encrypted_words.translate(str.maketrans('', '', string.punctuation))

        # Transform to uppercase and split.
        normalised_encrypted_words = normalised_encrypted_words.upper().split()

        # Remove words that aren't fully alphabetic e.g. "1,000".
        normalised_encrypted_words = [w for w in normalised_encrypted_words if w.isalpha()]

        # Remove duplicates.
        return list(dict.fromkeys(normalised_encrypted_words))

    def __build_alphabets_map(self, matched_encrypted_words: list, unmatched_encrypted_words: list, deducted_plaintext_matches: dict) -> dict:
        """
        Returns an OrderedDict keyed by the unique characters from the encrypted words. Each value is a list
        of and 1 or more possible plaintext matches, or '?' if unknown.
        """
        UNKNOWN_CHAR = '?'
        alphabets_map = dict()

        for index, encrypted_word in enumerate(matched_encrypted_words, start=1):
            encrypted_word_indexed_key = self.__string_to_indexed_pattern(index, encrypted_word)

            plaintext_matches = deducted_plaintext_matches[encrypted_word_indexed_key]

            for plaintext_match in plaintext_matches:
                for (plaintext_letter, enc_letter) in zip(plaintext_match, encrypted_word):
                    enc_letter = enc_letter.upper()
                    plaintext_letter = plaintext_letter.upper()

                    if enc_letter not in alphabets_map:
                        alphabets_map[enc_letter] = list()

                    current_letters = alphabets_map[enc_letter]

                    if plaintext_letter not in current_letters:
                        current_letters.append(plaintext_letter)

                        if UNKNOWN_CHAR in current_letters:
                            current_letters.remove(UNKNOWN_CHAR)

                    alphabets_map[enc_letter] = current_letters

        for encrypted_word in unmatched_encrypted_words:
            for enc_letter in encrypted_word:
                if enc_letter not in alphabets_map:
                    alphabets_map[enc_letter] = [UNKNOWN_CHAR]

        # Order by keys alphabetically.
        return OrderedDict(sorted(alphabets_map.items()))

    def __log_deducted_plaintext_match_counts(self, deducted_plaintext_matches: dict, pattern_key_to_enc_word_map: dict) -> None:
        left_just = len(max(pattern_key_to_enc_word_map.values(), key=len))
        for deducted_plaintext_match in deducted_plaintext_matches:
            encrypted_word = pattern_key_to_enc_word_map[deducted_plaintext_match]
            len_matches = len(deducted_plaintext_matches[deducted_plaintext_match])
            logger.info(f"{self.__bold_string(encrypted_word.ljust(left_just))} has {self.__bold_string(len_matches)} possible matches")

    @staticmethod
    def __pad_alphabets_map(alphabets_map: dict) -> dict:
        """Fill in the cyphertext alphabet with ascii letters that aren't part of the encrypted text."""
        PADDING_CHAR = '-'

        for ascii_letter in string.ascii_uppercase:
            if ascii_letter not in alphabets_map:
                alphabets_map[ascii_letter] = [PADDING_CHAR]

        # Order by keys alphabetically.
        return OrderedDict(sorted(alphabets_map.items()))

    @staticmethod
    def __bold_string(string: str) -> str:
        return f"\033[1m{string}\033[0m"
