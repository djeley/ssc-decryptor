import argparse
import codecs
import importlib
import itertools
import logging
import os
import pprint
import string
import sys
import time
import types
from collections import OrderedDict
from pathlib import Path

import tableformatter

from decryptor.examineorder import ExamineOrder
from decryptor.stringpattern import StringPattern

logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger()

def main(args):
    verbose_info = args.verbose_info
    verbose_debug = args.verbose_debug
    words_files = args.words_files
    examine_word_order = ExamineOrder[args.order]
    suppress_encrypted_text_output = args.suppress_encrypted_text_output

    decryptor_log_level = logging.WARN
    if verbose_info:
        decryptor_log_level = logging.INFO
    if verbose_debug:
        decryptor_log_level = logging.DEBUG

    # Create wordpatterns module from the given words files.
    _build_word_patterns_module(words_files, "decryptor/wordpatterns.py")

    from decryptor.decryptor import SscDecryptor
    decryptor = SscDecryptor(decryptor_log_level)

    # Get the encrypted message text.
    encrypted_message = _get_encrypted_message(args)

    logger.info("Decrypting...\n")
    begin_decrypt = time.perf_counter()

    # Invoke the main decryptor function.
    alphabets_map = decryptor.deduce_ciphertext_alphabet(encrypted_message, examine_word_order)

    # Print the alphabets table.
    _print_alphabets(alphabets_map)

    # Decrypt (translate) the message.
    decrypted_message = decryptor.decrypt_message(encrypted_message, alphabets_map)

    end_decrypt = time.perf_counter()

    logger.info(f"Total time to decrypt: {end_decrypt - begin_decrypt:0.4f} seconds")

    if not suppress_encrypted_text_output:
        logger.info(_bold_string("\nEncrypted message:"))
        logger.info(encrypted_message)
        logger.info("")

    logger.info(_bold_string("\nDecrypted message:"))
    logger.info(decrypted_message)
    logger.info("")


def _load_plaintext_words(words_file: str) -> list:
    with codecs.open(words_file, 'r', encoding='utf-8', errors="ignore") as words:
        return [word.rstrip().translate(str.maketrans('', '', string.punctuation)) for word in words]


def _build_word_patterns_module(words_files: list, module_file: str) -> types.ModuleType:
    """Generate patterns for all dictionary words and returns as a Python module"""
    module_name = ('.').join(module_file.split('.')[:-1])
    module_name = module_name.replace('/', '.')

    wordpatterns = None
    if os.path.exists(module_file):
        wordpatterns = importlib.import_module(module_name)

        if len(words_files) == len(set(words_files).intersection(wordpatterns.words_files)):
            return wordpatterns
        else:
            os.remove(module_file)

    words = list()
    for words_file in words_files:
        words.extend(_load_plaintext_words(words_file))

    # Remove any duplicates.
    words = list(dict.fromkeys(words))

    # Generate the patterns.
    patterns = dict()
    for word in words:
        pattern = StringPattern(word).get_pattern()
        if pattern not in patterns:
            patterns[pattern] = list()

        patterns[pattern].append(word.upper())

    # Write to a new module.
    wordpatterns_module = open(module_file, 'w')
    wordpatterns_module.write(f"words_files = {pprint.pformat(words_files)}\n")
    wordpatterns_module.write(f"patterns = {pprint.pformat(patterns)}")
    wordpatterns_module.close()

    if wordpatterns is not None:
        wordpatterns = importlib.reload(wordpatterns)
    else:
        wordpatterns = importlib.import_module(module_name)

    return wordpatterns


def _print_alphabets(alphabets_map: dict) -> None:
    columns = ['Cypher alphabet']
    columns.extend(alphabets_map.keys())
    rows = list()
    for value in itertools.zip_longest(*alphabets_map.values(), fillvalue=None):
        value_list = list(value)
        if len(rows) == 0:
            value_list.insert(0, 'Plain alphabet')
        else:
            value_list.insert(0, None)

        rows.append(tuple(value_list))

    #print("")
    # tableformatter doesn't appear to prevent further bold formatting.
    logger.info(tableformatter.generate_table(rows, columns)+"\033[0m")


def _get_encrypted_message(args: argparse.Namespace) -> str:
    encrypted_message = str()
    if args.message_file is not None:
        for line in args.message_file.readlines():
            # Ignore blank lines before we get to any text.
            if len(encrypted_message) == 0 and len(line.lstrip()) == 0:
                continue

            # Ignore commented lines.
            if not line.startswith("#"):
                encrypted_message += line
    else:
        encrypted_message = args.message

    return encrypted_message


def _bold_string(string: str) -> str:
    return f"\033[1m{string}\033[0m"


if __name__ == '__main__':
    """Command line arguments parsing and setup."""
    parser = argparse.ArgumentParser()

    msg_group = parser.add_mutually_exclusive_group()
    msg_group.add_argument("-m", "--message", help="An encrypted message")
    msg_group.add_argument("-f", "--message-file", type=argparse.FileType("r"), help="An encrypted message text file")

    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument("-v", "--verbose-info", default=False, action="store_true", help="Makes the decryptor output more verbose")
    verbosity_group.add_argument("-vv", "--verbose-debug", default=False, action="store_true", help="Makes the decryptor output even more verbose")

    parser.add_argument("-s", "--suppress-encrypted-text-output", default=False, action="store_true", help="Suppresses the encrypted text from the output")
    parser.add_argument('-w', '--words-files', action='store', type=str, nargs='*', default=['words/dictionary.txt'],
                        help="Dictionary (words) files. Example: -w words/dictionary.txt words/names.txt")
    parser.add_argument("-o", "--order", default="LONGEST_TO_SHORTEST", choices=[e.name for e in ExamineOrder], help="The word examine order")

    args = parser.parse_args()

    main(args)
