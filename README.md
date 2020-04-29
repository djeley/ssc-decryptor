# ssc-decryptor
A Python 3 script for decrypting text encrypted with [monoalphabetic/simple substitution ciphers](https://en.wikipedia.org/wiki/Substitution_cipher#Simple_substitution), where word boundaries remain in place, using a technique that I will call *combined pattern deduction*.

## Installation
Install required packages using `pip`:

`pip install -r requirements.txt`

## About
Each encrypted word from an encrypted message will have zero or more matching plaintext words that share the same [word pattern](http://pajhome.org.uk/crypt/wordpat.html). This script attempts to decipher encrypted messages by reducing the number of plaintext matches for each encrypted word to one (ideally).

__Example:__

Encrypted Word | Pattern   | No. Plaintext Matches
---------------|-----------|------------------
WSNNHGDK       |8-12334567 |675
SJJQGSJB       |8-12234125 |4
FTKJPAHG       |8-12345678 |5762

This number of tuples in the 3-fold cartesian product of the plaintext matches for these 3 words is ~15,000,000.

However, by sequentially combining encrypted words and comparing the longer pattern with the pattern of each combined tuple in the cartesian product of the plaintext matches, the number of matches for each word can be reduced to one by examining ~50,000 tuples.

## Decryption process: High-level Overview
The decryption process utilises word patterns and combines words to create larger, more useful, patterns. Consider the following two encrypted words and their corresponding patterns:

Encrypted Word | Pattern   
---------------|-----------
`S`JJQG`S`JB   |8-`1`2234`1`25
W`S`NNHGDK     |8-1`2`334567

In the first word, `S` is identified with a `1`. In the second word, `S` is identified with a `2`. If we combine both words and create a new pattern, such as:

Encrypted Word | Pattern   
---------------|-----------
`S`JJQG`S`JBW`S`NNHGDK       |16-`1`2234`1`256`1`77849A

Then in the new pattern we can now see that `S` is identified with a `1` for all three occurrences.

It is now possible to say that: *any set in the cartesian product of the plaintext matches for each of the individual word patterns that doesn't have the same combined pattern, can be deducted from the original sets of plaintext matches.*

We can keep building and comparing larger patterns as we iterate through the encrypted words in sequence, and through this process of deduction, we can determine a cyphertext alphabet to decrypt the message.

__*Note: You can run the script using the verbose (-v) flag and see this deduction in action*__

### Two Word Example
 * __PQACEIAMNSXU__ has __23__ word pattern matches
 * __RWCTJSXSZA__   has __261__ word pattern matches

By creating a combined pattern from __PQACEIAMNSXU__ and __RWCTJSXSZA__ and comparing it with a combined pattern for each tuple in the cartesian product of each word's word pattern matches, then there is only __1__ possible match for each word:

 * __PQACEIAMNSXU__ has __1__ word pattern matches
 * __RWCTJSXSZA__   has __1__ word pattern matches

"__*OVERWHELMING SCRUTINIZE*__"

Total tuples compared: (23 x 261) = 6,003

### Three Word Example

 * __OCUBICBP__ has __53__ word pattern matches
 * __KCXXPQUN__ has __675__ word pattern matches
 * __PUBOMNV__ has __8585__ word pattern matches

__First iteration__
 * __OCUBICBP__ has __53__ word pattern match
 * __KCXXPQUN__ has __675__ word pattern match

By creating a combined pattern from __OCUBICBP__ and __KCXXPQUN__ and comparing it with a combined pattern for each tuple in the cartesian product of each word's word pattern matches, then there are __6__ possible matches for __OCUBICBP__ and __7__ possible matches for __KCXXPQUN__.

__Second iteration after deductions__
 * __OCUBICBP__ has __6__ word pattern matches
 * __KCXXPQUN__ has __7__ word pattern matches
 * __PUBOMNV__  has __8585__ word pattern matches

By creating a combined pattern from __OCUBICBP__, __KCXXPQUN__ and __PUBOMNV__, and comparing it with a combined pattern for each tuple in the cartesian product of each word's word pattern matches, then there is only __1__ possible match for each word:

 * __OCUBICBP__ has __1__ word pattern match
 * __KCXXPQUN__ has __1__ word pattern match
 * __PUBOMNV__  has __1__ word pattern match

"__*ENGLISH LANGUAGE PATTERNS*__"

Total tuples compared: (53 x 675) + (6 x 7 x 8585) = 396,345

## Encrypted Word Ordering for Examination
The first step of the decryption process is to split the encrypted message into normalised alphabetic words. This can involve converting unicode characters to ascii, removing punctuation, transforming to uppercase, removing duplicates etc. We then need to consider the examination order of the words - taking into account that the larger the number of items in the cartesian product, then the more iterations/comparisons will be required.

There are 3 ordering options:
1. __LONGEST_TO_SHORTEST__: Longest length word to the shortest. In general, combing the largest words first will result in a large number of deductions early in the process. This is the default ordering option.
2. __FEWEST_TO_MOST_MATCHES__: Word with the fewest plaintext matches to the most. In general, LONGEST_TO_SHORTEST decrypts with the least iterations and is therefore quicker. However, `message_example_2.txt` is an example where FEWEST_TO_MOST_MATCHES is better.
3. __MATCHES_DIVIDED_BY_LENGTH__: Number of plaintext matches divided by the length of the word.


## Weaknesses
 * Depends on a word list (dictionary).
 * When a word isn't present in the dictionary, it *could* cause issues if the ordering places the word in the first two words to be examined.
 * Can struggle with some shorter sentences where each word has a lot of pattern matches.
 * Doesn't attempt to decrypt numbers.

## Strengths
 * Can often handle words not being present in the dictionary. For example:
 
    __Cyphertext:__
    
    `Zozm Nzgsrhlm Gfirmt LYV UIH; 23 Qfmv 1912 – 7 Qfmv 1954) dzh zm Vmtorhs nzgsvnzgrxrzm, xlnkfgvi hxrvmgrhg, oltrxrzm, xibkgzmzobhg, ksrolhlksvi, zmw gsvlivgrxzo yrloltrhg.`

    __Decrypts to:__

    `Alan Mathison Turing OBE [F,K,Q]RS; 23 June 1912 – 7 June 1954) [k,v,w,f]as an English mathematician, computer scientist, logician, cryptanalyst, philosopher, and theoretical biologist.`

    This isn't perfect as `U` mapped to `F, K, or Q` and `d` mapped to `k, v, w, or f`. This is because `frs`, `krs`, `qrs`, `kas`, `vas`, `was`, and `fas` are all words present in the `dictionary.txt` file, and there isn't enough information to determine a one-to-one mapping for `U` and `d`. 
    
    However, the word `Mathison` is not present in the dictionary but we can still decrypt is as we have deciphered the individual characters from other words that are in the dictionary.
 * Can be fast and very accurate.

## Usage

```
usage: decrypt.py [-h] [-m MESSAGE | -f MESSAGE_FILE] [-v | -vv] [-s]
                  [-w [WORDS_FILES [WORDS_FILES ...]]]
                  [-o {LONGEST_TO_SHORTEST,FEWEST_TO_MOST_MATCHES,MATCHES_DIVIDED_BY_LENGTH}]

optional arguments:
  -h, --help            show this help message and exit
  -m MESSAGE, --message MESSAGE
                        An encrypted message
  -f MESSAGE_FILE, --message-file MESSAGE_FILE
                        An encrypted message text file
  -v, --verbose-info    Makes the decryptor output more verbose
  -vv, --verbose-debug  Makes the decryptor output even more verbose
  -s, --suppress-encrypted-text-output
                        Suppresses the encrypted text from the output
  -w [WORDS_FILES [WORDS_FILES ...]], --words-files [WORDS_FILES [WORDS_FILES ...]]
                        Dictionary (words) files. Example: -w
                        words/dictionary.txt words/names.txt
  -o {LONGEST_TO_SHORTEST,FEWEST_TO_MOST_MATCHES,MATCHES_DIVIDED_BY_LENGTH}, --order {LONGEST_TO_SHORTEST,FEWEST_TO_MOST_MATCHES,MATCHES_DIVIDED_BY_LENGTH}
                        The word examine order
```

__Example usage:__

`python3 decrypt.py -f message_examples/message_example_10.txt`

Attempts to decrypt the contents of the `message_examples/message_example_10.txt` file using default word ordering LONGEST_TO_SHORTEST.


`python3 decrypt.py -f message_examples/message_example_10.txt -o FEWEST_TO_MOST_MATCHES`

Attempts to decrypt the contents of the message_examples/message_example_10.txt` file using FEWEST_TO_MOST_MATCHES word ordering.

## Message Examples:
There are a number of encrypted message examples provided in this repository. The screenshots below show the output for each one.

__message_example_1.txt__
![message_example_1](/screenshots/message_example_1.png)

__message_example_2.txt__
![message_example_2](/screenshots/message_example_2.png)

__message_example_3.txt__
![message_example_3](/screenshots/message_example_3.png)

__message_example_4.txt__
![message_example_4](/screenshots/message_example_4.png)

__message_example_5.txt__
![message_example_5](/screenshots/message_example_5.png)

__message_example_6.txt__
![message_example_6](/screenshots/message_example_6.png)

__message_example_7.txt__
![message_example_7](/screenshots/message_example_7.png)

__message_example_8.txt__
![message_example_8](/screenshots/message_example_8.png)

__message_example_9.txt__
![message_example_9](/screenshots/message_example_9.png)

__message_example_10.txt__
![message_example_10](/screenshots/message_example_10.png)

__message_example_11.txt__
![message_example_11](/screenshots/message_example_11.png)

__message_example_12.txt__
![message_example_12](/screenshots/message_example_12.png)

__message_example_13.txt__
![message_example_13](/screenshots/message_example_13.png)

__message_example_14.txt__
![message_example_14](/screenshots/message_example_14.png)

__message_example_15.txt__
![message_example_15](/screenshots/message_example_15.png)