from bitarray import bitarray
from math import floor
import re


class MIHIndex:
    """
    Implementation of MIH algorithm (see https://www.cs.toronto.edu/~norouzi/research/papers/multi_index_hashing.pdf
        (refer brief doc at https://github.com/facebook/ThreatExchange/blob/master/hashing/hashing.pdf)
    """
    def __init__(self, hashsize=256):
        """
        :param hashsize: Hash size in bits (not: NOT string length!)
        """
        if hashsize % 8 != 0:
            raise ValueError('hashsize ' + str(hashsize) + ' is not a multiple of 8')
        self._hashlength = hashsize
        self._items = []
        self._trained = False
        self._pattern = re.compile('^[a-f0-9]{' + str(int(hashsize/4)) + '}$', re.IGNORECASE)
        self._floor = None
        self._words = None
        self._wordlength = None
        self._threshold = None
        self._cache = None

    #candidate for cache tools here!
    def _getwindow(self, word, distance=2, _position=0, _entries=set()):
        """
        Calculate and return a set of all hex combinations within the provided hamming distance

        >>> x = MIHIndex()
        >>> b = bitarray()
        >>> b.frombytes(bytes.fromhex('358c'))
        >>> len(x._getwindow(b,distance = 1))
        17

        >>> len(_getwindow(b,distance = 2))
        137

        :param word: candidate word as bitarray
        :param distance: Maximum hamming distance (inclusive). Defaults to 2
        :param _position: Position to commence comparison. For internal (recursive) use only.
        :param _entries: Set of possible entries. For internal (recursive) use only.
        :return: set of hex strings within provided hamming distance of candidate word.
        """

        if _position == len(word):
            _entries.add(word.tobytes().hex())
            return _entries
        if distance > 0:
            temp = word[_position]
            for i in [True, False]:
                word[_position] = i
                distOffset = 0
                if temp != word[_position]:
                    distOffset = -1
                _entries.update(self._getwindow(word, distance + distOffset, _position+1, _entries))
            word[_position] = temp
        else:
            _entries.update(self._getwindow(word, distance, _position+1, _entries))
        return _entries

    def update(self, new):
        """
        Add more entries for indexing. Only accepts iterables of hex strings

        Keyword arguments:
        new -- iterable of hex strings to add
        """
        if isinstance(new, str):
            new = []
        for x in new:
            if self._pattern.fullmatch(x):
                self._items.append(x)
                self._trained = False
            else:
                raise ValueError('Not a valid hex string: ' + str(x))

    # train the index.
    def train(self, wordLength=16, threshold=32):
        """
        Train and initialise the index. (i.e. make it queryable)
        :param wordLength: Word length (in bits). Defaults to 16
        :param threshold:  Threshold for matching - i.e. hamming distance needs to be <= to guarantee entry to be returned. Defaults to 32
        :return: None
        """
        items = set(self._items)
        self._items = []
        length = -1
        for i in items:
            # convert to bit array
            b = bitarray()
            b.frombytes(bytes.fromhex(i))
            if len(b) != self._hashlength:
                raise ValueError('Invalid hash length encountered: ' + i)
            self._items.append(b)


        self._floor = floor(threshold/wordLength)

        self._words = []
        for i in range(0, self._hashlength, wordLength):
            w = {}
            for c in range(0, len(self._items)):
                hex = self._items[c][i:i+wordLength].tobytes().hex()
                if hex not in w.keys():
                    w[hex] = {c}
                else:
                    w[hex].add(c)
            for k in w.keys():
                w[k] = frozenset(w[k])
            self._words.append(w)

        self._trained = True
        self._wordlength = wordLength
        self._threshold = threshold

    # Check hamming distance - iterate through list. Returns None if distance exceeded
    @staticmethod
    def _gethamming(hash1, hash2, maxhd=None):
        """
        Calculate hamming distance between hashes
        :param hash1: Candidate hash
        :param hash2: Comparison hash
        :param maxhd: Maximum hamming distance. If none, defaults to length of hash1
        :return: Hamming distance if <= maxhd, else None
        """
        if maxhd is None:
            maxhd = len(hash1)
        hd = 0
        for b1, b2 in zip(hash1, hash2):
            if b1 != b2:
                hd += 1
                if hd > maxhd:
                    return None
        return hd

    def query(self, h):
        """
        Query index for candidates within pre-set hamming distance threshold (set at train())
        :param h: Candidate hash (hex string)
        :return: Generator returning matches as tuples (<hex>, <hamming distance>) format
        """
        if not self._trained:
            raise ValueError('Index not trained yet')
        b = bitarray()
        b.frombytes(bytes.fromhex(h))
        candidates = set()
        c = 0
        for i in range(0, self._hashlength, self._wordlength):
            window = self._getwindow(b[i:i+self._wordlength])
            for w in window:
                if w in self._words[c]:
                    for x in self._words[c][w]:
                        if x not in candidates:
                            r = self._gethamming(b, self._items[x], self._threshold)
                            if r is not None:
                                yield self._items[x].tobytes().hex(), r
                            candidates.add(x)
            c += 1

