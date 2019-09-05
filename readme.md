# pyMIH
A python implementation of multiple index hashing by [Norouzi et al](https://www.cs.toronto.edu/~norouzi/research/papers/multi_index_hashing.pdf), based on a description in the [threatexchange repository](https://github.com/facebook/ThreatExchange/blob/master/hashing/hashing.pdf)

***

### Description
Multiple Index Hashing (MIH) is a relatively lightweight means for accelerating lookups for fuzzy hashes (e.g. PhotoDNA and [PDQ](https://github.com/facebook/ThreatExchange/tree/master/hashing/pdq)) within a pre-defined [hamming distance](https://math.ryerson.ca/~danziger/professor/MTH108/Handouts/codes.pdf).
Instead of a linear search through every record, multiple indices are made for separate windows/slots *within* each hash.
The threatexchange document (linked above) provides a good, 'plain English' description for those who (like me) struggle with mathematical terminology and notation.

***

### Usage
```python
from pyMIH import MIHIndex
# Defaults to a 256 bit hash size
x = MIHIndex()

# For alternate hash sizes, enter bit size at declaration
x = MIHIndex(512)

# Example - load hashes from file.
# Update function only accepts hex strings (4 bits per char)
PDQs = set()
with open('ignorable.PDQ') as fi:
    for line in fi:
        PDQs.add(line.replace('\n', ''))

# Add to index
x.update(PDQs)

# Train index. Word length is internal slot/word size for individual indices (see afore mentioned documentation for more info)
# Threshold is maximum hamming distance (inclusive). Defaults to values shown here.
x.train(wordLength=16,threshold=32)

# To query, pass in a hex string
for y in x.query('358c86641a5269ab5b0db5f1b2315c1642cef9652c39b6ced9f646d91f071927'):
    # hits are returned as a tuple of hash value and hamming distance. 
    print(y)
    # ('358c86641a5269ab5b0db5f1b2315c1642cef9652c39b6ced9f646d91f071927', 0)          
    # ('358c86641a5269ab5b0db5f1b2315c1642cef9652c39b6ced9f646d91f071928', 4)

``` 

***
 ### Licensing
This is released under an MIT licence. This project utilises [bitarray](https://pypi.org/project/bitarray/), at time of writing, released under the Python Software Foundation License (PSF).  
***
