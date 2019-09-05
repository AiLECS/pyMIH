from setuptools import setup

setup(
    name='pyMIH',
    version='0.7.0',
    packages=[''],
    url='https://github.com/AiLECS/pyMIH',
    license='MIT',
    author='Janis Dalins',
    author_email='janis.dalins@monash.edu',
    description='Python implementation of Multiple-Index Hashing (MIH), an efficient technique for accelerating lookups for fuzzy hashes such as PDQ.',
    long_description='A python implementation of multiple index hashing (MIH) by Norouzi et al (see https://www.cs.toronto.edu/~norouzi/research/papers/multi_index_hashing.pdf), based on a description in the Threatexchange repository (see https://github.com/facebook/ThreatExchange/blob/master/hashing/hashing.pdf).\n See homepage for usage instructions'
)
