from setuptools import setup
from setuptools import find_packages
from distutils.core import setup

"""Returns contents of README.md."""
with open("README.md", "r", encoding="utf-8") as readme_fp:
    long_description = readme_fp.read()

setup(
  name = 'superpehasher',
  packages = ['superpehasher'],
  version = '0.5',
  license='Apache',
  author='Thomas Roccia @fr0gger_',
  description = 'SuperPEHasher is a wrapper written in Python3 for several hash algorithms dedicated to PE file.',
  long_description=long_description,
  long_description_content_type='text/markdown',
  url = 'https://github.com/fr0gger/SuperPeHasher',
  keywords = ['hashes', 'md5', 'sha256'],
  install_requires=[
          'mmh3',
          'pefile',
          'pyimpfuzzy',
          'ssdeep',
          'r2pipe',
          'hashlib',
          'bitstring'
      ],
  classifiers=[
    'Development Status :: 5 - Production/Stable',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: Apache Software License',
    'Programming Language :: Python :: 3',
  ],
)