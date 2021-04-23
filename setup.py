from distutils.core import setup

"""Returns contents of README.md."""
with open("README.md", "r", encoding="utf-8") as readme_fp:
    long_description = readme_fp.read()

setup(
  name = 'superpehasher',
  packages = ['superpehasher'],
  version = '0.4',
  license='APACHE',
  description = 'SuperPEHasher is a wrapper written in Python3 for several hash algorithms dedicated to PE file.',
  long_description=long_description,
  url = 'https://github.com/fr0gger/SuperPeHasher',
  keywords = ['hashes', 'md5', 'sha256'],
  install_requires=[            # I get to this in a second
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
    'License :: OSI Approved :: Apache 2 License',   # Again, pick a license
    'Programming Language :: Python :: 3',
  ],
)