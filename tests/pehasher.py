from superpehasher import superpehasher

import sys

# Test
malf = superpehasher.SuperPEHasher(sys.argv[1])
binary = sys.argv[1]
print("md5: \t\t" + malf.get_md5())
print("sha1: \t\t" + malf.get_sha1())
print("sha256: \t" + malf.get_sha2())
print("sha512: \t" + malf.get_sha5())
print("ssdeep: \t" + malf.get_ssdeep())
print("ImpHash: \t" + malf.get_imphash())
print("ImpFuzzy: \t" + malf.get_impfuzzy())
xored_richhash, clear_richhash = malf.get_richhash
print("RicHash xored: \t" + xored_richhash)
print("RicHash clear: \t" + clear_richhash)
print("PeHash: \t" + malf.get_pehash())
print("Machoc Hash: \t" + malf.get_machoc_hash())

