#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Super PE Hasher version 1.1 python 3 support - Thomas Roccia - @fr0gger_

This library is a wrapper to use hash algorithm including the following:
MD5, SHA1, SHA2, ImpHASH, IMPFUZZY, SSDEEP, Rich Header Hash, Murmurhash, Machoc Hash, PEHASH

"""

import hashlib
import os
import re
import sys
import mmh3
import tempfile
import pefile
import pyimpfuzzy
import ssdeep
import r2pipe
import json

from bz2 import compress
from bitstring import pack


class SuperPEHasher:
    def __init__(self, filename):
        """Definition of the kind of file"""
        try:
            exe = pefile.PE(filename)
        except OSError as e:
            print(e)
            sys.exit()
        except pefile.PEFormatError as e:
            print("[-] PEFormatError: %s" % e.value)
            print("[!] The file is not a valid PE")
            sys.exit()

        # Remove error output
        err = tempfile.NamedTemporaryFile(delete=False)
        sys.stderr.flush()
        os.dup2(err.fileno(), sys.stderr.fileno())

        self.file_read = open(filename, "rb")
        self.pe = exe
        self.filename = filename
        self.r2p = r2pipe.open(filename)

    def get_content(self):
        # Read the file
        fh = open(file, "r")
        content = ""
        for i in fh:
            content += i
        fh.close()
        return content

    def get_md5(self):
        # Get MD5
        fic = self.file_read
        c = hashlib.md5()
        while 1:
            try:
                d = fic.next()
                c.update(d)
            except:
                break
        return c.hexdigest()

    def get_sha1(self):
        # Get Sha1
        fic = open(self.filename, "r")
        c = hashlib.sha1()
        while 1:
            try:
                d = fic.next()
                c.update(d)
            except:
                break
        return c.hexdigest()

    def get_sha2(self):
        # Get Sha2
        fic = open(self.filename, "r")
        c = hashlib.sha256()
        while 1:
            try:
                d = fic.next()
                c.update(d)
            except:
                break
        return c.hexdigest()

    def get_sha5(self):
        # Get sha5
        fic = open(self.filename, "r")
        c = hashlib.sha512()
        while 1:
            try:
                d = fic.next()
                c.update(d)
            except:
                break
        return c.hexdigest()

    def get_ssdeep(self):
        # Get ssdeep
        filename = self.filename
        hashdeep = ssdeep.hash_from_file(filename)

        return hashdeep

    def get_imphash(self):
        # Get imphash
        pe = self.pe
        ih = pe.get_imphash()
        return ih

    def get_impfuzzy(self):
        # Get impfuzzy
        filename = self.filename
        impfuzzy = pyimpfuzzy.get_impfuzzy(filename)
        return impfuzzy

    @property
    def get_richhash(self):

        # get richhash
        fh = open(self.filename, "rb")
        content = fh.read()

        try:
            xorkey = re.search(b"\x52\x69\x63\x68....\x00", content).group(0)[4:8]
            dansAnchor = []

            for x, y in zip(xorkey, b"\x44\x61\x6e\x53"):
                xored = x ^ y
                dansAnchor.append(xored)
            dansAnchor = bytes(dansAnchor)

        except:
            return "No Rich header available", "No Rich header available"

        richStart = re.search(re.escape(dansAnchor), content).start(0)
        richEnd = re.search(b"\x52\x69\x63\x68" + re.escape(xorkey), content).start(0)

        if richStart < richEnd:
            rhData = content[richStart:richEnd]
        else:
            raise Exception("The Rich header is not properly formated!")

        clearData = []
        for i in range(0, len(rhData)):
            clearData.append(rhData[i] ^ xorkey[i % len(xorkey)])

        clearData = bytes(clearData)

        xored_richhash = hashlib.md5(rhData).hexdigest().lower()
        clear_richhash = hashlib.md5(clearData).hexdigest().lower()
        fh.close()

        return xored_richhash, clear_richhash

    def get_mmh(self):
        # Get murmurhash
        filename = self.filename
        mmhash = mmh3.hash(filename)
        return mmhash

    def get_pehash(self):
        # Get Pehash
        # https://github.com/AnyMaster/pehash/blob/master/pehash.py
        exe = self.pe

        # Image Characteristics
        img_chars = pack("uint:16", exe.FILE_HEADER.Characteristics)
        pehash_bin = img_chars[0:8] ^ img_chars[8:16]

        # Subsystem
        subsystem = pack("uint:16", exe.OPTIONAL_HEADER.Subsystem)
        pehash_bin.append(subsystem[0:8] ^ subsystem[8:16])

        # Stack Commit Size, rounded up to a value divisible by 4096,
        # Windows page boundary, 8 lower bits must be discarded
        # in PE32+ is 8 bytes
        stack_commit = exe.OPTIONAL_HEADER.SizeOfStackCommit
        if stack_commit % 4096:
            stack_commit += 4096 - stack_commit % 4096
        stack_commit = pack("uint:56", stack_commit >> 8)
        pehash_bin.append(
            stack_commit[:8]
            ^ stack_commit[8:16]
            ^ stack_commit[16:24]
            ^ stack_commit[24:32]
            ^ stack_commit[32:40]
            ^ stack_commit[40:48]
            ^ stack_commit[48:56]
        )

        # Heap Commit Size, rounded up to page boundary size,
        # 8 lower bits must be discarded
        # in PE32+ is 8 bytes
        heap_commit = exe.OPTIONAL_HEADER.SizeOfHeapCommit
        if heap_commit % 4096:
            heap_commit += 4096 - heap_commit % 4096
        heap_commit = pack("uint:56", heap_commit >> 8)
        pehash_bin.append(
            heap_commit[:8]
            ^ heap_commit[8:16]
            ^ heap_commit[16:24]
            ^ heap_commit[24:32]
            ^ heap_commit[32:40]
            ^ heap_commit[40:48]
            ^ heap_commit[48:56]
        )

        # Section structural information
        for section in exe.sections:
            # Virtual Address, 9 lower bits must be discarded
            pehash_bin.append(pack("uint:24", section.VirtualAddress >> 9))

            # Size Of Raw Data, 8 lower bits must be discarded
            pehash_bin.append(pack("uint:24", section.SizeOfRawData >> 8))

            # Section Characteristics, 16 lower bits must be discarded
            sect_chars = pack("uint:16", section.Characteristics >> 16)
            pehash_bin.append(sect_chars[:8] ^ sect_chars[8:16])

            # Kolmogorov Complexity, len(Bzip2(data))/len(data)
            # (0..1} ∈ R   ->  [0..7] ⊂ N
            kolmogorov = 0
            if section.SizeOfRawData:
                kolmogorov = int(
                    round(
                        len(compress(section.get_data())) * 7.0 / section.SizeOfRawData
                    )
                )
                if kolmogorov > 7:
                    kolmogorov = 7
            pehash_bin.append(pack("uint:8", kolmogorov))

        assert 0 == pehash_bin.len % 8

        return hashlib.sha1(pehash_bin.tobytes()).hexdigest()

    def get_machoc_hash(self):
        # Get Machoc Hash adapted from https://github.com/conix-security/machoke
        binary = self.r2p
        binary.cmd("aaa")
        mmh3_line = ""
        machoke_line = ""

        funcs = json.loads(binary.cmd("aflj"))
        if funcs is None:
            print("r2 could not retrieve functions list")

        def get_machoke_from_function(r2p, function):
            """Return machoke from specific
            :rtype: object
            """
            r2p.cmd("s {}".format(function["offset"]))
            agj_error = 0
            while True:
                try:
                    fcode = json.loads(r2p.cmd("agj"))
                    break
                except:
                    print >>sys.stderr, "Fail agj: %s" % hex(function["offset"])
                if agj_error == 5:
                    break
                agj_error += 1
            blocks = []
            id_block = 1
            try:
                for block in fcode[0]["blocks"]:
                    blocks.append(
                        {"id_block": id_block, "offset": hex(block["offset"])}
                    )
                    id_block += 1
            except:
                return ""
            line = ""
            id_block = 1
            for block in fcode[0]["blocks"]:
                word = "{}:".format(id_block)
                for instruction in block["ops"]:
                    # Check if call
                    if instruction["type"] == "call":
                        word = "{}c,".format(word)
                        for ublock in blocks:
                            if hex(instruction["offset"] + 2) == ublock["offset"]:
                                word = "{}{},".format(word, ublock["id_block"])

                    # Check if jmp
                    if instruction["type"] == "jmp":
                        for ublock in blocks:
                            if instruction["esil"] == ublock["offset"]:
                                word = "{}{},".format(word, ublock["id_block"])

                    # Check if conditional jmp
                    elif instruction["type"] == "cjmp":
                        for ublock in blocks:
                            if hex(instruction["jump"]) == ublock["offset"]:
                                word = "{}{},".format(word, ublock["id_block"])
                            if hex(instruction["offset"] + 2) == ublock["offset"]:
                                word = "{}{},".format(word, ublock["id_block"])
                    else:
                        pass
                if word[-2] == "c":
                    for ublock in blocks:
                        if hex(instruction["offset"] + 4) == ublock["offset"]:
                            word = "{}{},".format(word, ublock["id_block"])

                    if word[-2] == "c":
                        word = "{}{},".format(word, id_block + 1)

                if word[-1] == ":" and id_block != len(fcode[0]["blocks"]):
                    word = "{}{},".format(word, id_block + 1)
                # Clean word
                if word[-1] == ",":
                    word = "{};".format(word[:-1])
                elif word[-1] == ":":
                    word = "{};".format(word)
                line = "{}{}".format(line, word)
                id_block += 1
            return line

        for function in funcs:
            machoke = get_machoke_from_function(binary, function)
            machoke_line = "{}{}".format(machoke_line, machoke)
            mmh3_line = "{}{}".format(
                mmh3_line,
                hex(mmh3.hash(machoke) & 0xffffffff).replace("0x", "").replace("L", ""),
            )
        binary.quit()

        return mmh3_line
