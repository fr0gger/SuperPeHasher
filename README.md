# SuperPeHasher

SuperPEHasher is a wrapper for several hash algorithms dedicated to PE file. It includes the following:
* MD5, SHA2
* SSDEEP
* PeHash
* Import Hash
* Import Fuzzy
* Rich PE Hash
* Machoc Hash

## Getting Started
if you want more information about hashing algorithms you can visit the blog I wrote on [Medium](https://medium.com/@tom_rock/fifty-shades-of-malware-hashing-3783d98df59c?source=friends_link&sk=c3f3ed798e0c087eeb1d368868462724). 


### Installing

To run this tool you can git clone and install the requirements. 

```
pip install -r requirements.txt
```
          

## Running the tests

Once you installed the requirements you can run the file pehasher.py with a file as input. 

```
python pehasher.py sample.exe
md5:            60b7c0fead45f2066e5b805a91f4f0fc
sha1:           9018a7d6cdbe859a430e8794e73381f77c840be0
sha256:         80c10ee5f21f92f89cbc293a59d2fd4c01c7958aacad15642558db700943fa22
sha512:         68b9f9c00fc64df946684ce81a72a2624f0fc07e07c0c8b3db2fae8c9c0415bd1b4a03ad7ffa96985af0cc5e0410f6c5e29a30200efff21ab4b01369a3c59b58
ssdeep:         6144:Jv7Wc4dyC7dXNBzn68YoC+6VoQSkgrpZHqk61peBN1L+I8pfezYeWHMzyy14pL1k:JvSbJxPRC+XQSxb6Dc7RwIWHeGL7GOK
ImpHash:        f93b5d76132f6e6068946ec238813ce1
ImpFuzzy:       192:q9AW2Rpn8RrMqkNsQYDhs4kqp1qAw5tXLXVn/zgF79KPrzJ:qcp8lUNlc11qAw5tXLXV/zm79KP5
RicHash xored:  87107a65f8d4bac1712543f317925b49711249b750f31c4f21376c9385117fd8
RicHash clear:  951cfa6151f9b4301ba58bde359effe21b6af7d87a168de750067396ec4e5f78
PeHash:         fa5ad3991616af0bb9d76132db7e9d6009c55baa
Machoc Hash:    5ed7c76d41a02300e08e7177411a02300ead543fa0d346c2ed4ac25a954ac25a951a02300e1a02300e000039423f2825315453253154531a02300e253154532531545325315453[Truncated] 
```


## Built With

* [SSDEEP](https://ssdeep-project.github.io/ssdeep/index.html)
* [PeHash](https://www.usenix.org/legacy/events/leet09/tech/full_papers/wicherski/wicherski_html/index.html) 
* [ImpHash](https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html)
* [ImpFuzzy](https://github.com/JPCERTCC/impfuzzy)
* [Machoke Hash](https://blog.conixsecurity.fr/machoke-hashing/)
* [PeFile](https://github.com/erocarrera/pefile)

