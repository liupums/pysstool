# setup
```
python3 -m pip install asn1
python3 -m pip install pycryptodomex
```
# pysstool
python sstool
```
>python3 sstool.py 
Version=2
Protect=HybridXCG
Group=dynamicgroup://APMF\MWD.PuliuTest-Dev-CY2TEST02.CY2TEST02,APUSR\puliu
MasterkeyId=b07f61a4-8576-4599-ac4c-6d4534bf6ffe
SymkeyId=bea2e212-9263-18fe-6d1b-580cd568278f
Algo=2.16.840.1.101.3.4.2.1
Encrypted Symkey[256]=1dfea128bba1e2d571f837822ef85b9018d3619d1ebd6d8c3980745615718a7eac594e8c015cdd49eb2c22f1bee00e94c304f9aeddcf6c856bd39689e849d7ee8cb6306c0983eedf4993e032318f92c2716ba9a129f00770eaf583b018243155a1aff75074903790ac3f26d9de0b1fd8ff9b0ef8a80b6a99ad0efa460c384994ad2c8a3ae0211f9bbfd869cc1446f318bd0fb0b33271ac0daed813d16adabda9d3989715ba9e32f65e2c09e499abe9b5394746f0866145a1a5fe8ac45b61398e36bb43bd91ec75a85f0e1906f91692010c60f88c2147255658c56342569a5a79ed3071f3ca69cd992434b635d81160d1e0ab0f3b4f5ce098d71dee382c2374df
Nonce[12]=a7e2a6627e56f17d005c44a0
CiperText[10]=9f55020013730fdbc2c4
AuthTag[16]=cf8deab070154af15dadeca2753f1442
```

# test RSA and AES
```
>python3 testencrypt.py 
plaintext 'HelloWorld', decrypted data 'HelloWorld'
decrypted message 'HelloWorld'
```
