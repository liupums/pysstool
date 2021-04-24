

import urllib.parse
import os

with open("BuildDropManifest.ApSignature.csv","rb") as f:
    content = f.read()
l=len(b'#Signature:')
start = content.find(b'#Signature:')
end = content.find(b'\r\n', start)
sig = content[start+l:end]
sigbin = urllib.parse.unquote_to_bytes(sig.decode('utf-8'))
with open("test.bin", "wb") as binfile:
    binfile.write(sigbin)

os.system("openssl asn1parse --in test.bin --inform der -i > test.txt")
realcontent = content[end+2:]
with open("manifest.csv", "wb") as binfile:
	binfile.write(realcontent)

os.system("shasum manifest.csv")
os.system("shasum -a 256 manifest.csv")
