from builtins import open, bytes, str
import sys
import base64
import binascii

import asn1
import uuid
import optparse
import struct

def bytes_to_uuid(b):
    s = uuid.UUID(bytes=b)
    s1,s2,s3,s4,s5 = str(s).split("-")
    # break the string into pairs and then reversing that, finally concatenating the result back together
    rs1 = "".join(reversed([s1[i:i+2] for i in range(0,len(s1),2)]))
    rs2 = "".join(reversed([s2[i:i+2] for i in range(0,len(s2),2)]))
    rs3 = "".join(reversed([s3[i:i+2] for i in range(0,len(s3),2)]))
    return "-".join([rs1,rs2,rs3,s4,s5])

parser = optparse.OptionParser()
parser.add_option('-i', '--input', dest='input', help='input *.encr file')
parser.add_option('-o', '--output', dest='output', help='output to FILE instead', metavar='FILE')
parser.set_default('input', 'foo.encr')
(opts, args) = parser.parse_args()

if opts.output:
    output_file = open(opts.output, 'w')
else:
    output_file = sys.stdout
'''
type EncrFile struct {
    Version uint32
    Protect string
    Group   string
    MasterKeyId string
    SymKeyId string
    HashAlgo string
    SymKeyEncr []byte
    Secret []byte
    AuthTag byte[16]
}
'''
ProtectMethod = ["HybridXCG", "PKCS7Windows", "Unspecified"]

with open(opts.input, 'rb') as f:
    uint32 = f.read(4)
    version = struct.unpack('>i', uint32)[0]
    print("Version=%d" % version)
    uint32 = f.read(4)
    protect = struct.unpack('>i', uint32)[0]
    print("Protect=%s" % ProtectMethod[protect])
    data = f.read()
    input_stream = asn1.Decoder()
    input_stream.start(data)
    _, octStr = input_stream.read(asn1.Numbers.OctetString)
    group = octStr[:-1].decode()
    print("Group=%s" % group)
    _, octStr = input_stream.read(asn1.Numbers.OctetString)
    masterkey = bytes_to_uuid(octStr)
    print("MasterkeyId=%s" % masterkey)
    _, octStr = input_stream.read(asn1.Numbers.OctetString)
    symkey = bytes_to_uuid(octStr)
    print("SymkeyId=%s" % symkey)
    _, algo = input_stream.read(asn1.Numbers.ObjectIdentifier)
    print("Algo=%s" % algo)
    # read encrypted symkey, starting with length
    encrSymKeyLen = input_stream._read_length()
    value = input_stream._read_value(asn1.Classes.Universal, asn1.Numbers.OctetString, encrSymKeyLen)
    print("Encrypted Symkey[%d]=%s" % (encrSymKeyLen, bytearray(value).hex()))
    _, nonce = input_stream.read(asn1.Numbers.OctetString)
    print("Nonce[%d]=%s" % (len(nonce), bytearray(nonce).hex()))
    # read encrypted text, starting with length
    encrTextLen = input_stream._read_length()
    value = input_stream._read_value(asn1.Classes.Universal, asn1.Numbers.OctetString, encrTextLen)
    # helloworld
    print("CiperText[%d]=%s" % (len(value)-16, bytearray(value[:-16]).hex()))
    print("AuthTag[16]=%s" % bytearray(value[-16:]).hex())


