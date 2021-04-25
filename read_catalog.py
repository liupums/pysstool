# -*- coding: utf-8 -*-
from builtins import open, bytes, str
import sys
import base64
import binascii

import asn1
import optparse

ctl_version = 0
ctl_sequenceNumber = 0
ctl_utctime_thisUpdate = None
ctl_utctime_nextUpdate = None
ctl_alg = None
ctl_disallowed_list = {}

tag_id_to_string_map = {
    asn1.Numbers.Boolean: "BOOLEAN",
    asn1.Numbers.Integer: "INTEGER",
    asn1.Numbers.BitString: "BIT STRING",
    asn1.Numbers.UnicodeString: "BMP STRING",
    asn1.Numbers.OctetString: "OCTET STRING",
    asn1.Numbers.Null: "NULL",
    asn1.Numbers.ObjectIdentifier: "OBJECT",
    asn1.Numbers.PrintableString: "PRINTABLESTRING",
    asn1.Numbers.IA5String: "IA5STRING",
    asn1.Numbers.UTCTime: "UTCTIME",
    asn1.Numbers.Enumerated: "ENUMERATED",
    asn1.Numbers.Sequence: "SEQUENCE",
    asn1.Numbers.Set: "SET",
}

SIGNED_DATA = "PKCS#7 signedData"
CTL_LIST = "certTrustList (Microsoft contentType)"
SHA1_ALGO = "SHA-1 hash algorithm"
COMMON_NAME = "commonName"
CAT_LIST = "Catalog List"
CAT_LIST_MEMBER = "Catalog Member"
CAT_LIST_MEMBER_V2 = "Catalog Member V2"
CAT_NAMEVALUE_OBJID = "Catalog NameValue"
CAT_MEMBERINFO_OBJID = "Catalog MemberInfo"
CAT_MEMBERINFO2_OBJID = "Catalog MemberInfo2"
SPC_INDIRECT_DATA_OBJID = "Catalog SPC INDIRECT DATA"
SPC_CAB_DATA_OBJID = "Catalog CAB DATA"

TRACE = True
object_id_to_string_map = {
    "1.2.840.113549.1.7.2" : SIGNED_DATA,
    "1.3.6.1.4.1.311.10.1" : CTL_LIST,
    "1.3.6.1.4.1.311.12.1.1" : CAT_LIST,
    "1.3.6.1.4.1.311.12.1.2" : CAT_LIST_MEMBER,
    "1.3.6.1.4.1.311.12.1.3" : CAT_LIST_MEMBER_V2,
    "1.3.6.1.4.1.311.12.2.1" : CAT_NAMEVALUE_OBJID,
    "1.3.6.1.4.1.311.12.2.2" : CAT_MEMBERINFO_OBJID,
    "1.3.6.1.4.1.311.12.2.3" : CAT_MEMBERINFO2_OBJID,
    "1.3.6.1.4.1.311.2.1.4"  : SPC_INDIRECT_DATA_OBJID,
    "1.3.6.1.4.1.311.2.1.25" : SPC_CAB_DATA_OBJID,
    "1.3.14.3.2.26" :  SHA1_ALGO,
    "2.5.4.3": COMMON_NAME
}

def assert_oid(oid, expected):
    if oid != expected:
        raise SyntaxError("expecting oid '"+ expected +"', but got '" +oid+"'")

def assert_oids(oid, expected):
    if not oid in expected:
        raise SyntaxError("expecting oid '"+ expected +"', but got '" +oid+"'")

def trace(msg):
    global TRACE
    if TRACE:
        print(msg)

def tag_id_to_string(identifier):
    """Return a string representation of a ASN.1 id."""
    if identifier in tag_id_to_string_map:
        return tag_id_to_string_map[identifier]
    return '{:#02x}'.format(identifier)

def object_identifier_to_string(identifier):
    if identifier in object_id_to_string_map:
        return object_id_to_string_map[identifier]
    return identifier

def value_to_string(tag_number, value):
    if tag_number == asn1.Numbers.ObjectIdentifier:
        return object_identifier_to_string(value)
    elif isinstance(value, bytes):
        return '0x' + str(binascii.hexlify(value).upper())
    elif isinstance(value, str):
        return value
    else:
        return repr(value)

def Get_INT(input_stream):
    if input_stream.eof():
        return None
    tag = input_stream.peek()
    if tag.typ == asn1.Types.Primitive and tag_id_to_string(tag.nr) == 'INTEGER':
        tag, value = input_stream.read()
        return value
    
    return None

def Get_BMPString(input_stream):
    if input_stream.eof():
        return None
    tag = input_stream.peek()
    if tag.typ == asn1.Types.Primitive and tag_id_to_string(tag.nr) == 'BMP STRING':
        tag, value = input_stream.read()
        return value_to_string(tag.nr, value)
    else:
        trace(tag_id_to_string(tag.nr))
    return None

def Get_BMPString_RAW(input_stream):
    if input_stream.eof():
        return None
    tag = input_stream.peek()
    if tag.typ == asn1.Types.Primitive and tag_id_to_string(tag.nr) == 'BMP STRING':
        tag, value = input_stream.read()
        return value

    return None

def Get_OID(input_stream):
    if input_stream.eof():
        return None

    tag = input_stream.peek()
    if tag.typ == asn1.Types.Primitive and tag_id_to_string(tag.nr) == 'OBJECT':
        tag, value = input_stream.read()
        return value_to_string(tag.nr, value)
    
    return None

def Get_OCTET_STR(input_stream):
    if input_stream.eof():
        return None
    
    tag = input_stream.peek()
    if tag.typ == asn1.Types.Primitive and tag_id_to_string(tag.nr) == 'OCTET STRING':
        tag, value = input_stream.read()
        return binascii.hexlify(value).upper()

    return None

def Get_OCTET_STR_RAW(input_stream):
    if input_stream.eof():
        return None
    
    tag = input_stream.peek()
    if tag.typ == asn1.Types.Primitive and tag_id_to_string(tag.nr) == 'OCTET STRING':
        tag, value = input_stream.read()
        return value

    return None

def Get_UTIME(input_stream):
    if input_stream.eof():
        return None
    
    tag = input_stream.peek()
    if tag.typ == asn1.Types.Primitive and tag_id_to_string(tag.nr) == 'UTCTIME':
        tag, value = input_stream.read()
        return value_to_string(tag.nr, value)

    return None

def Get_OID_SEQUENCE(input_stream):
    if input_stream.eof():
        return None

    value = None
    tag = input_stream.peek()
    if tag.typ == asn1.Types.Constructed and tag_id_to_string(tag.nr) == 'SEQUENCE':
        input_stream.enter()
        value = Get_OID(input_stream)
        input_stream.leave()
    
    return value

def Get_ALG_SEQUENCE(input_stream):
    if input_stream.eof():
        return None

    value = None
    tag = input_stream.peek()
    if tag.typ == asn1.Types.Constructed and tag_id_to_string(tag.nr) == 'SEQUENCE':
        input_stream.enter()
        value = Get_OID(input_stream)
        input_stream.leave()
    
    return value

def GET_CAT_NAMEVALUE(input_stream):
    if input_stream.eof():
        return None

    ret_value = None
    tag = input_stream.peek()
    if tag.typ == asn1.Types.Constructed and tag_id_to_string(tag.nr) == 'SET':
        input_stream.enter()
        tag = input_stream.peek()
        if tag.typ == asn1.Types.Constructed and tag_id_to_string(tag.nr) == 'SEQUENCE':
            input_stream.enter()
            valuetype = Get_BMPString_RAW(input_stream)
            filetype = b'\x00F\x00i\x00l\x00e' # type should be 'File'
            if (valuetype != filetype):
                trace("expected file type not found: %s"%valuetype)
            intvalue = Get_INT(input_stream)
            if (intvalue != 0x10010001):
                trace("expected int value not found: %d"%intvalue)
            ret_value = Get_OCTET_STR_RAW(input_stream).decode('utf-16')
            input_stream.leave()
        input_stream.leave()
    return ret_value

def GET_CAT_NAME(input_stream):
    if input_stream.eof():
        return None

    ret_value = None
    tag = input_stream.peek()
    if tag.typ == asn1.Types.Constructed and tag_id_to_string(tag.nr) == 'SET':
        input_stream.enter()
        while not input_stream.eof():
            tag = input_stream.peek()
            if tag.typ == asn1.Types.Constructed and tag_id_to_string(tag.nr) == 'SEQUENCE':
                input_stream.enter()
                oid = Get_OID(input_stream)
                trace(oid)
                if oid == CAT_NAMEVALUE_OBJID:
                    ret_value = GET_CAT_NAMEVALUE(input_stream)
                input_stream.leave()
            else:
                break
        input_stream.leave()
    return ret_value

def Get_CAT_Entry(input_stream):
    if input_stream.eof():
        return None
    # CAT Entry
    # Octet string: hash 
    # SET
    hashvalue = None
    filename = None
    tag = input_stream.peek()
    if tag.typ == asn1.Types.Constructed and tag_id_to_string(tag.nr) == 'SEQUENCE':
        input_stream.enter()
        hashvalue  = Get_OCTET_STR(input_stream)
        filename = GET_CAT_NAME(input_stream)
        input_stream.leave()
        trace("hash=%s, filename=%s"%(hashvalue,filename))
    return hashvalue, filename

def Get_CAT_Entries_SEQUENCE(input_stream):
    if input_stream.eof():
        return None
    entries = {}
    tag = input_stream.peek()
    if tag.typ == asn1.Types.Constructed and tag_id_to_string(tag.nr) == 'SEQUENCE':
        input_stream.enter()
        while not input_stream.eof():
            entry = Get_CAT_Entry(input_stream)
            if entry is not None:
                id, name = entry
                entries[id] = name
        input_stream.leave()
    return entries

def Match_Catalog_List(input_stream):
    global cat_listIdentifier
    global cat_utctime_Update
    global cat_member_id
    global cat_member_list
    if input_stream.eof():
        return
    trace("-->Match_Catalog_List")
    tag = input_stream.peek()
    if tag.typ == asn1.Types.Constructed and tag_id_to_string(tag.nr) == 'SEQUENCE':
        input_stream.enter()
        oid = Get_OID_SEQUENCE(input_stream)
        assert_oid(oid, CAT_LIST)
        cat_listIdentifier = Get_OCTET_STR(input_stream)
        cat_utctime_Update = Get_UTIME(input_stream)
        cat_member_id = Get_OID_SEQUENCE(input_stream)
        cat_member_list = Get_CAT_Entries_SEQUENCE(input_stream)
        input_stream.leave()
    trace("<--Match_Catalog_List")
   
def Match_CertTrustList(input_stream):
    if input_stream.eof():
        return
    trace("-->Match_CertTrustList")
    tag = input_stream.peek()
    if tag.typ == asn1.Types.Constructed and tag_id_to_string(tag.nr) == 'SET':
        input_stream.enter()
        # sha-256, ignored
        input_stream.leave()

    tag = input_stream.peek()
    if tag.typ == asn1.Types.Constructed and tag_id_to_string(tag.nr) == 'SEQUENCE':
        input_stream.enter()
        oid = Get_OID(input_stream)
        assert_oid(oid, CTL_LIST)

        tag = input_stream.peek()
        if tag.typ == asn1.Types.Constructed:
            input_stream.enter()
            Match_Catalog_List(input_stream)
            input_stream.leave()        
        input_stream.leave()        
    trace("<--Match_CertTrustList")

def Match_SignedData(input_stream):
    if input_stream.eof():
        return
    trace("-->Match_SignedData")
    tag = input_stream.peek()
    if tag.typ == asn1.Types.Constructed and tag_id_to_string(tag.nr) == 'SEQUENCE':
        input_stream.enter()
        version = Get_INT(input_stream)
        trace("version=%d"%version)
        Match_CertTrustList(input_stream)
        input_stream.leave()
    trace("<--Match_SignedData")

def parse_catalog(input_data):
    input_stream = asn1.Decoder()
    input_stream.start(input_data)
    if input_stream.eof():
        return
    trace("-->parse_catalog")
    tag = input_stream.peek()
    if tag.typ == asn1.Types.Constructed and tag_id_to_string(tag.nr) == 'SEQUENCE':
        input_stream.enter()
        oid = Get_OID(input_stream)
        assert_oid(oid, SIGNED_DATA)
        tag = input_stream.peek()
        if tag.typ == asn1.Types.Constructed:
            input_stream.enter()
            Match_SignedData(input_stream)
            input_stream.leave()                 
        input_stream.leave()
    trace("<--parse_catalog")

def unit_test():
    input_file = open('manifest.cat', 'rb')
    input_data = input_file.read()
    parse_catalog(input_data)

if __name__ == "__main__":
    unit_test()