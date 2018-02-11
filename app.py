import ssl
import socket
import sys
#import certifi
from OpenSSL import SSL
import json
from cryptography import x509
import binascii
from flask import Flask,abort
from werkzeug.contrib.cache import SimpleCache

cache = SimpleCache()

app = Flask(__name__)

def dumpname(x):
    r = {}
    for e in x:
        r[e.oid._name] = e.value
    return r

def dumpcert(x):
    r = {}
    c = x.to_cryptography()
    r['version'] = c.version.value
    r['serial_number'] = c.serial_number
    r['not_valid_before'] = c.not_valid_before.isoformat()
    r['not_valid_after'] = c.not_valid_after.isoformat()
    r['issuer'] = dumpname(c.issuer)
    r['subject'] = dumpname(c.subject)
    r['signature_algorithm'] = c.signature_algorithm_oid._name
    r['signature'] = {
        'hex': binascii.hexlify(c.signature).decode('ascii').strip(),
        'base64': binascii.b2a_base64(c.signature).decode('ascii').strip(),
    }

    for e in c.extensions:
        if isinstance(e.value,x509.KeyUsage) or isinstance(e.value,x509.BasicConstraints):
            # _properties
            re = {}
            for (key,value) in e.value.__dict__.items():
                re[key[1:]] = value
        elif isinstance(e.value,x509.ExtendedKeyUsage):
            # list of oids
            re = []
            for usage in e.value:
                re.append(usage._name)
        elif isinstance(e.value,x509.SubjectAlternativeName):
            # list of oids
            re = []
            for name in e.value:
                re.append(name.value)
        elif isinstance(e.value,x509.AuthorityInformationAccess):
            re = []
            for desc in e.value:
                res = {}
                res['access_method'] = desc.access_method._name
                res['access_location'] = desc.access_location.value
                re.append(res)
        elif isinstance(e.value,x509.CRLDistributionPoints):
            re = []
            for crl in e.value:
                res = {}
                for (key,value) in crl.__dict__.items():
                    if isinstance(value,list):
                        result=[]
                        for element in value:
                            if isinstance(element,x509.UniformResourceIdentifier):
                                result.append(element.value)
                            else:
                                result.append(str(element))
                        res[key[1:]] = result
                    else:
                        res[key[1:]] = value
                re.append(res)
        elif isinstance(e.value,x509.AuthorityKeyIdentifier) or isinstance(e.value,x509.CertificatePolicies) or isinstance(e.value,x509.SubjectKeyIdentifier):
            #ignore these extensions for now because they contain binary data or 'Unknown OID' policies
            re = None
        else:
            re = str(e.value)

        if re != None:
            r[e.oid._name] = re
    return r

@app.route("/")
def empty():
    return ""

@app.route("/<host>:<int:port>")
@app.route("/<host>")
def cache_lookup(host,port=443):
    cachekey = host + ":" + str(port)
    data = cache.get(cachekey)
    if data is None:
        data = lookup(host,port)
        cache.set(cachekey, data, timeout=5*60)
    return data

def lookup(host,port=443):
    try:
        ctx = SSL.Context(SSL.SSLv23_METHOD) # Autonegotiating including TLS
        sock = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        sock.connect((host, int(port)))
        sock.set_tlsext_host_name(host.encode('utf8'))
        sock.set_alpn_protos([b'http/1.1', b'spdy/2', b'http/2'])
        sock.do_handshake()

        info = {}
        (info['peer_ip'], info['peer_port']) = sock.getpeername()
        info['server_name'] = sock.get_servername().decode('ascii')
        info['cipher_name'] = sock.get_cipher_name()
        info['cipher_bits'] = sock.get_cipher_bits()
        info['cipher_version'] = sock.get_cipher_version()
        info['application_layer_protocol_negotiated'] = sock.get_alpn_proto_negotiated().decode('ascii')
        info['state_string'] = sock.get_state_string().decode('ascii')
        info['client_ca_list'] = [dumpname(ca) for ca in sock.get_client_ca_list() ]
        info['certificate'] = dumpcert(sock.get_peer_certificate())
        info['chain'] = [dumpcert(cert) for cert in sock.get_peer_cert_chain()]

        sock.shutdown()
        sock.close()

        return json.dumps(info,sort_keys=True, indent=4)
    except:
        abort(400)

if __name__ == "__main__":
    app.run(host='0.0.0.0',port=8080)
