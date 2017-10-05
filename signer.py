# -*- coding: utf-8 -*-
from tempfile import NamedTemporaryFile as namedtmp
import sys
from OpenSSL.crypto import X509, X509Req, X509Name, PKey, TYPE_RSA

if(len(sys.argv) < 2):
	print 'Es necesario un archivo para firmar'
	sys.exit(1)


def getDoc(fileName=''):
	print 'Se tomará el archivo:', sys.argv[1]
	file = open(fileName,'r+')
	return file

# def generatePKey():
	
# def signDoc():


# def generateSignerCert():
def mk_request(bits, cn='UTNFRD WS Sistemas ejemplo'):
	"""
	Create a X509 request with the given number of bits in they key.
	Args:
	  bits -- number of RSA key bits
	  cn -- common name in the request
	Returns a X509 request and the private key (EVP)
	"""
	pk = PKey()
	x = X509Req()
	rsa = pk.generate_key(TYPE_RSA, bits)
	x.set_pubkey(pk)
	name = x.get_subject()
	name.C = "AR"
	name.CN = cn
	# name.ST = 'CA'
	name.O = 'UTN'
	name.L = 'Campana'
	# name.OU = 'testing'
	x.sign(pk,'sha1')
	return x, pk

def generateCACert():
	# Certificado fuerte
	req, pk = mk_request(4096)
	pkey = req.get_pubkey()
	cert = X509()
	# cert.set_serial_number(1)
	cert.set_version(3)
	# mk_cert_valid(cert)
	cert.set_issuer(mk_ca_issuer())
	cert.set_subject(cert.get_issuer())
	cert.set_pubkey(pkey)
	# cert.add_ext(X509.new_extension('basicConstraints', 'CA:TRUE'))
	# cert.add_ext(X509.new_extension('subjectKeyIdentifier', cert.get_fingerprint()))
	cert.sign(pk, "SHA1")
	return cert, pk, pkey

def mk_ca_issuer():
	# Datos del CA Issuer
	issuer = X509Name(X509().get_subject())
	issuer.C = "AR"
	issuer.CN = "UTNFRD WS Sistemas ejemplo"
	# issuer.ST = 'CA'
	issuer.L = 'Campana'
	issuer.O = 'UTN'
	issuer.emailAddress = 'franco.soto.z@gmail.com.ar'
	return issuer

print generateCACert()
# print file.read() 
# file.close()