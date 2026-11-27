#!/usr/bin/python3
# Client IMS-AKA minimal : REGISTER -> 401 (defi AKA) -> REGISTER avec reponse -> 200 OK
import socket, re, base64, hashlib, os, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

IMSI = sys.argv[1] if len(sys.argv) > 1 else "001010000010001"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5090
LOCAL_IP = "10.0.2.15"
PCSCF = (LOCAL_IP, 5060)
DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"
IMPI = IMSI + "@" + DOMAIN
KI = bytes.fromhex("5BAD8598D1F631E3ED76F9333B8AA26F")
OPC = bytes.fromhex("BA5205DDC6FCA1DF6B83A1CC69859514")

# ---------- Milenage (3GPP TS 35.206) ----------
def aes(k, d):
    e = Cipher(algorithms.AES(k), modes.ECB()).encryptor()
    return e.update(d) + e.finalize()

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def rot(x, n):
    return x[n:] + x[:n]

def cst(n):
    b = bytearray(16)
    b[15] = n
    return bytes(b)

def milenage(k, opc, rand, sqn, amf):
    temp = aes(k, xor(rand, opc))
    in1 = sqn + amf + sqn + amf
    out1 = xor(aes(k, xor(temp, rot(xor(in1, opc), 8))), opc)
    def out(r, c):
        return xor(aes(k, xor(rot(xor(temp, opc), r), cst(c))), opc)
    out2 = out(0, 1)
    out3 = out(4, 2)
    out4 = out(8, 4)
    return {"mac": out1[:8], "res": out2[8:], "ak": out2[:6], "ck": out3, "ik": out4}

# ---------- SIP ----------
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LOCAL_IP, PORT))
sock.settimeout(10)

def md5(s):
    return hashlib.md5(s).hexdigest()

def register(cseq, call_id, tag, auth):
    branch = "z9hG4bK" + os.urandom(6).hex()
    lines = [
        "REGISTER sip:" + DOMAIN + " SIP/2.0",
        "Via: SIP/2.0/UDP " + LOCAL_IP + ":" + str(PORT) + ";branch=" + branch + ";rport",
        "Max-Forwards: 70",
        "From: <sip:" + IMPI + ">;tag=" + tag,
        "To: <sip:" + IMPI + ">",
        "Call-ID: " + call_id,
        "CSeq: " + str(cseq) + " REGISTER",
        "Contact: <sip:" + IMSI + "@" + LOCAL_IP + ":" + str(PORT) + ">",
        "Supported: path",
        "Expires: 600",
        auth,
        "Content-Length: 0",
        "", ""]
    return "\r\n".join(lines)

def recv_final():
    while True:
        try:
            data = sock.recvfrom(65535)[0].decode(errors="replace")
        except socket.timeout:
            print("!! Pas de reponse apres 10 s")
            sys.exit(1)
        status = data.split("\r\n")[0]
        print("<<< recu :", status)
        m = re.match(r"SIP/2.0 (\d+)", status)
        if m and int(m.group(1)) >= 200:
            return int(m.group(1)), data

call_id = os.urandom(8).hex() + "@" + LOCAL_IP
tag = os.urandom(4).hex()

# --- 1er REGISTER (sans reponse AKA) ---
auth1 = ('Authorization: Digest username="' + IMPI + '",realm="' + DOMAIN +
         '",nonce="",uri="sip:' + DOMAIN + '",response=""')
print(">>> envoi REGISTER 1")
sock.sendto(register(1, call_id, tag, auth1).encode(), PCSCF)
code, resp = recv_final()
if code != 401:
    print("!! Reponse inattendue (401 attendu) :\n" + resp)
    sys.exit(1)

# --- lecture du defi ---
h = re.search(r"(?im)^WWW-Authenticate:(.*)$", resp)
if not h:
    print("!! Pas de WWW-Authenticate dans le 401 :\n" + resp)
    sys.exit(1)
h = h.group(1)
realm = re.search(r'realm="([^"]+)"', h).group(1)
nonce = re.search(r'nonce="([^"]+)"', h).group(1)
qop_m = re.search(r'qop="([^"]+)"', h)
opaque_m = re.search(r'opaque="([^"]+)"', h)
raw = base64.b64decode(nonce)
rand, autn = raw[:16], raw[16:32]
amf = autn[6:8]
ak = milenage(KI, OPC, rand, b"\x00" * 6, amf)["ak"]
sqn = xor(autn[:6], ak)
r = milenage(KI, OPC, rand, sqn, amf)
print("RAND =", rand.hex())
print("AUTN =", autn.hex())
print("SQN  =", sqn.hex(), "(", int(sqn.hex(), 16), ")")
print("RES  =", r["res"].hex())
print("MAC-A du reseau verifie :", "OUI" if r["mac"] == autn[8:16] else "NON (Ki/OPc ne correspondent pas ?)")

# --- reponse digest AKAv1-MD5 : le mot de passe est RES (octets bruts) ---
uri = "sip:" + DOMAIN
ha1 = md5((IMPI + ":" + realm + ":").encode() + r["res"])
ha2 = md5(("REGISTER:" + uri).encode())
if qop_m and "auth" in qop_m.group(1).split(","):
    nc = "00000001"
    cnonce = os.urandom(4).hex()
    response = md5((ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2).encode())
    extra = ",qop=auth,nc=" + nc + ',cnonce="' + cnonce + '"'
else:
    response = md5((ha1 + ":" + nonce + ":" + ha2).encode())
    extra = ""
if opaque_m:
    extra += ',opaque="' + opaque_m.group(1) + '"'
auth2 = ('Authorization: Digest username="' + IMPI + '",realm="' + realm +
         '",nonce="' + nonce + '",uri="' + uri + '",response="' + response +
         '",algorithm=AKAv1-MD5' + extra + ',integrity-protected="no"')

# --- 2eme REGISTER (avec reponse AKA) ---
print(">>> envoi REGISTER 2 (avec reponse AKA)")
sock.sendto(register(2, call_id, tag, auth2).encode(), PCSCF)
code, resp = recv_final()
print("\n===== REPONSE FINALE =====\n" + resp)
if code == 200:
    print(">>> ENREGISTREMENT REUSSI (200 OK) pour " + IMPI)
else:
    print(">>> ECHEC : code " + str(code))
