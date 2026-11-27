#!/usr/bin/python3
# Test d'appel IMS : enregistrement AKA d'Alice et Bob, puis INVITE / 180 / 200 / ACK / BYE
# Bob ecoute en UDP et en TCP (le P-CSCF bascule en TCP pour les messages trop gros)
import socket, re, base64, hashlib, os, sys, time, select
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

LOCAL_IP = "10.0.2.15"
PCSCF = (LOCAL_IP, 5060)
DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"
KI = bytes.fromhex("5BAD8598D1F631E3ED76F9333B8AA26F")
OPC = bytes.fromhex("BA5205DDC6FCA1DF6B83A1CC69859514")
ALLOW = "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS"

# ---------- Milenage ----------
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
    return {"mac": out1[:8], "res": out2[8:], "ak": out2[:6]}

# ---------- Utilitaires SIP ----------
def md5(s):
    return hashlib.md5(s).hexdigest()

def new_branch():
    return "z9hG4bK" + os.urandom(6).hex()

def hlines(msg, name):
    head = msg.split("\r\n\r\n")[0]
    res = []
    for line in head.split("\r\n")[1:]:
        if line.lower().startswith(name.lower() + ":"):
            res.append(line)
    return res

def hval(msg, name):
    l = hlines(msg, name)
    return l[0].split(":", 1)[1].strip() if l else None

def die(text, msg=None):
    print("!! " + text)
    if msg:
        print(msg)
    sys.exit(1)

def sdp(port):
    return ("v=0\r\no=- 1 1 IN IP4 " + LOCAL_IP + "\r\ns=TP IMS\r\nc=IN IP4 " + LOCAL_IP +
            "\r\nt=0 0\r\nm=audio " + str(port) + " RTP/AVP 0 8\r\n"
            "a=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n")

# ---------- Terminal IMS ----------
class UE:
    def __init__(self, name, imsi, msisdn, port):
        self.name, self.imsi, self.msisdn, self.port = name, imsi, msisdn, port
        self.impi = imsi + "@" + DOMAIN
        self.service_route = "<sip:orig@scscf." + DOMAIN + ":6060;lr>"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((LOCAL_IP, port))
        self.sock.settimeout(10)

    def reg_msg(self, cseq, call_id, tag, auth):
        lines = [
            "REGISTER sip:" + DOMAIN + " SIP/2.0",
            "Via: SIP/2.0/UDP %s:%d;branch=%s;rport" % (LOCAL_IP, self.port, new_branch()),
            "Max-Forwards: 70",
            "From: <sip:%s>;tag=%s" % (self.impi, tag),
            "To: <sip:%s>" % self.impi,
            "Call-ID: " + call_id,
            "CSeq: %d REGISTER" % cseq,
            "Contact: <sip:%s@%s:%d>" % (self.imsi, LOCAL_IP, self.port),
            "Supported: path",
            "Expires: 600",
            auth,
            "Content-Length: 0",
            "", ""]
        return "\r\n".join(lines)

    def recv_final(self):
        while True:
            try:
                data = self.sock.recvfrom(65535)[0].decode(errors="replace")
            except socket.timeout:
                die("Pas de reponse apres 10 s pendant l'enregistrement de " + self.name)
            status = data.split("\r\n")[0]
            print("   [%s] recu : %s" % (self.name, status))
            m = re.match(r"SIP/2.0 (\d+)", status)
            if m and int(m.group(1)) >= 200:
                return int(m.group(1)), data

    def register(self):
        print(">>> Enregistrement de " + self.name + " (" + self.impi + ")")
        call_id = os.urandom(8).hex() + "@" + LOCAL_IP
        tag = os.urandom(4).hex()
        auth1 = ('Authorization: Digest username="' + self.impi + '",realm="' + DOMAIN +
                 '",nonce="",uri="sip:' + DOMAIN + '",response=""')
        self.sock.sendto(self.reg_msg(1, call_id, tag, auth1).encode(), PCSCF)
        code, resp = self.recv_final()
        if code == 401:
            h = hval(resp, "WWW-Authenticate")
            if not h:
                die("401 sans WWW-Authenticate", resp)
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
            print("   [%s] SQN=%d, MAC-A verifie : %s" % (
                self.name, int(sqn.hex(), 16), "OUI" if r["mac"] == autn[8:16] else "NON"))
            uri = "sip:" + DOMAIN
            ha1 = md5((self.impi + ":" + realm + ":").encode() + r["res"])
            ha2 = md5(("REGISTER:" + uri).encode())
            if qop_m and "auth" in qop_m.group(1).split(","):
                nc, cnonce = "00000001", os.urandom(4).hex()
                response = md5((ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2).encode())
                extra = ",qop=auth,nc=" + nc + ',cnonce="' + cnonce + '"'
            else:
                response = md5((ha1 + ":" + nonce + ":" + ha2).encode())
                extra = ""
            if opaque_m:
                extra += ',opaque="' + opaque_m.group(1) + '"'
            auth2 = ('Authorization: Digest username="' + self.impi + '",realm="' + realm +
                     '",nonce="' + nonce + '",uri="' + uri + '",response="' + response +
                     '",algorithm=AKAv1-MD5' + extra + ',integrity-protected="no"')
            self.sock.sendto(self.reg_msg(2, call_id, tag, auth2).encode(), PCSCF)
            code, resp = self.recv_final()
        if code != 200:
            die("Enregistrement de " + self.name + " echoue (code " + str(code) + ")", resp)
        sr = hval(resp, "Service-Route")
        if sr:
            self.service_route = sr
        print("   [%s] ENREGISTRE (200 OK)\n" % self.name)

# ---------- Reponses cote Bob ----------
def make_resp(req, code, reason, to_tag=None, extra=None, body=""):
    lines = ["SIP/2.0 %d %s" % (code, reason)]
    lines += hlines(req, "Via")
    lines += hlines(req, "Record-Route")
    lines.append(hlines(req, "From")[0])
    to = hlines(req, "To")[0]
    if to_tag and "tag=" not in to:
        to += ";tag=" + to_tag
    lines.append(to)
    lines.append(hlines(req, "Call-ID")[0])
    lines.append(hlines(req, "CSeq")[0])
    lines += (extra or [])
    lines.append("Content-Length: " + str(len(body)))
    return "\r\n".join(lines) + "\r\n\r\n" + body

# ================= PROGRAMME =================
alice = UE("Alice", "001010000010001", "10001", 5090)
bob = UE("Bob  ", "001010000010002", "10002", 5091)

# Bob ecoute aussi en TCP sur le meme port
tcp_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp_srv.bind((LOCAL_IP, bob.port))
tcp_srv.listen(5)
tcp_conns = {}

BOB_TAG = os.urandom(4).hex()
state = {"bob_invite": False, "bob_ack": False, "alice_180": False,
         "alice_200": None, "bob_bye": False, "alice_bye_200": False}

def handle_bob(msg, reply):
    first = msg.split("\r\n")[0]
    print("   [Bob  ] recu : " + first)
    if first.startswith("INVITE") and not state["bob_invite"]:
        state["bob_invite"] = True
        reply(make_resp(msg, 180, "Ringing", BOB_TAG).encode())
        print("   [Bob  ] envoie : 180 Ringing")
        time.sleep(1)
        extra = ["Contact: <sip:" + bob.imsi + "@" + LOCAL_IP + ":" + str(bob.port) + ">",
                 ALLOW, "Content-Type: application/sdp"]
        reply(make_resp(msg, 200, "OK", BOB_TAG, extra, sdp(20002)).encode())
        print("   [Bob  ] envoie : 200 OK (decroche)")
    elif first.startswith("ACK"):
        state["bob_ack"] = True
    elif first.startswith("BYE"):
        state["bob_bye"] = True
        reply(make_resp(msg, 200, "OK").encode())
        print("   [Bob  ] envoie : 200 OK (au BYE)")

def handle_alice(msg, addr):
    first = msg.split("\r\n")[0]
    print("   [Alice] recu : " + first)
    m = re.match(r"SIP/2.0 (\d+)", first)
    if not m:
        return
    code = int(m.group(1))
    cseq = hval(msg, "CSeq") or ""
    if "INVITE" in cseq:
        if code == 180:
            state["alice_180"] = True
        elif code == 200 and state["alice_200"] is None:
            state["alice_200"] = msg
        elif code >= 300:
            die("INVITE refuse par le reseau (code " + str(code) + ")", msg)
    elif "BYE" in cseq and code == 200:
        state["alice_bye_200"] = True

def pump(seconds, cond=lambda: False):
    end = time.time() + seconds
    while time.time() < end and not cond():
        rl = [alice.sock, bob.sock, tcp_srv] + list(tcp_conns.keys())
        for s in select.select(rl, [], [], 0.5)[0]:
            if s is tcp_srv:
                c, a = tcp_srv.accept()
                tcp_conns[c] = b""
                print("   [Bob  ] connexion TCP recue du P-CSCF")
            elif s in tcp_conns:
                try:
                    d = s.recv(65535)
                except OSError:
                    d = b""
                if not d:
                    s.close()
                    del tcp_conns[s]
                    continue
                tcp_conns[s] += d
                while True:
                    buf = tcp_conns[s].lstrip(b"\r\n")
                    tcp_conns[s] = buf
                    i = buf.find(b"\r\n\r\n")
                    if i < 0:
                        break
                    head = buf[:i].decode(errors="replace")
                    m = re.search(r"(?im)^(?:Content-Length|l)\s*:\s*(\d+)", head)
                    n = int(m.group(1)) if m else 0
                    if len(buf) < i + 4 + n:
                        break
                    msg = buf[:i + 4 + n].decode(errors="replace")
                    tcp_conns[s] = buf[i + 4 + n:]
                    handle_bob(msg, lambda data, s=s: s.sendall(data))
            elif s is bob.sock:
                data, addr = s.recvfrom(65535)
                handle_bob(data.decode(errors="replace"),
                           lambda d, addr=addr: bob.sock.sendto(d, addr))
            else:
                data, addr = s.recvfrom(65535)
                handle_alice(data.decode(errors="replace"), addr)

alice.register()
bob.register()

print(">>> Alice (10001) appelle Bob (10002)")
call_id = os.urandom(8).hex() + "@" + LOCAL_IP
atag = os.urandom(4).hex()
body = sdp(20000)
invite = "\r\n".join([
    "INVITE sip:10002@" + DOMAIN + " SIP/2.0",
    "Via: SIP/2.0/UDP %s:%d;branch=%s;rport" % (LOCAL_IP, alice.port, new_branch()),
    "Max-Forwards: 70",
    "From: <sip:10001@" + DOMAIN + ">;tag=" + atag,
    "To: <sip:10002@" + DOMAIN + ">",
    "Call-ID: " + call_id,
    "CSeq: 1 INVITE",
    "Contact: <sip:" + alice.imsi + "@" + LOCAL_IP + ":" + str(alice.port) + ">",
    "Route: " + alice.service_route,
    "P-Preferred-Identity: <sip:10001@" + DOMAIN + ">",
    ALLOW,
    "Content-Type: application/sdp",
    "Content-Length: " + str(len(body)),
    "", body])
alice.sock.sendto(invite.encode(), PCSCF)
print("   [Alice] envoie : INVITE")

pump(40, lambda: state["alice_200"] is not None)
if state["alice_200"] is None:
    die("Pas de 200 OK pour l'INVITE apres 40 s")
resp = state["alice_200"]

# ACK : Request-URI = Contact de Bob, Route = Record-Route inverses
rr = []
for l in hlines(resp, "Record-Route"):
    rr += [x.strip() for x in l.split(":", 1)[1].split(",")]
routes = rr[::-1]
target = re.search(r"<([^>]+)>", hval(resp, "Contact")).group(1)
to_line = hlines(resp, "To")[0]
from_line = "From: <sip:10001@" + DOMAIN + ">;tag=" + atag

def in_dialog(method, cseq):
    lines = [method + " " + target + " SIP/2.0",
             "Via: SIP/2.0/UDP %s:%d;branch=%s;rport" % (LOCAL_IP, alice.port, new_branch()),
             "Max-Forwards: 70", from_line, to_line, "Call-ID: " + call_id,
             "CSeq: %d %s" % (cseq, method)]
    lines += ["Route: " + r for r in routes]
    lines += ["Content-Length: 0", "", ""]
    return "\r\n".join(lines)

alice.sock.sendto(in_dialog("ACK", 1).encode(), PCSCF)
print("   [Alice] envoie : ACK")
print(">>> Communication etablie, attente de 3 s ...")
pump(3)

alice.sock.sendto(in_dialog("BYE", 2).encode(), PCSCF)
print("   [Alice] envoie : BYE")
pump(10, lambda: state["alice_bye_200"])

print("\n========== BILAN ==========")
print("180 Ringing recu par Alice :", state["alice_180"])
print("200 OK recu par Alice      :", state["alice_200"] is not None)
print("ACK recu par Bob           :", state["bob_ack"])
print("BYE recu par Bob           :", state["bob_bye"])
print("200 OK au BYE recu         :", state["alice_bye_200"])
ok = state["alice_180"] and state["bob_ack"] and state["bob_bye"] and state["alice_bye_200"]
print(">>> APPEL COMPLET REUSSI" if ok else ">>> APPEL INCOMPLET (voir les lignes ci-dessus)")
