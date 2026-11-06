import base64, datetime, hashlib, hmac, json, math, pathlib, secrets, sqlite3, statistics, sys, threading, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = pathlib.Path(__file__).resolve().parent
SITE = ROOT.name
COOKIE = 'alm_' + SITE.lower()
DB = ROOT / 'data.sqlite3'
LOCK = threading.RLock()
SESSIONS = {}
def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c
with db() as c:
    c.execute('CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, salt BLOB, password BLOB, private BLOB, public TEXT, cert TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS rules (id INTEGER PRIMARY KEY, action TEXT, source TEXT, destination TEXT, port TEXT, protocol TEXT)')
def pem(k):
    return k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
def newkey(): return rsa.generate_private_key(public_exponent=65537, key_size=2048)
def enc(k, m): return k.public_key().encrypt(m, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
def dec(k, m): return k.decrypt(m, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
def b64(v): return base64.b64encode(v).decode()
def un64(v): return base64.b64decode(v, validate=True)
def session():
    return {'key':newkey(), 'user':None, 'cert':'', 'tunnel':None, 'events':[], 'alerts':[], 'counts':[], 'bastion':'192.168.1.10'}

TLS = [
 ('Client Hello', 'Client → Server', 'The client offers TLS 1.2 and TLS_RSA_WITH_AES_128_GCM_SHA256 with a fresh client random.'),
 ('Server Hello & Certificate', 'Server → Client', 'The server selects a suite and presents its certificate. This lab uses a self-signed certificate, verified against its own pinned trust anchor.'),
 ('Client Key Exchange', 'Client → Server', 'The client creates a 48-byte pre-master secret and encrypts it with the server RSA public key. Only the server private key can recover it.'),
 ('Session Key Generation', 'Client ↔ Server', 'Both peers derive matching session material with a TLS 1.2 SHA-256 PRF using the secret and both random values.'),
 ('Finished', 'Client ↔ Server', 'Peers check transcript-bound verification data, then protect a sample application message using AES-GCM. The secure channel is ready.')]
SSH = [
 ('Protocol Version Exchange','Client ↔ Server','Both peers announce SSH-2.0 and agree on the protocol version.'),
 ('Diffie-Hellman Key Exchange','Client ↔ Server','Each peer combines its private value with the other public value to derive the same secret. Small numbers are used only for teaching.'),
 ('Server Authentication','Server → Client','The server signs the exchange transcript. The client checks the signature with the pinned host public key, like a known_hosts entry.'),
 ('User Authentication','Client → Server','A simulated user proves possession of an RSA private key by signing a server challenge.'),
 ('Secure Channel Established','Client ↔ Server','A key derived from the shared secret encrypts a sample message using AES-GCM. This is an educational model, not an SSH implementation.')]
def prf(secret, seed, n):
    a = seed; out = b''
    while len(out) < n:
        a = hmac.new(secret,a,'sha256').digest()
        out += hmac.new(secret,a+seed,'sha256').digest()
    return out[:n]
def cert_for(k, name):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now+datetime.timedelta(days=365)).sign(k,hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
def info(s): return {'public':pem(s['key']), 'user':s['user'], 'certificate':s['cert']}
def crypto(s, op, d):
    if op == 'info': return info(s)
    if op in ('register','login'):
        name = str(d.get('username','')).strip(); password = str(d.get('password',''))
        if not 3 <= len(name) <= 64 or len(password) < 8: raise ValueError('Use a 3–64 character username and a password of at least 8 characters.')
        with db() as c:
            if op == 'register':
                if c.execute('SELECT name FROM users WHERE name=?',(name,)).fetchone(): raise ValueError('Username already exists.')
                k = newkey(); salt = secrets.token_bytes(16)
                digest = hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1)
                private = k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.BestAvailableEncryption(password.encode()))
                c.execute('INSERT INTO users VALUES (?,?,?,?,?,?)',(name,salt,digest,private,pem(k),cert_for(k,name)))
            row = c.execute('SELECT * FROM users WHERE name=?',(name,)).fetchone()
            if not row or not hmac.compare_digest(row['password'], hashlib.scrypt(password.encode(),salt=row['salt'],n=16384,r=8,p=1)): raise ValueError('Invalid username or password.')
            s['key'] = serialization.load_pem_private_key(row['private'],password.encode()); s['user']=name; s['cert']=row['cert']
        return info(s)
    if op == 'logout': s.update(session()); return info(s)
    if op == 'directory':
        with db() as c: return {'users':[dict(r) for r in c.execute('SELECT name, public, cert FROM users ORDER BY name')]}
    if op == 'private': return {'private':s['key'].private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()}
    if op == 'certificate':
        if not s['cert']: s['cert']=cert_for(s['key'],s['user'] or 'CryptoVault Demo')
        return {'certificate':s['cert']}
    message = str(d.get('message','')).encode()
    if op == 'encrypt':
        if len(message)>190: raise ValueError('RSA-OAEP supports at most 190 UTF-8 bytes with this key. Shorten the message.')
        return {'ciphertext':b64(enc(s['key'],message))}
    if op == 'decrypt': return {'plaintext':dec(s['key'],un64(d['ciphertext'])).decode()}
    if op == 'sign': return {'signature':b64(s['key'].sign(message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()))}
    if op == 'verify':
        try: s['key'].public_key().verify(un64(d['signature']),message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()); valid=True
        except Exception: valid=False
        return {'valid':valid}
    if op == 'dh':
        a=int(d.get('a',6)); b=int(d.get('b',15)); p=23; g=5
        if not 1<=a<=21 or not 1<=b<=21: raise ValueError('Private values must be between 1 and 21.')
        A=pow(g,a,p); B=pow(g,b,p)
        return {'p':p,'g':g,'a':a,'b':b,'A':A,'B':B,'alice':pow(B,a,p),'bob':pow(A,b,p)}
    if op in ('elgamal','elverify','hash'):
        digest=hashlib.sha512(message).hexdigest()
        if op=='hash': return {'hash':digest}
        p=467; g=2
        if 'elx' not in s: s['elx']=secrets.randbelow(p-2)+1
        x=s['elx']; y=pow(g,x,p); h=int(digest,16)
        if op=='elgamal':
            k=secrets.randbelow(p-2)+1
            while math.gcd(k,p-1)!=1: k=secrets.randbelow(p-2)+1
            r=pow(g,k,p); v=((h-x*r)*pow(k,-1,p-1))%(p-1)
            return {'hash':digest,'r':r,'s':v,'p':p,'g':g,'y':y,'valid':True}
        r=int(d['r']); v=int(d['s'])
        valid=0<r<p and 0<=v<p-1 and pow(g,h,p)==(pow(y,r,p)*pow(r,v,p))%p
        return {'hash':digest,'valid':valid}
    raise ValueError('Unknown operation.')

def tunnel(s,op,d):
    if op=='reset' or s['tunnel'] is None:
        mode=d.get('mode','TLS')
        if mode not in ('TLS','SSH'): raise ValueError('Unknown protocol.')
        s['tunnel']={'mode':mode,'step':0,'log':[],'key':newkey(),'cr':secrets.token_bytes(32),'sr':secrets.token_bytes(32)}
    t=s['tunnel']; steps=TLS if t['mode']=='TLS' else SSH
    if op=='next' and t['step']<5:
        n=t['step']; detail={}
        if t['mode']=='TLS':
            if n==0: detail={'client_random':t['cr'].hex()}
            if n==1:
                certificate=x509.load_pem_x509_certificate(cert_for(t['key'],'localhost').encode())
                t['key'].public_key().verify(certificate.signature,certificate.tbs_certificate_bytes,padding.PKCS1v15(),hashes.SHA256())
                detail={'certificate':'Pinned self-signed certificate signature verified','server_random':t['sr'].hex()}
            if n==2:
                secret=b'\x03\x03'+secrets.token_bytes(46)
                # TLS 1.2 RSA key transport uses PKCS1v15; OAEP is used only by CryptoVault.
                encrypted=t['key'].public_key().encrypt(secret,padding.PKCS1v15())
                recovered=t['key'].decrypt(encrypted,padding.PKCS1v15())
                t['client_secret']=secret; t['server_secret']=recovered
                detail={'encrypted_pre_master':b64(encrypted),'decryption_matches':secret==recovered}
            if n==3:
                client=prf(t['client_secret'],b'master secret'+t['cr']+t['sr'],48)
                server=prf(t['server_secret'],b'master secret'+t['cr']+t['sr'],48)
                t['master']=client; t['server_master']=server; t['aes']=prf(client,b'key expansion'+t['sr']+t['cr'],16)
                detail={'client_master':client.hex(),'server_master':server.hex(),'match':client==server}
        else:
            if n==0: detail={'client':'SSH-2.0-LabClient','server':'SSH-2.0-LabServer'}
            if n==1:
                a=secrets.randbelow(20)+1; b=secrets.randbelow(20)+1; A=pow(5,a,23); B=pow(5,b,23)
                shared=pow(B,a,23); t['aes']=hashlib.sha256(str(shared).encode()).digest()[:16]
                detail={'p':23,'g':5,'client_public':A,'server_public':B,'client_secret':shared,'server_secret':pow(A,b,23)}
            if n in (2,3):
                payload=json.dumps(t['log']).encode() if n==2 else secrets.token_bytes(32)
                signer=t['key'] if n==2 else newkey()
                sig=signer.sign(payload,padding.PKCS1v15(),hashes.SHA256())
                signer.public_key().verify(sig,payload,padding.PKCS1v15(),hashes.SHA256())
                detail={'signature':b64(sig),'verified':True,'identity':'Pinned demo host' if n==2 else 'Simulated demo user'}
        if n==4:
            nonce=secrets.token_bytes(12); cipher=AESGCM(t['aes']).encrypt(nonce,b'Hello through a secure channel',None)
            detail={'encrypted_message':b64(cipher),'recovered_message':AESGCM(t['aes']).decrypt(nonce,cipher,None).decode()}
            if t['mode']=='TLS':
                transcript_hash=hashlib.sha256(json.dumps(t['log']).encode()).digest()
                sent=prf(t['master'],b'client finished'+transcript_hash,12)
                expected=prf(t['server_master'],b'client finished'+transcript_hash,12)
                server_sent=prf(t['server_master'],b'server finished'+transcript_hash,12)
                client_expected=prf(t['master'],b'server finished'+transcript_hash,12)
                detail['finished_verify_data']=sent.hex()
                detail['both_finished_verified']=hmac.compare_digest(sent,expected) and hmac.compare_digest(server_sent,client_expected)
        title,direction,explanation=steps[n]
        t['log'].append({'title':title,'direction':direction,'explanation':explanation,'detail':detail}); t['step']+=1
    return {'mode':t['mode'],'step':t['step'],'log':t['log']}

def sentinel(s,op,d):
    if op in ('rules','save_rule','delete_rule'):
        with db() as c:
            if op=='save_rule':
                import ipaddress
                action=d.get('action'); protocol=d.get('protocol'); port=str(d.get('port','*')).strip(); source=d.get('source','*').strip(); dest=d.get('destination','*').strip()
                if action not in ('ALLOW','BLOCK') or protocol not in ('ANY','TCP','UDP','ICMP'): raise ValueError('Invalid rule.')
                for address in (source,dest):
                    if address!='*': ipaddress.ip_address(address)
                if port!='*' and not (port.isdigit() and 1<=int(port)<=65535): raise ValueError('Port must be * or 1–65535.')
                values=(action,source,dest,port,protocol)
                if d.get('id'): c.execute('UPDATE rules SET action=?,source=?,destination=?,port=?,protocol=? WHERE id=?',values+(int(d['id']),))
                else: c.execute('INSERT INTO rules(action,source,destination,port,protocol) VALUES (?,?,?,?,?)',values)
            if op=='delete_rule': c.execute('DELETE FROM rules WHERE id=?',(int(d['id']),))
            return {'rules':[dict(r) for r in c.execute('SELECT * FROM rules ORDER BY id')]}
    if op=='bastion':
        import ipaddress
        s['bastion']=str(ipaddress.ip_address(d['address']))
    if op=='reset': s['events']=[]; s['alerts']=[]; s['counts']=[]
    if op=='traffic':
        scenario=d.get('scenario','http'); count={'http':8,'ssh':6,'scan':12,'telnet':3,'burst':80}.get(scenario)
        if count is None: raise ValueError('Unknown scenario.')
        src='192.168.1.100' if scenario!='http' else '192.168.1.20'
        baseline=s['counts'][-20:]; mean=statistics.mean(baseline) if baseline else 8; sd=max(statistics.pstdev(baseline),1) if baseline else 2
        threshold=mean+3*sd; now=time.time()
        with db() as c: rules=[dict(r) for r in c.execute('SELECT * FROM rules ORDER BY id')]
        def alert(kind,text): s['alerts'].insert(0,{'kind':kind,'message':text,'time':time.strftime('%H:%M:%S')})
        for i in range(count):
            port={'http':80,'ssh':22,'telnet':23,'burst':443}.get(scenario,1000+i)
            packet={'source':src,'destination':s['bastion'],'port':port,'protocol':'TCP','time':time.strftime('%H:%M:%S'),'epoch':now,'failed':scenario=='ssh'}
            match=next((r for r in rules if r['source'] in ('*',src) and r['destination'] in ('*',packet['destination']) and r['port'] in ('*',str(port)) and r['protocol'] in ('ANY','TCP')),None)
            packet['action']=match['action'] if match else 'ALLOW'; packet['rule']=match['id'] if match else None
            s['events'].insert(0,packet)
        recent=[e for e in s['events'] if now-e['epoch']<=60 and e['source']==src]
        failures=sum(e['failed'] for e in recent)
        if scenario=='ssh' and failures>=5: alert('RULE',f'{src}: {failures} failed SSH attempts within 60 seconds.')
        if scenario=='telnet': alert('RULE',f'{src}: unencrypted Telnet traffic on port 23.')
        if scenario=='scan' and len({e['port'] for e in recent})>=10: alert('RULE',f'{src}: at least 10 destination ports within 60 seconds.')
        if count>threshold: alert('ANOMALY',f'{count} packets in this simulated 1-second sample exceeds the prior baseline threshold {threshold:.1f} (mean + 3σ).')
        s['counts'].append(count); s['threshold']=threshold
        s['events']=s['events'][:500]; s['alerts']=s['alerts'][:100]
    events=s['events']; counts=s['counts'][-20:]
    return {'events':events[:100],'alerts':s['alerts'],'counts':counts,'threshold':s.get('threshold',14),'bastion':s['bastion'],'total':len(events),'blocked':sum(e['action']=='BLOCK' for e in events)}

class Handler(BaseHTTPRequestHandler):
    def send_json(self,value,status=200,cookie=None):
        body=json.dumps(value).encode(); self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Cache-Control','no-store')
        if cookie: self.send_header('Set-Cookie',cookie)
        self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        path=self.path.split('?')[0]
        if path not in ('/','/index.html','/style.css','/app.js'): self.send_error(404); return
        p=ROOT/('index.html' if path=='/' else path[1:])
        data=p.read_bytes(); self.send_response(200); self.send_header('Content-Type',{'.html':'text/html; charset=utf-8','.css':'text/css','.js':'text/javascript'}[p.suffix]); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        if self.headers.get('Origin') and self.headers['Origin'] != 'http://'+self.headers.get('Host',''): self.send_json({'error':'Cross-origin request rejected.'},403); return
        if not self.path.startswith('/api/'): self.send_json({'error':'Not found'},404); return
        try:
            length=int(self.headers.get('Content-Length',0))
            if length>65536: raise ValueError('Request is too large.')
            d=json.loads(self.rfile.read(length) or '{}')
            cookies=SimpleCookie(self.headers.get('Cookie','')); token=cookies[COOKIE].value if COOKIE in cookies else ''
            with LOCK:
                if token not in SESSIONS: token=secrets.token_urlsafe(32); SESSIONS[token]=session()
                s=SESSIONS[token]; op=self.path[5:]
                value=({'CryptoVault':crypto,'SecureTunnel':tunnel,'Sentinel':sentinel}[SITE])(s,op,d)
            self.send_json(value,cookie=f'{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/')
        except Exception as e:
            self.send_json({'error':str(e) or 'Operation failed. Check your input and keys.'},400)

if __name__=='__main__':
    port=int(sys.argv[1]) if len(sys.argv)>1 else {'CryptoVault':8001,'SecureTunnel':8002,'Sentinel':8003}[SITE]
    print(f'{SITE} ready at http://127.0.0.1:{port}',flush=True)
    ThreadingHTTPServer(('127.0.0.1',port),Handler).serve_forever()
