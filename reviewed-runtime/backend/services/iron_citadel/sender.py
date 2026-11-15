"""Linux per-message sender checks and atomic dispatch-intent authorization.

The server and its private SQLite file are trusted. Workers must not have direct
database access, administrator credentials, ptrace access or credential-forging
capabilities. This is not a production admission authority or execution receipt. The runtime
entry point is ReleaseAuthority, with a mandatory signed-admission transaction guard.
"""
from contextlib import contextmanager
import array
import json
import os
from pathlib import Path
import select
import socket
import sqlite3
import struct
from .controller import FencedController,decision

LIMIT=16384


def strict_json(raw):
    def unique(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('duplicate_request_field')
            result[key]=value
        return result
    def reject(value):raise ValueError('nonfinite_request')
    value=json.loads(raw,object_pairs_hook=unique,parse_constant=reject)
    if type(value) is not dict:raise ValueError('request_not_object')
    return value


def start_ticks(pid):
    # comm may contain spaces or parentheses; fields after its last ')' start
    # at state (field3). starttime is field22, hence offset19.
    text=Path(f'/proc/{pid}/stat').read_text()
    return int(text[text.rfind(')')+2:].split()[19])


def alive(fd):
    poll=select.poll();poll.register(fd,select.POLLIN|select.POLLHUP|select.POLLERR)
    return not poll.poll(0)


class Peer:
    def __init__(self,connection):
        if connection.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)!=socket.SOCK_SEQPACKET:
            raise ValueError('seqpacket_required')
        self.credentials=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        pid,uid,gid=self.credentials
        self.pidfd=os.pidfd_open(pid,0)
        try:
            self.start=start_ticks(pid)
            if not alive(self.pidfd):raise ValueError('peer_already_exited')
            connection.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        except BaseException:
            os.close(self.pidfd);raise
    def close(self):
        if self.pidfd>=0:os.close(self.pidfd);self.pidfd=-1
    def check(self):
        if self.pidfd<0 or not alive(self.pidfd):raise ValueError('peer_process_exited')
    def receive(self,connection):
        raw,ancillary,flags,_=connection.recvmsg(LIMIT,socket.CMSG_SPACE(12)+socket.CMSG_SPACE(256),socket.MSG_CMSG_CLOEXEC)
        credentials=[];unexpected=False
        for level,kind,value in ancillary:
            if level==socket.SOL_SOCKET and kind==socket.SCM_CREDENTIALS and len(value)==12:
                credentials.append(struct.unpack('3i',value))
            else:
                unexpected=True
                if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                    descriptors=array.array('i');descriptors.frombytes(value[:len(value)//descriptors.itemsize*descriptors.itemsize])
                    for fd in descriptors:os.close(fd)
        if not raw:raise EOFError()
        if flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC) or unexpected or len(credentials)!=1:
            raise ValueError('message_ancillary_or_truncation')
        self.check()
        if credentials[0]!=self.credentials:raise ValueError('current_sender_mismatch')
        return strict_json(raw)


class Authority:
    def __init__(self,database,*,admission_guard,clock=None):
        self.admission_guard=admission_guard
        self.database=Path(database);self.clock=clock
        FencedController(database,clock=clock)
        self.boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS sender_bindings(operation_id TEXT,fence_token INTEGER,pid INTEGER,uid INTEGER,gid INTEGER,start_ticks INTEGER,boot_id TEXT,PRIMARY KEY(operation_id,fence_token))')
            db.execute('CREATE TABLE IF NOT EXISTS sender_revocations(operation_id TEXT PRIMARY KEY)')
            db.execute('CREATE TABLE IF NOT EXISTS sender_workers(pid INTEGER,uid INTEGER,gid INTEGER,start_ticks INTEGER,boot_id TEXT,PRIMARY KEY(pid,uid,gid,start_ticks,boot_id))')
    @contextmanager
    def connect(self):
        db=sqlite3.connect(self.database,timeout=15,isolation_level=None)
        try:
            db.execute('PRAGMA synchronous=FULL')
            yield db
        finally:db.close()
    def register_worker(self,pid,uid,gid):
        # Trusted administrator registration, not exposed to the socket client.
        fd=os.pidfd_open(pid,0)
        try:
            ticks=start_ticks(pid)
            if not alive(fd):raise ValueError('registration_process_exited')
            with self.connect() as db:
                db.execute('INSERT OR IGNORE INTO sender_workers VALUES(?,?,?,?,?)',(pid,uid,gid,ticks,self.boot))
        finally:os.close(fd)
    def revoke(self,operation_id):
        # Trusted administrator method, deliberately absent from the wire API.
        with self.connect() as db:
            db.execute('INSERT OR IGNORE INTO sender_revocations VALUES(?)',(operation_id,))
    def request(self,peer,req):
        try:
            peer.check()
            fields={'action','operation_id','admission_id','admission_sha256'}
            action=req.get('action')
            if action not in {'claim','dispatch'}:raise ValueError('wire_action')
            if req.keys() != fields|({'token'} if action!='claim' else set()):raise ValueError('wire_fields')
            oid,aid,ah=(req[k] for k in ('operation_id','admission_id','admission_sha256'))
            if not all(type(v) is str and 0<len(v)<=256 for v in (oid,aid,ah)):raise ValueError('wire_binding')
            pid,uid,gid=peer.credentials
            identity=(pid,uid,gid,peer.start,self.boot)
            owner=f'process:{self.boot}:{pid}:{peer.start}:{uid}:{gid}'
            def guard(db,operation_id,current_token):
                peer.check()
                if self.admission_guard is not None:
                    self.admission_guard(db,peer,operation_id,aid,ah)
                if not db.execute('SELECT 1 FROM sender_workers WHERE pid=? AND uid=? AND gid=? AND start_ticks=? AND boot_id=?',identity).fetchone():
                    raise ValueError('worker_not_registered')
                if db.execute('SELECT 1 FROM sender_revocations WHERE operation_id=?',(operation_id,)).fetchone():
                    raise ValueError('operation_revoked')
                if action!='claim':
                    row=db.execute('SELECT pid,uid,gid,start_ticks,boot_id FROM sender_bindings WHERE operation_id=? AND fence_token=?',
                                   (operation_id,current_token)).fetchone()
                    if row!=identity:raise ValueError('durable_sender_binding')
            def hook(db,operation_id,result):
                peer.check()
                if action=='claim' and result['decision']=='ALLOW':
                    db.execute('INSERT INTO sender_bindings VALUES(?,?,?,?,?,?,?)',
                        (operation_id,result['fence_token'],*identity))
            controller=FencedController(self.database,clock=self.clock,transaction_guard=guard,transaction_commit_hook=hook)
            if action=='claim':return controller.claim(oid,aid,ah,owner,lease_seconds=30)
            if action=='dispatch':return controller.dispatch(oid,aid,ah,owner,req['token'])
            return decision(False,'REAL_COMPLETION_EVIDENCE_REQUIRED')
        except (ValueError,OSError,KeyError,TypeError):return decision(False,'SENDER_AUTHORITY_REFUSED')
    def serve_connection(self,connection):
        peer=None
        try:
            peer=Peer(connection)
            while True:
                try:req=peer.receive(connection)
                except EOFError:break
                except ValueError as exc:
                    result=decision(False,str(exc))
                else:result=self.request(peer,req)
                connection.sendall(json.dumps(result,allow_nan=False).encode())
        except (OSError,EOFError):pass
        finally:
            if peer is not None:peer.close()
            connection.close()
