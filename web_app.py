#!/usr/bin/env python3
"""Interface web local para o Simulador Modular de Sistema Operacional.

Servidor didático, sem dependências web externas. Por segurança e simplicidade
para a apresentação, escuta apenas em 127.0.0.1 e mantém sessões em memória.
"""
from __future__ import annotations

import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from simulador import FileSystem, FileSystemError, execute, parse_size


PAGE = r'''<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#10151d"><title>SO Modular — Laboratório</title>
<style>
:root{color-scheme:dark;--bg:#0c1118;--panel:#131b25;--line:#273444;--text:#e8eef6;--muted:#94a4b8;--accent:#62d5b4;--blue:#8db9ff;--red:#ff8c8c;font:15px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 18% 0%,#152b34 0,transparent 40%),var(--bg);color:var(--text);min-height:100vh}
header{padding:24px clamp(18px,5vw,64px) 18px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:18px}h1{font:700 clamp(21px,3vw,30px)/1.2 system-ui;margin:0 0 6px;letter-spacing:-.03em}header p{color:var(--muted);margin:0;font:14px system-ui}.badge{border:1px solid #256d5b;border-radius:99px;color:var(--accent);padding:6px 11px;font-size:12px;white-space:nowrap}
main{max-width:1250px;margin:auto;padding:25px clamp(14px,4vw,44px) 50px}.layout{display:grid;grid-template-columns:minmax(0,1.8fr) minmax(260px,.8fr);gap:18px}.card{background:color-mix(in srgb,var(--panel) 94%,transparent);border:1px solid var(--line);border-radius:14px;overflow:hidden;box-shadow:0 15px 50px #0002}.cardhead{padding:14px 17px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:8px}.cardhead strong{font:600 14px system-ui}.tiny{color:var(--muted);font-size:11px}.terminal{height:min(58vh,590px);min-height:330px;overflow:auto;padding:17px;white-space:pre-wrap;overflow-wrap:anywhere;color:#c6d5e4;font-size:13px}.entry{padding:13px 15px;border-top:1px solid var(--line);display:flex;gap:9px}.entry input{flex:1;min-width:0;background:#0c131a;color:var(--text);border:1px solid #304153;border-radius:8px;padding:11px 12px;font:inherit;outline:none}.entry input:focus{border-color:var(--accent)}button{cursor:pointer;background:#1d6656;color:#eafff8;border:1px solid #29846d;border-radius:8px;padding:9px 13px;font:600 13px system-ui}button:hover{filter:brightness(1.14)}button.secondary{background:#1a2634;border-color:#334559;color:var(--text)}.side{padding:16px}.side h2{font:600 14px system-ui;margin:0 0 11px}.side p{color:var(--muted);font:13px/1.55 system-ui;margin:0 0 13px}.chips{display:flex;flex-wrap:wrap;gap:7px;margin:10px 0 20px}.chip{background:#182331;border:1px solid #304153;border-radius:7px;color:#b9d4f5;padding:6px 8px;font:11px ui-monospace;cursor:pointer}.chip:hover{border-color:var(--blue)}.group{border-top:1px solid var(--line);padding:14px 0 2px}.hint{border:1px solid #4b4525;background:#211f16;color:#d6ca91;padding:10px 11px;border-radius:8px;font:12px/1.5 system-ui;margin-top:14px}.output-error{color:var(--red)}.output-ok{color:#e0ebf5}.foot{color:var(--muted);font:12px system-ui;margin:17px 2px 0}.dot{color:var(--accent)}
@media(max-width:780px){.layout{grid-template-columns:1fr}header{align-items:flex-start}.badge{font-size:10px}.terminal{height:46vh;min-height:270px}}
</style></head><body>
<header><div><h1>Simulador de Sistema Operacional</h1><p>Laboratório modular · Etapas 1–5 · execução didática em memória</p></div><span class="badge"><span class="dot">●</span> AMBIENTE LOCAL</span></header>
<main><div class="layout"><section class="card"><div class="cardhead"><strong>Terminal interativo</strong><span class="tiny" id="who">iniciando sessão…</span></div><div class="terminal" id="terminal" aria-live="polite"></div><form class="entry" id="form"><input id="command" autocomplete="off" spellcheck="false" placeholder="Digite um comando — help para começar" aria-label="Comando do simulador"><button type="submit">Executar ↵</button></form></section>
<aside class="card side"><h2>Roteiro de demonstração</h2><p>Selecione um exemplo para preencher o terminal. Ajuste os nomes ou rode os comandos na ordem sugerida.</p>
<div class="group"><div class="tiny">1 · ARQUIVOS, BLOCOS E E/S</div><div class="chips"><button class="chip" data-cmd="mkdir /sistema">mkdir /sistema</button><button class="chip" data-cmd="create /sistema/app.log --size 8KB">create arquivo</button><button class="chip" data-cmd="fs_status">fs_status</button><button class="chip" data-cmd="write_file /sistema/app.log \"registro demonstrativo\"">write_file + RAID</button></div></div>
<div class="group"><div class="tiny">2 · PROCESSOS, PRIORIDADE E MEMÓRIA</div><div class="chips"><button class="chip" data-cmd="create_process --name App_Web --burst 6ms --priority 1 --type normal --syscall \"read_disk at 3ms (duration: 2ms)\"">criar processo + syscall</button><button class="chip" data-cmd="create_process --name App_Render --burst 4ms --priority 1 --type normal">criar par RR</button><button class="chip" data-cmd="schedule --algorithm Priority_RR --quantum 2ms">executar Priority_RR</button><button class="chip" data-cmd="memory_status --virtual">estado da RAM</button></div></div>
<div class="group"><div class="tiny">3 · SEGURANÇA</div><div class="chips"><button class="chip" data-cmd="whoami">modo e identidade</button><button class="chip" data-cmd="tree">árvore de arquivos</button><button class="chip" data-cmd="help">ver todos os comandos</button></div></div>
<div class="hint"><b>Credenciais da demonstração:</b> usuário inicial <code>root</code>, senha <code>root</code>. Para login, cadastro ou criptografia, use o botão correspondente abaixo: os segredos são enviados apenas no pedido da sessão e não entram no histórico visível.</div>
<div class="chips"><button class="secondary" id="login">Login</button><button class="secondary" id="newsession">Nova sessão</button></div><p>Estado temporário: ao reiniciar o servidor ou abrir uma nova sessão, os dados simulados são descartados.</p></aside></div>
<p class="foot">Simulador educacional, não é um sistema operacional real. Não use senhas ou dados pessoais. O servidor aceita conexões somente deste computador.</p></main>
<script>
const term=document.querySelector('#terminal'),form=document.querySelector('#form'),input=document.querySelector('#command');let sid=null;
function line(text,cls='output-ok'){const el=document.createElement('div');el.className=cls;el.textContent=text;term.appendChild(el);term.scrollTop=term.scrollHeight}
async function request(url,data={}){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const j=await r.json();if(!r.ok)throw Error(j.error||'Falha na solicitação');return j}
async function newSession(){try{const j=await request('/api/session');sid=j.session;term.textContent='';document.querySelector('#who').textContent='root · MODO_KERNEL · sessão temporária';line('Simulador pronto. Digite help ou use os exemplos ao lado.\n');line(j.output)}catch(e){line(e.message,'output-error')}}
async function send(command,secret=''){if(!sid)return;line('> '+command,'tiny');try{const j=await request('/api/command',{session:sid,command,secret});line(j.output);if(j.user)document.querySelector('#who').textContent=j.user+' · '+j.mode}catch(e){line('Erro: '+e.message,'output-error')}}
form.addEventListener('submit',e=>{e.preventDefault();const c=input.value.trim();if(!c)return;input.value='';send(c)});
document.querySelectorAll('[data-cmd]').forEach(b=>b.addEventListener('click',()=>{input.value=b.dataset.cmd;input.focus()}));
document.querySelector('#newsession').addEventListener('click',()=>newSession());
document.querySelector('#login').addEventListener('click',async()=>{const user=prompt('Usuário (demonstração: root):');if(user===null)return;const secret=prompt('Senha:');if(secret===null)return;await send('login --user '+JSON.stringify(user),secret)});
newSession();
</script></body></html>'''


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, FileSystem] = {}
        self._lock = threading.Lock()

    def create(self) -> tuple[str, FileSystem]:
        token = secrets.token_urlsafe(24)
        fs = FileSystem()
        with self._lock:
            self._sessions[token] = fs
        return token, fs

    def get(self, token: str) -> FileSystem | None:
        with self._lock:
            return self._sessions.get(token)


SESSIONS = SessionStore()
SENSITIVE = {"login", "useradd", "encrypt_file", "decrypt_file"}


def _run_command(fs: FileSystem, command: str, secret: str) -> str:
    """Executa comandos protegidos sem pedir entrada interativa ao servidor."""
    import shlex

    args = shlex.split(command)
    if not args:
        return ""
    name = args[0].lower()
    try:
        if name == "login" and len(args) == 3 and args[1] == "--user":
            return fs.login(args[2], secret)
        if name == "useradd" and len(args) == 3:
            return f"Usuário criado: {fs.add_user(args[1], secret, args[2])}"
        if name == "encrypt_file" and len(args) == 2:
            if not secret:
                raise FileSystemError("Informe a chave de criptografia pelo campo protegido da interface.")
            return fs.encrypt_file(args[1], secret)
        if name == "decrypt_file" and len(args) == 2:
            if not secret:
                raise FileSystemError("Informe a chave de criptografia pelo campo protegido da interface.")
            return fs.decrypt_file(args[1], secret)
        if name in SENSITIVE:
            raise FileSystemError("Uso: login --user <nome>, useradd <nome> <grupo>, encrypt_file <caminho> ou decrypt_file <caminho>.")
        keep_going, output = execute(fs, command)
        return output if keep_going else "Sessão do simulador encerrada. Atualize a página para iniciar outra sessão."
    except (FileSystemError, ValueError) as exc:
        return f"Erro: {exc}"


class Handler(BaseHTTPRequestHandler):
    server_version = "SO-Modular-Lab/1.0"

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if urlparse(self.path).path != "/":
            self.send_error(404)
            return
        body = PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        route = urlparse(self.path).path
        if route not in ("/api/session", "/api/command"):
            self._json(404, {"error": "Rota não encontrada."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 16_384:
                self._json(413, {"error": "Solicitação muito grande."})
                return
            data = json.loads(self.rfile.read(length) or b"{}")
            if route == "/api/session":
                token, fs = SESSIONS.create()
                self._json(200, {"session": token, "output": "Bem-vindo. O estado deste simulador existe apenas nesta sessão."})
                return
            token = str(data.get("session", ""))
            fs = SESSIONS.get(token)
            if fs is None:
                self._json(404, {"error": "Sessão inexistente ou reiniciada. Atualize a página."})
                return
            command = str(data.get("command", ""))
            if len(command) > 4000:
                self._json(413, {"error": "Comando muito longo."})
                return
            output = _run_command(fs, command, str(data.get("secret", "")))
            user = fs.identity.user.name
            mode = "MODO_KERNEL" if fs.identity.is_root else "MODO_USUARIO"
            self._json(200, {"output": output, "user": user, "mode": mode})
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json(400, {"error": "Corpo JSON inválido."})

    def log_message(self, format: str, *args: Any) -> None:
        # Evita registrar comandos, que podem conter dados digitados pelo usuário.
        return


def main() -> None:
    host = "127.0.0.1"
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Simulador disponível em http://{host}:{port} — pressione Ctrl+C para encerrar.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor encerrado.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()


__all__ = ["Handler", "SessionStore", "_run_command"]
