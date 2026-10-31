#!/usr/bin/env python3
"""Simulador didático de sistema de arquivos e alocação de blocos."""
from __future__ import annotations

import argparse
import hashlib
import math
import shlex
import sys
from dataclasses import dataclass, field
from getpass import getpass
from typing import Optional

from disk_io import DiskScheduler, IORequest, RAIDArray
from security import (IdentityManager, SecurityError, allowed, decrypt_bytes,
                      encrypt_bytes, mode_text)


@dataclass
class Node:
    name: str
    is_dir: bool
    parent: Optional["Node"] = None
    children: dict[str, "Node"] = field(default_factory=dict)
    size: int = 0
    blocks: list[int] = field(default_factory=list)
    index_block: Optional[int] = None
    owner: str = "root"
    group: str = "admin"
    mode: int = 0o755
    content: bytes = b""
    encrypted: bool = False
    encryption_salt: Optional[bytes] = None
    block_hashes: dict[int, str] = field(default_factory=dict)

    def path(self) -> str:
        if self.parent is None:
            return "/"
        parts, node = [], self
        while node.parent is not None:
            parts.append(node.name)
            node = node.parent
        return "/" + "/".join(reversed(parts))


class FileSystemError(Exception):
    """Erro de operação que pode ser mostrado diretamente no terminal."""


class FileSystem:
    STRATEGIES = ("contiguous", "linked", "indexed")

    def __init__(self, block_size: int = 4096, total_blocks: int = 16,
                 strategy: str = "indexed", scheduler: str = "SSTF",
                 disk_tracks: int = 200, head: int = 53,
                 raid_level: str = "5", raid_disks: int = 3):
        if block_size <= 0 or total_blocks <= 0:
            raise ValueError("O tamanho do bloco e a quantidade de blocos devem ser positivos.")
        if strategy not in self.STRATEGIES:
            raise ValueError(f"Estratégia inválida. Escolha: {', '.join(self.STRATEGIES)}")
        self.block_size = block_size
        self.total_blocks = total_blocks
        self.strategy = strategy
        self.scheduler = DiskScheduler(scheduler, disk_tracks, head)
        self.raid = RAIDArray(raid_level, raid_disks, block_size)
        self.root = Node("", True, owner="root", group="admin", mode=0o755)
        self.cwd = self.root
        self.io_log: list[str] = []
        self.identity = IdentityManager()
        self.audit_log: list[str] = []
        self.malicious_signatures = (b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", b"MALWARE_SIMULADO")

    def _require_privileged(self, operation: str) -> None:
        if not self.identity.is_root:
            message = f"[NEGADO] Operação '{operation}' exige MODO_KERNEL (root)."
            self.audit_log.append(f"NEGADO {self.identity.current_user}: {operation}")
            raise FileSystemError(message)

    def _check_access(self, node: Node, action: str) -> None:
        user = self.identity.user
        ok = allowed(node.mode, action, user.name == node.owner,
                     user.group == node.group, self.identity.is_root)
        if not ok:
            message = (f"[NEGADO] O usuário '{user.name}' não possui permissão de "
                       f"{action} no objeto '{node.path()}'.")
            self.audit_log.append(f"NEGADO {user.name}: {action} {node.path()}")
            raise FileSystemError(message)

    def _record_integrity(self, node: Node) -> None:
        node.block_hashes = {}
        for index, block in enumerate(node.blocks):
            start = index * self.block_size
            chunk = node.content[start:start + self.block_size]
            node.block_hashes[block] = hashlib.sha256(chunk).hexdigest()

    def add_group(self, name: str) -> str:
        self._require_privileged("criar grupo")
        try:
            return self.identity.add_group(name)
        except SecurityError as exc:
            raise FileSystemError(str(exc)) from exc

    def add_user(self, name: str, password: str, group: str) -> str:
        self._require_privileged("criar usuário")
        try:
            self.identity.add_user(name, password, group)
        except SecurityError as exc:
            raise FileSystemError(str(exc)) from exc
        home = self.root.children.get("home")
        if home is None:
            home = Node("home", True, self.root, owner="root", group="admin", mode=0o755)
            self.root.children["home"] = home
        if name not in home.children:
            home.children[name] = Node(name, True, home, owner=name, group=group, mode=0o700)
        return name

    def login(self, name: str, password: str) -> str:
        try:
            user = self.identity.authenticate(name, password)
        except SecurityError as exc:
            self.audit_log.append(f"FALHA DE LOGIN: {name}")
            raise FileSystemError(str(exc)) from exc
        mode = "MODO_KERNEL" if self.identity.is_root else "MODO_USUARIO"
        return f"Autenticado com sucesso. Usuário: '{user.name}' | Grupo: '{user.group}' | Modo: {mode}"

    def security_status(self) -> str:
        user = self.identity.user
        mode = "MODO_KERNEL (root)" if self.identity.is_root else "MODO_USUARIO"
        return f"Usuário atual: {user.name} | Grupo: {user.group} | Modo: {mode}"

    def set_permissions(self, path: str, mode: int) -> str:
        self._require_privileged("alterar ACL/permissões")
        if not 0 <= mode <= 0o777:
            raise FileSystemError("Permissões devem estar entre 000 e 777.")
        node = self._resolve(path)
        node.mode = mode
        return f"Permissões de '{node.path()}' atualizadas para {mode_text(mode)} ({mode:03o})."

    def acl_status(self, path: str) -> str:
        node = self._resolve(path)
        return (f"Objeto      : {node.path()}\nProprietário: {node.owner} (Grupo: {node.group})\n"
                f"Permissões  : {mode_text(node.mode)} ({node.mode:03o})")

    def encrypt_file(self, path: str, key: str) -> str:
        self._require_privileged("criptografar arquivo")
        node = self._resolve(path)
        if node.is_dir:
            raise FileSystemError(f"'{node.path()}' é um diretório, não um arquivo.")
        self._check_access(node, "write")
        if node.encrypted:
            raise FileSystemError("O arquivo já está criptografado.")
        try:
            ciphertext, salt = encrypt_bytes(node.content, key)
        except SecurityError as exc:
            raise FileSystemError(str(exc)) from exc
        original_content, original_size = node.content, node.size
        original_blocks, original_index = node.blocks, node.index_block
        node.content, node.encryption_salt, node.encrypted = ciphertext, salt, True
        node.size = len(ciphertext)
        node.blocks, node.index_block = [], None
        try:
            node.blocks, node.index_block = self._allocate(node, node.size)
        except FileSystemError:
            node.content, node.size = original_content, original_size
            node.blocks, node.index_block = original_blocks, original_index
            node.encrypted, node.encryption_salt = False, None
            raise
        self._record_integrity(node)
        io_result = self._schedule_file_io(node, "WRITE")
        self.raid.write(node.path(), ciphertext)
        return (f"Arquivo '{node.path()}' criptografado com sucesso.\n"
                f"Conteúdo gravado nos blocos físicos: [CIPHERTEXT: {ciphertext[:24].hex()}...]\n{io_result}")

    def _allocate_for_replacement(self, node: Node, size: int) -> tuple[list[int], Optional[int]]:
        previous_blocks, previous_index = node.blocks, node.index_block
        node.blocks, node.index_block = [], None
        try:
            blocks, index = self._allocate(node, size)
            return blocks, index
        finally:
            node.blocks, node.index_block = previous_blocks, previous_index

    def antivirus_scan(self, path: str = "/") -> str:
        self._require_privileged("varredura de segurança")
        root = self._resolve(path)
        if not root.is_dir:
            raise FileSystemError("A varredura deve começar em um diretório.")
        files: list[Node] = []
        def collect(node: Node) -> None:
            for child in node.children.values():
                if child.is_dir:
                    collect(child)
                else:
                    files.append(child)
        collect(root)
        lines = ["[MÓDULO DE SEGURANÇA - VARREDURA DE INTEGRIDADE]",
                 f"Analisando {len(files)} arquivo(s) em busca de assinaturas maliciosas e hashes corrompidos..."]
        for node in files:
            mismatched = []
            for index, block in enumerate(node.blocks):
                start = index * self.block_size
                chunk = node.content[start:start + self.block_size]
                current = hashlib.sha256(chunk).hexdigest()
                if node.block_hashes.get(block) != current:
                    mismatched.append(block)
            suspicious = any(signature in node.content for signature in self.malicious_signatures)
            if mismatched:
                result = f"[ALERTA] Hash do(s) bloco(s) {mismatched} difere do registro oficial! Possível modificação direta não autorizada."
                self.audit_log.append(f"INTEGRIDADE: {node.path()} blocos {mismatched}")
            elif suspicious:
                result = "[ALERTA] Assinatura maliciosa simulada identificada!"
                self.audit_log.append(f"ASSINATURA: {node.path()}")
            elif node.encrypted:
                result = "[OK - Criptografado e íntegro]"
            else:
                result = "[OK - íntegro]"
            lines.append(f"- {node.path():<28}: {result}")
        if not files:
            lines.append("Nenhum arquivo encontrado.")
        return "\n".join(lines)

    def tamper_block(self, path: str, block_number: int) -> str:
        self._require_privileged("simular adulteração de bloco")
        node = self._resolve(path)
        if node.is_dir or block_number not in node.blocks:
            raise FileSystemError("O bloco indicado não pertence a esse arquivo.")
        offset = node.blocks.index(block_number) * self.block_size
        if not node.content:
            raise FileSystemError("O arquivo não contém dados para adulterar.")
        changed = bytearray(node.content)
        changed[min(offset, len(changed) - 1)] ^= 1
        node.content = bytes(changed)
        return f"Bloco {block_number} de '{node.path()}' adulterado para teste de auditoria."

    def _schedule_file_io(self, node: Node, operation: str) -> str:
        requests = [IORequest(track=block % self.scheduler.tracks,
                              operation=operation.upper(), path=node.path(), block=block)
                    for block in node.blocks]
        if node.index_block is not None:
            requests.insert(0, IORequest(track=node.index_block % self.scheduler.tracks,
                                         operation="METADATA", path=node.path(), block=node.index_block))
        if not requests:
            return "[E/S] Arquivo vazio: nenhuma operação de bloco necessária."
        result = self.scheduler.schedule(requests)
        self.io_log.append(result)
        return result

    def write_data(self, path: str, data: bytes) -> str:
        node = self._resolve(path)
        if node.is_dir:
            raise FileSystemError(f"'{node.path()}' é um diretório, não um arquivo.")
        self._check_access(node, "write")
        if node.encrypted:
            raise FileSystemError("Arquivo criptografado: descriptografe-o explicitamente antes de gravar novos dados.")
        required_size = max(node.size, len(data))
        if required_size > node.size:
            self.update_file(path, required_size)
            node = self._resolve(path)
        node.content = data
        self._record_integrity(node)
        result = self._schedule_file_io(node, "WRITE")
        raid_lines = self.raid.write(node.path(), data)
        return result + "\n\n" + "\n".join(raid_lines)

    def read_data(self, path: str) -> str:
        node = self._resolve(path)
        if node.is_dir:
            raise FileSystemError(f"'{node.path()}' é um diretório, não um arquivo.")
        self._check_access(node, "read")
        result = self._schedule_file_io(node, "READ")
        raid_details = self.raid.status()
        content_line = (f"Conteúdo protegido: ciphertext ({len(node.content)} bytes)" if node.encrypted
                        else f"Conteúdo: {node.content.decode('utf-8', errors='replace')}")
        return result + "\n" + content_line + "\n\n[LEITURA RAID]\n" + raid_details

    def decrypt_file(self, path: str, key: str) -> str:
        node = self._resolve(path)
        if node.is_dir or not node.encrypted or node.encryption_salt is None:
            raise FileSystemError("O arquivo indicado não está criptografado.")
        self._check_access(node, "read")
        try:
            plaintext = decrypt_bytes(node.content, key, node.encryption_salt)
        except SecurityError as exc:
            raise FileSystemError(str(exc)) from exc
        return f"Conteúdo descriptografado de '{node.path()}': {plaintext.decode('utf-8', errors='replace')}"

    def io_status(self) -> str:
        return "\n\n".join(self.io_log) if self.io_log else "Nenhuma E/S executada nesta sessão."

    def fail_raid_disk(self, disk_number: int) -> str:
        self._require_privileged("simular falha de disco RAID")
        try:
            return "\n".join(self.raid.fail_and_rebuild(disk_number))
        except ValueError as exc:
            raise FileSystemError(str(exc)) from exc

    def raid_status(self) -> str:
        return self.raid.status()

    def _resolve(self, path: str) -> Node:
        if not path:
            return self.cwd
        current = self.root if path.startswith("/") else self.cwd
        for part in path.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if current.parent is not None:
                    current = current.parent
                continue
            if not current.is_dir:
                raise FileSystemError(f"'{current.path()}' não é um diretório.")
            self._check_access(current, "execute")
            if part not in current.children:
                raise FileSystemError(f"Caminho não encontrado: '{path}'.")
            current = current.children[part]
        return current

    def _parent_and_name(self, path: str) -> tuple[Node, str]:
        clean = path.rstrip("/")
        if not clean:
            raise FileSystemError("A raiz não pode ser criada ou removida.")
        parent_path, _, name = clean.rpartition("/")
        if not name or name in (".", ".."):
            raise FileSystemError("Nome de arquivo ou diretório inválido.")
        parent = self._resolve(parent_path or ("/" if path.startswith("/") else "."))
        if not parent.is_dir:
            raise FileSystemError(f"'{parent.path()}' não é um diretório.")
        return parent, name

    def _all_files(self) -> list[Node]:
        found: list[Node] = []
        def visit(node: Node) -> None:
            for child in node.children.values():
                if child.is_dir:
                    visit(child)
                else:
                    found.append(child)
        visit(self.root)
        return found

    def _used_blocks(self) -> set[int]:
        used = set()
        for file in self._all_files():
            used.update(file.blocks)
            if file.index_block is not None:
                used.add(file.index_block)
        return used

    def _free_blocks(self) -> list[int]:
        used = self._used_blocks()
        return [i for i in range(self.total_blocks) if i not in used]

    def _allocate(self, file: Node, size: int) -> tuple[list[int], Optional[int]]:
        data_count = math.ceil(size / self.block_size) if size else 0
        free = self._free_blocks()
        metadata_count = 1 if self.strategy == "indexed" and data_count else 0
        needed = data_count + metadata_count
        if len(free) < needed:
            raise FileSystemError(f"Espaço insuficiente: são necessários {needed} blocos, há {len(free)} livres.")
        if self.strategy == "contiguous" and data_count:
            run: list[int] = []
            for block in free:
                if run and block != run[-1] + 1:
                    run = []
                run.append(block)
                if len(run) == data_count:
                    return run, None
            raise FileSystemError(f"Sem sequência contígua de {data_count} blocos. Tente compactar ou usar outra estratégia.")
        if self.strategy == "indexed" and data_count:
            # O bloco de índice é reservado primeiro; os blocos de dados podem ser dispersos.
            return free[1:needed], free[0]
        return free[:data_count], None

    def mkdir(self, path: str) -> str:
        parent, name = self._parent_and_name(path)
        self._check_access(parent, "write")
        self._check_access(parent, "execute")
        if name in parent.children:
            raise FileSystemError(f"Já existe um item chamado '{name}'.")
        user = self.identity.user
        parent.children[name] = Node(name, True, parent, owner=user.name,
                                     group=user.group, mode=0o755)
        return parent.children[name].path()

    def create_file(self, path: str, size: int = 0) -> str:
        if size < 0:
            raise FileSystemError("O tamanho não pode ser negativo.")
        parent, name = self._parent_and_name(path)
        self._check_access(parent, "write")
        self._check_access(parent, "execute")
        if name in parent.children:
            raise FileSystemError(f"Já existe um item chamado '{name}'.")
        user = self.identity.user
        node = Node(name, False, parent, size=size, owner=user.name,
                    group=user.group, mode=0o644)
        node.blocks, node.index_block = self._allocate(node, size)
        parent.children[name] = node
        self._record_integrity(node)
        return node.path()

    def read_file(self, path: str) -> str:
        node = self._resolve(path)
        if node.is_dir:
            raise FileSystemError(f"'{node.path()}' é um diretório, não um arquivo.")
        self._check_access(node, "read")
        info = (f"Arquivo: {node.path()} | Tamanho: {node.size} bytes | Blocos de dados: {node.blocks} | "
                f"Proprietário: {node.owner} (Grupo: {node.group}) | ACL: {mode_text(node.mode)} ({node.mode:03o})")
        return info + "\n" + self.read_data(path)

    def update_file(self, path: str, size: int) -> str:
        if size < 0:
            raise FileSystemError("O tamanho não pode ser negativo.")
        node = self._resolve(path)
        if node.is_dir:
            raise FileSystemError(f"'{node.path()}' é um diretório, não um arquivo.")
        self._check_access(node, "write")
        if node.encrypted:
            raise FileSystemError("Descriptografe o arquivo antes de redimensioná-lo.")
        old_blocks, old_index, old_size = node.blocks, node.index_block, node.size
        node.blocks, node.index_block = [], None
        try:
            node.blocks, node.index_block = self._allocate(node, size)
        except FileSystemError:
            node.blocks, node.index_block, node.size = old_blocks, old_index, old_size
            raise
        node.size = size
        node.content = node.content[:size].ljust(size, b"\0")
        self._record_integrity(node)
        return f"Arquivo atualizado: {node.path()} ({size} bytes)."

    def delete(self, path: str) -> str:
        node = self._resolve(path)
        if node.parent is None:
            raise FileSystemError("A raiz não pode ser removida.")
        self._check_access(node.parent, "write")
        self._check_access(node.parent, "execute")
        if node.is_dir and node.children:
            raise FileSystemError("Diretório não vazio. Remova seu conteúdo primeiro.")
        del node.parent.children[node.name]
        if self.cwd is node:
            self.cwd = node.parent
        return f"Removido: {node.path()}"

    def change_dir(self, path: str) -> str:
        node = self._resolve(path)
        if not node.is_dir:
            raise FileSystemError(f"'{node.path()}' não é um diretório.")
        self.cwd = node
        return self.cwd.path()

    def tree(self) -> str:
        lines = ["/"]
        def visit(node: Node, prefix: str) -> None:
            children = sorted(node.children.values(), key=lambda x: (not x.is_dir, x.name.lower()))
            for i, child in enumerate(children):
                last = i == len(children) - 1
                branch = "└── " if last else "├── "
                label = f"{child.name}/ [DIR]" if child.is_dir else f"{child.name} ({self._human_size(child.size)}) [ARQ]"
                lines.append(prefix + branch + label)
                if child.is_dir:
                    visit(child, prefix + ("    " if last else "│   "))
        visit(self.root, "")
        return "\n".join(lines)

    @staticmethod
    def _human_size(size: int) -> str:
        if size and size % (1024 * 1024) == 0:
            return f"{size // (1024 * 1024)} MB"
        if size and size % 1024 == 0:
            return f"{size // 1024} KB"
        return f"{size} B"

    def status(self) -> str:
        files = self._all_files()
        used = self._used_blocks()
        free = self._free_blocks()
        map_lines = [f"Tamanho do Bloco: {self.block_size} B | Total de Blocos: {self.total_blocks} ({self.block_size * self.total_blocks} B)",
                     f"Estratégia de Alocação: {self.strategy}", "", "[MAPA DE ALOCAÇÃO DO DISCO]"]
        owners: dict[int, str] = {}
        for file in files:
            if file.index_block is not None:
                owners[file.index_block] = f"[ÍNDICE] {file.path()}"
            for idx, block in enumerate(file.blocks, 1):
                owners[block] = f"[DADO] {file.path()} (Bloco lógico {idx})"
        for block in range(self.total_blocks):
            map_lines.append(f"Bloco {block:02d}  {owners.get(block, '[LIVRE]')}")
        internal = sum((self.block_size - f.size % self.block_size) % self.block_size for f in files)
        free_runs: list[int] = []
        run = 0
        for block in range(self.total_blocks):
            if block not in used:
                run += 1
            elif run:
                free_runs.append(run)
                run = 0
        if run:
            free_runs.append(run)
        biggest_run = max(free_runs, default=0)
        # Há fragmentação externa quando o espaço livre está dividido em mais de uma
        # sequência e a sequência maior é menor que o total de blocos livres: há pedidos
        # contíguos possíveis em teoria que não caberiam sem compactação.
        free_run_count = sum(1 for length in free_runs if length > 0)
        external = (self.strategy == "contiguous" and free_run_count > 1
                    and biggest_run < len(free))
        compact = "SIM" if external else "NÃO"
        report = ["", "--- RELATÓRIO DE FRAGMENTAÇÃO ---",
                  f"Arquivos: {len(files)} | Blocos ocupados: {len(used)} | Blocos livres: {len(free)}",
                  f"Espaço livre total: {len(free) * self.block_size} B | Maior sequência livre: {biggest_run} blocos",
                  f"Fragmentação Interna: {internal} B (espaço desperdiçado nos últimos blocos dos arquivos)",
                  f"Fragmentação Externa: {'SIM' if external else 'NÃO'}" + (f" ({len(free)} blocos livres, maior sequência: {biggest_run})" if external else ""),
                  f"Necessidade de Compactação: {compact}" + (" (alocação contígua não encontra sequência livre suficiente)" if external else "")]
        if self.strategy != "contiguous":
            report.append("Compactação: não necessária para a estratégia selecionada; blocos não precisam ser contíguos.")
        return "\n".join(map_lines + report)

    def help_text(self) -> str:
        return """Comandos disponíveis:
  login --user <nome>             autentica usuário (senha solicitada)
  logout                          volta ao modo kernel/root
  whoami                          exibe usuário, grupo e modo
  groupadd <grupo>                [root] cria grupo
  useradd <usuário> <grupo>       [root] cadastra usuário (senha solicitada)
  chmod <modo octal> <caminho>    [root] altera ACL, ex.: chmod 750 /arquivo
  acl <caminho>                   exibe proprietário e permissões rwx
  encrypt_file <caminho>          criptografa em repouso (chave solicitada)
  decrypt_file <caminho>          descriptografa para leitura (chave solicitada)
  antivirus_scan [diretório]      verifica integridade e assinaturas simuladas
  tamper_block <caminho> <bloco>  [root] adultera bloco para demonstrar auditoria
  audit_log                       exibe tentativas e alertas registrados
  mkdir <caminho>                 cria diretório
  create <caminho> --size <bytes> cria arquivo e aloca espaço
  read <caminho>                  lê arquivo e gera E/S no disco
  write_file <caminho> "texto"    grava dados e gera E/S no RAID
  write_file <caminho> --size 8KB simula gravação por tamanho
  update <caminho> --size <bytes> altera tamanho e realoca o arquivo
  disk_status                     exibe o histórico de escalonamento de E/S
  raid_status                     exibe o estado do arranjo RAID
  fail_disk <número>              simula falha e reconstrução RAID
  rm <caminho>                    remove arquivo ou diretório vazio
  cd <caminho> | pwd              navega / mostra diretório atual
  tree                            exibe a árvore de diretórios
  fs_status [--details]           mapa de blocos e fragmentação
  help | exit                     ajuda / sair
Caminhos absolutos e relativos são aceitos. Tamanhos: bytes (ex.: 10240), ou K/M (ex.: 10KB, 2MB)."""


def parse_size(value: str) -> int:
    text = value.strip().upper().replace(" ", "")
    multiplier = 1
    if text.endswith("KB"):
        multiplier, text = 1024, text[:-2]
    elif text.endswith("K"):
        multiplier, text = 1024, text[:-1]
    elif text.endswith("MB"):
        multiplier, text = 1024 * 1024, text[:-2]
    elif text.endswith("M"):
        multiplier, text = 1024 * 1024, text[:-1]
    try:
        number = float(text)
    except ValueError as exc:
        raise FileSystemError(f"Tamanho inválido: '{value}'.") from exc
    if number < 0 or not number.is_integer():
        raise FileSystemError("O tamanho deve ser um número inteiro não negativo.")
    return int(number * multiplier)


def execute(fs: FileSystem, line: str) -> tuple[bool, str]:
    try:
        args = shlex.split(line)
    except ValueError as exc:
        return True, f"Erro: {exc}"
    if not args:
        return True, ""
    cmd = args[0].lower()
    try:
        if cmd in ("exit", "quit"):
            return False, "Encerrando simulador."
        if cmd == "help":
            return True, fs.help_text()
        if cmd == "logout" and len(args) == 1:
            fs.identity.logout()
            return True, fs.security_status()
        if cmd == "su" and len(args) == 1:
            if not fs.identity.is_root:
                raise FileSystemError("A troca para root exige autenticação explícita de root.")
            return True, fs.security_status()
        if cmd == "whoami" and len(args) == 1:
            return True, fs.security_status()
        if cmd == "login" and len(args) == 3 and args[1] == "--user":
            password = getpass("Senha: ")
            return True, fs.login(args[2], password)
        if cmd == "login" and len(args) == 4 and args[1] == "--user" and args[3] == "--password":
            raise FileSystemError("Por segurança, não informe senha na linha de comando; use login --user <nome>.")
        if cmd == "groupadd" and len(args) == 2:
            return True, f"Grupo criado: {fs.add_group(args[1])}"
        if cmd == "useradd" and len(args) == 3:
            password = getpass(f"Senha para {args[1]}: ")
            return True, f"Usuário criado: {fs.add_user(args[1], password, args[2])}"
        if cmd == "chmod" and len(args) == 3:
            try:
                mode = int(args[1], 8)
            except ValueError as exc:
                raise FileSystemError("Modo inválido; use octal como 750.") from exc
            return True, fs.set_permissions(args[2], mode)
        if cmd == "acl" and len(args) == 2:
            return True, fs.acl_status(args[1])
        if cmd == "encrypt_file" and len(args) == 2:
            key = getpass("Chave de criptografia: ")
            return True, fs.encrypt_file(args[1], key)
        if cmd == "decrypt_file" and len(args) == 2:
            key = getpass("Chave de criptografia: ")
            return True, fs.decrypt_file(args[1], key)
        if cmd == "antivirus_scan" and len(args) in (1, 2):
            return True, fs.antivirus_scan(args[1] if len(args) == 2 else "/")
        if cmd == "tamper_block" and len(args) == 3:
            try:
                block = int(args[2])
            except ValueError as exc:
                raise FileSystemError("Número do bloco inválido.") from exc
            return True, fs.tamper_block(args[1], block)
        if cmd == "audit_log" and len(args) == 1:
            return True, "\n".join(fs.audit_log) if fs.audit_log else "Nenhum evento de segurança registrado."
        if cmd == "mkdir" and len(args) == 2:
            return True, f"Diretório criado: {fs.mkdir(args[1])}"
        if cmd in ("create", "touch") and len(args) in (2, 4):
            size = 0
            if len(args) == 4 and args[2] == "--size":
                size = parse_size(args[3])
            elif len(args) != 2:
                raise FileSystemError("Uso: create <caminho> [--size <tamanho>]")
            return True, f"Arquivo criado: {fs.create_file(args[1], size)} ({size} bytes)."
        if cmd in ("read", "cat", "info") and len(args) == 2:
            return True, fs.read_file(args[1])
        if cmd == "write_file" and len(args) >= 3:
            if len(args) == 4 and args[2] == "--size":
                size = parse_size(args[3])
                payload = b"\0" * size
            elif len(args) == 3:
                payload = args[2].encode("utf-8")
            else:
                raise FileSystemError('Uso: write_file <caminho> "texto" ou --size <tamanho>')
            return True, fs.write_data(args[1], payload)
        if cmd == "update" and len(args) == 4 and args[2] == "--size":
            return True, fs.update_file(args[1], parse_size(args[3]))
        if cmd == "read_file" and len(args) == 2:
            return True, fs.read_file(args[1])
        if cmd in ("rm", "rmdir", "delete") and len(args) == 2:
            return True, fs.delete(args[1])
        if cmd == "cd" and len(args) == 2:
            return True, f"Diretório atual: {fs.change_dir(args[1])}"
        if cmd == "pwd" and len(args) == 1:
            return True, fs.cwd.path()
        if cmd == "tree" and len(args) == 1:
            return True, "[ÁRVORE DO SISTEMA DE ARQUIVOS]\n" + fs.tree()
        if cmd == "disk_status" and len(args) == 1:
            return True, fs.io_status()
        if cmd == "raid_status" and len(args) == 1:
            return True, fs.raid_status()
        if cmd == "fail_disk" and len(args) == 2:
            try:
                return True, fs.fail_raid_disk(int(args[1]))
            except ValueError as exc:
                raise FileSystemError("O número do disco deve ser inteiro.") from exc
        if cmd == "fs_status" and len(args) in (1, 2) and (len(args) == 1 or args[1] == "--details"):
            return True, fs.status()
        raise FileSystemError("Comando ou argumentos inválidos. Digite 'help' para ver os comandos.")
    except (FileSystemError, ValueError) as exc:
        return True, f"Erro: {exc}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Simulador didático de sistema de arquivos em árvore.")
    parser.add_argument("--block-size", type=int, default=4096, help="tamanho de cada bloco em bytes (padrão: 4096)")
    parser.add_argument("--blocks", type=int, default=16, help="número total de blocos (padrão: 16)")
    parser.add_argument("--strategy", choices=FileSystem.STRATEGIES, default="indexed", help="contiguous, linked ou indexed")
    parser.add_argument("--scheduler", choices=DiskScheduler.ALGORITHMS, default="SSTF",
                        help="FCFS, SSTF, SCAN ou C-SCAN (padrão: SSTF)")
    parser.add_argument("--tracks", type=int, default=200, help="quantidade de trilhas do disco")
    parser.add_argument("--head", type=int, default=53, help="posição inicial da cabeça")
    parser.add_argument("--raid", choices=RAIDArray.LEVELS, default="5", help="nível RAID: 0, 1, 4 ou 5")
    parser.add_argument("--raid-disks", type=int, default=3, help="quantidade de discos no arranjo RAID")
    parser.add_argument("--command", help="executa um comando e encerra (útil para demonstração)")
    args = parser.parse_args()
    try:
        fs = FileSystem(args.block_size, args.blocks, args.strategy,
                        args.scheduler, args.tracks, args.head, args.raid, args.raid_disks)
    except ValueError as exc:
        parser.error(str(exc))
    if args.command:
        keep_running, output = execute(fs, args.command)
        if output:
            print(output)
        return 0 if keep_running or output else 1
    print("Simulador de Sistema de Arquivos — digite 'help' para começar.")
    while True:
        try:
            line = input(f"{fs.cwd.path()} > ")
        except (EOFError, KeyboardInterrupt):
            print("\nEncerrando simulador.")
            break
        keep_running, output = execute(fs, line)
        if output:
            print(output)
        if not keep_running:
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
