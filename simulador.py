#!/usr/bin/env python3
"""Simulador didático de sistema de arquivos e alocação de blocos."""
from __future__ import annotations

import argparse
import math
import shlex
import sys
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Node:
    name: str
    is_dir: bool
    parent: Optional["Node"] = None
    children: dict[str, "Node"] = field(default_factory=dict)
    size: int = 0
    blocks: list[int] = field(default_factory=list)
    index_block: Optional[int] = None

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
                 strategy: str = "indexed"):
        if block_size <= 0 or total_blocks <= 0:
            raise ValueError("O tamanho do bloco e a quantidade de blocos devem ser positivos.")
        if strategy not in self.STRATEGIES:
            raise ValueError(f"Estratégia inválida. Escolha: {', '.join(self.STRATEGIES)}")
        self.block_size = block_size
        self.total_blocks = total_blocks
        self.strategy = strategy
        self.root = Node("", True)
        self.cwd = self.root

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
        if name in parent.children:
            raise FileSystemError(f"Já existe um item chamado '{name}'.")
        parent.children[name] = Node(name, True, parent)
        return parent.children[name].path()

    def create_file(self, path: str, size: int = 0) -> str:
        if size < 0:
            raise FileSystemError("O tamanho não pode ser negativo.")
        parent, name = self._parent_and_name(path)
        if name in parent.children:
            raise FileSystemError(f"Já existe um item chamado '{name}'.")
        node = Node(name, False, parent, size=size)
        node.blocks, node.index_block = self._allocate(node, size)
        parent.children[name] = node
        return node.path()

    def read_file(self, path: str) -> str:
        node = self._resolve(path)
        if node.is_dir:
            raise FileSystemError(f"'{node.path()}' é um diretório, não um arquivo.")
        return f"Arquivo: {node.path()} | Tamanho: {node.size} bytes | Blocos de dados: {node.blocks}"

    def update_file(self, path: str, size: int) -> str:
        if size < 0:
            raise FileSystemError("O tamanho não pode ser negativo.")
        node = self._resolve(path)
        if node.is_dir:
            raise FileSystemError(f"'{node.path()}' é um diretório, não um arquivo.")
        old_blocks, old_index, old_size = node.blocks, node.index_block, node.size
        node.blocks, node.index_block = [], None
        try:
            node.blocks, node.index_block = self._allocate(node, size)
        except FileSystemError:
            node.blocks, node.index_block, node.size = old_blocks, old_index, old_size
            raise
        node.size = size
        return f"Arquivo atualizado: {node.path()} ({size} bytes)."

    def delete(self, path: str) -> str:
        node = self._resolve(path)
        if node.parent is None:
            raise FileSystemError("A raiz não pode ser removida.")
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
  mkdir <caminho>                 cria diretório
  create <caminho> --size <bytes> cria arquivo e aloca espaço
  read <caminho>                  exibe informações do arquivo
  update <caminho> --size <bytes> altera tamanho e realoca o arquivo
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
        if cmd == "update" and len(args) == 4 and args[2] == "--size":
            return True, fs.update_file(args[1], parse_size(args[3]))
        if cmd in ("rm", "rmdir", "delete") and len(args) == 2:
            return True, fs.delete(args[1])
        if cmd == "cd" and len(args) == 2:
            return True, f"Diretório atual: {fs.change_dir(args[1])}"
        if cmd == "pwd" and len(args) == 1:
            return True, fs.cwd.path()
        if cmd == "tree" and len(args) == 1:
            return True, "[ÁRVORE DO SISTEMA DE ARQUIVOS]\n" + fs.tree()
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
    parser.add_argument("--command", help="executa um comando e encerra (útil para demonstração)")
    args = parser.parse_args()
    try:
        fs = FileSystem(args.block_size, args.blocks, args.strategy)
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
