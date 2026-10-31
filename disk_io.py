"""Escalonamento de E/S e abstração didática de arranjos RAID."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class IORequest:
    track: int
    operation: str
    path: str = ""
    block: int = 0


class DiskScheduler:
    """Agenda requisições por trilha e mantém a posição da cabeça entre operações."""

    ALGORITHMS = ("FCFS", "SSTF", "SCAN", "C-SCAN")

    def __init__(self, algorithm: str = "SSTF", tracks: int = 200,
                 head: int = 53, direction: str = "up"):
        algorithm = algorithm.upper()
        if algorithm not in self.ALGORITHMS:
            raise ValueError(f"Algoritmo inválido; escolha: {', '.join(self.ALGORITHMS)}")
        if tracks < 2 or not 0 <= head < tracks:
            raise ValueError("A quantidade de trilhas deve ser >= 2 e a cabeça deve estar no disco.")
        if direction not in ("up", "down"):
            raise ValueError("A direção deve ser 'up' ou 'down'.")
        self.algorithm, self.tracks, self.head, self.direction = algorithm, tracks, head, direction

    def schedule(self, requests: Iterable[IORequest]) -> str:
        pending = list(requests)
        if not pending:
            return "[E/S] Nenhuma requisição de disco pendente."
        if any(not 0 <= request.track < self.tracks for request in pending):
            raise ValueError(f"Trilha inválida: use valores entre 0 e {self.tracks - 1}.")
        start = self.head
        ordered: list[IORequest] = []
        route = [start]
        if self.algorithm == "FCFS":
            ordered = pending[:]
            route.extend(r.track for r in ordered)
        elif self.algorithm == "SSTF":
            current, remaining = start, pending[:]
            while remaining:
                request = min(remaining, key=lambda item: abs(item.track - current))
                ordered.append(request)
                remaining.remove(request)
                current = request.track
            route.extend(r.track for r in ordered)
        else:
            upward = self.direction == "up"
            near = sorted((r for r in pending if (r.track >= start if upward else r.track <= start)),
                          key=lambda r: r.track, reverse=not upward)
            far = sorted((r for r in pending if (r.track < start if upward else r.track > start)),
                         key=lambda r: r.track, reverse=not upward)
            ordered = near + far
            route.extend(r.track for r in near)
            if far:
                endpoint = self.tracks - 1 if upward else 0
                if route[-1] != endpoint:
                    route.append(endpoint)
                if self.algorithm == "C-SCAN":
                    route.append(0 if upward else self.tracks - 1)
                route.extend(r.track for r in far)
            elif not near:
                ordered = pending[:]
                route.extend(r.track for r in ordered)
        distances = [abs(b - a) for a, b in zip(route, route[1:])]
        self.head = ordered[-1].track
        details = " | ".join(
            f"{r.operation} {r.path or ''} bloco {r.block} (trilha {r.track})".strip()
            for r in ordered
        )
        serviced = " -> ".join(str(r.track) for r in ordered)
        route_text = " -> ".join(map(str, route))
        formula = " + ".join(map(str, distances)) or "0"
        return (f"[E/S] Requisições pendentes: {len(pending)} ({details})\n"
                f"Posição atual da cabeça: Trilha {start}\n\n"
                f"--- ESCALONAMENTO DE DISCO: {self.algorithm} ---\n"
                f"Ordem de Atendimento: {start} -> {serviced}\n"
                f"Trajeto da cabeça: {route_text}\n"
                f"Deslocamento da Cabeça: {formula} = {sum(distances)} trilhas\n"
                f"Total de Movimento: {sum(distances)} trilhas")


class RAIDArray:
    """Armazenamento em blocos com RAID 0/1/4/5 e reconstrução de uma falha."""

    LEVELS = ("0", "1", "4", "5")

    def __init__(self, level: str = "5", disks: int = 3, block_size: int = 4096):
        level = str(level).upper().replace("RAID", "")
        if level not in self.LEVELS:
            raise ValueError("Nível RAID inválido; use 0, 1, 4 ou 5.")
        minimum = 2 if level in ("0", "1") else 3
        if disks < minimum or block_size <= 0:
            raise ValueError(f"RAID {level} requer ao menos {minimum} discos e bloco positivo.")
        self.level, self.disk_count, self.block_size = level, disks, block_size
        self.storage: list[dict[int, bytes]] = [dict() for _ in range(disks)]
        self.failed_disks: set[int] = set()

    @property
    def data_disks(self) -> int:
        return self.disk_count if self.level == "0" else (1 if self.level == "1" else self.disk_count - 1)

    def _xor(self, blocks: Iterable[bytes]) -> bytes:
        result = bytearray(self.block_size)
        for block in blocks:
            for i, value in enumerate(block):
                result[i] ^= value
        return bytes(result)

    def write(self, path: str, data: bytes) -> list[str]:
        if self.failed_disks:
            raise ValueError("Não é possível gravar enquanto houver disco em falha; reconstrua-o primeiro.")
        chunks = [data[i:i + self.block_size].ljust(self.block_size, b"\0")
                  for i in range(0, len(data), self.block_size)]
        if not chunks:
            chunks = []
        existing_stripes = [stripe for disk in self.storage for stripe in disk]
        base_stripe = max(existing_stripes, default=-1) + 1
        lines = [f"Arranjo Ativo: RAID {self.level} ({self.disk_count} discos, blocos de {self.block_size} bytes)",
                 "[E/S - DISTRIBUIÇÃO EM DISCO]"]
        if self.level == "0":
            for logical, chunk in enumerate(chunks):
                disk, stripe = logical % self.disk_count, base_stripe + logical // self.disk_count
                self.storage[disk][stripe] = chunk
                lines.append(f"Disco {disk + 1}: [Bloco {stripe:02d}: {path} - Parte {logical + 1}]")
        elif self.level == "1":
            for logical, chunk in enumerate(chunks):
                stripe = base_stripe + logical
                for disk in range(self.disk_count):
                    self.storage[disk][stripe] = chunk
                lines.append(f"Discos 1..{self.disk_count}: [Bloco {stripe:02d}: cópia espelhada de {path}]")
        else:
            width = self.disk_count - 1
            for logical, chunk in enumerate(chunks):
                stripe, position = divmod(logical, width)
                stripe += base_stripe
                parity_disk = self.disk_count - 1 if self.level == "4" else (self.disk_count - 1 - stripe % self.disk_count)
                data_slots = [d for d in range(self.disk_count) if d != parity_disk]
                disk = data_slots[position]
                self.storage[disk][stripe] = chunk
                lines.append(f"Disco {disk + 1}: [Bloco {stripe:02d}: Dados de {path} - Parte {logical + 1}]")
            for stripe in range(base_stripe, base_stripe + (len(chunks) + width - 1) // width):
                parity_disk = self.disk_count - 1 if self.level == "4" else (self.disk_count - 1 - stripe % self.disk_count)
                data_slots = [d for d in range(self.disk_count) if d != parity_disk]
                parity = self._xor(self.storage[d][stripe] for d in data_slots if stripe in self.storage[d])
                self.storage[parity_disk][stripe] = parity
                lines.append(f"Disco {parity_disk + 1}: [PARIDADE XOR - Faixa {stripe:02d}]")
        return lines

    def fail_and_rebuild(self, disk_number: int) -> list[str]:
        disk = disk_number - 1
        if not 0 <= disk < self.disk_count:
            raise ValueError(f"Disco inválido; escolha entre 1 e {self.disk_count}.")
        if self.level == "0":
            raise ValueError("RAID 0 não possui redundância: os dados do disco falho não podem ser reconstruídos.")
        self.failed_disks.add(disk)
        failed_blocks = dict(self.storage[disk])
        self.storage[disk].clear()  # simula perda física antes de reconstruir
        recovered = 0
        for stripe in failed_blocks:
            if self.level == "1":
                source = next((self.storage[d] for d in range(self.disk_count)
                               if d != disk and stripe in self.storage[d]), None)
                if source is None:
                    raise ValueError("Não há cópia espelhada disponível para reconstrução.")
                self.storage[disk][stripe] = source[stripe]
            else:
                parity_disk = self.disk_count - 1 if self.level == "4" else (self.disk_count - 1 - stripe % self.disk_count)
                if disk == parity_disk:
                    data_slots = [d for d in range(self.disk_count) if d != parity_disk]
                    blocks = [self.storage[d][stripe] for d in data_slots if stripe in self.storage[d]]
                    self.storage[disk][stripe] = self._xor(blocks)
                else:
                    data_slots = [d for d in range(self.disk_count) if d != parity_disk]
                    data_blocks = [self.storage[d][stripe] for d in data_slots
                                   if d != disk and stripe in self.storage[d]]
                    parity = self.storage[parity_disk][stripe]
                    self.storage[disk][stripe] = self._xor([parity, *data_blocks])
            recovered += 1
        self.failed_disks.remove(disk)
        return ["[TESTE DE FALHA SIMULADO]", f"* Falha forçada no Disco {disk_number}!",
                f"* Reconstrução de {recovered} bloco(s) via redundância RAID {self.level}: [OK]"]

    def status(self) -> str:
        lines = [f"RAID {self.level} | Discos: {self.disk_count} | Capacidade útil: {self.data_disks} blocos por faixa de dados"]
        for number, blocks in enumerate(self.storage, 1):
            contents = ", ".join(f"faixa {stripe:02d}" for stripe in sorted(blocks)) or "vazio"
            lines.append(f"Disco {number}: {contents}")
        return "\n".join(lines)
