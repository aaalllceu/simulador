"""Gerenciador didático de RAM híbrida: região reservada e paginação por demanda."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field


class MemoryErrorSim(Exception):
    """Erro operacional da memória simulada."""


@dataclass
class Process:
    name: str
    size: int
    kind: str
    start: int | None = None
    pages: int = 0
    page_table: dict[int, int] = field(default_factory=dict)
    swapped: set[int] = field(default_factory=set)


@dataclass
class Frame:
    key: tuple[str, int] | None = None
    last_used: int = 0
    referenced: bool = False


class MemoryManager:
    """Simula alocação contígua crítica e memória virtual paginada sob demanda.

    Os valores padrão reservam 4 MiB para processos críticos, dos quais 1 MiB
    pertence ao núcleo, e oferecem oito molduras de 4 KiB à área dinâmica.
    """

    KIB = 1024
    MIB = 1024 * KIB

    def __init__(self, reserved_size: int = 4 * MIB, kernel_size: int = MIB,
                 page_size: int = 4 * KIB, frame_count: int = 8,
                 algorithm: str = "LRU"):
        algorithm = algorithm.upper().replace("-", "_")
        if algorithm == "SECONDCHANCE":
            algorithm = "SECOND_CHANCE"
        if reserved_size <= 0 or kernel_size < 0 or kernel_size >= reserved_size:
            raise ValueError("A região reservada deve ser positiva e maior que o núcleo base.")
        if page_size <= 0 or frame_count <= 0:
            raise ValueError("O tamanho da página e a quantidade de molduras devem ser positivos.")
        if algorithm not in ("LRU", "SECOND_CHANCE"):
            raise ValueError("Algoritmo deve ser LRU ou SECOND_CHANCE.")
        self.reserved_size = reserved_size
        self.kernel_size = kernel_size
        self.page_size = page_size
        self.frames = [Frame() for _ in range(frame_count)]
        self.algorithm = algorithm
        self.processes: dict[str, Process] = {}
        self.clock = 0
        self.hand = 0
        self.page_faults = 0
        self.evictions = 0

    @staticmethod
    def _human(size: int) -> str:
        if size % MemoryManager.MIB == 0:
            return f"{size // MemoryManager.MIB} MB"
        if size % MemoryManager.KIB == 0:
            return f"{size // MemoryManager.KIB} KB"
        return f"{size} B"

    def _reserved_processes(self) -> list[Process]:
        return sorted((p for p in self.processes.values() if p.kind == "critical"),
                      key=lambda p: p.start if p.start is not None else -1)

    def _find_hole(self, size: int) -> int | None:
        cursor = self.kernel_size
        for proc in self._reserved_processes():
            assert proc.start is not None
            if proc.start - cursor >= size:
                return cursor
            cursor = max(cursor, proc.start + proc.size)
        return cursor if self.reserved_size - cursor >= size else None

    def create_process(self, name: str, size: int, kind: str = "normal") -> str:
        kind = kind.lower()
        if not name or name in self.processes:
            raise MemoryErrorSim(f"Nome de processo inválido ou já existente: '{name}'.")
        if size <= 0:
            raise MemoryErrorSim("O tamanho do processo deve ser positivo.")
        if kind not in ("critical", "normal"):
            raise MemoryErrorSim("Tipo de processo deve ser critical ou normal.")
        if kind == "critical":
            start = self._find_hole(size)
            if start is None:
                free = self.reserved_size - self.kernel_size - sum(p.size for p in self._reserved_processes())
                raise MemoryErrorSim(f"Sem bloco contíguo de {self._human(size)} na região reservada; espaço livre total: {self._human(free)}. Compacte ou reduza o pedido.")
            process = Process(name, size, kind, start=start)
            self.processes[name] = process
            end = start + size
            return (f"Processo crítico '{name}' alocado de forma contígua na Área Reservada: "
                    f"[{self._human(start)} até {self._human(end)}] ({self._human(size)}).")
        pages = math.ceil(size / self.page_size)
        process = Process(name, size, kind, pages=pages)
        self.processes[name] = process
        waste = pages * self.page_size - size
        return ("[CRIAÇÃO DE PROCESSO NÃO CRÍTICO - MEMÓRIA VIRTUAL PAGINADA]\n"
                f"Tamanho do Processo : {size} bytes ({self._human(size)})\n"
                f"Tamanho da Página   : {self.page_size} bytes ({self._human(self.page_size)})\n"
                f"Páginas Lógicas     : {pages} (índices 0 a {pages - 1})\n"
                f"Fragmentação Interna: {waste} bytes\n"
                "Tabela de páginas criada sem molduras residentes (alocação por demanda).")

    def terminate_process(self, name: str) -> str:
        process = self.processes.get(name)
        if process is None:
            raise MemoryErrorSim(f"Processo não encontrado: '{name}'.")
        if process.kind == "critical":
            assert process.start is not None
            start, end = process.start, process.start + process.size
            del self.processes[name]
            return (f"[ENCERRAMENTO DE PROCESSO CRÍTICO] Processo '{name}' finalizado.\n"
                    f"Área de {self._human(end - start)} no intervalo [{self._human(start)} a {self._human(end)}] liberada.")
        for page in list(process.page_table):
            frame_index = process.page_table[page]
            self.frames[frame_index] = Frame()
        del self.processes[name]
        return f"Processo '{name}' finalizado; molduras residentes liberadas."

    def _touch(self, key: tuple[str, int]) -> tuple[int, bool]:
        process_name, page = key
        process = self.processes[process_name]
        self.clock += 1
        resident = process.page_table.get(page)
        if resident is not None:
            frame = self.frames[resident]
            frame.last_used = self.clock
            frame.referenced = True
            return resident, False

        self.page_faults += 1
        free = next((index for index, frame in enumerate(self.frames) if frame.key is None), None)
        if free is None:
            free = self._choose_victim()
            victim = self.frames[free].key
            assert victim is not None
            old_process = self.processes[victim[0]]
            old_process.page_table.pop(victim[1], None)
            old_process.swapped.add(victim[1])
            self.evictions += 1
        frame = self.frames[free]
        frame.key = key
        frame.last_used = self.clock
        frame.referenced = True
        process.page_table[page] = free
        process.swapped.discard(page)
        return free, True

    def _choose_victim(self) -> int:
        if self.algorithm == "LRU":
            return min(range(len(self.frames)), key=lambda index: self.frames[index].last_used)
        while True:
            frame = self.frames[self.hand]
            if not frame.referenced:
                victim = self.hand
                self.hand = (self.hand + 1) % len(self.frames)
                return victim
            frame.referenced = False
            self.hand = (self.hand + 1) % len(self.frames)

    def translate(self, process_name: str, page: int) -> str:
        process = self.processes.get(process_name)
        if process is None:
            raise MemoryErrorSim(f"Processo não encontrado: '{process_name}'.")
        if process.kind != "normal":
            raise MemoryErrorSim("Tradução por página se aplica somente a processos normais.")
        if page < 0 or page >= process.pages:
            raise MemoryErrorSim(f"Página lógica inválida: {page}; páginas válidas: 0 a {process.pages - 1}.")
        was_swapped = page in process.swapped
        frame, fault = self._touch((process_name, page))
        result = "PAGE FAULT" if fault else "HIT"
        extra = "Página recuperada do swap." if was_swapped else ""
        return ("[TRADUÇÃO DE ENDEREÇO: PÁGINA LÓGICA -> MOLDURA FÍSICA]\n"
                f"Solicitação: Processo {process_name}, página lógica {page} -> moldura física {frame} "
                f"(RAM Dinâmica) [{result}]. {extra}\n"
                f"Falhas de página acumuladas: {self.page_faults}; algoritmo: {self.algorithm}.")

    def execute_step(self, process_name: str, instruction: str) -> str:
        process = self.processes.get(process_name)
        if process is None or process.kind != "normal":
            raise MemoryErrorSim(f"Processo normal não encontrado: '{process_name}'.")
        match = re.search(r"(?:p[aá]gina|page)\s+(\d+)", instruction, re.IGNORECASE)
        if not match:
            raise MemoryErrorSim("A instrução deve indicar uma página, por exemplo: LOAD_DATA Página 2.")
        page = int(match.group(1))
        result = self.translate(process_name, page)
        return (f"[CPU - REFERÊNCIA DE MEMÓRIA]\n{process_name} executa: {instruction}\n"
                f"{result}")

    def compact_reserved(self) -> str:
        processes = self._reserved_processes()
        cursor = self.kernel_size
        moves = []
        for process in processes:
            assert process.start is not None
            old = process.start
            if old != cursor:
                moves.append(f"- '{process.name}': [{self._human(old)} a {self._human(old + process.size)}] -> [{self._human(cursor)} a {self._human(cursor + process.size)}]")
                process.start = cursor
            cursor += process.size
        return ("[COMPACTAÇÃO DA REGIÃO RESERVADA]\n" +
                ("\n".join(moves) if moves else "Nenhuma realocação necessária.") +
                f"\nMaior bloco livre após compactação: {self._human(self.reserved_size - cursor)}.")

    def status_reserved(self) -> str:
        processes = self._reserved_processes()
        lines = [f"--- MAPA DA ÁREA CRÍTICA/RESERVADA (Total: {self._human(self.reserved_size)}) ---"]
        cursor = 0
        segments: list[tuple[int, int, str, bool]] = [(0, self.kernel_size, "Núcleo Base do SO", True)]
        for process in processes:
            assert process.start is not None
            segments.append((process.start, process.start + process.size, process.name, True))
        segments.sort(key=lambda item: item[0])
        free_count = 0
        for start, end, label, occupied in segments:
            if start > cursor:
                free_count += 1
                lines.append(f"[{self._human(cursor)} - {self._human(start)}] : FRAGMENTO LIVRE {free_count} ({self._human(start - cursor)}) [LIVRE]")
            lines.append(f"[{self._human(start)} - {self._human(end)}] : {label} ({self._human(end - start)}) [{'OCUPADO' if occupied else 'LIVRE'}]")
            cursor = max(cursor, end)
        if cursor < self.reserved_size:
            free_count += 1
            lines.append(f"[{self._human(cursor)} - {self._human(self.reserved_size)}] : FRAGMENTO LIVRE {free_count} ({self._human(self.reserved_size - cursor)}) [LIVRE]")
        free_total = self.reserved_size - self.kernel_size - sum(p.size for p in processes)
        gaps = [b[0] - a[1] for a, b in zip(segments, segments[1:]) if b[0] > a[1]]
        if cursor < self.reserved_size:
            gaps.append(self.reserved_size - cursor)
        largest = max(gaps, default=0)
        fragmented = sum(gap > 0 for gap in gaps) > 1 and largest < free_total
        lines += ["", "--- DIAGNÓSTICO DE FRAGMENTAÇÃO EXTERNA ---",
                  f"Total de Memória Livre na Área Reservada: {self._human(free_total)}",
                  f"Maior Bloco Contíguo Disponível: {self._human(largest)}",
                  f"Fragmentação Externa Detectada: {'SIM' if fragmented else 'NÃO'} ({sum(gap > 0 for gap in gaps)} fragmento(s) livre(s))"]
        if free_total and largest < free_total:
            lines.append(f"Compactação recomendada para consolidar {self._human(free_total)} livres em um só bloco.")
        else:
            lines.append("Compactação não necessária no momento.")
        return "\n".join(lines)

    def status_virtual(self) -> str:
        normal = [p for p in self.processes.values() if p.kind == "normal"]
        resident = sum(frame.key is not None for frame in self.frames)
        lines = ["--- MEMÓRIA VIRTUAL / RAM DINÂMICA ---",
                 f"Tamanho da Página: {self._human(self.page_size)} | Molduras físicas: {len(self.frames)} | Capacidade dinâmica: {self._human(len(self.frames) * self.page_size)}",
                 f"Molduras ocupadas: {resident}/{len(self.frames)} | Livres: {len(self.frames) - resident} | Falhas de página: {self.page_faults} | Substituições: {self.evictions} | Algoritmo: {self.algorithm}"]
        for process in normal:
            internal = process.pages * self.page_size - process.size
            lines.append(f"Processo {process.name}: {self._human(process.size)}, {process.pages} página(s), residente(s) {len(process.page_table)}, em swap {len(process.swapped)}, fragmentação interna {internal} B")
            for page, frame in sorted(process.page_table.items()):
                lines.append(f"  Página {page} -> Moldura {frame}")
        if not normal:
            lines.append("Nenhum processo normal cadastrado.")
        return "\n".join(lines)

    def status(self) -> str:
        return self.status_reserved() + "\n\n" + self.status_virtual()
