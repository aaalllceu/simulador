"""Escalonador didático Priority + Round-Robin com E/S, mutex e paginação."""
from __future__ import annotations

import math
import random
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field


class SchedulerError(Exception):
    """Erro operacional do escalonador de processos."""


@dataclass(frozen=True)
class IOEvent:
    operation: str
    at_cpu_ms: int
    duration_ms: int


@dataclass(frozen=True)
class MutexEvent:
    name: str
    at_cpu_ms: int
    duration_ms: int
    thread: str = "T1"


@dataclass
class ScheduledProcess:
    pid: int
    name: str
    burst_ms: int
    priority: int
    kind: str
    arrival_ms: int = 0
    remaining_ms: int = field(init=False)
    state: str = "NOVO"
    cpu_elapsed_ms: int = 0
    wait_ms: int = 0
    blocked_ms: int = 0
    first_start_ms: int | None = None
    finish_ms: int | None = None
    io_events: list[IOEvent] = field(default_factory=list)
    mutex_events: list[MutexEvent] = field(default_factory=list)
    fired_io: set[int] = field(default_factory=set)
    fired_mutex: set[int] = field(default_factory=set)
    blocked_until: int | None = None
    blocked_since: int | None = None
    block_reason: str = ""
    page_references: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.remaining_ms = self.burst_ms

    @property
    def turnaround_ms(self) -> int | None:
        return None if self.finish_ms is None else self.finish_ms - self.arrival_ms


@dataclass
class MutexLock:
    owner_pid: int
    owner_thread: str
    release_at: int


class ProcessScheduler:
    """Fila multinível por prioridade, com RR entre processos de igual nível.

    Prioridade numérica menor significa maior prioridade. A simulação avança em
    milissegundos inteiros; o gerenciador de memória compartilhado recebe cada
    referência de página gerada durante a execução.
    """

    _IO_RE = re.compile(r"([\w-]+)\s+at\s+(\d+)\s*ms?\s*\(\s*duration\s*:\s*(\d+)\s*ms?\s*\)", re.I)
    _MUTEX_RE = re.compile(r"([\w.-]+)\s+at\s+(\d+)\s*ms?\s*\(\s*duration\s*:\s*(\d+)\s*ms?\s*\)", re.I)

    def __init__(self, memory, disk_scheduler=None, seed: int = 7) -> None:
        self.memory = memory
        self.disk_scheduler = disk_scheduler
        self._initial_priority_cursor: dict[int, int] = {}
        self._rr_cursor: dict[int, int] = {}
        self._cpu_busy_ms = 0
        self.processes: dict[str, ScheduledProcess] = {}
        self.next_pid = 101
        self.rng = random.Random(seed)
        self.time_ms = 0
        self.context_switches = 0
        self._last_pid: int | None = None
        self.mutexes: dict[str, MutexLock] = {}
        self.mutex_waiters: dict[str, deque[tuple[int, MutexEvent]]] = defaultdict(deque)

    @classmethod
    def parse_io_profile(cls, profile: str, burst_ms: int, rng: random.Random) -> list[IOEvent]:
        text = profile.strip()
        if not text or text.lower() in ("none", "nenhum", "-", "false"):
            return []
        if text.lower() == "random":
            if burst_ms < 2:
                raise SchedulerError("Perfil random requer burst de pelo menos 2 ms.")
            at = rng.randint(1, burst_ms - 1)
            return [IOEvent("random_io", at, rng.randint(1, 4))]
        events: list[IOEvent] = []
        for part in text.split(";"):
            match = cls._IO_RE.fullmatch(part.strip())
            if not match:
                raise SchedulerError('Syscall inválida. Use, por exemplo, "read_disk at 3ms (duration: 4ms)" ou "random".')
            operation, at_text, duration_text = match.groups()
            at, duration = int(at_text), int(duration_text)
            if at <= 0 or at >= burst_ms or duration <= 0:
                raise SchedulerError("A syscall deve ocorrer após 0 ms e antes do fim do burst; duração deve ser positiva.")
            events.append(IOEvent(operation, at, duration))
        if len({event.at_cpu_ms for event in events}) != len(events):
            raise SchedulerError("Agende no máximo uma syscall por instante de CPU.")
        return sorted(events, key=lambda event: event.at_cpu_ms)

    @classmethod
    def parse_mutex_profile(cls, profile: str, burst_ms: int, thread: str = "T1") -> list[MutexEvent]:
        text = profile.strip()
        if not text or text.lower() in ("none", "nenhum", "-"):
            return []
        events: list[MutexEvent] = []
        for part in text.split(";"):
            match = cls._MUTEX_RE.fullmatch(part.strip())
            if not match:
                raise SchedulerError('Mutex inválido. Use "Buffer_Video at 2ms (duration: 3ms)".')
            name, at_text, duration_text = match.groups()
            at, duration = int(at_text), int(duration_text)
            if at <= 0 or at > burst_ms or duration <= 0:
                raise SchedulerError("O evento mutex deve ocorrer durante o burst e ter duração positiva.")
            events.append(MutexEvent(name, at, duration, thread))
        if len({event.at_cpu_ms for event in events}) != len(events):
            raise SchedulerError("Agende no máximo uma disputa por mutex em cada instante de CPU.")
        return sorted(events, key=lambda event: event.at_cpu_ms)

    def create_process(self, name: str, burst_ms: int, priority: int = 1,
                       kind: str = "normal", syscall: str = "",
                       mutex: str = "", thread: str = "T1") -> str:
        kind = kind.lower()
        if not name or name in self.processes or name in self.memory.processes:
            raise SchedulerError(f"Nome inválido ou já utilizado por outro processo: '{name}'.")
        if burst_ms <= 0 or priority <= 0:
            raise SchedulerError("Burst e prioridade devem ser inteiros positivos.")
        if kind not in ("normal", "critical"):
            raise SchedulerError("Tipo de processo deve ser normal ou critical.")
        io_events = self.parse_io_profile(syscall, burst_ms, self.rng)
        mutex_events = self.parse_mutex_profile(mutex, burst_ms, thread)
        if {event.at_cpu_ms for event in io_events} & {event.at_cpu_ms for event in mutex_events}:
            raise SchedulerError("Não agende syscall e disputa de mutex no mesmo instante de CPU.")
        allocated = self.memory.create_process(name, burst_ms * self.memory.page_size, kind)
        proc = ScheduledProcess(self.next_pid, name, burst_ms, priority, kind,
                                io_events=io_events, mutex_events=mutex_events)
        if kind == "normal":
            pages = self.memory.processes[name].pages
            proc.page_references = [self.rng.randrange(pages) for _ in range(burst_ms)]
        self.next_pid += 1
        self.processes[name] = proc
        proc.state = "PRONTO"
        profile_text = "Evento aleatório habilitado (semente reproduzível)" if syscall.strip().lower() == "random" else (
            "; ".join(f"{event.operation} em t_CPU={event.at_cpu_ms} ms (bloqueio {event.duration_ms} ms)" for event in io_events)
            if io_events else "Nenhuma")
        return (f"[CRIAÇÃO DE PROCESSO] PID: {proc.pid} | Nome: {name} | Prioridade: {priority}\n"
                f"Tipo: {kind} | Burst: {burst_ms} ms\nAlocação: {allocated}\n"
                f"Syscall/E/S: {profile_text}\nEventos mutex: {len(mutex_events)} | Estado Inicial: PRONTO")

    def _release_events(self, now: int, log: list[str]) -> None:
        for proc in self.processes.values():
            if proc.state == "BLOQUEADO" and proc.blocked_until is not None and proc.blocked_until <= now:
                if proc.blocked_since is not None:
                    proc.blocked_ms += max(0, proc.blocked_until - proc.blocked_since)
                proc.blocked_until = None
                proc.blocked_since = None
                proc.state = "PRONTO"
                log.append(f"[t={now} ms] PID {proc.pid} {proc.name}: BLOQUEADO -> PRONTO (fim da E/S; {proc.block_reason}).")
                proc.block_reason = ""
        expired = [name for name, lock in self.mutexes.items() if lock.release_at <= now]
        for name in expired:
            lock = self.mutexes.pop(name)
            log.append(f"[t={now} ms] Mutex '{name}' liberado por PID {lock.owner_pid}/{lock.owner_thread}.")
            while self.mutex_waiters[name]:
                pid, event = self.mutex_waiters[name].popleft()
                waiter = next((p for p in self.processes.values() if p.pid == pid), None)
                if waiter is None or waiter.state != "BLOQUEADO" or waiter.block_reason != f"mutex:{name}":
                    continue
                self.mutexes[name] = MutexLock(pid, event.thread, now + event.duration_ms)
                if waiter.blocked_since is not None:
                    waiter.blocked_ms += max(0, now - waiter.blocked_since)
                waiter.state = "PRONTO"
                waiter.blocked_until = None
                waiter.blocked_since = None
                waiter.block_reason = ""
                log.append(f"[t={now} ms] PID {pid} {event.thread} recebeu Mutex '{name}' e voltou a PRONTO; liberação em t={now + event.duration_ms} ms.")
                break

    def _ready_names(self) -> list[str]:
        return [p.name for p in self.processes.values() if p.state == "PRONTO"]

    def _select(self, last_priority: int | None, last_name: str | None,
                quantum_used: int, quantum: int) -> tuple[ScheduledProcess | None, int, str | None]:
        ready = sorted((p for p in self.processes.values() if p.state == "PRONTO"),
                       key=lambda p: (p.priority, p.pid))
        if not ready:
            return None, 0, None
        best_priority = ready[0].priority
        same = [p for p in ready if p.priority == best_priority]
        if last_name is not None and last_priority == best_priority and quantum_used < quantum:
            current = self.processes[last_name]
            if current.state == "EXECUTANDO":
                return current, quantum_used, last_name
        # Round-Robin por prioridade: percorre em ordem de entrada usando um cursor PID.
        cursor = getattr(self, "_rr_cursor", {}).get(best_priority, -1)
        chosen = next((p for p in same if p.pid > cursor), same[0])
        if not hasattr(self, "_rr_cursor"):
            self._rr_cursor = {}
        self._rr_cursor[best_priority] = chosen.pid
        return chosen, 0, chosen.name

    def run(self, quantum_ms: int = 2, process_name: str | None = None,
            max_steps: int | None = None) -> str:
        quantum = quantum_ms
        if quantum_ms <= 0:
            raise SchedulerError("O quantum deve ser positivo.")
        selected = list(self.processes.values())
        if process_name:
            if process_name not in self.processes:
                raise SchedulerError(f"Processo não encontrado no escalonador: '{process_name}'.")
            selected = [self.processes[process_name]]
        pending = [p for p in selected if p.state not in ("CONCLUÍDO",)]
        if not pending:
            return "Nenhum processo pendente para executar."
        log = ["--- ESCALONAMENTO COMBINADO: PRIORIDADE + ROUND-ROBIN ---",
               f"Quantum: {quantum_ms} ms | Processos: " + ", ".join(f"PID {p.pid} P{p.priority} {p.name}" for p in pending)]
        timeline: list[str] = []
        now = self.time_ms
        wall_start = now
        cpu_time = 0
        quantum_used = 0
        current: ScheduledProcess | None = None
        last_dispatched: int | None = None
        last_priority: int | None = None
        ticks = 0
        while any(p.state != "CONCLUÍDO" for p in pending):
            ticks += 1
            if ticks > 1_000_000:
                raise SchedulerError("Limite da simulação atingido; há processos bloqueados sem evento de liberação.")
            self._release_events(now, log)
            pending = [p for p in selected if p.state != "CONCLUÍDO"]
            if not pending:
                break
            ready = [p for p in pending if p.state == "PRONTO"]
            if current is not None and current.state == "EXECUTANDO":
                higher = [p for p in ready if p.priority < current.priority]
                if higher:
                    current.state = "PRONTO"
                    log.append(f"[t={now} ms] Preempção por prioridade: PID {current.pid} retorna à fila PRONTO.")
                    current = None
                    quantum_used = 0
            if current is None:
                ready = sorted((p for p in pending if p.state == "PRONTO"), key=lambda p: (p.priority, p.pid))
                if ready:
                    best_priority = ready[0].priority
                    same_priority = [p for p in ready if p.priority == best_priority]
                    # Escolha RR entre pares, avançando após o último PID executado nesse nível.
                    cursors = getattr(self, "_rr_cursor", {})
                    cursor = cursors.get(best_priority, -1)
                    current = next((p for p in same_priority if p.pid > cursor), same_priority[0])
                    self._rr_cursor = cursors
                    self._rr_cursor[best_priority] = current.pid
                    current.state = "EXECUTANDO"
                    if current.first_start_ms is None:
                        current.first_start_ms = now
                    if last_dispatched is not None and last_dispatched != current.pid:
                        self.context_switches += 1
                    last_dispatched = current.pid
                    quantum_used = 0
                    log.append(f"[t={now} ms] Dispatch PID {current.pid} {current.name} (prioridade {current.priority}).")
                else:
                    next_times = [p.blocked_until for p in pending if p.state == "BLOQUEADO" and p.blocked_until is not None]
                    next_times += [lock.release_at for lock in self.mutexes.values()]
                    if not next_times:
                        if max_steps is not None:
                            break
                        raise SchedulerError("Deadlock ou bloqueio sem evento de liberação.")
                    jump = max(now + 1, min(next_times))
                    log.append(f"[t={now} ms] CPU ociosa até t={jump} ms.")
                    now = jump
                    continue
            proc = current
            if proc.state != "EXECUTANDO":
                current = None
                continue
            start_time = now
            proc.state = "EXECUTANDO"
            logical_page = None
            if proc.kind == "normal" and proc.page_references:
                logical_page = proc.page_references[proc.cpu_elapsed_ms]
                try:
                    translation = self.memory.translate(proc.name, logical_page)
                except Exception as exc:
                    raise SchedulerError(f"Falha ao referenciar memória de {proc.name}: {exc}") from exc
                frame_match = re.search(r"moldura física (\d+)", translation, re.I)
                frame = frame_match.group(1) if frame_match else "?"
                hit = "PAGE FAULT" if "PAGE FAULT" in translation else "HIT"
                log.append(f"CPU acessa PID {proc.pid}/{proc.name}: Página {logical_page:02d} -> Moldura {frame} [{hit}] | LRU t={now} ms")
            proc.cpu_elapsed_ms += 1
            proc.remaining_ms -= 1
            cpu_time += 1
            self._cpu_busy_ms += 1
            quantum_used += 1
            now += 1
            self.time_ms = now
            for ready_proc in selected:
                if ready_proc.state == "PRONTO":
                    ready_proc.wait_ms += 1
            timeline.append(f"[{start_time}-{now} ms] PID {proc.pid} {proc.name} (P{proc.priority})")

            io_event = next(((index, event) for index, event in enumerate(proc.io_events)
                             if index not in proc.fired_io and event.at_cpu_ms == proc.cpu_elapsed_ms), None)
            mutex_event = next(((index, event) for index, event in enumerate(proc.mutex_events)
                                if index not in proc.fired_mutex and event.at_cpu_ms == proc.cpu_elapsed_ms), None)
            if io_event is not None:
                index, event = io_event
                proc.fired_io.add(index)
                proc.state = "BLOQUEADO"
                proc.block_reason = event.operation
                proc.blocked_since = now
                proc.blocked_until = now + event.duration_ms
                io_detail = ""
                if self.disk_scheduler is not None:
                    from disk_io import IORequest
                    request = IORequest(track=(proc.pid * 7 + proc.cpu_elapsed_ms) % self.disk_scheduler.tracks,
                                        operation=event.operation.upper(), path=f"process:{proc.name}", block=proc.cpu_elapsed_ms)
                    io_detail = "\n" + self.disk_scheduler.schedule([request])
                log.append(f"[SYSCALL] PID {proc.pid} {proc.name} atingiu {event.operation} em t_CPU={proc.cpu_elapsed_ms} ms: EXECUTANDO -> BLOQUEADO até t={proc.blocked_until} ms.{io_detail}")
                current = None
                quantum_used = 0
            elif mutex_event is not None:
                index, event = mutex_event
                proc.fired_mutex.add(index)
                lock = self.mutexes.get(event.name)
                if lock is None:
                    self.mutexes[event.name] = MutexLock(proc.pid, event.thread, now + event.duration_ms)
                    log.append(f"[MUTEX] t={now} ms Thread {event.thread} (PID {proc.pid}) adquiriu '{event.name}' até t={now + event.duration_ms} ms.")
                else:
                    proc.state = "BLOQUEADO"
                    proc.block_reason = f"mutex:{event.name}"
                    proc.blocked_since = now
                    proc.blocked_until = None
                    self.mutex_waiters[event.name].append((proc.pid, event))
                    log.append(f"[MUTEX] t={now} ms Thread {event.thread} (PID {proc.pid}) encontrou '{event.name}' ocupado por PID {lock.owner_pid}; EXECUTANDO -> BLOQUEADO.")
                    current = None
                    quantum_used = 0
            if proc.state == "EXECUTANDO" and proc.remaining_ms == 0:
                proc.state = "CONCLUÍDO"
                proc.finish_ms = now
                log.append(f"[t={now} ms] PID {proc.pid} {proc.name}: CONCLUÍDO.")
                current = None
                quantum_used = 0
            elif proc.state == "EXECUTANDO" and quantum_used >= quantum:
                proc.state = "PRONTO"
                log.append(f"[t={now} ms] Quantum expirou; PID {proc.pid} retorna à fila PRONTO.")
                current = None
                quantum_used = 0
            if max_steps is not None and cpu_time >= max_steps:
                break
        if current is not None and current.state == "EXECUTANDO":
            current.state = "PRONTO"
            log.append(f"[t={now} ms] Execução interrompida pelo limite de passos; PID {current.pid} retorna a PRONTO.")
        self.time_ms = now
        log.append("\n--- LINHA DO TEMPO DA CPU ---")
        log.extend(timeline)
        completed = [p for p in selected if p.state == "CONCLUÍDO" and p.finish_ms is not None]
        if completed:
            log.append("\n--- MÉTRICAS FINAIS ---")
            log.append("PID | Processo | Prioridade | Chegada | WT | TAT | Bloqueado")
            for proc in completed:
                log.append(f"{proc.pid} | {proc.name} | {proc.priority} | {proc.arrival_ms} ms | {proc.wait_ms} ms | {proc.turnaround_ms} ms | {proc.blocked_ms} ms")
            log.append(f"Tempo médio de espera: {sum(p.wait_ms for p in completed) / len(completed):.2f} ms")
            log.append(f"Turnaround médio: {sum(p.turnaround_ms or 0 for p in completed) / len(completed):.2f} ms")
            log.append(f"Trocas de contexto: {self.context_switches}")
            elapsed = max(0, now - wall_start)
            utilization = (cpu_time / elapsed) * 100 if elapsed else 0.0
            log.append(f"Utilização da CPU nesta execução: {utilization:.1f}%")
        else:
            log.append("\nSimulação parcial: nenhum processo selecionado foi concluído nesta execução.")
        log.append("\n--- MOLDURAS DA RAM DINÂMICA ---")
        log.append(self.memory.status_virtual())
        return "\n".join(log)

    def status(self) -> str:
        lines = ["PID | Processo | Prioridade | Burst | Restante | Estado"]
        for proc in sorted(self.processes.values(), key=lambda item: item.pid):
            lines.append(f"{proc.pid} | {proc.name} | {proc.priority} | {proc.burst_ms} ms | {proc.remaining_ms} ms | {proc.state}")
        return "\n".join(lines)


__all__ = ["ProcessScheduler", "SchedulerError", "ScheduledProcess", "IOEvent", "MutexEvent"]
