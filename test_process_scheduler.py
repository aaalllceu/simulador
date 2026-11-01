import unittest

from memoria import MemoryManager
from process_scheduler import ProcessScheduler, SchedulerError
from simulador import FileSystem, execute


class ProcessSchedulerTests(unittest.TestCase):
    def make_scheduler(self, frames=3):
        memory = MemoryManager(reserved_size=1024, kernel_size=128,
                               page_size=4, frame_count=frames)
        return ProcessScheduler(memory), memory

    def test_priority_round_robin_and_page_references(self):
        scheduler, memory = self.make_scheduler()
        scheduler.create_process("Web", 5, 1, "normal")
        scheduler.create_process("Render", 3, 1, "normal")
        scheduler.create_process("Music", 2, 2, "normal")
        output = scheduler.run(quantum_ms=2)
        self.assertLess(output.index("Dispatch PID 101 Web"), output.index("Dispatch PID 102 Render"))
        self.assertIn("Quantum expirou", output)
        self.assertIn("Página", output)
        self.assertEqual([p.state for p in scheduler.processes.values()], ["CONCLUÍDO"] * 3)
        self.assertIn("MÉTRICAS FINAIS", output)
        self.assertIn("Trocas de contexto:", output)
        self.assertGreater(memory.page_faults, 0)

    def test_scheduled_syscall_blocks_and_generates_disk_io(self):
        fs = FileSystem(block_size=4, total_blocks=40, strategy="linked", frames=2)
        fs.create_scheduled_process("Web", 5, 1, "normal", "read_disk at 2ms (duration: 3ms)")
        output = fs.run_processes(quantum_ms=2)
        self.assertIn("EXECUTANDO -> BLOQUEADO", output)
        self.assertIn("fim da E/S", output)
        self.assertIn("ESCALONAMENTO DE DISCO", output)
        self.assertIn("WT | TAT", output)
        self.assertEqual(fs.process_scheduler.processes["Web"].blocked_ms, 3)
        self.assertEqual(fs.process_scheduler.processes["Web"].state, "CONCLUÍDO")
        self.assertEqual(len(fs.io_log), 1)

    def test_mutex_contention_blocks_and_unblocks_waiter(self):
        scheduler, _ = self.make_scheduler()
        scheduler.create_process("A", 5, 1, "normal", mutex="Buffer at 1ms (duration: 4ms)")
        scheduler.create_process("B", 4, 1, "normal", mutex="Buffer at 1ms (duration: 2ms)", thread="T2")
        output = scheduler.run(quantum_ms=1)
        self.assertIn("adquiriu 'Buffer'", output)
        self.assertIn("encontrou 'Buffer' ocupado", output)
        self.assertIn("recebeu Mutex 'Buffer'", output)
        self.assertIn("PID 102", output)
        self.assertTrue(all(p.state == "CONCLUÍDO" for p in scheduler.processes.values()))

    def test_random_profile_is_reproducible_and_validated(self):
        first, _ = self.make_scheduler()
        second, _ = self.make_scheduler()
        first.create_process("A", 8, 1, "normal", "random")
        second.create_process("A", 8, 1, "normal", "random")
        self.assertEqual(first.processes["A"].io_events, second.processes["A"].io_events)
        with self.assertRaises(SchedulerError):
            first.create_process("B", 1, 1, "normal", "random")

    def test_cli_create_schedule_status_and_lifecycle(self):
        fs = FileSystem(block_size=4, total_blocks=40, strategy="linked", frames=2)
        ok, output = execute(fs, 'create_process --name "App Web" --burst 4ms --priority 1 --type normal --syscall "read_disk at 2ms (duration: 1ms)"')
        self.assertTrue(ok, output)
        self.assertIn("Estado Inicial: PRONTO", output)
        self.assertIn("App Web", execute(fs, "process_status")[1])
        ok, output = execute(fs, "run_simulation --process 'App Web' --steps 1 --quantum 2ms")
        self.assertTrue(ok, output)
        self.assertIn("Simulação parcial", output)
        ok, output = execute(fs, "schedule --algorithm Priority_RR --quantum 2ms")
        self.assertTrue(ok, output)
        self.assertIn("CONCLUÍDO", output)

    def test_parser_rejects_invalid_profiles_and_zero_quantum(self):
        scheduler, _ = self.make_scheduler()
        with self.assertRaises(SchedulerError):
            scheduler.create_process("Bad", 5, 1, "normal", "read_disk at 5ms (duration: 2ms)")
        with self.assertRaises(SchedulerError):
            scheduler.run(0)


if __name__ == "__main__":
    unittest.main()
