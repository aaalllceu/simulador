import unittest

from memoria import MemoryErrorSim, MemoryManager


class MemoryManagerTests(unittest.TestCase):
    def test_critical_processes_allocate_contiguously_and_compact(self):
        memory = MemoryManager(reserved_size=20, kernel_size=4, page_size=4, frame_count=2)
        memory.create_process("A", 4, "critical")
        memory.create_process("B", 4, "critical")
        memory.create_process("C", 4, "critical")
        memory.terminate_process("B")
        self.assertIn("Fragmentação Externa Detectada: SIM", memory.status_reserved())
        with self.assertRaises(MemoryErrorSim):
            memory.create_process("D", 8, "critical")
        memory.compact_reserved()
        self.assertIn("Fragmentação Externa Detectada: NÃO", memory.status_reserved())
        self.assertIn("C", memory.status_reserved())

    def test_page_translation_fault_and_hit(self):
        memory = MemoryManager(reserved_size=64, kernel_size=8, page_size=4, frame_count=2)
        memory.create_process("App", 10, "normal")
        first = memory.translate("App", 1)
        second = memory.translate("App", 1)
        self.assertIn("PAGE FAULT", first)
        self.assertIn("HIT", second)
        self.assertIn("Fragmentação Interna: 2 bytes", memory.create_process("Another", 6, "normal"))

    def test_lru_swaps_least_recently_used_page(self):
        memory = MemoryManager(reserved_size=64, kernel_size=8, page_size=4, frame_count=2, algorithm="LRU")
        memory.create_process("App", 12, "normal")
        memory.translate("App", 0)
        memory.translate("App", 1)
        memory.translate("App", 0)
        memory.translate("App", 2)
        process = memory.processes["App"]
        self.assertIn(1, process.swapped)
        self.assertEqual(set(process.page_table), {0, 2})

    def test_second_chance_and_invalid_page(self):
        memory = MemoryManager(reserved_size=64, kernel_size=8, page_size=4, frame_count=1, algorithm="SECOND_CHANCE")
        memory.create_process("App", 8, "normal")
        memory.translate("App", 0)
        memory.translate("App", 1)
        self.assertIn(0, memory.processes["App"].swapped)
        with self.assertRaises(MemoryErrorSim):
            memory.translate("App", 9)

    def test_command_facing_methods_and_termination(self):
        memory = MemoryManager(reserved_size=64, kernel_size=8, page_size=4, frame_count=2)
        memory.create_process("App", 5, "normal")
        self.assertIn("PAGE FAULT", memory.execute_step("App", "LOAD_DATA Página 1"))
        self.assertIn("Molduras ocupadas", memory.status_virtual())
        self.assertIn("finalizado", memory.terminate_process("App"))
        self.assertIn("Nenhum processo normal", memory.status_virtual())


if __name__ == "__main__":
    unittest.main()
