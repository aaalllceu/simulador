import unittest

from simulador import FileSystem, FileSystemError, execute, parse_size


class FileSystemTests(unittest.TestCase):
    def test_absolute_and_relative_paths_and_tree(self):
        fs = FileSystem()
        fs.mkdir("/sistema")
        fs.mkdir("/sistema/logs")
        fs.create_file("/sistema/logs/app.log", 10 * 1024)
        fs.change_dir("/sistema")
        fs.create_file("logs/relative.txt", 1)
        self.assertIn("app.log (10 KB)", fs.tree())
        self.assertIn("relative.txt (1 B)", fs.tree())
        self.assertEqual(fs.cwd.path(), "/sistema")

    def test_indexed_allocation_and_internal_fragmentation(self):
        fs = FileSystem(block_size=4096, total_blocks=16, strategy="indexed")
        fs.mkdir("/sistema")
        fs.mkdir("/sistema/logs")
        fs.create_file("/sistema/logs/app.log", 10 * 1024)
        status = fs.status()
        self.assertIn("Fragmentação Interna: 2048 B", status)
        self.assertIn("Necessidade de Compactação: NÃO", status)
        self.assertIn("[ÍNDICE] /sistema/logs/app.log", status)

    def test_contiguous_external_fragmentation_after_deletion(self):
        fs = FileSystem(1, 8, "contiguous")
        fs.create_file("/a", 2)
        fs.create_file("/b", 2)
        fs.create_file("/c", 2)
        fs.delete("/b")
        self.assertIn("Fragmentação Externa: SIM", fs.status())
        with self.assertRaises(FileSystemError):
            fs.create_file("/d", 3)

    def test_update_failure_keeps_original_file(self):
        fs = FileSystem(4, 3, "indexed")
        fs.create_file("/a", 4)
        original = fs._resolve("/a").blocks[:]
        with self.assertRaises(FileSystemError):
            fs.update_file("/a", 100)
        self.assertEqual(fs._resolve("/a").blocks, original)
        self.assertEqual(fs._resolve("/a").size, 4)

    def test_directory_deletion_requires_empty_directory(self):
        fs = FileSystem()
        fs.mkdir("/dir")
        fs.create_file("/dir/file", 0)
        with self.assertRaises(FileSystemError):
            fs.delete("/dir")
        fs.delete("/dir/file")
        fs.delete("/dir")

    def test_commands_and_size_parser(self):
        fs = FileSystem()
        for command in ["mkdir /docs", "create /docs/a.txt --size 10KB"]:
            ok, message = execute(fs, command)
            self.assertTrue(ok, message)
        self.assertEqual(parse_size("2MB"), 2 * 1024 * 1024)
        self.assertIn("10240 bytes", fs.read_file("/docs/a.txt"))


if __name__ == "__main__":
    unittest.main()
