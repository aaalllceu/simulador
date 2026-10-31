import unittest

from disk_io import DiskScheduler, IORequest, RAIDArray
from simulador import FileSystem, FileSystemError, execute


class SchedulerTests(unittest.TestCase):
    def test_sstf_sample_movement_is_208(self):
        scheduler = DiskScheduler("SSTF", tracks=200, head=53)
        requests = [IORequest(t, "READ") for t in [98, 183, 37, 122, 14]]
        output = scheduler.schedule(requests)
        self.assertIn("53 -> 37 -> 14 -> 98 -> 122 -> 183", output)
        self.assertIn("= 208 trilhas", output)

    def test_fcfs_order_and_head_persists(self):
        scheduler = DiskScheduler("FCFS", head=10)
        output = scheduler.schedule([IORequest(20, "READ"), IORequest(5, "WRITE")])
        self.assertIn("10 -> 20 -> 5", output)
        self.assertEqual(scheduler.head, 5)

    def test_scan_visits_disk_end_before_wrapping(self):
        scheduler = DiskScheduler("SCAN", tracks=200, head=53)
        output = scheduler.schedule([IORequest(14, "READ"), IORequest(98, "READ")])
        self.assertIn("Trajeto da cabeça: 53 -> 98 -> 199 -> 14", output)

    def test_out_of_range_track_is_rejected(self):
        with self.assertRaises(ValueError):
            DiskScheduler().schedule([IORequest(200, "READ")])


class RAIDTests(unittest.TestCase):
    def test_raid5_rebuild_recovers_failed_data(self):
        raid = RAIDArray("5", disks=3, block_size=4)
        payload = b"abcdefgh"
        raid.write("/data.bin", payload)
        original = [dict(disk) for disk in raid.storage]
        raid.fail_and_rebuild(1)
        self.assertEqual(raid.storage[0], original[0])
        self.assertEqual(raid.storage[0][0], b"abcd")

    def test_raid1_rebuild_recovers_replica(self):
        raid = RAIDArray("1", disks=2, block_size=4)
        raid.write("/mirror", b"test")
        raid.fail_and_rebuild(2)
        self.assertEqual(raid.storage[1][0], b"test")

    def test_raid0_cannot_rebuild(self):
        raid = RAIDArray("0", disks=2)
        raid.write("/stripe", b"data")
        with self.assertRaisesRegex(ValueError, "não possui redundância"):
            raid.fail_and_rebuild(1)


class FileSystemIntegrationTests(unittest.TestCase):
    def test_read_and_write_create_io_requests_and_raid_layout(self):
        fs = FileSystem(block_size=4, total_blocks=20, strategy="linked",
                        scheduler="SSTF", raid_level="5", raid_disks=3)
        fs.create_file("/notes", 8)
        write_output = fs.write_data("/notes", b"abcdefgh")
        self.assertIn("ESCALONAMENTO DE DISCO: SSTF", write_output)
        self.assertIn("PARIDADE XOR", write_output)
        read_output = fs.read_file("/notes")
        self.assertIn("ESCALONAMENTO DE DISCO: SSTF", read_output)
        self.assertEqual(len(fs.io_log), 2)

    def test_cli_commands_for_raid_and_disk_io(self):
        fs = FileSystem(block_size=4, total_blocks=20, strategy="linked")
        fs.create_file("/doc", 4)
        ok, out = execute(fs, 'write_file /doc "DATA"')
        self.assertTrue(ok)
        self.assertIn("RAID 5", out)
        ok, out = execute(fs, "fail_disk 1")
        self.assertTrue(ok)
        self.assertIn("[OK]", out)
        ok, out = execute(fs, "disk_status")
        self.assertTrue(ok)
        self.assertIn("E/S", out)

    def test_raid0_failure_reports_loss_without_crash(self):
        fs = FileSystem(4, 20, "linked", raid_level="0", raid_disks=2)
        fs.create_file("/doc", 4)
        fs.write_data("/doc", b"data")
        ok, out = execute(fs, "fail_disk 1")
        self.assertTrue(ok)
        self.assertIn("não possui redundância", out)


if __name__ == "__main__":
    unittest.main()
