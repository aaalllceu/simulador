import unittest
from unittest.mock import patch

from security import IdentityManager, decrypt_bytes, encrypt_bytes
from simulador import FileSystem, FileSystemError, execute


class IdentityTests(unittest.TestCase):
    def test_password_is_salted_and_verified(self):
        identities = IdentityManager()
        identities.add_group("devs")
        identities.add_user("carlos", "SenhaSegura", "devs")
        user = identities.users["carlos"]
        self.assertNotEqual(user.password_hash, b"SenhaSegura")
        self.assertEqual(len(user.salt), 16)
        self.assertEqual(identities.authenticate("carlos", "SenhaSegura").group, "devs")
        with self.assertRaises(Exception):
            identities.authenticate("carlos", "errada")

    def test_encryption_authenticates_ciphertext(self):
        cipher, salt = encrypt_bytes(b"segredo", "chave correta")
        self.assertNotIn(b"segredo", cipher)
        self.assertEqual(decrypt_bytes(cipher, "chave correta", salt), b"segredo")
        with self.assertRaises(Exception):
            decrypt_bytes(cipher, "chave errada", salt)


class SecurityFeatureTests(unittest.TestCase):
    def setUp(self):
        self.fs = FileSystem(block_size=256, total_blocks=32, strategy="linked",
                             raid_level="1", raid_disks=2)
        self.fs.add_group("devs")
        self.fs.add_user("carlos", "SenhaSegura", "devs")

    def test_root_privilege_required_for_critical_operations(self):
        self.fs.login("carlos", "SenhaSegura")
        with self.assertRaisesRegex(FileSystemError, "MODO_KERNEL"):
            self.fs.add_group("ops")
        with self.assertRaisesRegex(FileSystemError, "MODO_KERNEL"):
            self.fs.set_permissions("/home/carlos", 0o755)
        self.assertTrue(self.fs.audit_log)
        self.fs.login("root", "root")
        self.fs.add_group("ops")
        self.fs.identity.logout()
        self.assertFalse(self.fs.identity.is_root)
        with self.assertRaisesRegex(FileSystemError, "MODO_KERNEL"):
            self.fs.set_permissions("/home/carlos", 0o755)
        with self.assertRaisesRegex(Exception, "Credenciais inválidas"):
            self.fs.login("guest", "qualquer")

    def test_acl_denies_and_allows_by_group(self):
        self.fs.mkdir("/shared")
        self.fs.create_file("/shared/config.sys", 4)
        self.fs.write_data("/shared/config.sys", b"data")
        self.fs.set_permissions("/shared/config.sys", 0o640)
        node = self.fs._resolve("/shared/config.sys")
        node.owner, node.group = "root", "admin"
        self.fs.login("carlos", "SenhaSegura")
        with self.assertRaisesRegex(FileSystemError, "permissão de read"):
            self.fs.read_file("/shared/config.sys")
        self.fs.login("root", "root")
        self.fs._resolve("/shared/config.sys").group = "devs"
        self.fs.login("carlos", "SenhaSegura")
        self.assertIn("data", self.fs.read_file("/shared/config.sys"))
        with self.assertRaisesRegex(FileSystemError, "permissão de write"):
            self.fs.write_data("/shared/config.sys", b"nope")
        self.fs.login("root", "root")
        self.fs.add_group("visitors")
        self.fs.add_user("bia", "OutraSenha", "visitors")
        self.fs.login("bia", "OutraSenha")
        with self.assertRaisesRegex(FileSystemError, "permissão de read"):
            self.fs.read_file("/shared/config.sys")

    def test_encrypt_write_read_decrypt_and_scan(self):
        self.fs.create_file("/home/carlos/segredo.txt", 7)
        self.fs.write_data("/home/carlos/segredo.txt", b"segredo")
        result = self.fs.encrypt_file("/home/carlos/segredo.txt", "MinhaChave123")
        self.assertIn("CIPHERTEXT", result)
        node = self.fs._resolve("/home/carlos/segredo.txt")
        self.assertTrue(node.encrypted)
        self.assertNotIn(b"segredo", node.content)
        clear = self.fs.decrypt_file("/home/carlos/segredo.txt", "MinhaChave123")
        self.assertIn("segredo", clear)
        with self.assertRaisesRegex(FileSystemError, "Chave incorreta"):
            self.fs.decrypt_file("/home/carlos/segredo.txt", "chave errada")
        self.assertIn("Criptografado e íntegro", self.fs.antivirus_scan("/home/carlos"))

    def test_integrity_tamper_and_malware_detection(self):
        self.fs.create_file("/home/carlos/log.txt", 32)
        self.fs.write_data("/home/carlos/log.txt", b"conteudo limpo")
        node = self.fs._resolve("/home/carlos/log.txt")
        self.fs.tamper_block("/home/carlos/log.txt", node.blocks[0])
        self.assertIn("Hash do(s) bloco(s)", self.fs.antivirus_scan("/home/carlos"))
        self.fs.write_data("/home/carlos/log.txt", b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
        self.assertIn("Assinatura maliciosa", self.fs.antivirus_scan("/home/carlos"))

    def test_cli_login_uses_hidden_password_prompt(self):
        with patch("simulador.getpass", return_value="SenhaSegura"):
            keep_running, output = execute(self.fs, "login --user carlos")
        self.assertTrue(keep_running)
        self.assertIn("MODO_USUARIO", output)
        self.assertIn("carlos", execute(self.fs, "whoami")[1])


if __name__ == "__main__":
    unittest.main()
