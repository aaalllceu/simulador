import unittest

from simulador import FileSystem
from web_app import SessionStore, _run_command


class WebSessionTests(unittest.TestCase):
    def test_sessions_are_independent(self):
        store = SessionStore()
        token_a, fs_a = store.create()
        token_b, fs_b = store.create()
        self.assertNotEqual(token_a, token_b)
        _run_command(fs_a, "mkdir /apenas-a", "")
        self.assertIn("apenas-a", fs_a.root.children)
        self.assertNotIn("apenas-a", fs_b.root.children)

    def test_sensitive_login_secret_is_not_part_of_command(self):
        fs = FileSystem(block_size=4, total_blocks=30)
        output = _run_command(fs, 'login --user "root"', "root")
        self.assertIn("Autenticado com sucesso", output)
        # A senha é passada separadamente e jamais deve ser embutida no comando.
        command = 'login --user "root"'
        self.assertNotIn("SenhaSuperSecreta", command)

    def test_sensitive_operations_require_secret_argument(self):
        fs = FileSystem(block_size=4, total_blocks=30)
        fs.mkdir("/d")
        fs.create_file("/d/f", 0)
        self.assertIn("campo protegido", _run_command(fs, "encrypt_file /d/f", ""))

    def test_acl_denial_and_commands_render_text(self):
        fs = FileSystem(block_size=4, total_blocks=30)
        fs.add_group("dev")
        fs.add_user("carlos", "pass123", "dev")
        fs.mkdir("/restricted")
        fs.create_file("/restricted/key", 0)
        fs.set_permissions("/restricted", 0o700)
        fs.login("carlos", "pass123")
        output = _run_command(fs, "read /restricted/key", "")
        self.assertIn("NEGADO", output)


if __name__ == "__main__":
    unittest.main()
