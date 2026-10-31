"""Identidade, autenticação, ACL e criptografia didática para o simulador."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError as exc:  # pragma: no cover - instrução clara para instalações mínimas
    raise RuntimeError("Instale a dependência com: python3 -m pip install -r requirements.txt") from exc


class SecurityError(Exception):
    """Falha de autenticação, autorização ou operação criptográfica."""


@dataclass
class User:
    name: str
    group: str
    salt: bytes
    password_hash: bytes


class IdentityManager:
    """Cadastro de grupos e usuários com verificação de senha via PBKDF2-HMAC."""

    ITERATIONS = 310_000

    def __init__(self) -> None:
        self.groups: set[str] = {"admin", "guests"}
        self.users: dict[str, User] = {}
        self.add_user("root", "root", "admin")
        # A sessão anônima não tem uma senha pública nem privilégios de kernel.
        self.add_user("guest", os.urandom(32).hex(), "guests")
        self.current_user = "root"

    def logout(self) -> None:
        self.current_user = "guest"

    @property
    def user(self) -> User:
        return self.users[self.current_user]

    @property
    def is_root(self) -> bool:
        return self.current_user == "root"

    @classmethod
    def _derive(cls, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, cls.ITERATIONS)

    def add_group(self, name: str) -> str:
        self._validate_name(name)
        if name in self.groups:
            raise SecurityError(f"O grupo '{name}' já existe.")
        self.groups.add(name)
        return name

    def add_user(self, name: str, password: str, group: str) -> str:
        self._validate_name(name)
        if name in self.users:
            raise SecurityError(f"O usuário '{name}' já existe.")
        if group not in self.groups:
            raise SecurityError(f"O grupo '{group}' não existe; crie-o primeiro.")
        if len(password) < 4:
            raise SecurityError("A senha deve ter pelo menos 4 caracteres neste simulador.")
        salt = os.urandom(16)
        self.users[name] = User(name, group, salt, self._derive(password, salt))
        return name

    def authenticate(self, name: str, password: str) -> User:
        user = self.users.get(name)
        if name == "guest" or user is None or not hmac.compare_digest(user.password_hash, self._derive(password, user.salt)):
            raise SecurityError("Credenciais inválidas.")
        self.current_user = name
        return user

    @staticmethod
    def _validate_name(name: str) -> None:
        if not name or name in (".", "..") or "/" in name or any(c.isspace() for c in name):
            raise SecurityError("Nome de usuário/grupo inválido.")


def derive_fernet(key: str, salt: bytes) -> Fernet:
    """Deriva uma chave Fernet a partir de uma frase secreta e salt aleatório."""
    if not key:
        raise SecurityError("A chave de criptografia não pode ser vazia.")
    raw = hashlib.pbkdf2_hmac("sha256", key.encode("utf-8"), salt, 310_000, dklen=32)
    return Fernet(base64.urlsafe_b64encode(raw))


def encrypt_bytes(data: bytes, key: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    salt = salt or os.urandom(16)
    return derive_fernet(key, salt).encrypt(data), salt


def decrypt_bytes(data: bytes, key: str, salt: bytes) -> bytes:
    try:
        return derive_fernet(key, salt).decrypt(data)
    except InvalidToken as exc:
        raise SecurityError("Chave incorreta ou conteúdo criptografado adulterado.") from exc


def permission_bits(mode: int, owner: bool, group: bool) -> int:
    shift = 6 if owner else (3 if group else 0)
    return (mode >> shift) & 0b111


def mode_text(mode: int) -> str:
    return "".join("rwx"[i] if permission_bits(mode, owner, group) & (4 >> i) else "-"
                   for owner, group in ((True, False), (False, True), (False, False))
                   for i in range(3))


def allowed(mode: int, action: str, owner: bool, group: bool, root: bool = False) -> bool:
    if root:
        return True
    bits = permission_bits(mode, owner, group)
    mask = {"read": 4, "write": 2, "execute": 1}[action]
    return bool(bits & mask)


__all__ = ["SecurityError", "IdentityManager", "encrypt_bytes", "decrypt_bytes", "mode_text", "allowed"]
