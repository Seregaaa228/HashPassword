import hashlib
import base64
import random


class PasswordHandler:
    def hash_password_raw(self, password: str) -> str:
        return base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest()).decode("utf-8")

    def hash_password(self, password: str, peper="") -> str:
        salt = base64.b64encode(random.randint(0, 2 ** 256 - 1).to_bytes(32, "little")).decode("utf-8")
        return self.hash_password_raw(password + ":" + salt + ":" + peper) + ":" + salt + ":" + peper

    def passwords_equal(self, password: str, hash_password: str) -> bool:
        raw_hash, salt, peper = hash_password.split(":", 3)
        return self.hash_password(password + ":" + salt + ":" + peper) == raw_hash


password1 = PasswordHandler()
print(password1.passwords_equal("password", password1.hash_password("password")))
