import hashlib
import base64
import random


class PasswordHandler:

    def __init__(self, hashlibType: type(hashlib.md5), coderType: type(base64.b32encode), pepper=""):
        self.hashlibType = hashlibType
        self.coderType = coderType
        self.pepper = pepper

    def hash_password_raw(self, password: str) -> str:
        return self.coderType(self.hashlibType(password.encode("utf-8")).digest()).decode("utf-8")

    def hash_password(self, password: str) -> str:
        salt = self.coderType(random.randint(0, 2 ** 256 - 1).to_bytes(32, "little")).decode("utf-8")
        return self.hash_password_raw(password + self.pepper + ":" + salt) + ":" + salt

    def passwords_equal(self, password: str, hash_password: str) -> bool:
        raw_hash, salt = hash_password.split(":", 2)
        return self.hash_password(password) == raw_hash


password1 = PasswordHandler(hashlibType=hashlib.sha256, coderType=base64.b16encode, pepper="dsdsdsddsd")
print(password1.passwords_equal("password", password1.hash_password("password")))


