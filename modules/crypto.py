from pathlib import Path
from secrets import token_hex
from werkzeug.utils import secure_filename

from cryptography.fernet import Fernet


SECURE_DIR = Path("logs")
KEY_PATH = SECURE_DIR / "fernet.key"
SECURE_DIR.mkdir(exist_ok=True)


def _load_or_create_key():
    if KEY_PATH.exists():
        return KEY_PATH.read_bytes()

    key = Fernet.generate_key()
    KEY_PATH.write_bytes(key)
    return key


def encrypt_file(file_storage):
    original_name = secure_filename(file_storage.filename or "artifact.bin")
    original_data = file_storage.read()
    cipher = Fernet(_load_or_create_key())
    encrypted_data = cipher.encrypt(original_data)

    encrypted_name = f"{Path(original_name).stem}-{token_hex(4)}.bin"
    output_path = SECURE_DIR / encrypted_name
    output_path.write_bytes(encrypted_data)

    return {
        "ok": True,
        "original_name": original_name,
        "encrypted_name": encrypted_name,
        "output_path": str(output_path),
        "original_size": len(original_data),
        "encrypted_size": len(encrypted_data),
        "message": "File encrypted successfully.",
    }
