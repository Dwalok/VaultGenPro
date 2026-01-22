from __future__ import annotations

import base64
import json
import math
import os
import secrets
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text

APP_NAME = "VaultgenPro"
VAULT_PATH = Path("vault.json")
AAD = b"vaultgenpro|v1"

KDF_PARAMS = {
    "n": 2**15,
    "r": 8,
    "p": 1,
    "length": 32,
}

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/\\|~"

BANNER_TEXT_STYLE = "#89B4FA"
BANNER_BORDER_STYLE = "#89B4FA"

COLOR_INFO = "#74C7EC"
COLOR_WARNING = "#F9E2AF"
COLOR_ERROR = "#F38BA8"
COLOR_SUCCESS = "#A6E3A1"

COLOR_PASSWORD = "#CBA6F7"
COLOR_ID = "#89B4FA"

COLOR_MENU_TITLE = "#EDEFF7"
COLOR_MENU_RULE = "#2A2E3E"
COLOR_MENU_NUMBER = "#89B4FA"
COLOR_MENU_TEXT = "#EDEFF7"

COLOR_PROMPT = "#89B4FA"

SORT_ENTRIES = False



MAIN_MENU_OPTIONS = (
    ("1", "Vault"),
    ("2", "Notes"),
    ("3", "Password generator"),
    ("4", "Exit"),
)
MAIN_MENU_DEFAULT = "4"
MAIN_MENU_CHOICES = tuple(key for key, _ in MAIN_MENU_OPTIONS)

VAULT_MENU_OPTIONS = (
    ("1", "View passwords"),
    ("2", "Add a password"),
    ("3", "Delete a password"),
    ("4", "Back"),
)
VAULT_MENU_DEFAULT = "4"
VAULT_MENU_CHOICES = tuple(key for key, _ in VAULT_MENU_OPTIONS)

GEN_MENU_OPTIONS = (
    ("1", "Generate password"),
    ("2", "Back"),
)
GEN_MENU_DEFAULT = "2"
GEN_MENU_CHOICES = tuple(key for key, _ in GEN_MENU_OPTIONS)

NOTES_MENU_OPTIONS = (
    ("1", "View notes"),
    ("2", "Add note"),
    ("3", "Edit note"),
    ("4", "Delete note"),
    ("5", "Back"),
)
NOTES_MENU_DEFAULT = "5"
NOTES_MENU_CHOICES = tuple(key for key, _ in NOTES_MENU_OPTIONS)

BANNER = r"""
██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗ ██████╗ ███████╗███╗   ██╗██████╗ ██████╗  ██████╗ 
██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝██╔════╝ ██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔═══██╗
██║   ██║███████║██║   ██║██║     ██║   ██║  ███╗█████╗  ██╔██╗ ██║██████╔╝██████╔╝██║   ██║
╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ██║   ██║██╔══╝  ██║╚██╗██║██╔═══╝ ██╔══██╗██║   ██║
 ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ╚██████╔╝███████╗██║ ╚████║██║     ██║  ██║╚██████╔╝
  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝    ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝ ╚═════╝  
                         a simple password vault manager
""".strip("\n")


@dataclass
class VaultData:
    entries: List[Dict[str, str]]
    notes: List[Dict[str, str]]


class VaultError(Exception):
    pass


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(raw: str) -> bytes:
    return base64.b64decode(raw.encode("ascii"))


def _derive_key(password: str, salt: bytes, params: Dict[str, int]) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=params["length"],
        n=params["n"],
        r=params["r"],
        p=params["p"],
    )
    return kdf.derive(password.encode("utf-8"))


def _kdf_params_from_blob(blob: Dict[str, Any]) -> Dict[str, int]:
    kdf = blob.get("kdf", {})
    if not isinstance(kdf, dict):
        raise VaultError("Vault format error")
    if kdf.get("name", "scrypt") != "scrypt":
        raise VaultError("Unsupported KDF")
    params = {
        "n": int(kdf.get("n", KDF_PARAMS["n"])),
        "r": int(kdf.get("r", KDF_PARAMS["r"])),
        "p": int(kdf.get("p", KDF_PARAMS["p"])),
        "length": int(kdf.get("length", KDF_PARAMS["length"])),
    }
    return params


def _encrypt(password: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    salt = os.urandom(16)
    key = _derive_key(password, salt, KDF_PARAMS)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    ciphertext = aesgcm.encrypt(nonce, plaintext, AAD)
    return {
        "version": 1,
        "kdf": {"name": "scrypt", **KDF_PARAMS},
        "salt": _b64e(salt),
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
    }


def _decrypt(password: str, blob: Dict[str, Any]) -> Dict[str, Any]:
    try:
        salt = _b64d(blob["salt"])
        nonce = _b64d(blob["nonce"])
        ciphertext = _b64d(blob["ciphertext"])
    except KeyError as exc:
        raise VaultError("Vault format error") from exc

    params = _kdf_params_from_blob(blob)
    key = _derive_key(password, salt, params)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, AAD)
    except Exception as exc:
        raise VaultError("Invalid master password or corrupted vault") from exc

    try:
        return json.loads(plaintext.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise VaultError("Vault data is corrupted") from exc


def _load_vault(path: Path, password: str) -> VaultData:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise VaultError("Vault file not found") from exc
    except json.JSONDecodeError as exc:
        raise VaultError("Vault file is not valid JSON") from exc

    payload = _decrypt(password, raw)
    entries = payload.get("entries")
    notes = payload.get("notes", [])
    if not isinstance(entries, list):
        raise VaultError("Vault entries missing")
    if not isinstance(notes, list):
        raise VaultError("Vault notes missing")
    return VaultData(entries=entries, notes=notes)


def _save_vault(path: Path, password: str, data: VaultData) -> None:
    payload = {"entries": data.entries, "notes": data.notes}
    blob = _encrypt(password, payload)
    path.write_text(
        json.dumps(blob, separators=(",", ":"), ensure_ascii=True), encoding="utf-8"
    )


def _print_banner(console: Console) -> None:
    text = Text(BANNER, style=BANNER_TEXT_STYLE)
    console.print(Panel.fit(text, border_style=BANNER_BORDER_STYLE))


def _print_menu(console: Console, title: str, options: tuple[tuple[str, str], ...]) -> None:
    console.rule(Text(title, style=COLOR_MENU_TITLE), style=COLOR_MENU_RULE)
    for key, label in options:
        line = Text()
        line.append(key, style=COLOR_MENU_NUMBER)
        line.append(" - ", style=COLOR_MENU_TEXT)
        line.append(label, style=COLOR_MENU_TEXT)
        console.print(line)


def _ask_menu_choice(
    console: Console, choices: tuple[str, ...], default: str
) -> Optional[str]:
    while True:
        prompt = Text()
        prompt.append("Choose ", style=COLOR_PROMPT)
        prompt.append("[", style=COLOR_PROMPT)
        for index, key in enumerate(choices):
            if index:
                prompt.append("/", style=COLOR_PROMPT)
            prompt.append(key, style=COLOR_MENU_NUMBER)
        prompt.append("]", style=COLOR_PROMPT)
        prompt.append(f" ({default}): ", style=COLOR_PROMPT)
        console.print(prompt, end="")
        try:
            choice = console.input("").strip()
        except KeyboardInterrupt:
            console.print("\nCanceled.", style=COLOR_WARNING)
            return None
        if not choice:
            choice = default
        if choice in choices:
            return choice
        console.print("Invalid selection.", style=COLOR_ERROR)


def _prompt_new_master(console: Console) -> str:
    console.print("No vault found. Creating a new one.", style=COLOR_WARNING)
    while True:
        first = Prompt.ask("Create master password", password=True)
        second = Prompt.ask("Confirm master password", password=True)
        if first != second:
            console.print("Passwords do not match. Try again.", style=COLOR_ERROR)
            continue
        if len(first) < 8:
            console.print("Password too short (min 8 chars).", style=COLOR_ERROR)
            continue
        return first


def _unlock_vault(console: Console, path: Path) -> tuple[str, VaultData]:
    if not path.exists():
        master = _prompt_new_master(console)
        data = VaultData(entries=[], notes=[])
        _save_vault(path, master, data)
        return master, data

    while True:
        master = Prompt.ask("Master password", password=True)
        try:
            data = _load_vault(path, master)
            return master, data
        except VaultError as exc:
            console.print(str(exc), style=COLOR_ERROR)
            if not Confirm.ask("Try again?", default=True):
                raise SystemExit(1)


def _view_entries(console: Console, data: VaultData) -> None:
    if not data.entries:
        console.print("No passwords stored yet.", style=COLOR_WARNING)
        return

    entries = data.entries
    if SORT_ENTRIES:
        entries = sorted(entries, key=lambda e: e.get("name", ""))

    table = Table(title="Stored passwords", box=box.SIMPLE_HEAVY)
    table.add_column("ID", style=COLOR_ID, width=4, justify="right")
    table.add_column("Name", style="bold")
    table.add_column("Username")
    table.add_column("URL")
    table.add_column("Notes")
    table.add_column("Password", style=COLOR_PASSWORD)

    for idx, entry in enumerate(entries, 1):
        table.add_row(
            str(idx),
            entry.get("name", ""),
            entry.get("username", ""),
            entry.get("url", ""),
            entry.get("notes", ""),
            entry.get("password", ""),
        )

    console.print(table)


def _add_entry(console: Console, data: VaultData) -> None:
    try:
        name = Prompt.ask("Name / label").strip()
        if not name:
            console.print("Name is required.", style=COLOR_ERROR)
            return

        username = Prompt.ask("Username (optional)", default="")
        url = Prompt.ask("Site URL (optional)", default="")
        password = Prompt.ask("Password", password=True)
        notes = Prompt.ask("Notes (optional)", default="")
    except KeyboardInterrupt:
        console.print("\nCanceled.", style=COLOR_WARNING)
        return

    if not password:
        console.print("Password cannot be empty.", style=COLOR_ERROR)
        return

    data.entries.append(
        {
            "name": name,
            "username": username,
            "url": url,
            "password": password,
            "notes": notes,
        }
    )
    console.print("Entry added.", style=COLOR_SUCCESS)


def _generate_password(console: Console) -> None:
    rng = secrets.SystemRandom()
    try:
        while True:
            length = IntPrompt.ask("Password length", default=16)
            if length < 4 or length > 128:
                console.print("Length must be between 4 and 128.", style=COLOR_ERROR)
                continue

            include_digits = Confirm.ask("Include digits?", default=True)
            include_symbols = Confirm.ask("Include symbols?", default=True)

            charsets = [string.ascii_lowercase]
            if include_digits:
                charsets.append(string.digits)
            if include_symbols:
                charsets.append(SYMBOLS)

            if length < len(charsets):
                console.print(
                    f"Length must be at least {len(charsets)} for selected options.",
                    style=COLOR_ERROR,
                )
                continue

            alphabet = "".join(charsets)
            password_chars = [rng.choice(cs) for cs in charsets]
            password_chars.extend(
                rng.choice(alphabet) for _ in range(length - len(charsets))
            )
            rng.shuffle(password_chars)
            password = "".join(password_chars)

            alphabet_size = len(set(alphabet))
            entropy_bits = length * math.log2(alphabet_size)
            if entropy_bits < 40:
                strength = "faible"
            elif entropy_bits < 60:
                strength = "moyen"
            else:
                strength = "fort"

            console.print(f"Generated password: [bold]{password}[/bold]")
            console.print(f"Entropy: {entropy_bits:.1f} bits ({strength})", style=COLOR_INFO)
            return
    except KeyboardInterrupt:
        console.print("\nCanceled.", style=COLOR_WARNING)


def _view_notes(console: Console, data: VaultData) -> None:
    if not data.notes:
        console.print("No notes stored yet.", style=COLOR_WARNING)
        return

    table = Table(title="Secure notes", box=box.SIMPLE_HEAVY)
    table.add_column("ID", style=COLOR_ID, width=4, justify="right")
    table.add_column("Title", style="bold")
    table.add_column("Note")

    for idx, note in enumerate(data.notes, 1):
        table.add_row(
            str(idx),
            note.get("title", ""),
            note.get("body", ""),
        )

    console.print(table)


def _add_note(console: Console, data: VaultData) -> None:
    try:
        title = Prompt.ask("Title").strip()
        if not title:
            console.print("Title is required.", style=COLOR_ERROR)
            return
        body = Prompt.ask("Note", default="")
    except KeyboardInterrupt:
        console.print("\nCanceled.", style=COLOR_WARNING)
        return

    data.notes.append({"title": title, "body": body})
    console.print("Note added.", style=COLOR_SUCCESS)


def _edit_note(console: Console, data: VaultData) -> None:
    if not data.notes:
        console.print("No notes stored yet.", style=COLOR_WARNING)
        return

    table = Table(title="Select note to edit", box=box.SIMPLE_HEAVY)
    table.add_column("ID", style=COLOR_ID, width=4, justify="right")
    table.add_column("Title", style="bold")
    for idx, note in enumerate(data.notes, 1):
        table.add_row(str(idx), note.get("title", ""))

    console.print(table)
    try:
        choice = IntPrompt.ask("Edit which ID? (0 to cancel)", default=0)
    except KeyboardInterrupt:
        console.print("\nCanceled.", style=COLOR_WARNING)
        return
    if choice == 0:
        console.print("Edit canceled.", style=COLOR_WARNING)
        return
    if choice < 1 or choice > len(data.notes):
        console.print("Invalid selection.", style=COLOR_ERROR)
        return

    note = data.notes[choice - 1]
    try:
        title = Prompt.ask("Title", default=note.get("title", ""))
        body = Prompt.ask("Note", default=note.get("body", ""))
    except KeyboardInterrupt:
        console.print("\nCanceled.", style=COLOR_WARNING)
        return
    if not title.strip():
        console.print("Title is required.", style=COLOR_ERROR)
        return

    note["title"] = title
    note["body"] = body
    console.print("Note updated.", style=COLOR_SUCCESS)


def _delete_note(console: Console, data: VaultData) -> None:
    if not data.notes:
        console.print("No notes stored yet.", style=COLOR_WARNING)
        return

    table = Table(title="Select note to delete", box=box.SIMPLE_HEAVY)
    table.add_column("ID", style=COLOR_ID, width=4, justify="right")
    table.add_column("Title", style="bold")
    for idx, note in enumerate(data.notes, 1):
        table.add_row(str(idx), note.get("title", ""))

    console.print(table)
    try:
        choice = IntPrompt.ask("Delete which ID? (0 to cancel)", default=0)
    except KeyboardInterrupt:
        console.print("\nCanceled.", style=COLOR_WARNING)
        return
    if choice == 0:
        console.print("Delete canceled.", style=COLOR_WARNING)
        return
    if choice < 1 or choice > len(data.notes):
        console.print("Invalid selection.", style=COLOR_ERROR)
        return

    note = data.notes[choice - 1]
    try:
        if Confirm.ask(f"Delete '{note.get('title', '')}'?", default=False):
            data.notes.pop(choice - 1)
            console.print("Note deleted.", style=COLOR_SUCCESS)
        else:
            console.print("Delete canceled.", style=COLOR_WARNING)
    except KeyboardInterrupt:
        console.print("\nCanceled.", style=COLOR_WARNING)


def _delete_entry(console: Console, data: VaultData) -> None:
    if not data.entries:
        console.print("Vault is empty.", style=COLOR_WARNING)
        return

    table = Table(title="Select entry to delete", box=box.SIMPLE_HEAVY)
    table.add_column("ID", style=COLOR_ID, width=4, justify="right")
    table.add_column("Name", style="bold")
    table.add_column("Username")
    table.add_column("URL")

    for idx, entry in enumerate(data.entries, 1):
        table.add_row(
            str(idx),
            entry.get("name", ""),
            entry.get("username", ""),
            entry.get("url", ""),
        )

    console.print(table)
    try:
        choice = IntPrompt.ask("Delete which ID? (0 to cancel)", default=0)
    except KeyboardInterrupt:
        console.print("\nCanceled.", style=COLOR_WARNING)
        return
    if choice == 0:
        console.print("Delete canceled.", style=COLOR_WARNING)
        return
    if choice < 1 or choice > len(data.entries):
        console.print("Invalid selection.", style=COLOR_ERROR)
        return

    entry = data.entries[choice - 1]
    try:
        if Confirm.ask(f"Delete '{entry.get('name', '')}'?", default=False):
            data.entries.pop(choice - 1)
            console.print("Entry deleted.", style=COLOR_SUCCESS)
        else:
            console.print("Delete canceled.", style=COLOR_WARNING)
    except KeyboardInterrupt:
        console.print("\nCanceled.", style=COLOR_WARNING)


def _vault_menu(console: Console, master: str, data: VaultData, path: Path) -> None:
    while True:
        console.print()
        _print_menu(console, "Vault", VAULT_MENU_OPTIONS)
        console.print(f"Entries: {len(data.entries)}", style=COLOR_INFO)

        choice = _ask_menu_choice(console, VAULT_MENU_CHOICES, VAULT_MENU_DEFAULT)
        if choice is None or choice == "4":
            return
        if choice == "1":
            _view_entries(console, data)
        elif choice == "2":
            _add_entry(console, data)
            _save_vault(path, master, data)
        elif choice == "3":
            _delete_entry(console, data)
            _save_vault(path, master, data)


def _generator_menu(console: Console) -> None:
    while True:
        console.print()
        _print_menu(console, "Generator", GEN_MENU_OPTIONS)

        choice = _ask_menu_choice(console, GEN_MENU_CHOICES, GEN_MENU_DEFAULT)
        if choice is None or choice == "2":
            return
        if choice == "1":
            _generate_password(console)


def _notes_menu(console: Console, master: str, data: VaultData, path: Path) -> None:
    while True:
        console.print()
        _print_menu(console, "Notes", NOTES_MENU_OPTIONS)
        console.print(f"Notes: {len(data.notes)}", style=COLOR_INFO)

        choice = _ask_menu_choice(console, NOTES_MENU_CHOICES, NOTES_MENU_DEFAULT)
        if choice is None or choice == "5":
            return
        if choice == "1":
            _view_notes(console, data)
        elif choice == "2":
            _add_note(console, data)
            _save_vault(path, master, data)
        elif choice == "3":
            _edit_note(console, data)
            _save_vault(path, master, data)
        elif choice == "4":
            _delete_note(console, data)
            _save_vault(path, master, data)


def _menu(console: Console, master: str, data: VaultData, path: Path) -> None:
    while True:
        console.print()
        _print_menu(console, "Main", MAIN_MENU_OPTIONS)

        choice = _ask_menu_choice(console, MAIN_MENU_CHOICES, MAIN_MENU_DEFAULT)
        if choice is None:
            break
        if choice == "1":
            _vault_menu(console, master, data, path)
        elif choice == "2":
            _notes_menu(console, master, data, path)
        elif choice == "3":
            _generator_menu(console)
        elif choice == "4":
            console.print("Bye!", style=COLOR_INFO)
            break


def main() -> None:
    console = Console()
    console.clear()
    _print_banner(console)
    try:
        master, data = _unlock_vault(console, VAULT_PATH)
    except KeyboardInterrupt:
        console.print("\nCanceled.", style=COLOR_WARNING)
        raise SystemExit(1)

    _menu(console, master, data, VAULT_PATH)


if __name__ == "__main__":
    main()
