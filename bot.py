import os
import logging
import sqlite3
from io import BytesIO
import telebot
from telebot import types
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
import time
import struct
import re
import pefile
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from pwn import asm, context  # Note: pwntools is imported as pwn

# Enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Replace with your bot token from environment
BOT_TOKEN = os.getenv('7343295464:AAEM7vk5K3cNXAywZC_Q11wmMzMu4gk09PU')
if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN environment variable is not set.")

bot = telebot.TeleBot(BOT_TOKEN)

# Telegram message length limit
MAX_MESSAGE_LENGTH = 4096

# SQLite database setup for password history
DB_PATH = 'password_history.db'
LOCK_FILE = 'bot_lock.lock'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS password_history
                 (user_id INTEGER, hashed_password TEXT, timestamp TEXT)''')
    conn.commit()
    conn.close()

init_db()

# Helper function to acquire lock
def acquire_lock():
    if os.path.exists(LOCK_FILE):
        logger.warning("Lock file exists. Removing old lock.")
        os.remove(LOCK_FILE)
    with open(LOCK_FILE, 'w') as f:
        f.write(str(os.getpid()))
    return True

# Helper function to release lock
def release_lock():
    if os.path.exists(LOCK_FILE):
        os.remove(LOCK_FILE)

# Helper function to store password hash
def store_password(user_id, password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO password_history (user_id, hashed_password, timestamp) VALUES (?, ?, ?)",
              (user_id, hashed, timestamp))
    conn.commit()
    conn.close()

# Helper function to get recent passwords
def get_recent_passwords(user_id, limit=3):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT hashed_password FROM password_history WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?",
              (user_id, limit))
    passwords = [row[0] for row in c.fetchall()]
    conn.close()
    return passwords

# Helper function to split long messages
def send_long_message(chat_id, text, parse_mode='Markdown'):
    if len(text) <= MAX_MESSAGE_LENGTH:
        try:
            bot.send_message(chat_id, text, parse_mode=parse_mode)
        except telebot.apihelper.ApiTelegramException as e:
            logger.error(f"Error sending message: {e}")
            bot.send_message(chat_id, "*ERROR: FAILED TO SEND MESSAGE!*", parse_mode='Markdown')
    else:
        parts = [text[i:i+MAX_MESSAGE_LENGTH] for i in range(0, len(text), MAX_MESSAGE_LENGTH)]
        for part in parts:
            try:
                bot.send_message(chat_id, part, parse_mode=parse_mode)
            except telebot.apihelper.ApiTelegramException as e:
                logger.error(f"Error sending message part: {e}")
                bot.send_message(chat_id, "*ERROR: FAILED TO SEND PART OF THE MESSAGE!*", parse_mode='Markdown')

# Helper function to check weak password
def is_weak_password(password):
    if len(password) < 8:
        return True
    if not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
        return True
    return False

# Helper function to derive key from password (using PBKDF2)
def derive_key(password: str, salt: bytes = None) -> tuple[bytes, bytes, bytes]:
    if not password:
        raise ValueError("PASSWORD CANNOT BE EMPTY.")
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    return key, iv, salt

# Encrypt data
def encrypt_data(data: bytes, password: str) -> bytes:
    if not data:
        raise ValueError("DATA TO ENCRYPT CANNOT BE EMPTY.")
    salt = os.urandom(16)
    key, iv, _ = derive_key(password, salt)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return salt + iv + ciphertext

# Decrypt data
def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    try:
        if len(encrypted_data) < 32:  # Minimum length for salt (16) + iv (16)
            raise ValueError("INVALID ENCRYPTED DATA.")
        salt, iv, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
        key, _, _ = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()
    except Exception as e:
        raise ValueError(f"DECRYPTION FAILED: {str(e)}")

# Encrypt file with stub for executable
def encrypt_file_with_stub(file_path: str, password: str, output_path: str):
    with open(file_path, 'rb') as f:
        original_data = f.read()
    
    encrypted_data = encrypt_data(original_data, password)
    
    # Generate stub loader (x86_64 example, adjust for other architectures)
    context.arch = 'x86_64'
    stub_code = """
    global _start
    section .text
    _start:
        mov rax, [rel encrypted_data_end - encrypted_data]  ; Size of encrypted data
        mov rdi, encrypted_data
        mov rsi, 0x400000          ; Load address (adjust as needed)
        mov rdx, 0x7              ; PROT_READ | PROT_WRITE | PROT_EXEC
        mov r10, 0x22             ; MAP_PRIVATE | MAP_ANONYMOUS
        mov r8, -1
        mov r9, 0
        syscall                    ; mmap
        mov rbx, rax               ; Save mapped address
        
        ; Decrypt (simplified, replace with actual decryption logic)
        mov rcx, [rel encrypted_data_end - encrypted_data]
        mov rsi, encrypted_data
        mov rdi, rbx
    decrypt_loop:
        xor byte [rdi], 0x55      ; Dummy XOR (replace with AES)
        inc rdi
        dec rcx
        jnz decrypt_loop
        
        ; Jump to decrypted code
        jmp rbx
        
    section .data
    encrypted_data:
    """
    stub_code += "".join(f"    db 0x{byte:02x}\n" for byte in encrypted_data)
    stub_code += "    encrypted_data_end:\n"
    
    # Assemble stub
    stub_binary = asm(stub_code, arch='x86_64')
    with open(output_path, 'wb') as f:
        f.write(stub_binary)
    os.chmod(output_path, 0o755)

# Analyze binary metadata
def analyze_binary(file_path: str) -> str:
    try:
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            return "*ERROR: FILE IS EMPTY OR DOES NOT EXIST!*"
        with open(file_path, 'rb') as f:
            data = f.read(10240)  # Read first 10KB
        
        result = []
        
        # ELF analysis
        if data.startswith(b'\x7fELF'):
            with open(file_path, 'rb') as f:
                elf = ELFFile(f)
                header = elf.header
                result.append("🔍 *FILE TYPE:* ELF BINARY")
                result.append(f"🏷 *ARCHITECTURE:* {header['e_machine']} ({'x86_64' if header['e_machine'] == 'EM_X86_64' else 'ARM' if header['e_machine'] == 'EM_ARM' else 'Unknown'})")
                result.append(f"🏷 *ENTRY POINT:* 0x{header['e_entry']:x}")
                result.append(f"🏷 *SECTIONS COUNT:* {header['e_shnum']}")
                
                sections = []
                for section in elf.iter_sections():
                    flags = section['sh_flags']
                    name = section.name
                    size = section['sh_size']
                    addr = section['sh_addr']
                    sections.append(f"- {name}: size=0x{size:x}, addr=0x{addr:x}, {'executable' if flags & 0x4 else 'non-executable'}, {'writable' if flags & 0x2 else 'read-only'}")
                result.append("📋 *SECTIONS:*")
                result.extend(sections)
                
                # Imports (Dynamic section)
                dynsym = elf.get_section_by_name('.dynsym')
                if dynsym and isinstance(dynsym, SymbolTableSection):
                    imports = [sym.name for sym in dynsym.iter_symbols() if sym.name]
                    if imports:
                        result.append("📚 *IMPORTED SYMBOLS:* " + ", ".join(imports[:10]) + ("..." if len(imports) > 10 else ""))
                
                # Strings (potential payloads)
                strings = re.findall(b'[ -~]{4,}', data)
                if strings:
                    result.append("💾 *EXTRACTED STRINGS/PAYLOADS:*")
                    for s in strings[:50]:  # Limit to 50 strings
                        try:
                            result.append(f"- `{s.decode('ascii', errors='ignore')}`")
                        except UnicodeDecodeError:
                            result.append(f"- `0x{int.from_bytes(s, 'big'):x}`")
                
                # Language detection
                if b'__cxa' in data or b'_Z' in data or b'GLIBCXX' in data:
                    language = "C++"
                elif b'go.buildid' in data or b'runtime.main' in data:
                    language = "Go"
                elif b'GCC' in data or b'__libc_start_main' in data:
                    language = "C"
                else:
                    language = "UNKNOWN"
                result.append(f"🔍 *DETECTED LANGUAGE:* {language}")
                
                # Compiler hints
                compiler_strings = re.findall(b'GCC[:\d\.]+', data)
                if compiler_strings:
                    result.append(f"🛠 *COMPILER VERSION:* {compiler_strings[0].decode('ascii')}")

        # PE analysis
        elif data.startswith(b'MZ'):
            pe = pefile.PE(file_path)
            result.append("🔍 *FILE TYPE:* PE BINARY (Windows)")
            result.append(f"🏷 *ARCHITECTURE:* {'x86' if pe.FILE_HEADER.Machine == 0x14c else 'x86_64' if pe.FILE_HEADER.Machine == 0x8664 else 'Unknown'}")
            result.append(f"🏷 *ENTRY POINT:* 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
            
            sections = []
            for section in pe.sections:
                name = section.Name.decode(errors='ignore').rstrip('\x00')
                size = section.SizeOfRawData
                addr = section.VirtualAddress
                flags = []
                if section.Characteristics & 0x20: flags.append('executable')
                if section.Characteristics & 0x40: flags.append('writable')
                sections.append(f"- {name}: size=0x{size:x}, addr=0x{addr:x}, {' '.join(flags) or 'read-only'}")
            result.append("📋 *SECTIONS:*")
            result.extend(sections)
            
            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                imports = []
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode(errors='ignore')
                    for imp in entry.imports:
                        name = imp.name.decode(errors='ignore') if imp.name else f"Ordinal {imp.ordinal}"
                        imports.append(f"{dll}.{name}")
                if imports:
                    result.append("📚 *IMPORTED FUNCTIONS:* " + ", ".join(imports[:10]) + ("..." if len(imports) > 10 else ""))
            
            # Strings
            strings = re.findall(b'[ -~]{4,}', data)
            if strings:
                result.append("💾 *EXTRACTED STRINGS/PAYLOADS:*")
                for s in strings[:50]:
                    try:
                        result.append(f"- `{s.decode('ascii', errors='ignore')}`")
                    except UnicodeDecodeError:
                        result.append(f"- `0x{int.from_bytes(s, 'big'):x}`")
            
            # Language detection
            if b'.rdata' in data or b'__cxa' in data:
                language = "C++ (Windows PE)"
            elif b'go.buildid' in data:
                language = "Go (Windows PE)"
            elif b'GCC' in data:
                language = "C (Windows PE)"
            else:
                language = "UNKNOWN"
            result.append(f"🔍 *DETECTED LANGUAGE:* {language}")
        
        else:
            result.append("🔍 *FILE TYPE:* NOT A RECOGNIZED EXECUTABLE BINARY")
        
        # Mock code snippet
        if language.startswith("C++"):
            result.append("📝 *SAMPLE CODE SNIPPET (APPROXIMATION):*\n```cpp\n#include <iostream>\nint main() {\n    std::cout << \"Hello, World!\" << std::endl;\n    return 0;\n}\n```")
        elif language.startswith("C"):
            result.append("📝 *SAMPLE CODE SNIPPET (APPROXIMATION):*\n```c\n#include <stdio.h>\nint main() {\n    printf(\"Hello, World!\\n\");\n    return 0;\n}\n```")
        elif language.startswith("Go"):
            result.append("📝 *SAMPLE CODE SNIPPET (APPROXIMATION):*\n```go\npackage main\nimport \"fmt\"\nfunc main() {\n    fmt.Println(\"Hello, World!\")\n}\n```")
        
        result.append("*NOTE: FULL SOURCE CODE DECOMPILATION IS NOT SUPPORTED. USE GHIDRA OR IDA PRO FOR DETAILED ANALYSIS.*")
        return "\n".join(result)
    except Exception as e:
        return f"*ERROR ANALYZING BINARY:* {str(e)}"

# Bot handlers
@bot.message_handler(commands=['start'])
def start(message):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    btn_encrypt_text = types.KeyboardButton('🔒 ENCRYPT TEXT')
    btn_decrypt_text = types.KeyboardButton('🔓 DECRYPT TEXT')
    btn_encrypt_file = types.KeyboardButton('📁 ENCRYPT FILE')
    btn_encrypt_run = types.KeyboardButton('📥 ENCRYPT & MAKE RUNNABLE')
    btn_decrypt_file = types.KeyboardButton('📂 DECRYPT FILE')
    btn_analyze_binary = types.KeyboardButton('🕵️ ANALYZE BINARY')
    btn_clear_history = types.KeyboardButton('🗑 CLEAR PASSWORD HISTORY')
    markup.add(btn_encrypt_text, btn_decrypt_text, btn_encrypt_file, btn_encrypt_run, btn_decrypt_file, btn_analyze_binary, btn_clear_history)
    welcome_message = (
        "*WELCOME TO ENCRYPTION BOT!*\n\n"
        "🔒 *ENCRYPT/DECRYPT TEXT SECURELY WITH PASSWORD.*\n"
        "📁 *ENCRYPT FILES.*\n"
        "📥 *ENCRYPT AND CREATE RUNNABLE BINARY.*\n"
        "📂 *DECRYPT FILES.*\n"
        "🕵️ *ANALYZE BINARIES FOR DETAILED METADATA.*\n"
        "🗑 *CLEAR PASSWORD HISTORY WHEN NEEDED.*"
    )
    send_long_message(message.chat.id, welcome_message)
    bot.send_message(message.chat.id, "*CHOOSE AN OPTION:*", reply_markup=markup, parse_mode='Markdown')

@bot.message_handler(func=lambda message: True)
def handle_message(message):
    text = message.text
    try:
        if text == '🔒 ENCRYPT TEXT':
            msg = bot.reply_to(message, "*SEND THE TEXT TO ENCRYPT:*", parse_mode='Markdown')
            bot.register_next_step_handler(msg, process_encrypt_text)
        elif text == '🔓 DECRYPT TEXT':
            msg = bot.reply_to(message, "*SEND THE ENCRYPTED TEXT (BASE64 STRING):*", parse_mode='Markdown')
            bot.register_next_step_handler(msg, process_decrypt_text)
        elif text == '📁 ENCRYPT FILE':
            msg = bot.reply_to(message, "*SEND A FILE TO ENCRYPT:*", parse_mode='Markdown')
            bot.register_next_step_handler(msg, process_encrypt_file)
        elif text == '📥 ENCRYPT & MAKE RUNNABLE':
            msg = bot.reply_to(message, "*SEND A BINARY FILE TO ENCRYPT AND MAKE RUNNABLE:*", parse_mode='Markdown')
            bot.register_next_step_handler(msg, process_encrypt_run)
        elif text == '📂 DECRYPT FILE':
            msg = bot.reply_to(message, "*SEND THE ENCRYPTED FILE:*", parse_mode='Markdown')
            bot.register_next_step_handler(msg, process_decrypt_file)
        elif text == '🕵️ ANALYZE BINARY':
            msg = bot.reply_to(message, "*SEND THE BINARY FILE (E.G., EXECUTABLE):*", parse_mode='Markdown')
            bot.register_next_step_handler(msg, process_analyze_binary)
        elif text == '🗑 CLEAR PASSWORD HISTORY':
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("DELETE FROM password_history WHERE user_id = ?", (message.from_user.id,))
            conn.commit()
            conn.close()
            bot.reply_to(message, "*PASSWORD HISTORY CLEARED SUCCESSFULLY!*", parse_mode='Markdown')
        else:
            bot.reply_to(message, "*INVALID OPTION! PLEASE USE THE BUTTONS.*", parse_mode='Markdown')
    except telebot.apihelper.ApiTelegramException as e:
        logger.error(f"Telegram API error: {e}")
        if "Conflict: terminated by other getUpdates request" in str(e):
            bot.reply_to(message, "*ERROR: ANOTHER BOT INSTANCE IS RUNNING. STOP OTHER INSTANCES AND TRY AGAIN!*", parse_mode='Markdown')
        else:
            bot.reply_to(message, "*ERROR: TELEGRAM API ISSUE. TRY AGAIN LATER.*", parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Unexpected error in handle_message: {e}")
        bot.reply_to(message, f"*ERROR: {str(e)}*", parse_mode='Markdown')

def process_encrypt_text(message):
    try:
        text = message.text
        if not text:
            bot.reply_to(message, "*ERROR: TEXT CANNOT BE EMPTY!*", parse_mode='Markdown')
            return
        msg = bot.reply_to(message, "*ENTER A STRONG PASSWORD:*", parse_mode='Markdown')
        bot.register_next_step_handler(msg, lambda m: finalize_encrypt_text(m, text))
    except Exception as e:
        logger.error(f"Error in process_encrypt_text: {e}")
        bot.reply_to(message, f"*ERROR: {str(e)}*", parse_mode='Markdown')

def finalize_encrypt_text(password_msg, original_text):
    try:
        password = password_msg.text
        if not password:
            bot.reply_to(password_msg, "*ERROR: PASSWORD CANNOT BE EMPTY!*", parse_mode='Markdown')
            return
        if is_weak_password(password):
            bot.reply_to(password_msg, "*WARNING: WEAK PASSWORD DETECTED! USE 8+ CHARACTERS WITH UPPERCASE AND NUMBERS.*", parse_mode='Markdown')
        store_password(password_msg.from_user.id, password)
        encrypted = encrypt_text(original_text, password)
        response = f"*ENCRYPTED TEXT:*\n```{encrypted}```\n\n*💡 SAVE THIS! DELETE AFTER USE.*"
        send_long_message(password_msg.chat.id, response)
    except Exception as e:
        logger.error(f"Error in finalize_encrypt_text: {e}")
        bot.reply_to(password_msg, f"*ERROR: {str(e)}*", parse_mode='Markdown')
    finally:
        try:
            bot.delete_message(password_msg.chat.id, password_msg.message_id)
            bot.delete_message(password_msg.chat.id, password_msg.reply_to_message.message_id)
        except telebot.apihelper.ApiTelegramException as e:
            logger.error(f"Error deleting messages: {e}")

def process_decrypt_text(message):
    try:
        encrypted_text = message.text
        if not encrypted_text:
            bot.reply_to(message, "*ERROR: ENCRYPTED TEXT CANNOT BE EMPTY!*", parse_mode='Markdown')
            return
        recent_passwords = get_recent_passwords(message.from_user.id)
        if recent_passwords:
            markup = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True)
            btn_new = types.KeyboardButton('USE NEW PASSWORD')
            markup.add(btn_new)
            msg = bot.reply_to(message, "*TRY A RECENT PASSWORD OR USE A NEW ONE:*", reply_markup=markup, parse_mode='Markdown')
            bot.register_next_step_handler(msg, lambda m: handle_decrypt_text_choice(m, encrypted_text, recent_passwords))
        else:
            msg = bot.reply_to(message, "*ENTER THE PASSWORD:*", parse_mode='Markdown')
            bot.register_next_step_handler(msg, lambda m: finalize_decrypt_text(m, encrypted_text))
    except Exception as e:
        logger.error(f"Error in process_decrypt_text: {e}")
        bot.reply_to(message, f"*ERROR: {str(e)}*", parse_mode='Markdown')

def handle_decrypt_text_choice(message, encrypted_text, recent_passwords):
    try:
        if message.text == 'USE NEW PASSWORD':
            msg = bot.reply_to(message, "*ENTER THE PASSWORD:*", parse_mode='Markdown')
            bot.register_next_step_handler(msg, lambda m: finalize_decrypt_text(m, encrypted_text))
        else:
            bot.reply_to(message, "*PLEASE SELECT 'USE NEW PASSWORD' OR CANCEL.*", parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error in handle_decrypt_text_choice: {e}")
        bot.reply_to(message, f"*ERROR: {str(e)}*", parse_mode='Markdown')

def finalize_decrypt_text(password_msg, encrypted_text):
    try:
        password = password_msg.text
        if not password:
            bot.reply_to(password_msg, "*ERROR: PASSWORD CANNOT BE EMPTY!*", parse_mode='Markdown')
            return
        decrypted = decrypt_text(encrypted_text, password)
        response = f"*DECRYPTED TEXT:*\n```{decrypted}```"
        send_long_message(password_msg.chat.id, response)
        store_password(password_msg.from_user.id, password)
    except ValueError as e:
        bot.reply_to(password_msg, f"*ERROR: {str(e)}*", parse_mode='Markdown')
        recent_passwords = get_recent_passwords(password_msg.from_user.id)
        if recent_passwords:
            bot.reply_to(password_msg, "*TRY A RECENT PASSWORD? SEND 'RETRY' OR A NEW PASSWORD.*", parse_mode='Markdown')
            bot.register_next_step_handler(password_msg, lambda m: retry_decrypt_text(m, encrypted_text))
    except Exception as e:
        logger.error(f"Error in finalize_decrypt_text: {e}")
        bot.reply_to(password_msg, f"*ERROR: {str(e)}*", parse_mode='Markdown')
    finally:
        try:
            bot.delete_message(password_msg.chat.id, password_msg.message_id)
        except telebot.apihelper.ApiTelegramException as e:
            logger.error(f"Error deleting password message: {e}")

def retry_decrypt_text(message, encrypted_text):
    try:
        if message.text.lower() == 'retry':
            bot.reply_to(message, "*RETRYING WITH RECENT PASSWORDS NOT SUPPORTED (ONLY HASHES STORED). ENTER A NEW PASSWORD:*", parse_mode='Markdown')
            bot.register_next_step_handler(message, lambda m: finalize_decrypt_text(m, encrypted_text))
        else:
            finalize_decrypt_text(message, encrypted_text)
    except Exception as e:
        logger.error(f"Error in retry_decrypt_text: {e}")
        bot.reply_to(message, f"*ERROR: {str(e)}*", parse_mode='Markdown')

def process_encrypt_file(message):
    try:
        if message.document:
            file_info = bot.get_file(message.document.file_id)
            downloaded_file = bot.download_file(file_info.file_path)
            file_path = f"temp_{message.document.file_name}"
            try:
                with open(file_path, 'wb') as f:
                    f.write(downloaded_file)
            except IOError as e:
                logger.error(f"IO error writing file: {e}")
                bot.reply_to(message, "*ERROR: FAILED TO WRITE FILE!*", parse_mode='Markdown')
                return
            
            msg = bot.reply_to(message, "*ENTER A STRONG PASSWORD:*", parse_mode='Markdown')
            bot.register_next_step_handler(msg, lambda m: finalize_encrypt_file(m, file_path, message.document.file_name))
        else:
            bot.reply_to(message, "*ERROR: PLEASE SEND A VALID FILE!*", parse_mode='Markdown')
    except telebot.apihelper.ApiTelegramException as e:
        logger.error(f"Telegram API error in process_encrypt_file: {e}")
        bot.reply_to(message, "*ERROR: FAILED TO PROCESS FILE. TRY AGAIN!*", parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error in process_encrypt_file: {e}")
        bot.reply_to(message, f"*ERROR: {str(e)}*", parse_mode='Markdown')

def finalize_encrypt_file(password_msg, file_path, original_name):
    try:
        password = password_msg.text
        if not password:
            bot.reply_to(password_msg, "*ERROR: PASSWORD CANNOT BE EMPTY!*", parse_mode='Markdown')
            return
        if is_weak_password(password):
            bot.reply_to(password_msg, "*WARNING: WEAK PASSWORD DETECTED! USE 8+ CHARACTERS WITH UPPERCASE AND NUMBERS.*", parse_mode='Markdown')
        store_password(password_msg.from_user.id, password)
        encrypted_buffer = BytesIO()
        with open(file_path, 'rb') as f:
            encrypted_buffer.write(encrypt_data(f.read(), password))
        encrypted_buffer.name = f"encrypted_{original_name}"
        encrypted_buffer.seek(0)
        bot.send_document(password_msg.chat.id, encrypted_buffer, caption="*ENCRYPTED FILE! DELETE AFTER DOWNLOADING.*", parse_mode='Markdown')
        os.remove(file_path)
    except telebot.apihelper.ApiTelegramException as e:
        logger.error(f"Telegram API error in finalize_encrypt_file: {e}")
        bot.reply_to(password_msg, "*ERROR: FAILED TO SEND ENCRYPTED FILE. TRY AGAIN!*", parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error in finalize_encrypt_file: {e}")
        bot.reply_to(password_msg, f"*ERROR: {str(e)}*", parse_mode='Markdown')
    finally:
        try:
            bot.delete_message(password_msg.chat.id, password_msg.message_id)
        except telebot.apihelper.ApiTelegramException as e:
            logger.error(f"Error deleting password message: {e}")

def process_encrypt_run(message):
    try:
        if message.document:
            file_info = bot.get_file(message.document.file_id)
            downloaded_file = bot.download_file(file_info.file_path)
            file_path = f"temp_{message.document.file_name}"
            with open(file_path, 'wb') as f:
                f.write(downloaded_file)
            
            msg = bot.reply_to(message, "*ENTER A STRONG PASSWORD:*", parse_mode='Markdown')
            bot.register_next_step_handler(msg, lambda m: finalize_encrypt_run(m, file_path, message.document.file_name))
        else:
            bot.reply_to(message, "*ERROR: PLEASE SEND A VALID BINARY FILE!*", parse_mode='Markdown')
    except telebot.apihelper.ApiTelegramException as e:
        logger.error(f"Telegram API error in process_encrypt_run: {e}")
        bot.reply_to(message, "*ERROR: FAILED TO PROCESS FILE. TRY AGAIN!*", parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error in process_encrypt_run: {e}")
        bot.reply_to(message, f"*ERROR: {str(e)}*", parse_mode='Markdown')

def finalize_encrypt_run(password_msg, file_path, original_name):
    try:
        password = password_msg.text
        if not password:
            bot.reply_to(password_msg, "*ERROR: PASSWORD CANNOT BE EMPTY!*", parse_mode='Markdown')
            return
        if is_weak_password(password):
            bot.reply_to(password_msg, "*WARNING: WEAK PASSWORD DETECTED! USE 8+ CHARACTERS WITH UPPERCASE AND NUMBERS.*", parse_mode='Markdown')
        store_password(password_msg.from_user.id, password)
        output_path = f"runnable_{original_name}"
        encrypt_file_with_stub(file_path, password, output_path)
        with open(output_path, 'rb') as f:
            runnable_buffer = BytesIO(f.read())
        runnable_buffer.name = output_path
        runnable_buffer.seek(0)
        bot.send_document(password_msg.chat.id, runnable_buffer, caption="*RUNNABLE ENCRYPTED FILE! RUN WITH PASSWORD PROMPT.*", parse_mode='Markdown')
        os.remove(file_path)
        os.remove(output_path)
    except telebot.apihelper.ApiTelegramException as e:
        logger.error(f"Telegram API error in finalize_encrypt_run: {e}")
        bot.reply_to(password_msg, "*ERROR: FAILED TO SEND RUNNABLE FILE. TRY AGAIN!*", parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error in finalize_encrypt_run: {e}")
        bot.reply_to(password_msg, f"*ERROR: {str(e)}*", parse_mode='Markdown')
    finally:
        try:
            bot.delete_message(password_msg.chat.id, password_msg.message_id)
        except telebot.apihelper.ApiTelegramException as e:
            logger.error(f"Error deleting password message: {e}")

def process_decrypt_file(message):
    try:
        if message.document:
            file_info = bot.get_file(message.document.file_id)
            downloaded_file = bot.download_file(file_info.file_path)
            encrypted_buffer = BytesIO(downloaded_file)
            original_name = message.document.file_name.replace("encrypted_", "", 1) if "encrypted_" in message.document.file_name else message.document.file_name
            
            recent_passwords = get_recent_passwords(message.from_user.id)
            if recent_passwords:
                markup = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True)
                btn_new = types.KeyboardButton('USE NEW PASSWORD')
                markup.add(btn_new)
                msg = bot.reply_to(message, "*TRY A RECENT PASSWORD OR USE A NEW ONE:*", reply_markup=markup, parse_mode='Markdown')
                bot.register_next_step_handler(msg, lambda m: handle_decrypt_file_choice(m, encrypted_buffer, original_name))
            else:
                msg = bot.reply_to(message, "*ENTER THE PASSWORD:*", parse_mode='Markdown')
                bot.register_next_step_handler(msg, lambda m: finalize_decrypt_file(m, encrypted_buffer, original_name))
        else:
            bot.reply_to(message, "*ERROR: PLEASE SEND A VALID ENCRYPTED FILE!*", parse_mode='Markdown')
    except telebot.apihelper.ApiTelegramException as e:
        logger.error(f"Telegram API error in process_decrypt_file: {e}")
        bot.reply_to(message, "*ERROR: FAILED TO PROCESS FILE. TRY AGAIN!*", parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error in process_decrypt_file: {e}")
        bot.reply_to(message, f"*ERROR: {str(e)}*", parse_mode='Markdown')

def handle_decrypt_file_choice(message, encrypted_buffer, original_name):
    try:
        if message.text == 'USE NEW PASSWORD':
            msg = bot.reply_to(message, "*ENTER THE PASSWORD:*", parse_mode='Markdown')
            bot.register_next_step_handler(msg, lambda m: finalize_decrypt_file(m, encrypted_buffer, original_name))
        else:
            bot.reply_to(message, "*PLEASE SELECT 'USE NEW PASSWORD' OR CANCEL.*", parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error in handle_decrypt_file_choice: {e}")
        bot.reply_to(message, f"*ERROR: {str(e)}*", parse_mode='Markdown')

def finalize_decrypt_file(password_msg, encrypted_buffer, original_name):
    try:
        password = password_msg.text
        if not password:
            bot.reply_to(password_msg, "*ERROR: PASSWORD CANNOT BE EMPTY!*", parse_mode='Markdown')
            return
        encrypted_data = encrypted_buffer.getvalue()
        decrypted_data = decrypt_data(encrypted_data, password)
        decrypted_buffer = BytesIO(decrypted_data)
        decrypted_buffer.name = original_name
        decrypted_buffer.seek(0)
        bot.send_document(password_msg.chat.id, decrypted_buffer, caption="*DECRYPTED FILE!*", parse_mode='Markdown')
        store_password(password_msg.from_user.id, password)
    except ValueError as e:
        bot.reply_to(password_msg, f"*ERROR: {str(e)}*", parse_mode='Markdown')
        recent_passwords = get_recent_passwords(password_msg.from_user.id)
        if recent_passwords:
            bot.reply_to(password_msg, "*TRY A RECENT PASSWORD? SEND 'RETRY' OR A NEW PASSWORD.*", parse_mode='Markdown')
            bot.register_next_step_handler(password_msg, lambda m: retry_decrypt_file(m, encrypted_buffer, original_name))
    except telebot.apihelper.ApiTelegramException as e:
        logger.error(f"Telegram API error in finalize_decrypt_file: {e}")
        bot.reply_to(password_msg, "*ERROR: FAILED TO SEND DECRYPTED FILE. TRY AGAIN!*", parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error in finalize_decrypt_file: {e}")
        bot.reply_to(password_msg, f"*ERROR: {str(e)}*", parse_mode='Markdown')
    finally:
        try:
            bot.delete_message(password_msg.chat.id, password_msg.message_id)
        except telebot.apihelper.ApiTelegramException as e:
            logger.error(f"Error deleting password message: {e}")

def retry_decrypt_file(message, encrypted_buffer, original_name):
    try:
        if message.text.lower() == 'retry':
            bot.reply_to(message, "*RETRYING WITH RECENT PASSWORDS NOT SUPPORTED (ONLY HASHES STORED). ENTER A NEW PASSWORD:*", parse_mode='Markdown')
            bot.register_next_step_handler(message, lambda m: finalize_decrypt_file(m, encrypted_buffer, original_name))
        else:
            finalize_decrypt_file(message, encrypted_buffer, original_name)
    except Exception as e:
        logger.error(f"Error in retry_decrypt_file: {e}")
        bot.reply_to(message, f"*ERROR: {str(e)}*", parse_mode='Markdown')

def process_analyze_binary(message):
    try:
        if message.document:
            file_info = bot.get_file(message.document.file_id)
            downloaded_file = bot.download_file(file_info.file_path)
            file_path = f"temp_{message.document.file_name}"
            with open(file_path, 'wb') as f:
                f.write(downloaded_file)
            
            analysis_result = analyze_binary(file_path)
            send_long_message(message.chat.id, analysis_result)
            os.remove(file_path)
        else:
            bot.reply_to(message, "*ERROR: PLEASE SEND A VALID BINARY FILE!*", parse_mode='Markdown')
    except telebot.apihelper.ApiTelegramException as e:
        logger.error(f"Telegram API error in process_analyze_binary: {e}")
        bot.reply_to(message, "*ERROR: FAILED TO PROCESS BINARY. TRY AGAIN!*", parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error in process_analyze_binary: {e}")
        bot.reply_to(message, f"*ERROR: {str(e)}*", parse_mode='Markdown')

# Run the bot with error handling and lock
if __name__ == '__main__':
    import sys
    print("BOT STARTING...")
    if not acquire_lock():
        print("ANOTHER INSTANCE IS RUNNING. EXITING...")
        exit(1)
    try:
        if '--test-mode' in sys.argv:
            print("Test mode: Bot initialized successfully.")
            release_lock()
            exit(0)
        bot.infinity_polling()
    except telebot.apihelper.ApiTelegramException as e:
        logger.error(f"Telegram API error during polling: {e}")
        if "Conflict: terminated by other getUpdates request" in str(e):
            print("CONFLICT DETECTED: ANOTHER INSTANCE IS RUNNING. STOP OTHER INSTANCES AND TRY AGAIN.")
        else:
            print(f"API ERROR: {e}")
        time.sleep(5)
    except Exception as e:
        logger.error(f"Unexpected error during polling: {e}")
        time.sleep(5)
    finally:
        release_lock()