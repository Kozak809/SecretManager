import os
import sys
import ctypes
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SECRETS_DIR = "secrets"

def check_debugger():
    if sys.platform == 'win32':
        kernel32 = ctypes.windll.kernel32
        if kernel32.IsDebuggerPresent():
            # В реальном приложении лучше просто тихо завершаться,
            # чтобы не давать подсказок реверс-инженеру.
            try:
                messagebox.showerror("Ошибка", "Обнаружен отладчик")
            except:
                pass
            sys.exit(1)

def secure_zero_memory(data):
    """
    Безопасно затирает данные нулями.
    Работает ТОЛЬКО с изменяемыми типами (bytearray, ctypes arrays).
    Игнорирует immutable типы (str, bytes), чтобы избежать крашей.
    """
    if data is None:
        return

    # 1. Работа с bytearray (изменяемый массив байтов)
    if isinstance(data, (bytearray, memoryview)):
        try:
            # Получаем адрес буфера в памяти
            if isinstance(data, memoryview):
                obj_address = data.obj
            else:
                obj_address = data
            
            # Используем ctypes для заполнения памяти нулями
            # (c_char * len) создает массив char нужной длины по адресу буфера
            location = (ctypes.c_char * len(data)).from_buffer(obj_address)
            ctypes.memset(location, 0, len(data))
        except Exception:
            # Если ctypes не сработал, делаем обычное зануление циклами
            # (это медленнее, но безопаснее для стабильности)
            for i in range(len(data)):
                data[i] = 0

    # 2. Работа с ctypes объектами
    elif hasattr(data, '_obj'): 
        ctypes.memset(ctypes.addressof(data), 0, ctypes.sizeof(data))

    # 3. Строки (str) и bytes НЕ трогаем намеренно.
    # Попытка изменить их содержимое напрямую через память почти гарантированно
    # приведет к Access Violation или порче внутренних структур Python.

class SecurePassword:
    def __init__(self, password: str):
        # Конвертируем строку в изменяемый массив байтов сразу же
        if password:
            self.data = bytearray(password.encode('utf-8'))
        else:
            self.data = bytearray()
        
        # ВАЖНО: Мы НЕ можем очистить переменную `password` (str), переданную сюда.
        # Она управляется Python GC. Мы просто не храним ссылку на неё.
    
    def get_bytes(self):
        return bytes(self.data)
    
    def get_string(self):
        return self.data.decode('utf-8')
    
    def clear(self):
        # Здесь мы можем безопасно очистить наш bytearray
        secure_zero_memory(self.data)
        self.data = bytearray()
    
    def __del__(self):
        self.clear()

def derive_key(password: SecurePassword, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    # password.get_bytes() создает временный bytes объект, 
    # который к сожалению останется в памяти до GC.
    return kdf.derive(password.get_bytes())

def decrypt_content(file_path: str, password: SecurePassword) -> bytes:
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    salt = file_data[:16]
    nonce = file_data[16:28]
    encrypted_data = file_data[28:]
    
    key = derive_key(password, salt)
    
    try:
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce, encrypted_data, None)
        return decrypted
    finally:
        # Пытаемся удалить ссылку на ключ, хотя bytes нельзя занулить
        del key 

def encrypt_content(data: bytes, password: SecurePassword) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    
    try:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, data, None)
        return salt + nonce + encrypted
    finally:
        del key

class SecretManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secret Manager")
        self.root.geometry("600x400")
        
        check_debugger()
        
        if not os.path.exists(SECRETS_DIR):
            os.makedirs(SECRETS_DIR)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.create_widgets()
        self.refresh_file_list()
        
        self.root.after(5000, self.periodic_debugger_check)
    
    def periodic_debugger_check(self):
        check_debugger()
        self.root.after(5000, self.periodic_debugger_check)
    
    def on_closing(self):
        self.root.destroy()
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Button(button_frame, text="Создать новый", command=self.create_new).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Открыть", command=self.open_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Удалить", command=self.delete_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Обновить", command=self.refresh_file_list).pack(side=tk.LEFT, padx=5)
        
        list_frame = ttk.Frame(main_frame)
        list_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.file_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, font=("Arial", 11))
        self.file_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.file_listbox.bind('<Double-Button-1>', lambda e: self.open_selected())
        
        scrollbar.config(command=self.file_listbox.yview)
    
    def refresh_file_list(self):
        self.file_listbox.delete(0, tk.END)
        if os.path.exists(SECRETS_DIR):
            files = [f for f in os.listdir(SECRETS_DIR) if f.endswith('.secret')]
            for file in sorted(files):
                self.file_listbox.insert(tk.END, file[:-7])
    
    def ask_password(self, prompt):
        dialog = tk.Toplevel(self.root)
        dialog.title("Пароль")
        dialog.geometry("300x120")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        if sys.platform == 'win32':
            dialog.attributes('-topmost', True)
        
        label = ttk.Label(dialog, text=prompt, padding=10)
        label.pack()
        
        password_var = tk.StringVar()
        entry = ttk.Entry(dialog, textvariable=password_var, show='*', width=30)
        entry.pack(pady=10)
        entry.focus()
        
        result = {'password': None}
        
        def on_ok():
            pwd = password_var.get()
            if pwd:
                result['password'] = SecurePassword(pwd)
            
            # Мы не можем безопасно затереть `pwd` (str), 
            # поэтому просто удаляем ссылку
            del pwd
            password_var.set('')
            dialog.destroy()
        
        def on_cancel():
            password_var.set('')
            dialog.destroy()
        
        entry.bind('<Return>', lambda e: on_ok())
        entry.bind('<Escape>', lambda e: on_cancel())
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Отмена", command=on_cancel).pack(side=tk.LEFT, padx=5)
        
        dialog.wait_window()
        return result['password']
    
    def create_new(self):
        check_debugger()
        
        name = simpledialog.askstring("Новый файл", "Введите название файла:")
        if not name:
            return
        
        name = name.strip()
        if not name:
            messagebox.showerror("Ошибка", "Название не может быть пустым")
            return
        
        file_path = os.path.join(SECRETS_DIR, f"{name}.secret")
        if os.path.exists(file_path):
            messagebox.showerror("Ошибка", "Файл с таким названием уже существует")
            return
        
        password = self.ask_password("Придумайте пароль:")
        if not password:
            return
        
        try:
            encrypted_data = encrypt_content(b"", password)
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            self.refresh_file_list()
            messagebox.showinfo("Успех", f"Файл '{name}' создан")
        finally:
            password.clear()
    
    def open_selected(self):
        check_debugger()
        
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showwarning("Внимание", "Выберите файл из списка")
            return
        
        filename = self.file_listbox.get(selection[0])
        file_path = os.path.join(SECRETS_DIR, f"{filename}.secret")
        
        password = self.ask_password(f"Введите пароль для '{filename}':")
        if not password:
            return
        
        data = None
        try:
            data = decrypt_content(file_path, password)
            self.open_editor(file_path, data, filename, password)
        except Exception as e:
            messagebox.showerror("Ошибка", "Неверный пароль или повреждённый файл")
            password.clear()
        finally:
            # `data` здесь bytes, мы не можем её затереть безопасно.
            # Но если бы мы переделали decrypt на возврат bytearray, то могли бы.
            # Пока что просто del.
            del data
    
    def open_editor(self, file_path, data, filename, password):
        editor_window = tk.Toplevel(self.root)
        editor_window.title(f"Редактирование: {filename}")
        editor_window.geometry("700x500")
        
        text_widget = tk.Text(editor_window, wrap=tk.WORD, font=("Consolas", 10))
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Декодируем для отображения. Это создает str в памяти.
        text_content = data.decode('utf-8', errors='replace')
        text_widget.insert(1.0, text_content)
        
        # Удаляем промежуточные переменные
        del text_content
        
        def save_and_close():
            check_debugger()
            
            try:
                # Получаем текст (str)
                text_content = text_widget.get(1.0, tk.END).rstrip('\n')
                # Кодируем в байты
                updated_data = text_content.encode('utf-8')
                
                encrypted_data = encrypt_content(updated_data, password)
                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)
                
                # Удаляем ссылки
                del text_content
                del updated_data
                
                messagebox.showinfo("Успех", "Файл сохранён и зашифрован")
                password.clear()
                editor_window.destroy()
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {str(e)}")
        
        def close_without_save():
            # Очищаем виджет (не гарантирует удаление из памяти Tcl, но полезно)
            text_widget.delete(1.0, tk.END)
            password.clear()
            editor_window.destroy()
        
        editor_window.protocol("WM_DELETE_WINDOW", close_without_save)
        
        button_frame = ttk.Frame(editor_window)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Button(button_frame, text="Сохранить и закрыть", command=save_and_close).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Отмена", command=close_without_save).pack(side=tk.RIGHT, padx=5)
    
    def delete_selected(self):
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showwarning("Внимание", "Выберите файл из списка")
            return
        
        filename = self.file_listbox.get(selection[0])
        
        if messagebox.askyesno("Подтверждение", f"Удалить файл '{filename}'?"):
            file_path = os.path.join(SECRETS_DIR, f"{filename}.secret")
            
            try:
                with open(file_path, 'r+b') as f:
                    length = f.seek(0, 2)
                    f.seek(0)
                    # Перезапись случайными данными перед удалением
                    f.write(os.urandom(length))
                    f.flush()
                    os.fsync(f.fileno())
                
                os.remove(file_path)
                self.refresh_file_list()
                messagebox.showinfo("Успех", f"Файл '{filename}' безопасно удалён")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось удалить файл: {e}")

def main():
    check_debugger()
    root = tk.Tk()
    app = SecretManagerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()