import os
import base64
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.fernet import Fernet
from pathlib import Path


def generate_key(password: str) -> bytes:
    # Gera uma chave baseada na senha do usuário
    from hashlib import sha256
    return base64.urlsafe_b64encode(sha256(password.encode()).digest())


def encrypt_file(filepath: str, password: str):
    key = generate_key(password)
    fernet = Fernet(key)
    try:
        with open(filepath, 'rb') as file:
            original = file.read()
        encrypted = fernet.encrypt(original)
        output_path = filepath + '.enc'
        with open(output_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)
        print(f'Arquivo criptografado: {output_path}')
        return True
    except Exception as e:
        print(f'Erro ao criptografar {filepath}: {str(e)}')
        return False


def decrypt_file(filepath: str, password: str):
    key = generate_key(password)
    fernet = Fernet(key)
    try:
        with open(filepath, 'rb') as enc_file:
            encrypted = enc_file.read()
        try:
            decrypted = fernet.decrypt(encrypted)
        except Exception:
            print('Senha incorreta ou arquivo corrompido!')
            return False
        
        output_path = filepath.replace('.enc', '')
        with open(output_path, 'wb') as dec_file:
            dec_file.write(decrypted)
        print(f'Arquivo descriptografado: {output_path}')
        return True
    except Exception as e:
        print(f'Erro ao descriptografar {filepath}: {str(e)}')
        return False


def encrypt_folder(folderpath: str, password: str):
    """Criptografa todos os arquivos em uma pasta e suas subpastas"""
    path = Path(folderpath)
    if not path.exists() or not path.is_dir():
        print(f"Pasta não encontrada: {folderpath}")
        return
    
    count = 0
    for file_path in path.rglob('*'):
        if file_path.is_file() and not file_path.name.endswith('.enc'):
            if encrypt_file(str(file_path), password):
                count += 1
    
    print(f"{count} arquivo(s) criptografado(s) com sucesso na pasta {folderpath}")


def decrypt_folder(folderpath: str, password: str):
    """Descriptografa todos os arquivos .enc em uma pasta e suas subpastas"""
    path = Path(folderpath)
    if not path.exists() or not path.is_dir():
        print(f"Pasta não encontrada: {folderpath}")
        return
    
    count = 0
    for file_path in path.rglob('*.enc'):
        if file_path.is_file():
            if decrypt_file(str(file_path), password):
                count += 1
    
    print(f"{count} arquivo(s) descriptografado(s) com sucesso na pasta {folderpath}")


class SecureFileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Encryption Tool")
        self.root.geometry("600x400")
        self.root.resizable(False, False)
        
        # Configuração de cores e estilos
        self.bg_color = "#333333"
        self.text_color = "#FFFFFF"
        self.button_color = "#007BFF"
        self.button_text_color = "#FFFFFF"
        
        self.root.configure(bg=self.bg_color)
        
        # Título
        self.title_label = tk.Label(
            self.root,
            text="SECURE FILE ENCRYPTION TOOL",
            font=("Arial", 16, "bold"),
            fg=self.text_color,
            bg=self.bg_color,
            pady=20
        )
        self.title_label.pack()
        
        # Subtítulo
        self.subtitle_label = tk.Label(
            self.root,
            text="Proteja seus arquivos com criptografia forte",
            font=("Arial", 12),
            fg=self.text_color,
            bg=self.bg_color,
            pady=10
        )
        self.subtitle_label.pack()
        
        # Frame para os botões
        self.button_frame = tk.Frame(self.root, bg=self.bg_color)
        self.button_frame.pack(pady=20)
        
        # Botões
        button_width = 25
        button_height = 2
        
        self.encrypt_file_button = tk.Button(
            self.button_frame,
            text="Criptografar arquivo",
            width=button_width,
            height=button_height,
            bg=self.button_color,
            fg=self.button_text_color,
            command=self.encrypt_file_action
        )
        self.encrypt_file_button.grid(row=0, column=0, padx=10, pady=10)
        
        self.decrypt_file_button = tk.Button(
            self.button_frame,
            text="Descriptografar arquivo",
            width=button_width,
            height=button_height,
            bg=self.button_color,
            fg=self.button_text_color,
            command=self.decrypt_file_action
        )
        self.decrypt_file_button.grid(row=0, column=1, padx=10, pady=10)
        
        self.encrypt_folder_button = tk.Button(
            self.button_frame,
            text="Criptografar pasta",
            width=button_width,
            height=button_height,
            bg=self.button_color,
            fg=self.button_text_color,
            command=self.encrypt_folder_action
        )
        self.encrypt_folder_button.grid(row=1, column=0, padx=10, pady=10)
        
        self.decrypt_folder_button = tk.Button(
            self.button_frame,
            text="Descriptografar pasta",
            width=button_width,
            height=button_height,
            bg=self.button_color,
            fg=self.button_text_color,
            command=self.decrypt_folder_action
        )
        self.decrypt_folder_button.grid(row=1, column=1, padx=10, pady=10)
        
        # Status
        self.status_label = tk.Label(
            self.root,
            text="Pronto para operações de criptografia",
            font=("Arial", 10),
            fg=self.text_color,
            bg=self.bg_color,
            pady=10
        )
        self.status_label.pack(pady=10)
        
        # Versão do software
        self.version_label = tk.Label(
            self.root,
            text="Versão 1.0",
            font=("Arial", 8),
            fg=self.text_color,
            bg=self.bg_color
        )
        self.version_label.pack(side=tk.BOTTOM, pady=10)
    
    def update_status(self, message):
        self.status_label.config(text=message)
        self.root.update()
    
    def get_password(self):
        password = simpledialog.askstring("Senha", "Digite uma senha forte:", show='*')
        if password:
            confirm = simpledialog.askstring("Confirmar Senha", "Confirme a senha:", show='*')
            if password == confirm:
                return password
            else:
                messagebox.showerror("Erro", "As senhas não coincidem!")
                return None
        return None
    
    def encrypt_file_action(self):
        filepath = filedialog.askopenfilename(title="Selecione o arquivo para criptografar")
        if not filepath:
            return
            
        password = self.get_password()
        if not password:
            return
            
        self.update_status("Criptografando arquivo...")
        if encrypt_file(filepath, password):
            messagebox.showinfo("Sucesso", f"Arquivo criptografado com sucesso:\n{filepath}.enc")
        else:
            messagebox.showerror("Erro", "Falha ao criptografar o arquivo.")
        self.update_status("Pronto para operações de criptografia")
    
    def decrypt_file_action(self):
        filepath = filedialog.askopenfilename(title="Selecione o arquivo para descriptografar", 
                                            filetypes=[("Arquivos criptografados", "*.enc"), ("Todos arquivos", "*.*")])
        if not filepath:
            return
            
        password = simpledialog.askstring("Senha", "Digite a senha de descriptografia:", show='*')
        if not password:
            return
            
        self.update_status("Descriptografando arquivo...")
        if decrypt_file(filepath, password):
            messagebox.showinfo("Sucesso", f"Arquivo descriptografado com sucesso!")
        else:
            messagebox.showerror("Erro", "Senha incorreta ou arquivo corrompido!")
        self.update_status("Pronto para operações de criptografia")
    
    def encrypt_folder_action(self):
        folderpath = filedialog.askdirectory(title="Selecione a pasta para criptografar")
        if not folderpath:
            return
            
        password = self.get_password()
        if not password:
            return
            
        self.update_status("Criptografando pasta...")
        encrypt_folder(folderpath, password)
        messagebox.showinfo("Sucesso", "Pasta criptografada com sucesso!")
        self.update_status("Pronto para operações de criptografia")
    
    def decrypt_folder_action(self):
        folderpath = filedialog.askdirectory(title="Selecione a pasta para descriptografar")
        if not folderpath:
            return
            
        password = simpledialog.askstring("Senha", "Digite a senha de descriptografia:", show='*')
        if not password:
            return
            
        self.update_status("Descriptografando pasta...")
        decrypt_folder(folderpath, password)
        messagebox.showinfo("Sucesso", "Pasta descriptografada com sucesso!")
        self.update_status("Pronto para operações de criptografia")


def main():
    root = tk.Tk()
    app = SecureFileEncryptorApp(root)
    root.mainloop()


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        messagebox.showerror("Erro", f"Ocorreu um erro inesperado: {str(e)}")
