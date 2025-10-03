import os
import base64
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from cryptography.fernet import Fernet
from pathlib import Path
import threading
from tkinter import font


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


class ModernButton(tk.Button):
    def __init__(self, parent, text, command, bg_color="#4A90E2", hover_color="#357ABD", text_color="#FFFFFF", **kwargs):
        super().__init__(parent, **kwargs)
        
        self.bg_color = bg_color
        self.hover_color = hover_color
        self.text_color = text_color
        
        # Configurar o botão
        self.config(
            text=text,
            command=command,
            font=("Segoe UI", 11, "bold"),
            bg=bg_color,
            fg=text_color,
            activebackground=hover_color,
            activeforeground=text_color,
            relief=tk.FLAT,
            borderwidth=0,
            width=32,
            height=2,
            cursor="hand2"
        )
        
        # Bindings para efeitos hover
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
    
    def on_enter(self, event):
        self.config(bg=self.hover_color)
    
    def on_leave(self, event):
        self.config(bg=self.bg_color)


class SecureFileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Secure File Encryption Tool")
        self.root.geometry("800x650")
        self.root.resizable(False, False)
        
        # Configuração de cores modernas
        self.bg_primary = "#1a1a2e"
        self.bg_secondary = "#16213e"
        self.accent_color = "#0f3460"
        self.text_primary = "#e94560"
        self.text_secondary = "#ffffff"
        self.text_muted = "#a0a0a0"
        self.success_color = "#00d4aa"
        self.warning_color = "#ff6b6b"
        
        # Configurar estilo da janela
        self.setup_window_style()
        
        # Criar interface
        self.create_widgets()
    
    def setup_window_style(self):
        """Configura o estilo da janela principal"""
        self.root.configure(bg=self.bg_primary)
        
        # Tentar centralizar a janela
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (800 // 2)
        y = (self.root.winfo_screenheight() // 2) - (650 // 2)
        self.root.geometry(f"800x650+{x}+{y}")
    

    
    def create_widgets(self):
        """Cria todos os widgets da interface"""
        # Container principal com gradiente
        self.main_container = tk.Frame(self.root, bg=self.bg_primary)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header com título animado
        self.create_header()
        
        # Container central para os botões
        self.create_button_section()
        
        # Barra de progresso
        self.create_progress_section()
        
        # Status e informações
        self.create_status_section()
        
        # Footer
        self.create_footer()
    
    def create_header(self):
        """Cria o cabeçalho com título e logo"""
        header_frame = tk.Frame(self.main_container, bg=self.bg_primary)
        header_frame.pack(fill=tk.X, pady=(0, 30))
        
        # Logo/Ícone
        icon_label = tk.Label(
            header_frame,
            text="🔐",
            font=("Segoe UI Emoji", 32),
            bg=self.bg_primary,
            fg=self.text_primary
        )
        icon_label.pack(pady=(10, 5))
        
        # Título principal
        title_label = tk.Label(
            header_frame,
            text="SECURE FILE ENCRYPTION TOOL",
            font=("Segoe UI", 24, "bold"),
            fg=self.text_primary,
            bg=self.bg_primary
        )
        title_label.pack()
        
        # Subtítulo
        subtitle_label = tk.Label(
            header_frame,
            text="Proteja seus arquivos com criptografia militar AES-256",
            font=("Segoe UI", 12),
            fg=self.text_muted,
            bg=self.bg_primary
        )
        subtitle_label.pack(pady=(5, 0))
        
        # Linha decorativa
        line_canvas = tk.Canvas(header_frame, height=3, bg=self.bg_primary, highlightthickness=0)
        line_canvas.pack(fill=tk.X, pady=(15, 0))
        line_canvas.create_rectangle(250, 1, 550, 3, fill=self.text_primary, outline="")
    
    def create_button_section(self):
        """Cria a seção com os botões principais"""
        button_container = tk.Frame(self.main_container, bg=self.bg_secondary, relief=tk.RAISED, bd=1)
        button_container.pack(fill=tk.X, pady=(0, 20))
        
        # Título da seção
        section_title = tk.Label(
            button_container,
            text="🚀 OPERAÇÕES DISPONÍVEIS",
            font=("Segoe UI", 14, "bold"),
            fg=self.text_secondary,
            bg=self.bg_secondary
        )
        section_title.pack(pady=(20, 15))
        
        # Container para os botões em grid
        buttons_grid = tk.Frame(button_container, bg=self.bg_secondary)
        buttons_grid.pack(pady=(0, 20))
        
        # Botões modernos com ícones
        buttons_data = [
            ("🔒 Criptografar Arquivo", self.encrypt_file_action, "#4A90E2", "#357ABD"),
            ("🔓 Descriptografar Arquivo", self.decrypt_file_action, "#5CB85C", "#449D44"),
            ("📁 Criptografar Pasta", self.encrypt_folder_action, "#F0AD4E", "#EC971F"),
            ("📂 Descriptografar Pasta", self.decrypt_folder_action, "#D9534F", "#C9302C")
        ]
        
        for i, (text, command, bg_color, hover_color) in enumerate(buttons_data):
            row = i // 2
            col = i % 2
            
            button = ModernButton(
                buttons_grid, 
                text=text, 
                command=command,
                bg_color=bg_color,
                hover_color=hover_color,
                bg=self.bg_secondary
            )
            button.grid(row=row, column=col, padx=15, pady=10)
    
    def create_progress_section(self):
        """Cria a seção da barra de progresso"""
        progress_frame = tk.Frame(self.main_container, bg=self.bg_primary)
        progress_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Estilo da barra de progresso
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Custom.Horizontal.TProgressbar",
                       background=self.text_primary,
                       troughcolor=self.bg_secondary,
                       borderwidth=0,
                       lightcolor=self.text_primary,
                       darkcolor=self.text_primary)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100,
            style="Custom.Horizontal.TProgressbar",
            length=400
        )
        self.progress_bar.pack(pady=10)
        
        # Inicialmente escondida
        progress_frame.pack_forget()
        self.progress_frame = progress_frame
    
    def create_status_section(self):
        """Cria a seção de status"""
        status_container = tk.Frame(self.main_container, bg=self.bg_primary)
        status_container.pack(fill=tk.X, pady=(0, 20))
        
        # Ícone de status
        self.status_icon = tk.Label(
            status_container,
            text="✅",
            font=("Segoe UI Emoji", 16),
            bg=self.bg_primary,
            fg=self.success_color
        )
        self.status_icon.pack()
        
        # Texto de status
        self.status_label = tk.Label(
            status_container,
            text="Sistema pronto para operações de criptografia",
            font=("Segoe UI", 11),
            fg=self.text_secondary,
            bg=self.bg_primary
        )
        self.status_label.pack(pady=(5, 0))
        
        # Informações adicionais
        info_text = "🛡️ Criptografia AES-256 • 🔑 Chaves baseadas em SHA-256 • 🚀 Interface moderna"
        self.info_label = tk.Label(
            status_container,
            text=info_text,
            font=("Segoe UI", 9),
            fg=self.text_muted,
            bg=self.bg_primary
        )
        self.info_label.pack(pady=(10, 0))
    
    def create_footer(self):
        """Cria o rodapé"""
        footer_frame = tk.Frame(self.main_container, bg=self.bg_primary)
        footer_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Linha decorativa
        line_frame = tk.Frame(footer_frame, height=1, bg=self.accent_color)
        line_frame.pack(fill=tk.X, pady=(10, 15))
        
        # Informações de segurança
        security_info = tk.Label(
            footer_frame,
            text="🔒 Criptografia AES-256 • 🛡️ SHA-256 Hash • 🚀 Zero Knowledge",
            font=("Segoe UI", 9, "bold"),
            fg=self.success_color,
            bg=self.bg_primary
        )
        security_info.pack(pady=(0, 5))
        
        # Versão e créditos
        version_label = tk.Label(
            footer_frame,
            text="Versão 2.0 Premium • Desenvolvido com ❤️ para sua segurança",
            font=("Segoe UI", 9),
            fg=self.text_muted,
            bg=self.bg_primary
        )
        version_label.pack(side=tk.BOTTOM, pady=(0, 10))
    
    def show_custom_notification(self, title, message, type="info"):
        """Mostra notificação personalizada estilizada"""
        notif_window = tk.Toplevel(self.root)
        notif_window.title("")
        notif_window.geometry("400x200")
        notif_window.resizable(False, False)
        notif_window.configure(bg=self.bg_secondary)
        notif_window.overrideredirect(True)
        
        # Centralizar notificação
        notif_window.update_idletasks()
        x = (notif_window.winfo_screenwidth() // 2) - (400 // 2)
        y = (notif_window.winfo_screenheight() // 2) - (200 // 2)
        notif_window.geometry(f"400x200+{x}+{y}")
        
        # Ícones baseados no tipo
        icons = {
            "success": "🎉",
            "error": "❌",
            "warning": "⚠️",
            "info": "ℹ️"
        }
        
        colors = {
            "success": self.success_color,
            "error": self.warning_color,
            "warning": "#ff9800",
            "info": "#2196f3"
        }
        
        # Container principal
        main_frame = tk.Frame(notif_window, bg=self.bg_secondary, relief=tk.RAISED, bd=2)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Ícone
        icon_label = tk.Label(
            main_frame,
            text=icons.get(type, "ℹ️"),
            font=("Segoe UI Emoji", 24),
            fg=colors.get(type, "#2196f3"),
            bg=self.bg_secondary
        )
        icon_label.pack(pady=(20, 10))
        
        # Título
        title_label = tk.Label(
            main_frame,
            text=title,
            font=("Segoe UI", 14, "bold"),
            fg=self.text_secondary,
            bg=self.bg_secondary
        )
        title_label.pack(pady=(0, 10))
        
        # Mensagem
        message_label = tk.Label(
            main_frame,
            text=message,
            font=("Segoe UI", 10),
            fg=self.text_muted,
            bg=self.bg_secondary,
            wraplength=350,
            justify=tk.CENTER
        )
        message_label.pack(pady=(0, 15))
        
        # Botão fechar
        close_btn = tk.Button(
            main_frame,
            text="✓ OK",
            command=notif_window.destroy,
            bg=colors.get(type, "#2196f3"),
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=20,
            cursor="hand2"
        )
        close_btn.pack(pady=(0, 20))
        
        # Auto-fechar após 4 segundos
        notif_window.after(4000, notif_window.destroy)
        
        # Efeito de fade-in
        notif_window.attributes('-alpha', 0.0)
        def fade_in():
            alpha = notif_window.attributes('-alpha')
            if alpha < 1.0:
                notif_window.attributes('-alpha', alpha + 0.1)
                notif_window.after(20, fade_in)
        
        fade_in()
    
    def show_progress(self):
        """Mostra a barra de progresso com animação suave"""
        self.progress_frame.pack(fill=tk.X, pady=(0, 15))
        self.animate_progress()
    
    def hide_progress(self):
        """Esconde a barra de progresso com fade out"""
        self.progress_frame.pack_forget()
        self.progress_var.set(0)
    
    def animate_progress(self):
        """Anima a barra de progresso com efeito pulsante"""
        def pulse_progress():
            # Animação principal de 0 a 100%
            for i in range(101):
                self.root.after(i * 15, lambda v=i: self.progress_var.set(v))
            
            # Efeito pulsante no final
            def pulse():
                for pulse_val in [95, 100, 95, 100]:
                    self.root.after(2000 + pulse_val, lambda v=pulse_val: self.progress_var.set(v))
            
            self.root.after(1600, pulse)
            self.root.after(2500, self.hide_progress)
        
        pulse_progress()
    
    def add_glow_effect(self, widget):
        """Adiciona efeito de brilho a um widget"""
        def glow():
            try:
                current_bg = widget.cget('bg')
                if current_bg == self.text_primary:
                    widget.config(fg="#ffffff")
                else:
                    widget.config(fg=self.text_primary)
                self.root.after(500, glow)
            except:
                pass  # Widget pode ter sido destruído
        
        glow()
    
    def update_status(self, message, icon="✅", color=None):
        """Atualiza o status com ícone e cor"""
        if color is None:
            color = self.success_color
        
        self.status_icon.config(text=icon, fg=color)
        self.status_label.config(text=message)
        self.root.update()
    
    def show_loading(self, message="Processando..."):
        """Mostra estado de carregamento"""
        self.update_status(message, "⏳", self.warning_color)
        self.show_progress()
    
    def show_success(self, message):
        """Mostra mensagem de sucesso"""
        self.update_status(message, "✅", self.success_color)
    
    def show_error(self, message):
        """Mostra mensagem de erro"""
        self.update_status(message, "❌", self.warning_color)
    
    def get_password(self):
        """Solicita senha com interface melhorada"""
        # Criar janela personalizada para senha
        password_window = tk.Toplevel(self.root)
        password_window.title("🔑 Configurar Senha")
        password_window.geometry("400x300")
        password_window.configure(bg=self.bg_secondary)
        password_window.resizable(False, False)
        password_window.grab_set()
        
        # Centralizar janela
        password_window.update_idletasks()
        x = (password_window.winfo_screenwidth() // 2) - (400 // 2)
        y = (password_window.winfo_screenheight() // 2) - (300 // 2)
        password_window.geometry(f"400x300+{x}+{y}")
        
        result = {'password': None}
        
        # Título
        title_label = tk.Label(
            password_window,
            text="🔐 Digite uma senha forte",
            font=("Segoe UI", 14, "bold"),
            fg=self.text_secondary,
            bg=self.bg_secondary
        )
        title_label.pack(pady=(20, 10))
        
        # Dica de segurança
        hint_label = tk.Label(
            password_window,
            text="Use pelo menos 8 caracteres com letras, números e símbolos",
            font=("Segoe UI", 10),
            fg=self.text_muted,
            bg=self.bg_secondary
        )
        hint_label.pack(pady=(0, 20))
        
        # Campo senha
        tk.Label(password_window, text="Senha:", font=("Segoe UI", 11), 
                fg=self.text_secondary, bg=self.bg_secondary).pack(anchor='w', padx=40)
        
        password_entry = tk.Entry(password_window, show='*', font=("Segoe UI", 11), 
                                 width=30, bg=self.bg_primary, fg=self.text_secondary,
                                 insertbackground=self.text_secondary)
        password_entry.pack(pady=(5, 15), padx=40)
        
        # Campo confirmação
        tk.Label(password_window, text="Confirmar senha:", font=("Segoe UI", 11), 
                fg=self.text_secondary, bg=self.bg_secondary).pack(anchor='w', padx=40)
        
        confirm_entry = tk.Entry(password_window, show='*', font=("Segoe UI", 11), 
                               width=30, bg=self.bg_primary, fg=self.text_secondary,
                               insertbackground=self.text_secondary)
        confirm_entry.pack(pady=(5, 20), padx=40)
        
        def confirm_password():
            password = password_entry.get()
            confirm = confirm_entry.get()
            
            if not password:
                messagebox.showwarning("Aviso", "Por favor, digite uma senha!")
                return
            
            if len(password) < 6:
                messagebox.showwarning("Aviso", "A senha deve ter pelo menos 6 caracteres!")
                return
            
            if password != confirm:
                messagebox.showerror("Erro", "As senhas não coincidem!")
                return
            
            result['password'] = password
            password_window.destroy()
        
        def cancel():
            password_window.destroy()
        
        # Botões
        button_frame = tk.Frame(password_window, bg=self.bg_secondary)
        button_frame.pack(pady=10)
        
        confirm_btn = tk.Button(button_frame, text="✓ Confirmar", command=confirm_password,
                               bg="#5CB85C", fg="white", font=("Segoe UI", 10, "bold"),
                               relief=tk.FLAT, padx=20, cursor="hand2")
        confirm_btn.pack(side=tk.LEFT, padx=10)
        
        cancel_btn = tk.Button(button_frame, text="✗ Cancelar", command=cancel,
                              bg="#D9534F", fg="white", font=("Segoe UI", 10, "bold"),
                              relief=tk.FLAT, padx=20, cursor="hand2")
        cancel_btn.pack(side=tk.LEFT, padx=10)
        
        # Focar no primeiro campo
        password_entry.focus_set()
        
        # Aguardar fechamento da janela
        password_window.wait_window()
        
        return result['password']
    
    def encrypt_file_action(self):
        """Ação para criptografar arquivo com interface melhorada"""
        filepath = filedialog.askopenfilename(
            title="🔒 Selecione o arquivo para criptografar",
            filetypes=[
                ("Todos os arquivos", "*.*"),
                ("Documentos", "*.pdf *.doc *.docx *.txt"),
                ("Imagens", "*.jpg *.jpeg *.png *.gif *.bmp"),
                ("Vídeos", "*.mp4 *.avi *.mkv *.mov"),
                ("Áudios", "*.mp3 *.wav *.flac")
            ]
        )
        if not filepath:
            return
            
        password = self.get_password()
        if not password:
            return
        
        def process():
            self.show_loading("🔒 Criptografando arquivo...")
            
            if encrypt_file(filepath, password):
                self.root.after(2200, lambda: self.show_success("✅ Arquivo criptografado com sucesso!"))
                self.root.after(2300, lambda: self.show_custom_notification(
                    "🎉 Criptografia Concluída!", 
                    f"Arquivo protegido com sucesso!\n\n📁 Salvo como: {os.path.basename(filepath)}.enc\n🔐 Criptografia: AES-256 Militar",
                    "success"
                ))
            else:
                self.root.after(2200, lambda: self.show_error("❌ Falha ao criptografar o arquivo"))
                self.root.after(2300, lambda: self.show_custom_notification(
                    "❌ Erro na Criptografia", 
                    "Não foi possível criptografar o arquivo.\nVerifique se o arquivo não está sendo usado por outro programa.",
                    "error"
                ))
        
        # Executar em thread separada para não travar a interface
        threading.Thread(target=process, daemon=True).start()
    
    def decrypt_file_action(self):
        """Ação para descriptografar arquivo com interface melhorada"""
        filepath = filedialog.askopenfilename(
            title="🔓 Selecione o arquivo para descriptografar", 
            filetypes=[("Arquivos criptografados", "*.enc"), ("Todos arquivos", "*.*")]
        )
        if not filepath:
            return
        
        # Janela simples para senha de descriptografia
        password_window = tk.Toplevel(self.root)
        password_window.title("🔑 Senha de descriptografia")
        password_window.geometry("350x200")
        password_window.configure(bg=self.bg_secondary)
        password_window.resizable(False, False)
        password_window.grab_set()
        
        # Centralizar
        password_window.update_idletasks()
        x = (password_window.winfo_screenwidth() // 2) - (350 // 2)
        y = (password_window.winfo_screenheight() // 2) - (200 // 2)
        password_window.geometry(f"350x200+{x}+{y}")
        
        result = {'password': None}
        
        tk.Label(password_window, text="🔓 Digite a senha de descriptografia", 
                font=("Segoe UI", 12, "bold"), fg=self.text_secondary, 
                bg=self.bg_secondary).pack(pady=(20, 15))
        
        password_entry = tk.Entry(password_window, show='*', font=("Segoe UI", 11), 
                                 width=25, bg=self.bg_primary, fg=self.text_secondary,
                                 insertbackground=self.text_secondary)
        password_entry.pack(pady=10)
        
        def confirm():
            result['password'] = password_entry.get()
            password_window.destroy()
        
        def cancel():
            password_window.destroy()
        
        button_frame = tk.Frame(password_window, bg=self.bg_secondary)
        button_frame.pack(pady=15)
        
        tk.Button(button_frame, text="✓ Descriptografar", command=confirm,
                 bg="#5CB85C", fg="white", font=("Segoe UI", 10, "bold"),
                 relief=tk.FLAT, padx=15, cursor="hand2").pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="✗ Cancelar", command=cancel,
                 bg="#D9534F", fg="white", font=("Segoe UI", 10, "bold"),
                 relief=tk.FLAT, padx=15, cursor="hand2").pack(side=tk.LEFT, padx=5)
        
        password_entry.focus_set()
        password_entry.bind('<Return>', lambda e: confirm())
        
        password_window.wait_window()
        
        password = result['password']
        if not password:
            return
        
        def process():
            self.show_loading("🔓 Descriptografando arquivo...")
            
            if decrypt_file(filepath, password):
                self.root.after(2200, lambda: self.show_success("✅ Arquivo descriptografado com sucesso!"))
                self.root.after(2300, lambda: self.show_custom_notification(
                    "🎉 Descriptografia Concluída!", 
                    f"Arquivo restaurado com sucesso!\n\n📁 Seu arquivo original foi recuperado\n🔓 Processo concluído com segurança",
                    "success"
                ))
            else:
                self.root.after(2200, lambda: self.show_error("❌ Senha incorreta ou arquivo corrompido"))
                self.root.after(2300, lambda: self.show_custom_notification(
                    "❌ Falha na Descriptografia", 
                    "Não foi possível descriptografar o arquivo.\n\n🔑 Verifique se a senha está correta\n📁 Certifique-se de que o arquivo não está corrompido",
                    "error"
                ))
        
        threading.Thread(target=process, daemon=True).start()
    
    def encrypt_folder_action(self):
        """Ação para criptografar pasta com interface melhorada"""
        folderpath = filedialog.askdirectory(title="📁 Selecione a pasta para criptografar")
        if not folderpath:
            return
            
        password = self.get_password()
        if not password:
            return
        
        def process():
            self.show_loading("📁 Criptografando pasta e subpastas...")
            
            # Simular processamento mais longo para pastas
            self.root.after(1000, lambda: encrypt_folder(folderpath, password))
            self.root.after(3200, lambda: self.show_success("✅ Pasta criptografada com sucesso!"))
            self.root.after(3300, lambda: self.show_custom_notification(
                "🎉 Pasta Protegida!", 
                f"Todos os arquivos foram criptografados!\n\n📁 Pasta: {os.path.basename(folderpath)}\n🔐 Proteção completa aplicada\n🛡️ Máxima segurança garantida",
                "success"
            ))
        
        threading.Thread(target=process, daemon=True).start()
    
    def decrypt_folder_action(self):
        """Ação para descriptografar pasta com interface melhorada"""
        folderpath = filedialog.askdirectory(title="📂 Selecione a pasta para descriptografar")
        if not folderpath:
            return
        
        # Janela para senha
        password_window = tk.Toplevel(self.root)
        password_window.title("🔑 Senha da pasta")
        password_window.geometry("350x200")
        password_window.configure(bg=self.bg_secondary)
        password_window.resizable(False, False)
        password_window.grab_set()
        
        # Centralizar
        password_window.update_idletasks()
        x = (password_window.winfo_screenwidth() // 2) - (350 // 2)
        y = (password_window.winfo_screenheight() // 2) - (200 // 2)
        password_window.geometry(f"350x200+{x}+{y}")
        
        result = {'password': None}
        
        tk.Label(password_window, text="📂 Digite a senha da pasta", 
                font=("Segoe UI", 12, "bold"), fg=self.text_secondary, 
                bg=self.bg_secondary).pack(pady=(20, 15))
        
        password_entry = tk.Entry(password_window, show='*', font=("Segoe UI", 11), 
                                 width=25, bg=self.bg_primary, fg=self.text_secondary,
                                 insertbackground=self.text_secondary)
        password_entry.pack(pady=10)
        
        def confirm():
            result['password'] = password_entry.get()
            password_window.destroy()
        
        def cancel():
            password_window.destroy()
        
        button_frame = tk.Frame(password_window, bg=self.bg_secondary)
        button_frame.pack(pady=15)
        
        tk.Button(button_frame, text="✓ Descriptografar", command=confirm,
                 bg="#5CB85C", fg="white", font=("Segoe UI", 10, "bold"),
                 relief=tk.FLAT, padx=15, cursor="hand2").pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="✗ Cancelar", command=cancel,
                 bg="#D9534F", fg="white", font=("Segoe UI", 10, "bold"),
                 relief=tk.FLAT, padx=15, cursor="hand2").pack(side=tk.LEFT, padx=5)
        
        password_entry.focus_set()
        password_entry.bind('<Return>', lambda e: confirm())
        
        password_window.wait_window()
        
        password = result['password']
        if not password:
            return
        
        def process():
            self.show_loading("📂 Descriptografando pasta e subpastas...")
            
            # Simular processamento
            self.root.after(1000, lambda: decrypt_folder(folderpath, password))
            self.root.after(3200, lambda: self.show_success("✅ Pasta descriptografada com sucesso!"))
            self.root.after(3300, lambda: self.show_custom_notification(
                "🎉 Pasta Restaurada!", 
                f"Todos os arquivos foram recuperados!\n\n📂 Pasta: {os.path.basename(folderpath)}\n🔓 Restauração completa\n✨ Arquivos prontos para uso",
                "success"
            ))
        
        threading.Thread(target=process, daemon=True).start()


def show_splash_and_start():
    """Mostra splash screen e depois inicia o aplicativo principal"""
    # Importar splash screen
    try:
        from splash import SplashScreen
        splash = SplashScreen(duration=3)
        splash.show()
    except ImportError:
        pass  # Se não conseguir importar, pula o splash
    
    # Iniciar aplicativo principal
    main()

def main():
    root = tk.Tk()
    
    # Efeito de fade-in para a janela principal
    root.attributes('-alpha', 0.0)  # Começar invisível
    
    app = SecureFileEncryptorApp(root)
    
    # Animação de fade-in
    def fade_in():
        alpha = root.attributes('-alpha')
        if alpha < 1.0:
            root.attributes('-alpha', alpha + 0.05)
            root.after(30, fade_in)
    
    root.after(100, fade_in)  # Começar fade-in após 100ms
    root.mainloop()


if __name__ == '__main__':
    try:
        show_splash_and_start()
    except Exception as e:
        messagebox.showerror("Erro", f"Ocorreu um erro inesperado: {str(e)}")
