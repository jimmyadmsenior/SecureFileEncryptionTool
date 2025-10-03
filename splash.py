import tkinter as tk
import time
import threading

class SplashScreen:
    def __init__(self, duration=3):
        self.duration = duration
        self.splash = tk.Tk()
        self.splash.title("")
        self.splash.geometry("600x400")
        self.splash.resizable(False, False)
        self.splash.overrideredirect(True)  # Remove barra de título
        
        # Cores
        self.bg_color = "#0a0a0a"
        self.accent_color = "#e94560"
        self.text_color = "#ffffff"
        
        self.splash.configure(bg=self.bg_color)
        
        # Centralizar na tela
        self.center_window()
        
        # Criar interface
        self.create_splash_content()
        
        # Barra de progresso simulada
        self.progress_value = 0
        self.animate_loading()
        
        # Auto-fechar após duração especificada
        self.splash.after(duration * 1000, self.close)
    
    def center_window(self):
        self.splash.update_idletasks()
        x = (self.splash.winfo_screenwidth() // 2) - (600 // 2)
        y = (self.splash.winfo_screenheight() // 2) - (400 // 2)
        self.splash.geometry(f"600x400+{x}+{y}")
    
    def create_splash_content(self):
        # Logo/Ícone grande
        logo_label = tk.Label(
            self.splash,
            text="🔐",
            font=("Segoe UI Emoji", 64),
            fg=self.accent_color,
            bg=self.bg_color
        )
        logo_label.pack(pady=(80, 20))
        
        # Título
        title_label = tk.Label(
            self.splash,
            text="SECURE FILE ENCRYPTION TOOL",
            font=("Segoe UI", 22, "bold"),
            fg=self.text_color,
            bg=self.bg_color
        )
        title_label.pack(pady=(0, 10))
        
        # Versão
        version_label = tk.Label(
            self.splash,
            text="Versão 2.0 Premium",
            font=("Segoe UI", 12),
            fg=self.accent_color,
            bg=self.bg_color
        )
        version_label.pack(pady=(0, 40))
        
        # Status de carregamento
        self.status_label = tk.Label(
            self.splash,
            text="Iniciando sistema de criptografia...",
            font=("Segoe UI", 10),
            fg="#888888",
            bg=self.bg_color
        )
        self.status_label.pack(pady=(20, 10))
        
        # Barra de progresso visual
        progress_frame = tk.Frame(self.splash, bg=self.bg_color)
        progress_frame.pack(pady=(10, 0))
        
        self.progress_canvas = tk.Canvas(
            progress_frame, 
            width=300, 
            height=4, 
            bg=self.bg_color, 
            highlightthickness=0
        )
        self.progress_canvas.pack()
        
        # Barra de fundo
        self.progress_canvas.create_rectangle(0, 0, 300, 4, fill="#333333", outline="")
    
    def animate_loading(self):
        """Anima o carregamento"""
        loading_texts = [
            "Iniciando sistema de criptografia...",
            "Carregando módulos de segurança...",
            "Verificando integridade dos algoritmos...",
            "Preparando interface do usuário...",
            "Sistema pronto para uso!"
        ]
        
        def update_progress():
            if self.progress_value <= 100:
                # Atualizar barra de progresso
                progress_width = int((self.progress_value / 100) * 300)
                self.progress_canvas.delete("progress_bar")
                self.progress_canvas.create_rectangle(
                    0, 0, progress_width, 4, 
                    fill=self.accent_color, 
                    outline="", 
                    tags="progress_bar"
                )
                
                # Atualizar texto baseado no progresso
                text_index = min(int(self.progress_value / 25), len(loading_texts) - 1)
                self.status_label.config(text=loading_texts[text_index])
                
                self.progress_value += 2
                self.splash.after(50, update_progress)
        
        update_progress()
    
    def show(self):
        self.splash.mainloop()
    
    def close(self):
        self.splash.destroy()

if __name__ == "__main__":
    splash = SplashScreen(duration=3)
    splash.show()