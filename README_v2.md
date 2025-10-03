# 🔐 Secure File Encryption Tool - Versão 2.0 Premium

Uma ferramenta moderna e elegante para criptografia de arquivos com interface visual completamente renovada.

## ✨ Novidades da Versão 2.0

### 🎨 Design Completamente Renovado
- **Interface Dark Premium**: Tema escuro moderno com gradientes elegantes
- **Animações Suaves**: Transições fluidas e efeitos visuais
- **Splash Screen**: Tela de carregamento animada com barra de progresso
- **Efeitos Hover**: Botões interativos com feedback visual
- **Notificações Personalizadas**: Sistema de notificações estilizadas
- **Ícones Modernos**: Emojis e ícones visuais em toda interface

### 🚀 Melhorias na Experiência do Usuário
- **Barra de Progresso Animada**: Feedback visual durante operações
- **Status Dinâmico**: Indicadores de estado com ícones coloridos
- **Janelas Modais Estilizadas**: Diálogos de senha redesenhados
- **Fade Effects**: Efeitos de transparência e transição
- **Centralização Automática**: Janelas sempre centralizadas na tela

### 🛡️ Recursos de Segurança (Mantidos)
- **Criptografia AES-256**: Padrão militar de segurança
- **Hash SHA-256**: Geração segura de chaves
- **Criptografia de Arquivos**: Proteção individual de arquivos
- **Criptografia de Pastas**: Proteção completa de diretórios
- **Zero Knowledge**: Senhas não são armazenadas

## 🎯 Como Usar

### 1. Executar o Aplicativo
```bash
python main.py
```

### 2. Operações Disponíveis
- **🔒 Criptografar Arquivo**: Protege um arquivo individual
- **🔓 Descriptografar Arquivo**: Restaura um arquivo .enc
- **📁 Criptografar Pasta**: Protege todos os arquivos de uma pasta
- **📂 Descriptografar Pasta**: Restaura todos os arquivos .enc de uma pasta

### 3. Interface Visual
- **Splash Screen**: Carregamento animado de 3 segundos
- **Interface Principal**: Design dark com botões modernos
- **Diálogos de Senha**: Janelas estilizadas para entrada segura
- **Notificações**: Feedback visual elegante para todas as operações
- **Barra de Progresso**: Acompanhamento visual do processamento

## 🎨 Paleta de Cores

- **Fundo Principal**: `#1a1a2e` (Dark Navy)
- **Fundo Secundário**: `#16213e` (Darker Blue)
- **Cor de Destaque**: `#e94560` (Vibrant Red)
- **Texto Principal**: `#ffffff` (Pure White)
- **Texto Secundário**: `#a0a0a0` (Light Gray)
- **Sucesso**: `#00d4aa` (Mint Green)
- **Aviso/Erro**: `#ff6b6b` (Coral Red)

## 🔧 Requisitos

```
cryptography>=3.0.0
tkinter (incluído no Python)
```

## 📁 Estrutura do Projeto

```
SecureFileEncryptionTool/
├── main.py              # Aplicativo principal com interface moderna
├── splash.py            # Tela de splash screen
├── icon.ico            # Ícone do aplicativo
├── requirements.txt     # Dependências
├── README.md           # Esta documentação
└── build/              # Arquivos de build (PyInstaller)
```

## 🚀 Compilação para Executável

Para gerar um executável standalone:

```bash
pip install pyinstaller
pyinstaller SecureFileEncryptor.spec
```

O executável será gerado na pasta `dist/`.

## 🔒 Segurança

- **Algoritmo**: AES-256 em modo CBC
- **Derivação de Chave**: SHA-256 da senha do usuário
- **Arquivos Originais**: Mantidos intactos durante criptografia
- **Extensão**: Arquivos criptografados recebem extensão `.enc`

## 📸 Screenshots

### Splash Screen
- Tela de carregamento animada com logo e barra de progresso

### Interface Principal
- Design dark moderno com 4 botões principais estilizados
- Barra de status com ícones dinâmicos
- Informações de segurança no rodapé

### Notificações
- Sistema de notificações personalizadas com ícones e cores
- Auto-fechamento após 4 segundos
- Efeitos de fade-in/fade-out

## 🎉 Créditos

Desenvolvido com ❤️ para proporcionar máxima segurança com design moderno.

**Versão 2.0 Premium** - Interface completamente redesenhada
- Design responsivo e elegante
- Animações suaves e profissionais
- Experiência de usuário premium
- Máxima segurança mantida

---

💡 **Dica**: Mantenha sempre backups de seus arquivos importantes antes da criptografia!