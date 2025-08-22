# SecureFileEncryptionTool

## Descrição
O **SecureFileEncryptionTool** é uma aplicação gráfica (GUI) desenvolvida em Python para criptografar e descriptografar arquivos e pastas de forma simples, rápida e segura. Utiliza criptografia forte baseada em senha, garantindo a proteção de dados sensíveis contra acessos não autorizados.

## Funcionalidades
- **Criptografia de Arquivos:** Proteja arquivos individuais com senha.
- **Descriptografia de Arquivos:** Recupere arquivos protegidos informando a senha correta.
- **Criptografia de Pastas:** Criptografe todos os arquivos de uma pasta (e subpastas) de uma só vez.
- **Descriptografia de Pastas:** Descriptografe todos os arquivos criptografados de uma pasta.
- **Interface Intuitiva:** Interface gráfica moderna, fácil de usar, com feedback visual de status.
- **Proteção por Senha:** A senha nunca é armazenada, sendo utilizada apenas para gerar a chave de criptografia.
- **Compatibilidade:** Funciona em Windows (e pode ser adaptado para outros sistemas).

## Instalação

### Pré-requisitos
- Python 3.7+
- Pip

### Instalação dos requisitos
```bash
pip install -r requirements.txt
```

### Executando o programa
```bash
python main.py
```

### Gerando executável (opcional)
Se desejar gerar um executável standalone (Windows):

1. Instale o PyInstaller:
	```bash
	pip install pyinstaller
	```
2. Gere o executável:
	```bash
	pyinstaller SecureFileEncryptor.spec
	```
3. O executável estará na pasta `build/SecureFileEncryptor/`.

## Como Usar
1. **Criptografar Arquivo:** Clique em "Criptografar arquivo" e selecione o arquivo desejado. Defina e confirme uma senha forte. O arquivo criptografado será salvo com extensão `.enc`.
2. **Descriptografar Arquivo:** Clique em "Descriptografar arquivo" e selecione o arquivo `.enc`. Informe a senha utilizada na criptografia. O arquivo original será restaurado.
3. **Criptografar Pasta:** Clique em "Criptografar pasta" e selecione a pasta desejada. Defina e confirme uma senha forte. Todos os arquivos da pasta serão criptografados.
4. **Descriptografar Pasta:** Clique em "Descriptografar pasta" e selecione a pasta desejada. Informe a senha utilizada na criptografia. Todos os arquivos criptografados serão restaurados.

## Segurança
- A chave de criptografia é derivada da senha do usuário utilizando SHA-256.
- Os arquivos são criptografados com o algoritmo **Fernet** da biblioteca `cryptography`.
- A senha nunca é salva ou transmitida.

## Requisitos
- Python 3.7 ou superior
- Biblioteca [cryptography](https://pypi.org/project/cryptography/)

## Licença
Este projeto está licenciado sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## Autor
Desenvolvido por Jimmy Adams (jimmyadmsenior)

## Contribuição
Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou pull requests.

## Aviso Legal
Este software é fornecido "no estado em que se encontra", sem garantias de qualquer tipo. Use por sua conta e risco.

