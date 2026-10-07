# demo.tape — grava o GIF de demonstração do GynToolkit.
#
# Pré-requisitos:
#   - VHS (charmbracelet):  https://github.com/charmbracelet/vhs
#   - ttyd e ffmpeg (deps do VHS)
#   - Ambiente com o gyntoolkit instalado:  pip install -e ".[dev]"
#
# Gerar o GIF:
#   vhs demo.tape
#
# Saída: docs/demo.gif  (referenciado no topo do README.md)

Output docs/demo.gif

# ---- Aparência (tema dark, estética gyntoolkit:~#) ----
Set Shell        "bash"
Set FontSize     18
Set Width        1200
Set Height       700
Set Padding      24
Set Theme        { "name": "gyntoolkit-dark", "background": "#0d0d0d", "foreground": "#00ff00", "cursor": "#00ff00", "selection": "#1a1a1a", "black": "#1a1a1a", "red": "#ff0033", "green": "#00ff00", "yellow": "#d7ff00", "blue": "#00afff", "magenta": "#ff00ff", "cyan": "#00ffff", "white": "#e0e0e0", "brightBlack": "#555555", "brightRed": "#ff5577", "brightGreen": "#55ff55", "brightYellow": "#ffff55", "brightBlue": "#55afff", "brightMagenta": "#ff55ff", "brightCyan": "#55ffff", "brightWhite": "#ffffff" }
Set TypingSpeed  60ms

# ---- Limpa a tela ----
Type "clear"
Enter
Sleep 500ms

# ---- 1. Inicialização da ferramenta (banner + menu interativo) ----
Type "python -m gyntoolkit"
Sleep 800ms
Enter
Sleep 3s

# Mostra o menu interativo por alguns segundos
Sleep 2s

# Sai da ferramenta (opção de saída do menu principal)
Type "0"
Sleep 500ms
Enter
Sleep 1s

# ---- 2. Execução da suite E2E do lab local ----
Type "python lab/run_e2e.py"
Sleep 800ms
Enter

# Deixa a suite rodar (sobe mocks SSH/HTTP, ataca, valida, encerra)
Sleep 12s

# Segura o frame final mostrando os resultados [OK]
Sleep 3s
