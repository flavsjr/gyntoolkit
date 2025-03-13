# GynToolkit v1.2 🔍🛡️

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20MacOS-lightgrey.svg)

Ferramenta de Pentest com múltiplas funcionalidades para análise de segurança e testes de invasão éticos.

**AVISO:** Use apenas em redes onde você tem autorização explícita. O mau uso desta ferramenta é de sua inteira responsabilidade.

---

## Índice 📑
- [Recursos Principais](#recursos-principais-)
- [Instalação](#instalação-)
- [Uso Básico](#uso-básico-)
- [Capturas de Tela](#capturas-de-tela-)
- [Contribuição](#contribuição-)
- [Licença](#licença-)
- [Disclaimer](#disclaimer-)

---

## Recursos Principais 🚀

### 🔎 Obtenção de Informações
- Varredura de Portas (SYN/Connect Scan)
- Consulta WHOIS de domínios
- Detecção de serviços e banners
- Verificação de vulnerabilidades (CVE)

### 💣 Brute Force
- Gerador de Wordlists (Integração com CUPP)
- Ataque SSH (Em desenvolvimento)
- Ataque HTTP (Em desenvolvimento)

### 🛠️ Funcionalidades Avançadas
- Varredura rápida (Top 21 portas)
- Varredura completa (1-65535 portas)
- Detecção de hosts ativos em rede
- Classificação automática de risco
- Multiplataforma (Windows/Linux/Mac)

---

## Instalação ⚙️

### Pré-requisitos
- Python 3.8+
- Pip package manager

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/gyntoolkit.git
cd gyntoolkit

# Instale as dependências
pip install scapy colorama requests python-whois

# (Opcional) Para usar o CUPP
git clone https://github.com/Mebus/cupp.git
```

##Contribuição 🤝

- 1º - Faça um Fork do projeto

- 2º - Crie uma Branch para sua feature:

```bash
git checkout -b feature/nova-feature
```

- 3º - Commit suas mudanças:

```bash
git commit -m 'Adicionei uma nova feature'
```
- 4º - Push para a Branch:

```bash
git push origin feature/nova-feature
```

- 5º - Abra um Pull Request



## Disclaimer ⚠️
### ATENÇÃO: Esta ferramenta é destinada exclusivamente para:

- Testes de segurança autorizados

- Pesquisa acadêmica

- Práticas éticas de pentest

###

## Licença 📜
#### Este projeto está licenciado sob a Licença MIT - consulte o arquivo LICENSE para detalhes.
##

**Qualquer uso não autorizado em sistemas sem permissão explícita é estritamente proibido. Os desenvolvedores não se responsabilizam por uso indevido ou danos causados por esta ferramenta.**
