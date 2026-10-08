#!/usr/bin/env python3
"""Internacionalização (i18n) leve por catálogo de dicionário.

Sem dependências externas e sem etapa de build (.mo). Resolução do idioma:

1. ``ui.lang`` do ``.gyntoolkit.yaml`` (quando diferente de ``auto``).
2. Variável de ambiente ``GYNTOOLKIT_LANG``.
3. Locale do SO (``locale.getlocale`` / ``$LANG``).
4. Fallback para :data:`DEFAULT_LANG` (``en``).

Uso::

    from . import i18n
    i18n.set_lang(i18n.resolve_lang(CONFIG["ui"]["lang"]))
    print(i18n.t("menu.main.title"))
    print(i18n.t("scan.hosts_found", n=3))
"""

import locale
import os

DEFAULT_LANG = "en"
SUPPORTED: tuple[str, ...] = ("en", "pt")

# Catálogo de mensagens. Chave namespaceada → string por idioma.
# Interpolação via str.format: use {name} e passe t(key, name=...).
MESSAGES: dict[str, dict[str, str]] = {
    "en": {
        # menu principal
        "menu.main.title": "Main Menu:",
        "menu.main.info": "Information Gathering",
        "menu.main.brute": "Brute Force",
        "menu.main.scan": "Advanced Scanning",
        "menu.main.utils": "Utilities",
        "menu.main.audit": "Audit (full profile)",
        # submenu: information gathering
        "menu.info.title": "Information Gathering:",
        "menu.info.whois": "WHOIS Lookup",
        "menu.info.dns": "DNS Lookup",
        "menu.info.geo": "IP Geolocation",
        "menu.info.revdns": "Reverse DNS (PTR)",
        "menu.info.subenum": "Subdomain Enum (crt.sh)",
        "menu.info.ssl": "SSL/TLS Cert Inspector",
        "menu.info.httpfp": "HTTP Fingerprint",
        "menu.info.internetdb": "InternetDB (Shodan free)",
        "menu.info.hibp": "HIBP Breach Check",
        "menu.info.macvendor": "MAC Vendor Lookup",
        "menu.info.traceroute": "Traceroute (TCP)",
        "menu.info.axfr": "DNS Zone Transfer (AXFR)",
        "menu.info.webscan": "Web Content Discovery",
        "menu.info.shodan": "Shodan Host (API key)",
        "menu.info.mailsec": "Email Security (SPF/DKIM/DMARC)",
        # submenu: brute force
        "menu.brute.title": "Brute Force:",
        "menu.brute.cupp": "Generate Wordlist (CUPP)",
        "menu.brute.genwl": "Generate Wordlist (native)",
        "menu.brute.ssh": "SSH Attack",
        "menu.brute.http": "HTTP Attack",
        # submenu: utilities
        "menu.utils.title": "Utilities:",
        "menu.utils.hashtext": "Text hash (MD5/SHA1/SHA256/SHA512)",
        "menu.utils.hashfile": "File hash",
        "menu.utils.b64enc": "Base64 encode",
        "menu.utils.b64dec": "Base64 decode",
        "menu.utils.jwt": "JWT decode (no signature check)",
        # brute force (runtime)
        "brute.progress": "[{tried}/{total}] attempts...",
        "brute.ssh_valid": "[+] SSH valid: {user}:{pwd}",
        "brute.http_valid": "[+] HTTP valid: {user}:{pwd}",
        "brute.warn_active": "[!] WARNING: {action} is an active attack.",
        "brute.warn_authorized": "[!] Use only on targets with written authorization.",
        "brute.warn_crime": "[!] Unauthorized use is a crime (Lei 12.737/12, CFAA, etc).",
        "brute.confirm": "Confirm authorization? (type 'AUTHORIZE'): ",
        "brute.confirm_word": "AUTHORIZE",
        "brute.wordlist_not_found": "Wordlist not found: {path}",
        "brute.cupp_not_found": "CUPP not found. Clone: git clone https://github.com/Mebus/cupp.git",
        "brute.cupp_err": "Error running CUPP: {err}",
        "brute.paramiko_missing": "paramiko not installed. Run: pip install paramiko",
        "brute.aiohttp_missing": "aiohttp not installed. Run: pip install aiohttp",
        # prompts de input
        "prompt.domain": "Enter domain: ",
        "prompt.dns_server": "DNS server (ENTER for default): ",
        "prompt.ip_or_domain": "IP or domain: ",
        "prompt.root_domain": "Root domain: ",
        "prompt.host": "Host: ",
        "prompt.port_443": "Port [443]: ",
        "prompt.url_http": "URL (with http/https): ",
        "prompt.domain_simple": "Domain: ",
        "prompt.mac": "MAC (e.g. 00:1A:2B:3C:4D:5E): ",
        "prompt.target": "Target: ",
        "prompt.max_hops": "Max hops [{n}]: ",
        "prompt.dest_port": "Dest TCP port [{n}]: ",
        "prompt.target_host": "Target host: ",
        "prompt.port_22": "Port [22]: ",
        "prompt.user_or_users_wl": "Single user or users wordlist path{default}: ",
        "prompt.user_or_wl": "Single user or wordlist path{default}: ",
        "prompt.pass_wl": "Passwords wordlist path{default}: ",
        "prompt.workers": "Concurrent workers [{n}]: ",
        "prompt.url_target": "Target URL (with http/https): ",
        "prompt.mode": "Mode [basic/form] (default basic): ",
        "prompt.user_field": "Username field name [username]: ",
        "prompt.pass_field": "Password field name [password]: ",
        "prompt.fail_sig": "Text snippet that indicates failure (e.g. 'Invalid'): ",
        "prompt.target_net": "Target (IP/network): ",
        "prompt.scan_type": "Scan type [fast/full] (default {d}): ",
        "prompt.select_host": "Select host (ENTER for all): ",
        "prompt.text": "Text: ",
        "prompt.algo": "Algorithm [sha256]: ",
        "prompt.file_path": "File path: ",
        "prompt.base64": "Base64: ",
        "prompt.jwt": "JWT: ",
        "prompt.wl_terms": "Base words (comma-separated: name, pet, company, ...): ",
        "prompt.wl_years": "Years/numbers (comma-separated, ENTER to skip): ",
        "prompt.wl_leet": "Include leet variants? [y/N]: ",
        "prompt.wl_save": "Save to file (ENTER to only print): ",
        # status (spinners)
        "status.whois": "Querying WHOIS for {d}...",
        "status.dns": "Querying {t} record for {d}...",
        "status.geo": "Querying geolocation for {t}...",
        "status.revdns": "Reverse DNS for {t}...",
        "status.subenum": "Enumerating subdomains via crt.sh (may take a while)...",
        "status.ssl": "Inspecting TLS cert of {h}:{p}...",
        "status.httpfp": "Fingerprinting {u}...",
        "status.internetdb": "Querying InternetDB (Shodan free)...",
        "status.hibp": "Querying HIBP breaches for {d}...",
        "status.macvendor": "Querying vendor...",
        "status.traceroute": "TCP traceroute to {t}:{p}...",
        "status.discover": "Discovering live hosts...",
        "status.scanning": "Scanning {h}...",
        "status.axfr": "Attempting zone transfer (AXFR) for {d}...",
        "status.webscan": "Enumerating web content on {u}...",
        "status.shodan": "Querying Shodan for {t}...",
        "status.mailsec": "Analyzing email security for {d}...",
        "status.audit": "Running full audit on {t} (may take a while)...",
        # labels / títulos / result
        "label.result": "Result:",
        "label.dns_records": "{t} records of {d}",
        "label.geo": "Geolocation of {t}",
        "label.revdns": "Reverse DNS of {t}",
        "label.subdomains": "Subdomains of {d} (total: {n})",
        "label.ssl": "TLS certificate of {h}:{p}",
        "label.httpfp": "HTTP Fingerprint of {u}",
        "label.internetdb": "InternetDB of {t}",
        "label.breaches": "Breaches of {d}",
        "label.macvendor": "MAC Vendor",
        "label.traceroute": "Traceroute {t}:{p}",
        "label.axfr": "Zone transfer of {d}",
        "label.webscan": "Web content on {u} (found: {n})",
        "label.shodan": "Shodan host {t}",
        "label.mailsec": "Email security of {d}",
        "label.audit": "Audit summary — {t}",
        "audit.stages_run": "stages",
        "label.creds_found": "Credentials found",
        "label.hosts_found": "Hosts found: {n}",
        "label.scan_results": "Results for {h}",
        "label.hash": "Hash",
        "label.file_hash": "File hash",
        "label.b64enc": "Base64 encode",
        "label.b64dec": "Base64 decode",
        # geo field labels
        "geo.ip": "IP", "geo.country": "Country", "geo.region": "Region",
        "geo.city": "City", "geo.zip": "ZIP", "geo.lat": "Latitude",
        "geo.lon": "Longitude", "geo.timezone": "Timezone", "geo.isp": "ISP",
        "geo.org": "Organization", "geo.as": "ASN", "geo.reverse": "Reverse DNS",
        "geo.mobile": "Mobile", "geo.proxy": "Proxy", "geo.hosting": "Hosting",
        # internetdb shown labels
        "idb.ip": "IP", "idb.hostnames": "Hostnames", "idb.ports": "Open ports",
        "idb.tags": "Tags", "idb.cpes": "CPEs", "idb.cves": "CVEs",
        # kv labels diversos
        "kv.mac": "MAC", "kv.vendor": "Vendor",
        # table headers
        "table.breaches": "Name|Date|Accounts|Classes",
        "table.creds": "User|Password",
        "table.traceroute": "TTL|IP|RTT",
        "table.scan": "Port|Service|Risk|Banner|CVEs",
        "table.webscan": "Status|Path|Length|Location",
        "table.mailsec": "Check|Verdict|Detail",
        "mailsec.verdict_ok": "OK", "mailsec.verdict_weak": "Weak",
        "mailsec.verdict_missing": "Missing", "mailsec.verdict_unknown": "Unknown",
        # mensagens
        "msg.no_subdomains": "No subdomains found.",
        "msg.webscan_none": "No content discovered on {u}.",
        "msg.wl_empty": "No base words given. Aborting.",
        "msg.wl_generated": "Generated {n} words.",
        "msg.wl_saved": "Wordlist saved: {path}",
        "msg.audit_passive_note": "Menu audit runs passive stages only. For the active scan use the CLI: gyntoolkit audit <t> --active --authorize",
        "msg.axfr_vulnerable": "[!] AXFR ALLOWED — zone transfer exposed on at least one NS.",
        "msg.axfr_safe": "All nameservers refused the zone transfer (good).",
        "msg.no_breaches": "No known breach for {d}.",
        "msg.auth_not_confirmed": "Authorization not confirmed. Aborting.",
        "msg.empty_wordlist": "Empty wordlist. Aborting.",
        "msg.ssh_start": "Starting SSH brute on {h}:{p} ({u}x{pw} = {c} combos)...",
        "msg.http_start": "Starting HTTP brute on {u} ({c} combos)...",
        "msg.no_valid_creds": "No valid credentials found.",
        "msg.no_host_responded": "No host responded.",
        "msg.invalid_selection": "Invalid selection.",
        "msg.no_open_ports": "No open ports on {h}.",
        "msg.invalid_algo": "Invalid algorithm: {err}",
        "msg.export_prompt": "Export result? [json/html/N]: ",
        "msg.report_saved": "Report saved: {path}",
        "msg.export_fail": "Export failed: {err}",
        # scan (display de valores-DATA + prints)
        "scan.risk_critical": "Critical", "scan.risk_high": "High",
        "scan.risk_medium": "Medium", "scan.risk_low": "Low",
        "scan.service_unknown": "Unknown",
        "scan.banner_none": "No banner identified",
        "scan.cidr_invalid": "Invalid CIDR: {err}",
        "scan.arp_priv": "ARP scan requires root/admin privilege.",
        "scan.arp_fail": "ARP scan failed: {err}",
        # recon (valores de erro retornados)
        "recon.whois_err": "WHOIS query error: {err}",
        "recon.resolve_fail": "Failed to resolve {t}: {err}",
        "recon.resolve_fail_simple": "Failed to resolve: {err}",
        "recon.query_failed": "Query failed",
        "recon.no_ptr": "No PTR: {err}",
        "recon.ssl_fail": "TLS failure for {h}:{p}: {err}",
        "recon.no_cert": "Peer did not send a certificate",
        "recon.cert_parse_fail": "Certificate parse failure: {err}",
        "recon.http_fail": "HTTP failure: {err}",
        "recon.internetdb_nodata": "No data in InternetDB",
        "recon.mac_invalid": "Invalid MAC: {mac}",
        "recon.not_found_http": "Not found (HTTP {code})",
        "recon.error": "Error: {err}",
        "recon.traceroute_priv": "traceroute requires root/admin privilege",
        "recon.scapy_err": "scapy: {err}",
        "recon.axfr_no_ns": "Could not resolve NS records for {d}: {err}",
        "recon.shodan_no_key": "Shodan API key required. Set api_keys.shodan in config, or use InternetDB (free, no key).",
        "recon.shodan_unauthorized": "Shodan rejected the API key (401). Check api_keys.shodan.",
        "recon.shodan_nodata": "No data in Shodan for this host.",
        # dns chooser
        "dns.select": "Select the DNS record type:",
        "dns.back": "Back",
        "dns.invalid": "Invalid choice. Try again.",
        "dns.desc.A": "IPv4 address",
        "dns.desc.AAAA": "IPv6 address",
        "dns.desc.MX": "Mail servers",
        "dns.desc.NS": "Authoritative DNS servers",
        "dns.desc.CNAME": "Alias of another domain",
        "dns.desc.TXT": "Text records like SPF, DKIM, etc.",
        "dns.desc.SOA": "Domain administrative info",
        "dns.no_record": "No {t} record found for {d}",
        "dns.nxdomain": "Domain {d} does not exist",
        "dns.error": "Error: {err}",
        # utils
        "utils.file_not_found": "File not found: {path}",
        "utils.decode_err": "Decode error: {err}",
        "utils.jwt_parts": "JWT must have 3 parts (header.payload.signature)",
        "utils.jwt_malformed": "Malformed JWT: {err}",
        # comuns / framing
        "common.back_exit": "Back/Exit",
        "common.invalid_option": "Invalid option! Try again.",
        "common.press_enter": "Press Enter to continue...",
        "common.exiting": "Exiting...",
        "common.interrupted": "Interrupted by user.",
        # avisos de privilégio
        "warn.need_root": "Warning: advanced features require root!",
        "warn.need_admin": "Warning: advanced features require administrator!",
        # relatório HTML exportado
        "report.generated_by": "Generated by GynToolkit {version}",
        "report.footer": "GynToolkit · use only on authorized targets.",
    },
    "pt": {
        # menu principal
        "menu.main.title": "Menu Principal:",
        "menu.main.info": "Obter Informações",
        "menu.main.brute": "Brute Force",
        "menu.main.scan": "Varredura Avançada",
        "menu.main.utils": "Utilitários",
        "menu.main.audit": "Audit (perfil completo)",
        # submenu: obter informações
        "menu.info.title": "Obter Informações:",
        "menu.info.whois": "Consulta WHOIS",
        "menu.info.dns": "DNS Lookup",
        "menu.info.geo": "Geolocalização IP",
        "menu.info.revdns": "Reverse DNS (PTR)",
        "menu.info.subenum": "Subdomain Enum (crt.sh)",
        "menu.info.ssl": "SSL/TLS Cert Inspector",
        "menu.info.httpfp": "HTTP Fingerprint",
        "menu.info.internetdb": "InternetDB (Shodan free)",
        "menu.info.hibp": "HIBP Breach Check",
        "menu.info.macvendor": "MAC Vendor Lookup",
        "menu.info.traceroute": "Traceroute (TCP)",
        "menu.info.axfr": "DNS Zone Transfer (AXFR)",
        "menu.info.webscan": "Web Content Discovery",
        "menu.info.shodan": "Shodan Host (API key)",
        "menu.info.mailsec": "Segurança de E-mail (SPF/DKIM/DMARC)",
        # submenu: brute force
        "menu.brute.title": "Brute Force:",
        "menu.brute.cupp": "Gerar Wordlist (CUPP)",
        "menu.brute.genwl": "Gerar Wordlist (nativo)",
        "menu.brute.ssh": "Ataque SSH",
        "menu.brute.http": "Ataque HTTP",
        # submenu: utilitários
        "menu.utils.title": "Utilitários:",
        "menu.utils.hashtext": "Hash de texto (MD5/SHA1/SHA256/SHA512)",
        "menu.utils.hashfile": "Hash de arquivo",
        "menu.utils.b64enc": "Base64 encode",
        "menu.utils.b64dec": "Base64 decode",
        "menu.utils.jwt": "JWT decode (sem verificar assinatura)",
        # brute force (runtime)
        "brute.progress": "[{tried}/{total}] tentativas...",
        "brute.ssh_valid": "[+] SSH válido: {user}:{pwd}",
        "brute.http_valid": "[+] HTTP válido: {user}:{pwd}",
        "brute.warn_active": "[!] AVISO: {action} é ataque ativo.",
        "brute.warn_authorized": "[!] Use apenas em alvos com autorização por escrito.",
        "brute.warn_crime": "[!] Uso não autorizado é crime (Lei 12.737/12, CFAA, etc).",
        "brute.confirm": "Confirmar autorização? (digite 'AUTORIZO'): ",
        "brute.confirm_word": "AUTORIZO",
        "brute.wordlist_not_found": "Wordlist não encontrada: {path}",
        "brute.cupp_not_found": "CUPP não encontrado. Clone: git clone https://github.com/Mebus/cupp.git",
        "brute.cupp_err": "Erro ao rodar CUPP: {err}",
        "brute.paramiko_missing": "paramiko não instalado. Rode: pip install paramiko",
        "brute.aiohttp_missing": "aiohttp não instalado. Rode: pip install aiohttp",
        # prompts de input
        "prompt.domain": "Digite o domínio: ",
        "prompt.dns_server": "Servidor DNS (ENTER para default): ",
        "prompt.ip_or_domain": "IP ou domínio: ",
        "prompt.root_domain": "Domínio raiz: ",
        "prompt.host": "Host: ",
        "prompt.port_443": "Porta [443]: ",
        "prompt.url_http": "URL (com http/https): ",
        "prompt.domain_simple": "Domínio: ",
        "prompt.mac": "MAC (ex: 00:1A:2B:3C:4D:5E): ",
        "prompt.target": "Alvo: ",
        "prompt.max_hops": "Max hops [{n}]: ",
        "prompt.dest_port": "Porta TCP destino [{n}]: ",
        "prompt.target_host": "Host alvo: ",
        "prompt.port_22": "Porta [22]: ",
        "prompt.user_or_users_wl": "Usuário único ou path de wordlist de usuários{default}: ",
        "prompt.user_or_wl": "Usuário único ou path de wordlist{default}: ",
        "prompt.pass_wl": "Path da wordlist de senhas{default}: ",
        "prompt.workers": "Workers concorrentes [{n}]: ",
        "prompt.url_target": "URL alvo (com http/https): ",
        "prompt.mode": "Modo [basic/form] (default basic): ",
        "prompt.user_field": "Nome do campo usuário [username]: ",
        "prompt.pass_field": "Nome do campo senha [password]: ",
        "prompt.fail_sig": "Trecho de texto que indica falha (ex: 'Invalid'): ",
        "prompt.target_net": "Alvo (IP/rede): ",
        "prompt.scan_type": "Tipo de varredura [rápido/completo] (default {d}): ",
        "prompt.select_host": "Selecione o host (ENTER para todos): ",
        "prompt.text": "Texto: ",
        "prompt.algo": "Algoritmo [sha256]: ",
        "prompt.file_path": "Path do arquivo: ",
        "prompt.base64": "Base64: ",
        "prompt.jwt": "JWT: ",
        "prompt.wl_terms": "Palavras-base (separadas por vírgula: nome, pet, empresa, ...): ",
        "prompt.wl_years": "Anos/números (separados por vírgula, ENTER p/ pular): ",
        "prompt.wl_leet": "Incluir variações leet? [s/N]: ",
        "prompt.wl_save": "Salvar em arquivo (ENTER p/ só imprimir): ",
        # status (spinners)
        "status.whois": "Consultando WHOIS de {d}...",
        "status.dns": "Consultando registro {t} para {d}...",
        "status.geo": "Consultando geolocalização de {t}...",
        "status.revdns": "Reverse DNS de {t}...",
        "status.subenum": "Enumerando subdomínios via crt.sh (pode demorar)...",
        "status.ssl": "Inspecionando cert TLS de {h}:{p}...",
        "status.httpfp": "Fingerprinting {u}...",
        "status.internetdb": "Consultando InternetDB (Shodan free)...",
        "status.hibp": "Consultando HIBP breaches para {d}...",
        "status.macvendor": "Consultando fabricante...",
        "status.traceroute": "Traceroute TCP para {t}:{p}...",
        "status.discover": "Descobrindo hosts ativos...",
        "status.scanning": "Escaneando {h}...",
        "status.axfr": "Tentando zone transfer (AXFR) de {d}...",
        "status.webscan": "Enumerando conteúdo web em {u}...",
        "status.shodan": "Consultando Shodan para {t}...",
        "status.mailsec": "Analisando segurança de e-mail de {d}...",
        "status.audit": "Rodando audit completo em {t} (pode demorar)...",
        # labels / títulos / result
        "label.result": "Resultado:",
        "label.dns_records": "Registros {t} de {d}",
        "label.geo": "Geolocalização de {t}",
        "label.revdns": "Reverse DNS de {t}",
        "label.subdomains": "Subdomínios de {d} (total: {n})",
        "label.ssl": "Certificado TLS de {h}:{p}",
        "label.httpfp": "HTTP Fingerprint de {u}",
        "label.internetdb": "InternetDB de {t}",
        "label.breaches": "Breaches de {d}",
        "label.macvendor": "MAC Vendor",
        "label.traceroute": "Traceroute {t}:{p}",
        "label.axfr": "Zone transfer de {d}",
        "label.webscan": "Conteúdo web em {u} (encontrados: {n})",
        "label.shodan": "Host Shodan {t}",
        "label.mailsec": "Segurança de e-mail de {d}",
        "label.audit": "Resumo do audit — {t}",
        "audit.stages_run": "etapas",
        "label.creds_found": "Credenciais encontradas",
        "label.hosts_found": "Hosts encontrados: {n}",
        "label.scan_results": "Resultados para {h}",
        "label.hash": "Hash",
        "label.file_hash": "Hash de arquivo",
        "label.b64enc": "Base64 encode",
        "label.b64dec": "Base64 decode",
        # geo field labels
        "geo.ip": "IP", "geo.country": "País", "geo.region": "Região",
        "geo.city": "Cidade", "geo.zip": "CEP", "geo.lat": "Latitude",
        "geo.lon": "Longitude", "geo.timezone": "Fuso", "geo.isp": "ISP",
        "geo.org": "Organização", "geo.as": "ASN", "geo.reverse": "Reverse DNS",
        "geo.mobile": "Mobile", "geo.proxy": "Proxy", "geo.hosting": "Hosting",
        # internetdb shown labels
        "idb.ip": "IP", "idb.hostnames": "Hostnames", "idb.ports": "Portas abertas",
        "idb.tags": "Tags", "idb.cpes": "CPEs", "idb.cves": "CVEs",
        # kv labels diversos
        "kv.mac": "MAC", "kv.vendor": "Fabricante",
        # table headers
        "table.breaches": "Nome|Data|Contas|Classes",
        "table.creds": "Usuário|Senha",
        "table.traceroute": "TTL|IP|RTT",
        "table.scan": "Porta|Serviço|Risco|Banner|CVEs",
        "table.webscan": "Status|Path|Tamanho|Location",
        "table.mailsec": "Checagem|Veredito|Detalhe",
        "mailsec.verdict_ok": "OK", "mailsec.verdict_weak": "Fraco",
        "mailsec.verdict_missing": "Ausente", "mailsec.verdict_unknown": "Indeterminado",
        # mensagens
        "msg.no_subdomains": "Nenhum subdomínio encontrado.",
        "msg.webscan_none": "Nenhum conteúdo descoberto em {u}.",
        "msg.wl_empty": "Nenhuma palavra-base informada. Abortando.",
        "msg.wl_generated": "Geradas {n} palavras.",
        "msg.wl_saved": "Wordlist salva: {path}",
        "msg.audit_passive_note": "Audit no menu roda só etapas passivas. Para o scan ativo use a CLI: gyntoolkit audit <t> --active --authorize",
        "msg.axfr_vulnerable": "[!] AXFR PERMITIDO — zone transfer exposto em ao menos um NS.",
        "msg.axfr_safe": "Todos os nameservers recusaram o zone transfer (bom).",
        "msg.no_breaches": "Nenhum breach conhecido para {d}.",
        "msg.auth_not_confirmed": "Autorização não confirmada. Abortando.",
        "msg.empty_wordlist": "Wordlist vazia. Abortando.",
        "msg.ssh_start": "Iniciando SSH brute em {h}:{p} ({u}x{pw} = {c} combos)...",
        "msg.http_start": "Iniciando HTTP brute em {u} ({c} combos)...",
        "msg.no_valid_creds": "Nenhuma credencial válida encontrada.",
        "msg.no_host_responded": "Nenhum host respondeu.",
        "msg.invalid_selection": "Seleção inválida.",
        "msg.no_open_ports": "Nenhuma porta aberta em {h}.",
        "msg.invalid_algo": "Algoritmo inválido: {err}",
        "msg.export_prompt": "Exportar resultado? [json/html/N]: ",
        "msg.report_saved": "Relatório salvo: {path}",
        "msg.export_fail": "Falha ao exportar: {err}",
        # scan (display de valores-DATA + prints)
        "scan.risk_critical": "Crítico", "scan.risk_high": "Alto",
        "scan.risk_medium": "Médio", "scan.risk_low": "Baixo",
        "scan.service_unknown": "Desconhecido",
        "scan.banner_none": "Nenhum banner identificado",
        "scan.cidr_invalid": "CIDR inválido: {err}",
        "scan.arp_priv": "ARP scan requer privilégio root/admin.",
        "scan.arp_fail": "Falha no ARP scan: {err}",
        # recon (valores de erro retornados)
        "recon.whois_err": "Erro na consulta WHOIS: {err}",
        "recon.resolve_fail": "Falha ao resolver {t}: {err}",
        "recon.resolve_fail_simple": "Falha ao resolver: {err}",
        "recon.query_failed": "Consulta falhou",
        "recon.no_ptr": "Sem PTR: {err}",
        "recon.ssl_fail": "Falha SSL para {h}:{p}: {err}",
        "recon.no_cert": "Peer não enviou certificado",
        "recon.cert_parse_fail": "Falha ao parsear cert: {err}",
        "recon.http_fail": "Falha HTTP: {err}",
        "recon.internetdb_nodata": "Sem dados no InternetDB",
        "recon.mac_invalid": "MAC inválido: {mac}",
        "recon.not_found_http": "Não encontrado (HTTP {code})",
        "recon.error": "Erro: {err}",
        "recon.traceroute_priv": "traceroute requer privilégio root/admin",
        "recon.scapy_err": "scapy: {err}",
        "recon.axfr_no_ns": "Não foi possível resolver os NS de {d}: {err}",
        "recon.shodan_no_key": "API key do Shodan necessária. Defina api_keys.shodan no config, ou use o InternetDB (free, sem key).",
        "recon.shodan_unauthorized": "Shodan rejeitou a API key (401). Verifique api_keys.shodan.",
        "recon.shodan_nodata": "Sem dados no Shodan para este host.",
        # dns chooser
        "dns.select": "Selecione o tipo de registro DNS:",
        "dns.back": "Voltar",
        "dns.invalid": "Escolha inválida. Tente novamente.",
        "dns.desc.A": "Endereço IPv4",
        "dns.desc.AAAA": "Endereço IPv6",
        "dns.desc.MX": "Servidores de e-mail",
        "dns.desc.NS": "Servidores DNS autoritativos",
        "dns.desc.CNAME": "Apelido de outro domínio",
        "dns.desc.TXT": "Registros de texto como SPF, DKIM, etc.",
        "dns.desc.SOA": "Informações administrativas do domínio",
        "dns.no_record": "Nenhum registro {t} encontrado para {d}",
        "dns.nxdomain": "Domínio {d} não existe",
        "dns.error": "Erro: {err}",
        # utils
        "utils.file_not_found": "Arquivo não encontrado: {path}",
        "utils.decode_err": "Erro decode: {err}",
        "utils.jwt_parts": "JWT deve ter 3 partes (header.payload.signature)",
        "utils.jwt_malformed": "JWT malformado: {err}",
        # comuns / framing
        "common.back_exit": "Voltar/Sair",
        "common.invalid_option": "Opção inválida! Tente novamente.",
        "common.press_enter": "Pressione Enter para continuar...",
        "common.exiting": "Saindo...",
        "common.interrupted": "Interrompido pelo usuário.",
        # avisos de privilégio
        "warn.need_root": "Aviso: Funcionalidades avançadas requerem root!",
        "warn.need_admin": "Aviso: Funcionalidades avançadas requerem administrador!",
        # relatório HTML exportado
        "report.generated_by": "Gerado por GynToolkit {version}",
        "report.footer": "GynToolkit · use apenas em alvos autorizados.",
    },
}

_current_lang = DEFAULT_LANG


def _normalize(value: str | None) -> str | None:
    """Reduz 'pt_BR.UTF-8' / 'en-US' → 'pt' / 'en' se suportado, senão None."""
    if not value:
        return None
    code = value.strip().lower().replace("-", "_").split("_", 1)[0]
    return code if code in SUPPORTED else None


def _from_locale() -> str | None:
    for getter in (lambda: locale.getlocale()[0], locale.getdefaultlocale):
        try:
            code = _normalize(getter()[0] if getter is locale.getdefaultlocale else getter())
        except (ValueError, IndexError, TypeError):
            code = None
        if code:
            return code
    for env_var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        code = _normalize(os.environ.get(env_var))
        if code:
            return code
    return None


def resolve_lang(config_lang: str | None = None) -> str:
    """Resolve o idioma efetivo seguindo a ordem de precedência documentada."""
    cfg = _normalize(config_lang)
    if cfg and (config_lang or "").strip().lower() != "auto":
        return cfg
    env = _normalize(os.environ.get("GYNTOOLKIT_LANG"))
    if env:
        return env
    loc = _from_locale()
    if loc:
        return loc
    return DEFAULT_LANG


def set_lang(lang: str | None) -> str:
    """Define o idioma atual (normalizado). Retorna o idioma efetivo."""
    global _current_lang
    _current_lang = _normalize(lang) or DEFAULT_LANG
    return _current_lang


def get_lang() -> str:
    return _current_lang


def t(key: str, **kwargs: object) -> str:
    """Traduz ``key`` no idioma atual.

    Fallback: idioma atual → :data:`DEFAULT_LANG` → a própria chave.
    ``kwargs`` são aplicados via :meth:`str.format`.
    """
    msg = MESSAGES.get(_current_lang, {}).get(key)
    if msg is None:
        msg = MESSAGES.get(DEFAULT_LANG, {}).get(key, key)
    if kwargs:
        try:
            return msg.format(**kwargs)
        except (KeyError, IndexError, ValueError):
            return msg
    return msg
