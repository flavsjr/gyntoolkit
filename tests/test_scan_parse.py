"""Testes do parser de banner → (produto, versão) p/ CVE/CPE lookup (offline)."""
from gyntoolkit.scan import _build_cpe, parse_service


def test_parse_openssh():
    prod, ver = parse_service("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3")
    assert prod == "openssh"
    assert ver == "8.2p1"


def test_parse_nginx_server_header():
    prod, ver = parse_service("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n")
    assert prod == "nginx"
    assert ver == "1.18.0"


def test_parse_apache_aliases_to_cpe_product():
    prod, ver = parse_service("Server: Apache/2.4.41 (Ubuntu)")
    assert prod == "http_server"      # alias CPE do apache httpd
    assert ver == "2.4.41"


def test_parse_vsftpd():
    prod, ver = parse_service("220 (vsFTPd 3.0.3)")
    assert prod == "vsftpd"
    assert ver == "3.0.3"


def test_parse_numeric_token_skipped():
    # Banner que começa com código de status e não tem versão → sem produto
    # (evita keyword lookup ruidoso tipo "220").
    assert parse_service("220 mail.example.com ESMTP Postfix") == ("", None)


def test_parse_no_version_keeps_product_token():
    prod, ver = parse_service("lighttpd")
    assert prod == "lighttpd"
    assert ver is None


def test_parse_empty():
    assert parse_service("") == ("", None)


def test_build_cpe_shape():
    cpe = _build_cpe("openssh", "8.2p1")
    assert cpe == "cpe:2.3:a:*:openssh:8.2p1:*:*:*:*:*:*:*"
