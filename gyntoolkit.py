#!/usr/bin/env python3.7
#coding: utf-8

import sys
import argparse
import subprocess
import re
import socket
import urllib
import sys
import json
import telnetlib
import glob
import random
import threading
import base64
import time
import whois
from os import system
import os
from sys import exit
from time import sleep
from socket import *

'''
PortScan
'''

def limparTela():
    os.system('clear')

logo = """
\033[1;32m
 ██████╗██╗   ██╗███╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝╚██╗ ██╔╝████╗  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
██║  ███╗╚████╔╝ ██╔██╗ ██║       ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
██║   ██║ ╚██╔╝  ██║╚██╗██║       ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   v1.0
╚██████╔╝  ██║   ██║ ╚████║       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║ by: PH,Fl4vs
 ╚═════╝   ╚═╝   ╚═╝  ╚═══╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   
                                       
  """

gynToolkitPrompt = "\033[1;91mgyntoolkit:~# "

def menu():
    system("reset")
    print(logo)
    
def opcoes():
    menu()
    try:
        print("\033[1;32mEscolha uma opção:\033[1;32m \n")
        escolha = int(input("\033[1;32m [1] Obter Informações\n \033[1;32m[2] Sair\n\n \033[1;91m▬▶\033[1;m "))
    except:
        print("\n\033[1;32mEscolha invalida\033[1;m")
        sleep(1)
        opcoes()
        
    if escolha == 1:
        obterInfo()
    elif escolha == 2:
        system("reset")
        exit(1)
    else:
         print("\n\033[1;32mEscolha invalida\033[1;m")
         sleep(1)
         opcoes()

"""
Colocar as funções aqui abaixo
"""

LogoInfo = '''
    \033[1;32m
    ██╗███╗   ██╗███████╗ ██████╗ 
    ██║████╗  ██║██╔════╝██╔═══██╗
    ██║██╔██╗ ██║█████╗  ██║   ██║
    ██║██║╚██╗██║██╔══╝  ██║   ██║
    ██║██║ ╚████║██║     ╚██████╔╝
    ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ 
    ~Obtenção de Informação~
    '''

def obterInfo():
        limparTela()
        print(LogoInfo)
        print(" \033[1;32m [1] Escanear Portas")
        print(" \033[1;32m [2] Whois")
        print(" \033[1;32m [0] Voltar\n")
        escolha2 = input(gynToolkitPrompt)
        limparTela()
        if escolha2 == "1":
            PortScan()
        if escolha2 == "2":
            WhoisScan()
        elif escolha2 == "0":
            system("reset")
            opcoes()
        else:
         print("\n\033[1;32mEscolha invalida\033[1;m")
         sleep(1)
         obterInfo()

def PortScan():
    menu()
    try:
        host = input("\033[1;32mDigite o host:\033[1;m ")
        print("")
    except:
        PortScan()
    try:       
        ip = gethostbyname(host)
        print("\033[1;32mEndereco IP ▬▶\033[1;m %s \n" %(ip))
    except:
        print("\033[1;32mHost invalido.\033[1;m")   
        sleep(3)
        PortScan()
    try:
        pi = int(input("\n\033[1;32mPorta inicial (ex: 80):\033[1;m "))
        print("")
    except:
        print("\033[1;32mPorta inicial invalida.\033[1;m")
        sleep(3)
        PortScan()    
    try:
        pf = int(input("\033[1;32mPorta final (ex: 443):\033[1;m "))
        print("\n")
    except:
        print("\033[1;32mPorta final invalida.\033[1;m")
        sleep(3)
        PortScan()         
        
    print("\033[33mIniciando o escaneamento\033[1;m\033[32m...\033[1;m\n")  
    for i in range(pi, pf+1):
            sckt = socket(AF_INET, SOCK_STREAM)
            res = sckt.connect_ex((ip,  i))
            if (res == 0):
                print("\033[32m▬▶ Porta\033[1;m %d \033[32maberta\033[1;m" %(i))
            else:
                print("\033[1;32m▬▶ Porta\033[1;m %d \033[1;32mfechada\033[1;m" %(i))
    print("\n\033[33mEscaneamento finalizado\033[1;m\n")
    continuar = input("\n\033[1;32mDeseja fazer outro escaneamento (s/n):\033[1;m ")
    if continuar == "s":
        PortScan()
    elif continuar == "n":
        opcoes()
#sckt.close()

def WhoisScan():
    menu()
    try:
        data = input("Enter a domain: ")
        w = whois.whois(data)
    except:
        WhoisScan()
    print(w)
    continuar = input("\n\033[1;32mDeseja outra consulta? (s/n):\033[1;m ")
    if continuar == "s":
        WhoisScan()
    elif continuar == "n":
        opcoes()

opcoes() 

