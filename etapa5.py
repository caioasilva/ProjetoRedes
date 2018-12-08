#!/usr/bin/python3
# -*- encoding: utf-8 -*-
'''
Antes de usar, execute o seguinte comando para evitar que o Linux feche
as conexoes TCP abertas por este programa:

sudo iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP

# Projeto para a disciplina de Redes de Computadores
CCO-130 / 21237 - DC/UFSCar

- Caio Augusto Silva
- Luís Felipe Tomazini
- Mateus Barros
- Antonio Lopes

Etapa 5 - Integração
'''

from app import HTTPServer
from etapa2 import PORT, FILES_DIR
import etapa4
import socket
import asyncio

# Coloque aqui o nome da sua placa de rede
if_name = 'wlp2s0'

# Coloque abaixo o endereço IP do seu computador na sua rede local
etapa4.src_ip = '10.0.1.61'

# Coloque aqui o endereço MAC da sua placa de rede (ip link show dev wlan0)
etapa4.my_mac = '5c:c9:d3:63:27:3e'

if __name__ == '__main__':
    app = HTTPServer(FILES_DIR)
    fd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(etapa4.ETH_P_ALL))
    fd.bind((if_name, 0))
    print("Servidor rodando em: http://{}:{}\n".format(etapa4.src_ip, PORT))
    loop = asyncio.get_event_loop()
    loop.add_reader(fd, etapa4.raw_recv, fd, app)

    loop.run_forever()
