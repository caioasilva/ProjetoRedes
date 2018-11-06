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

Tarefas:
OK  Estabelecer conexão (handshake SYN, SYN+ACK, ACK) com número de sequência inicial aleatório.
OK  Transmitir e receber corretamente os segmentos. (Transmissão OK)
OK  Retransmitir corretamente segmentos que forem perdidos ou corrompidos.
OK  Estimar o timeout para retransmissão de acordo com as recomendações do livro-texto (RFC 2988).
OK  Implementar a semântica para timeout e ACKs duplos de acordo com as recomendações do livro-texto.
OK  Tratar e informar corretamente o campo window size, implementando controle de fluxo.
OK  Realizar controle de congestionamento de acordo com as recomendações do livro-texto (RFC 5681).
OK  Fechar a conexão de forma limpa (lidando corretamente com a flag FIN).
'''

import asyncio
import socket
import struct
import os
import time
from app import HTTPServer

FLAGS_FIN = 1 << 0  # Fim de conexao
FLAGS_SYN = 1 << 1  # Sicronizacao
FLAGS_RST = 1 << 2  # Warning de socket não existente
FLAGS_ACK = 1 << 4  # ACK
FLAGS_SYNACK = FLAGS_ACK | FLAGS_SYN

# Configurações

PORT = 8080  # Porta utilizada
FILES_DIR = "www"  # Pasta do servidor HTTP

MSS = 16384  # Maximum Segment Size
TIMEOUT = 9 * 60  # segundos


class TCP_Socket:
    # Lista static de conexões abertas
    open_conns = {}

    # Construtor Conexão
    def __init__(self, fd, src_addr, src_port, dst_addr, dst_port, seq_no, ack_no, send_window_size=MSS):
        # Identificador da conexao
        self.id_conn = self.generate_id(src_addr, src_port, dst_addr, dst_port)

        # Informações da conexão
        self.src_addr = src_addr  # Endereço origem
        self.src_port = src_port  # Porta Origem
        self.dst_addr = dst_addr  # Endereço Destino
        self.dst_port = dst_port  # Porta Destino
        self.ack_no = ack_no  # Controle do envio de ack_no
        self.seq_no_base = seq_no  # Controle de recebimento de ack_no
        self.next_seq_no = seq_no  # Controle de envio de seq_no

        self.packet_time = {}  # Dicionario (seq_no, current time)
        self.packet_first_time = {}

        # Fila de envio
        self.send_queue = b""
        self.sent_bytes_not_ack = 0
        self.duplicate_count = 0

        # Timer
        self.packet_timers = {}

        # Flags
        self.flag_handshake = True
        self.flag_close_connection = False
        self.flag_fin_recv = False
        self.flag_fin_sent = False

        self.send_window_size = send_window_size
        self.recv_window_size = 1460
        if MSS > 2190:
            self.congestion_window = int(MSS * 2)
        elif MSS > 1095:
            self.congestion_window = int(MSS * 3)
        else:
            self.congestion_window = int(MSS * 4)

        self.ssthresh = 65536
        self.lasterror_congestion_window = self.ssthresh

        # RTT
        self.estimated_rtt = 1  # inicial 1 segundos
        self.dev_rtt = 0
        self.timeout_interval = 0

        # Raw Socket a ser utilizado na conexão (File descriptor)
        self.fd = fd

        # Colocando a nova conexão na lista static
        self.open_conns[self.id_conn] = self

        self.packet_time[self.next_seq_no] = time.time()

        # Print de informação de nova conexão
        print('/\\/\\ Nova Conexão: %s:%d -> %s:%d (seq=%d, ack=%d) /\\/\\'
              % (self.src_addr, self.src_port, self.dst_addr, self.dst_port, seq_no, ack_no))

    @staticmethod
    def generate_id(src_addr, src_port, dst_addr, dst_port):
        return str(src_addr) + str(src_port) + str(dst_addr) + str(dst_port)

    # Metodo chamado no loop principal para receber os dados do socket
    @staticmethod
    def raw_recv(fd):
        # Recebe um pacote do socket
        src_addr, dst_addr, segment = IPv4_TCP.handle_ipv4_header(fd.recv(12000))
        packet = IPv4_TCP(src_addr, dst_addr, segment)

        # Aceita somente a porta 7000
        if packet.dst_port != PORT:
            return

        # identificador da conexao
        id_conn = TCP_Socket.generate_id(packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)

        # Identificacao das flags
        # Conexao requerida e aceita
        if (packet.flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = TCP_Socket(fd, packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port,
                                 struct.unpack('I', os.urandom(4))[0], packet.seq_no + 1, packet.window_size)
            conexao.send_segment(conexao.make_tcp_packet(FLAGS_SYNACK))
            conexao.next_seq_no += 1

        elif id_conn in TCP_Socket.open_conns:
            conexao = TCP_Socket.open_conns[id_conn]

            if (packet.flags & FLAGS_FIN) == FLAGS_FIN:
                conexao.flag_fin_recv = True
                conexao.fin_recv(packet)

            if (packet.flags & FLAGS_ACK) == FLAGS_ACK:
                # Recebe e processa pacote ACK
                conexao.ack_recv(packet)

                if (len(packet.payload) != 0):
                    # Recebe payload e envia pacote com ack e sem dados
                    conexao.payload_recv(packet)
        else:
            print('INVALIDA: %s:%d -> %s:%d (pacote associado a conexao desconhecida)' %
                  (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port))

    # Enviando dados pelo raw socket
    def raw_send(self, payload):
        # Montando pacote
        segment = self.make_tcp_packet(FLAGS_ACK) + payload

        # Enviando
        self.send_segment(segment)
        # print(segment)
        self.next_seq_no = (self.next_seq_no + len(payload)) & 0xffffffff
        # Adiciona timer se nao tiver
        if self.next_seq_no not in self.packet_timers:
            self.packet_timers[self.next_seq_no] = asyncio.get_event_loop().call_later(self.timeout_interval,
                                                                                       self.resend,
                                                                                       self.next_seq_no, segment,
                                                                                       self.timeout_interval)
            print("++ Timer Criado", self.next_seq_no, 'Timeout:', self.timeout_interval)

        # Adicionando current time do seq_no enviado
        self.packet_time[self.next_seq_no] = time.time()
        self.packet_first_time[self.next_seq_no] = self.packet_time[self.next_seq_no]

    def close(self):
        # Flag que avisa intenção do app de fechar conexão
        print("\nXX Fechamento de conexão solicitada pela aplicação\n")
        self.flag_close_connection = True
        if self.send_queue == b'':
            print("Enviando FIN")
            timer_list = list(self.packet_timers.keys())
            for key in timer_list:
                self.packet_timers[key].cancel()
                del self.packet_timers[key]
                # del self.packet_first_time[key]

            # Enviando fechamento de conexão
            self.send_segment(self.make_tcp_packet(FLAGS_FIN))
            self.flag_fin_sent = True
            self.next_seq_no += 1

    def make_tcp_packet(self, flags):
        return struct.pack('!HHIIHHHH', self.dst_port, self.src_port, self.next_seq_no, self.ack_no,
                           (5 << 12) | flags, self.recv_window_size, 0, 0)

    def send_segment(self, segment):
        self.fd.sendto(IPv4_TCP(self.src_addr, self.dst_addr, segment).fix_checksum().packet,
                       (self.src_addr, self.src_port))

    def send(self, total_payload=b''):
        self.send_queue += total_payload

        window_size = self.transmission_window()
        send_now = self.send_queue[:window_size]
        self.send_queue = self.send_queue[window_size:]
        print("\nSend Window size:", self.send_window_size)
        print("Congestion Window size:", self.congestion_window)
        print("Transmission Window size:", window_size)
        print("ssthresh:", self.ssthresh)
        print("Last error size", self.lasterror_congestion_window, "\n")
        self.sent_bytes_not_ack = len(send_now)

        for i in range(0, len(send_now), MSS):
            payload = send_now[i:i + MSS]
            self.raw_send(payload)

    def resend(self, expected_ack, segment, last_time):
        if time.time() - self.packet_first_time[expected_ack] >= TIMEOUT:
            del self.packet_timers[expected_ack]
            del self.packet_first_time[expected_ack]
            print("xx TIMEOUT Pacote", expected_ack)
        else:
            print('\nrr Retransmission', expected_ack)
            self.ssthresh = max(self.transmission_window() / 2, MSS * 2)
            self.lasterror_congestion_window = self.congestion_window
            self.congestion_window = MSS
            print("rr ssthresh redefinido:", self.ssthresh, "Congestion window:", self.congestion_window)
            self.send_segment(segment)
            last_time = last_time * 2
            self.packet_timers[expected_ack] = asyncio.get_event_loop().call_later(last_time, self.resend,
                                                                                   expected_ack, segment, last_time)
            print("r++ Timer Retransmission", expected_ack, "Tempo:", last_time, "\n")

    def fin_recv(self, packet_tcp):
        if self.ack_no == packet_tcp.seq_no:
            # Se tiver recebido tudo certo até aqui, incrementa 1 para informar que é um ACK do FIN
            self.ack_no += 1
        print("FIN Recebido")
        if not self.flag_fin_sent:
            self.send_segment(self.make_tcp_packet(FLAGS_ACK | FLAGS_FIN))
            self.flag_fin_sent = True
            print("Enviando FIN, ACK")
        else:
            self.send_segment(self.make_tcp_packet(FLAGS_ACK))

    def transmission_window(self):
        return int(min(self.send_window_size, self.congestion_window))

    def calc_timeout(self, pack_time):
        # sampleRTT
        sample_rtt = time.time() - pack_time
        # print("sampleRTT: " + str(sample_rtt))

        # EstimatedRTT
        self.estimated_rtt = 0.875 * self.estimated_rtt + 0.0125 * sample_rtt
        # print("EstimatedRTT: " + str(self.estimated_rtt))

        # DevRTT
        self.dev_rtt = 0.75 * self.dev_rtt + 0.25 * abs(sample_rtt - self.estimated_rtt)
        # print("DevRTT: " + str(self.dev_rtt))

        # Timeout
        self.timeout_interval = self.estimated_rtt + 4 * self.dev_rtt
        print("i New Timeout: " + str(self.timeout_interval))

    # Trata recebimento do ack_no
    def ack_recv(self, packet_tcp):
        ack_no = packet_tcp.ack_no
        self.send_window_size = packet_tcp.window_size
        if self.flag_fin_recv:
            for timer in self.packet_timers:
                timer.cancel()
            self.packet_timers = {}
            print("------------------ Conexão encerrada -------------------------------\n")
            del self.open_conns[self.id_conn]

        elif ack_no > self.seq_no_base:

            if self.flag_handshake:
                self.seq_no_base = ack_no
                self.flag_handshake = False
                print("+++ Handshake\n")

                # atualiza timeout combase no rtt
                self.calc_timeout(self.packet_time[ack_no - 1])
                del self.packet_time[ack_no - 1]

            else:
                # Dados confirmados a serem removidos da noAck_
                print(">>>>>>> Recebido ack:", ack_no)
                qtd_dados = ack_no - self.seq_no_base
                print("Quant dados:", qtd_dados)
                self.sent_bytes_not_ack -= qtd_dados
                print("Quant dados faltando ACK: ", self.sent_bytes_not_ack)

                # ajusta janela
                self.send_window_size = self.ssthresh
                # slow start
                if self.congestion_window <= self.ssthresh and self.transmission_window() <= self.lasterror_congestion_window / 2:
                    # duplica a congestion window após o recebimento de todos os ack
                    self.congestion_window += min(self.sent_bytes_not_ack, MSS)
                # congestion avoidance
                else:
                    self.congestion_window += int(MSS * MSS / self.congestion_window)

                # Atualiza seq_no_base
                self.seq_no_base = ack_no

                # atualiza timeout combaseno rtt
                self.calc_timeout(self.packet_time[ack_no])

                del self.packet_time[ack_no]

                timer_list = list(self.packet_timers.keys())
                if ack_no in timer_list:
                    self.duplicate_count = 0
                    for key in timer_list:
                        if key <= ack_no:
                            self.packet_timers[key].cancel()
                            del self.packet_timers[key]
                            del self.packet_first_time[key]
                            print("-- Timer Pacote", key, "cancelado")
                else:
                    print("\nddd ACK DUPLICADO", ack_no)
                    # Fast Retransmit/Fast Recovery
                    self.duplicate_count += 1
                    if self.duplicate_count < 3:
                        self.congestion_window = self.send_window_size + int(MSS * 2)
                    elif self.duplicate_count == 3:
                        self.ssthresh = max(int(self.transmission_window() / 2), int(MSS * 2))
                        print("ssthresh redefinido", self.ssthresh, "\n")
                        self.send_window_size = self.ssthresh + int(MSS * 3)
                    else:
                        self.send_window_size += int(MSS * 1)
                    self.lasterror_congestion_window = self.congestion_window
                    # self.ssthresh = int(self.transmission_window()/2)
                print("")

                # Se todos os acks chegaram
                if len(self.packet_timers) == 0:
                    # Envia proxima janela
                    if self.send_queue != b'':
                        self.send()
                    # Se a flag de fechamento estiver definida, executa o envio de FIN
                    elif self.flag_close_connection:
                        print("Fim da fila de envio e retransmissoes. Enviando FIN")
                        # Enviando fechamento de conexão
                        self.send_segment(self.make_tcp_packet(FLAGS_FIN))
                        self.flag_fin_sent = True
                        self.next_seq_no += 1

    # Trata recebimento de payload
    def payload_recv(self, packet_tcp):
        if self.ack_no == packet_tcp.seq_no:
            self.ack_no += len(packet_tcp.payload)
            self.send_segment(self.make_tcp_packet(FLAGS_ACK))
            self.send(app.request(packet_tcp.payload))
            self.close()
        else:
            self.send_segment(self.make_tcp_packet(FLAGS_ACK))
            self.send_segment(self.make_tcp_packet(FLAGS_ACK))


class IPv4_TCP:

    def __init__(self, src_addr, dst_addr, segment):
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.segment = segment
        self.src_port, self.dst_port, self.seq_no, self.ack_no, self.flags, self.window_size, self.checksum, \
        self.urg_ptr = struct.unpack('!HHIIHHHH', segment[:20])
        self.payload = segment[4 * (self.flags >> 12):]

    @staticmethod
    def handle_ipv4_header(packet):
        version = packet[0] >> 4
        ihl = packet[0] & 0xf
        assert version == 4
        src_addr = IPv4_TCP.addr2str(packet[12:16])
        dst_addr = IPv4_TCP.addr2str(packet[16:20])
        segment = packet[4 * ihl:]
        return src_addr, dst_addr, segment

    @staticmethod
    def addr2str(addr):
        return '%d.%d.%d.%d' % tuple(int(x) for x in addr)

    @staticmethod
    def str2addr(addr):
        return bytes(int(x) for x in addr.split('.'))

    def fix_checksum(self):
        # Endereco de origem | Endereco de destino | formato, Identificador TCP, Tamanho do segmento
        pseudohdr = self.str2addr(self.src_addr) + self.str2addr(self.dst_addr) + struct.pack('!HH', 0x0006,
                                                                                              len(self.segment))
        seg = bytearray(self.segment)
        seg[16:18] = b'\x00\x00'
        seg[16:18] = struct.pack('!H', self.calc_checksum(pseudohdr + seg))
        self.packet = bytes(seg)
        return self

    @staticmethod
    def calc_checksum(segment):
        # se for ímpar, faz padding à direita
        if len(segment) % 2 == 1:
            segment += b'\x00'
        checksum = 0
        for i in range(0, len(segment), 2):
            x, = struct.unpack('!H', segment[i:i + 2])
            checksum += x
            while checksum > 0xffff:
                checksum = (checksum & 0xffff) + 1
        checksum = ~checksum
        return checksum & 0xffff


if __name__ == '__main__':
    # O app é a camada de aplicação que desenvolvemos na etapa 1
    app = HTTPServer(FILES_DIR)
    fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    print("Servidor rodando em: http://{}:{}\n".format("127.0.0.1", PORT))

    loop = asyncio.get_event_loop()
    loop.add_reader(fd, TCP_Socket.raw_recv, fd)
    loop.run_forever()
