#!/usr/bin/python3
#
# Antes de usar, execute o seguinte comando para evitar que o Linux feche
# as conexoes TCP abertas por este programa:
#
# sudo iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP
#
import asyncio
import socket
import struct
import os
import time
from app import HTTPServer

'''
Tarefas:
OK  Estabelecer conexão (handshake SYN, SYN+ACK, ACK) com número de sequência inicial aleatório.
OK? Transmitir e receber corretamente os segmentos. 
    (A transmissão de arquivos grandes ta beleza. O recebimento não foi testado e provavelmente falhará para esse caso)
OK  Retransmitir corretamente segmentos que forem perdidos ou corrompidos.
OK  Estimar o timeout para retransmissão de acordo com as recomendações do livro-texto (RFC 2988).
?   Implementar a semântica para timeout e ACKs duplos de acordo com as recomendações do livro-texto.
?   Tratar e informar corretamente o campo window size, implementando controle de fluxo.
?   Realizar controle de congestionamento de acordo com as recomendações do livro-texto (RFC 5681).
OK? Fechar a conexão de forma limpa (lidando corretamente com a flag FIN).
    Acho que nao ta certo
'''

FLAGS_FIN = 1 << 0  # Fim de conexao
FLAGS_SYN = 1 << 1  # Sicronizacao
FLAGS_RST = 1 << 2  # Warning de socket não existente
FLAGS_ACK = 1 << 4  # ACK
FLAGS_SYNACK = FLAGS_ACK | FLAGS_SYN

# Configurações

PORT = 8080  # Porta utilizada
FILES_DIR = "www"  # Pasta do servidor HTTP

# MSS = 1460  # Maximum Segment Size
MSS = 65483  # Maximum Segment Size

class TCP_Socket:
    # Lista static de conexões abertas
    open_conns = {}

    # Construtor Conexão
    def __init__(self, fd, src_addr, src_port, dst_addr, dst_port, seq_no, ack_no):
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

        # Fila de envio
        self.send_queue = b""

        # Timer
        self.packet_timers = {}

        # Flags
        self.flag_handshake = True
        self.flag_close_conection = False
        self.flag_fin = False

        # Windows size (em desenvolvimento)
        self.send_window_size = MSS
        self.recv_window_size = 1024

        # RTT
        self.estimated_rtt = 0
        self.dev_rtt = 0
        self.timeout_interval = 2  # inicial 2 segundos

        # Raw Socket a ser utilizado na conexão (File descriptor)
        self.fd = fd

        # Colocando a nova conexão na lista static
        self.open_conns[self.id_conn] = self

        # Print de informação de nova conexão
        print('/\\/\\ Nova Conexão: %s:%d -> %s:%d (seq=%d, ack=%d) /\\/\\'
              % (self.src_addr, self.src_port, self.dst_addr, self.dst_port, seq_no, ack_no))

    @staticmethod
    def generate_id(src_addr, src_port, dst_addr, dst_port):
        return str(src_addr)+str(src_port)+str(dst_addr)+str(dst_port)

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
                                 struct.unpack('I', os.urandom(4))[0], packet.seq_no + 1)
            conexao.packet_time[conexao.next_seq_no] = time.time()
            conexao.send_window_size = packet.window_size
            conexao.send_segment(conexao.make_tcp_packet(FLAGS_SYNACK))
            conexao.next_seq_no += 1

        elif id_conn in TCP_Socket.open_conns:
            conexao = TCP_Socket.open_conns[id_conn]

            if (packet.flags & FLAGS_FIN) == FLAGS_FIN:
                conexao.flag_fin = True
                conexao.fin_recv(packet)

            if (packet.flags & FLAGS_ACK) == FLAGS_ACK:
                # Recebe ack e tirar da fila de nao confirmados
                conexao.ack_recv(packet)

            if (len(packet.payload) != 0):
                # Recebe payload e envia pacote com ack e sem dados
                conexao.payload_recv(packet)
        else:
            print('INVALIDA: %s:%d -> %s:%d (pacote associado a conexao desconhecida)' %
                  (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port))


    # Enviando dados pelo raw socket
    def send_raw(self, payload):

        # Montando pacote
        segment = self.make_tcp_packet(FLAGS_ACK) + payload

        # Enviando
        self.send_segment(segment)
        # print(segment)
        expected_ack = self.next_seq_no + len(payload)
        # Adiciona timer se nao tiver
        if expected_ack not in self.packet_timers:
            self.packet_timers[expected_ack] = asyncio.get_event_loop().call_later(self.timeout_interval, self.resend,
                                                                                   expected_ack, segment)
            print("++ Timer Criado", expected_ack, 'Timeout:', self.timeout_interval)

        # Adicionando current time do seq_no enviado
        self.packet_time[self.next_seq_no] = time.time()

        # Atualizando sequence number
        self.next_seq_no = (self.next_seq_no + len(payload)) & 0xffffffff


    def close(self):
        # Flag que avisa intenção do app de fechar conexão
        print("\nXX Fechamento de conexão solicitada pela aplicação\n")
        self.flag_close_conection = True

    def make_tcp_packet(self, flags):
        return struct.pack('!HHIIHHHH', self.dst_port, self.src_port, self.next_seq_no, self.ack_no,
                           (5 << 12) | flags, self.recv_window_size, 0, 0)

    def send_segment(self, segment):
        self.fd.sendto(IPv4_TCP(self.src_addr, self.dst_addr, segment).fix_checksum().packet,
                       (self.src_addr, self.src_port))

    def send(self, total_payload = b''):
        self.send_queue += total_payload

        send_now = self.send_queue[:self.send_window_size]
        self.send_queue = self.send_queue[self.send_window_size:]

        for i in range(0, len(send_now), MSS):
            payload = send_now[i:i + MSS]
            self.send_raw(payload)

    def resend(self, expected_ack, segment):
        print('Retransmission')
        self.send_segment(segment)
        self.packet_timers[expected_ack] = asyncio.get_event_loop().call_later(self.timeout_interval, self.resend,
                                                                               expected_ack, segment)
        print("Timer resend criado", expected_ack)


    def fin_recv(self, packet_tcp):
        if self.ack_no == packet_tcp.seq_no:
            # Se tiver recebido tudo certo até aqui, incrementa 1 para informar que é um ACK do FIN
            self.ack_no += 1
        # Senão, o valor de ack_no terá sido mantido, fazendo com que a outra ponta saiba onde paramos de receber dados
        self.send_segment(self.make_tcp_packet(FLAGS_ACK))


    # Trata recebimento do ack_no
    def ack_recv(self, packet_tcp):
        ack_no = packet_tcp.ack_no
        self.send_window_size = packet_tcp.window_size
        if ack_no > self.seq_no_base:
            # Handshake, nenhum dado presente nas filas
            # Duvidas... o que fzr

            if self.flag_handshake:
                self.seq_no_base = ack_no
                self.flag_handshake = False
                print("Conexao estabelecida...\n")

                # inicializando variaveis de controle de tempo
                # sampleRTT
                sample_rtt = time.time() - self.packet_time[ack_no - 1]
                print("sampleRTT Inicial: " + str(sample_rtt))

                # EstimatedRTT
                self.estimated_rtt = sample_rtt
                print("EstimatedRTT  Inicial: " + str(self.estimated_rtt))

                # DevRTT
                self.dev_rtt = sample_rtt / 2
                print("DevRTT  Inicial: " + str(self.dev_rtt))
            # Flag de finalizar conexão ativa
            elif self.flag_fin and len(self.packet_timers)==0:
                self.seq_no_base = ack_no
                self.open_conns.pop(self.id_conn)
                print("------------------ Conexão encerrada -------------------------------\n")
            else:
                # Dados confirmados a serem removidos da noAck_
                print(">>>>>>> Recebido ack:", ack_no)
                qtd_dados_reconhecidos = ack_no - self.seq_no_base
                print("Quant dados:", qtd_dados_reconhecidos)
                # Atualiza seq_no_base
                self.seq_no_base = ack_no

                # sampleRTT
                if ack_no - qtd_dados_reconhecidos in self.packet_time:
                    sample_rtt = time.time() - self.packet_time[ack_no - qtd_dados_reconhecidos]
                    print("sampleRTT: " + str(sample_rtt))
                else:
                    sample_rtt = self.estimated_rtt
                    print("problema de key")

                # EstimatedRTT
                self.estimated_rtt = 0.875 * self.estimated_rtt + 0.0125 * sample_rtt
                print("EstimatedRTT: " + str(self.estimated_rtt))

                # DevRTT
                self.dev_rtt = 0.75 * self.dev_rtt + 0.25 * abs(sample_rtt - self.estimated_rtt)
                print("DevRTT: " + str(self.dev_rtt))

                # Timeout
                self.timeout_interval = self.estimated_rtt + 4 * self.dev_rtt
                print("Timeout: " + str(self.timeout_interval))
                for key in list(self.packet_timers.keys()):
                    if key <= ack_no:
                        self.packet_timers[key].cancel()
                        del self.packet_timers[key]
                        print("-- Timer Pacote", key, "cancelado")
                print("")

                # Se todos os acks chegaram
                if len(self.packet_timers) == 0:
                    # Envia proxima janela
                    if self.send_queue != b'':
                        self.send()
                    else:
                        # Se a flag de fechamento estiver definida, executa o envio de FIN
                        if self.flag_close_conection:
                            print("______ Fim da fila de envio e retrasmissoes. Envio de FIN")
                            # Enviando fechamento de conexão
                            self.send_segment(self.make_tcp_packet(FLAGS_FIN))
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
        pseudohdr = self.str2addr(self.src_addr) + self.str2addr(self.dst_addr) + struct.pack('!HH', 0x0006, len(self.segment))
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
