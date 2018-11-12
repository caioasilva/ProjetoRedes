import socket
import asyncio
import struct

ETH_P_IP = 0x0800

# Coloque aqui o endereço de destino para onde você quer mandar o ping
dest_addr = '127.0.0.1'


class IP:

    # static dictionary
    received_packets = {}

    def __init__(self, packet):
        version_and_len, self.service_type, self.total_lenght, self.id, \
        flags_and_fragemnted, self.time_to_live, self.protocol, \
        self.header_checksum, self.src_ip, self.dest_ip \
            = struct.unpack('!BBHHHBBHII', packet[:20])

        self.version = (version_and_len & (0b11110000)) >> 4
        self.header_length = (version_and_len & 0b00001111) * 4  # header size em bytes
        self.options = packet[20:self.header_length]

        self.flags = (flags_and_fragemnted & 0b1110000000000000) >> 13
        self.fragmented_offset = int(flags_and_fragemnted & 0b1111111111111)
        self.this_payload = bytes(packet[self.header_length:])
        self.more_packets = self.flags & 0b001
        self.received_all = False

        if not self.id in IP.received_packets:
            IP.received_packets[self.id] = {'payload': b'', 'received_size': 0, 'received_frags': []}

        if self.fragmented_offset not in IP.received_packets[self.id]['received_frags']:
            old_payload = IP.received_packets[self.id]['payload']
            if len(old_payload) < self.fragmented_offset:
                old_payload = old_payload + b'\0' * self.fragmented_offset-len(old_payload)

            IP.received_packets[self.id]['payload'] = old_payload[:self.fragmented_offset] + self.this_payload + \
                                                      old_payload[self.fragmented_offset+len(self.this_payload):]
            IP.received_packets[self.id]['received_size'] += len(self.this_payload)
            IP.received_packets[self.id]['received_frags'].append(self.fragmented_offset)
        else:
            print("Erro fragmento ja recebido", self.fragmented_offset)

        if not self.more_packets:
            self.received_all = True
            self.payload = IP.received_packets[self.id]['payload']
            IP.received_packets[self.id]['received_all'] = True

    @staticmethod
    def addr2str(ip):
        return ".".join(map(lambda n: str(ip >> n & 0xFF), [24, 16, 8, 0]))


def send_ping(send_fd):
    print('enviando ping')
    # Exemplo de pacote ping (ICMP echo request) com payload grande
    msg = bytearray(b"\x08\x00\x00\x00" + 5000 * b"\xba\xdc\x0f\xfe")
    msg[2:4] = struct.pack('!H', calc_checksum(msg))
    send_fd.sendto(msg, (dest_addr, 0))

    asyncio.get_event_loop().call_later(1, send_ping, send_fd)


def raw_recv(recv_fd):
    packet = recv_fd.recv(12000)
    # print('recebido pacote de %d bytes' % len(packet))
    ip_packet = IP(packet)
    # print(IP.addr2str(ip_packet.src_ip))
    # if IP.addr2str(ip_packet.src_ip) == "10.0.1.45":
    print("\nID do pacote:", ip_packet.id)
    print("Pacote recebido de", ip_packet.src_ip)
    print("Destino", ip_packet.dest_ip)
    print("Tamanho do pacote", ip_packet.total_lenght)
    print("Offset Frag", ip_packet.fragmented_offset)
    print("Tamanho do Header", ip_packet.header_length)
    print("Flag More Packets", ip_packet.more_packets, "\n")

    if ip_packet.received_all:
        print("Payload:")
        print("Tamanho:", len(ip_packet.payload), "bytes")
        print("Bytes:")
        string = ""
        for byte in ip_packet.payload:
            string += str(format(byte, "#04x")) + " "
        print(string)

def calc_checksum(segment):
    if len(segment) % 2 == 1:
        # se for ímpar, faz padding à direita
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
    # Ver http://man7.org/linux/man-pages/man7/raw.7.html
    send_fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # Para receber existem duas abordagens. A primeira é a da etapa anterior
    # do trabalho, de colocar socket.IPPROTO_TCP, socket.IPPROTO_UDP ou
    # socket.IPPROTO_ICMP. Assim ele filtra só datagramas IP que contenham um
    # segmento TCP, UDP ou mensagem ICMP, respectivamente, e permite que esses
    # datagramas sejam recebidos. No entanto, essa abordagem faz com que o
    # próprio sistema operacional realize boa parte do trabalho da camada IP,
    # como remontar datagramas fragmentados. Para que essa questão fique a
    # cargo do nosso programa, é necessário uma outra abordagem: usar um socket
    # de camada de enlace, porém pedir para que as informações de camada de
    # enlace não sejam apresentadas a nós, como abaixo. Esse socket também
    # poderia ser usado para enviar pacotes, mas somente se eles forem quadros,
    # ou seja, se incluírem cabeçalhos da camada de enlace.
    # Ver http://man7.org/linux/man-pages/man7/packet.7.html
    recv_fd = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP))

    loop = asyncio.get_event_loop()
    loop.add_reader(recv_fd, raw_recv, recv_fd)
    # asyncio.get_event_loop().call_later(1, send_ping, send_fd)
    loop.run_forever()
