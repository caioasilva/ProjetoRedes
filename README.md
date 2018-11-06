# Projeto para a disciplina de Redes de Computadores
CCO-130 / 21237 - DC/UFSCar

- Caio Augusto Silva
- Luís Felipe Tomazini
- Mateus Barros
- Antonio Lopes

## Etapa 1
Implementação de uma camada de aplicação. 
Foi desenvolvido um servidor HTTP básico (somente GET), capaz de fornecer arquivos a partir de um diretório.

### Como usar
Executar o script "etapa1.py"
O servidor HTTP sera iniciado na porta 8080

## Etapa 2
Implementar o protocolo TCP. Deverão ser implementados e exercitados (testar e comprovar que funcionam) os seguintes aspectos do protocolo TCP:
- Estabelecer conexão (handshake SYN, SYN+ACK, ACK) com número de sequência inicial aleatório.
- Transmitir e receber corretamente os segmentos.
- Retransmitir corretamente segmentos que forem perdidos ou corrompidos.
- Estimar o timeout para retransmissão de acordo com as recomendações do livro-texto (RFC 2988).
- Implementar a semântica para timeout e ACKs duplos de acordo com as recomendações do livro-texto.
- Tratar e informar corretamente o campo window size, implementando controle de fluxo.
- Realizar controle de congestionamento de acordo com as recomendações do livro-texto (RFC 5681).
- Fechar a conexão de forma limpa (lidando corretamente com a flag FIN).

### Como usar
Antes de usar, execute o seguinte comando para evitar que o Linux feche
as conexoes TCP abertas por este programa:

    sudo iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP

Executar através do comando:

    sudo python3 etapa2.py
    
O servidor HTTP sera iniciado na porta 8080
È recomendada autilização do Wireshark para monitorar o tráfego de pacotes.
