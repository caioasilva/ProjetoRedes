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

## Etapa 3
Implementação da camada de rede.
Foram exercitados os seguintes aspectos:
- Interpretação de cabeçalhos IP.
- Reconstrução de datagramas IP fragmentados.

### Como usar
Executar através do comando:

    sudo python3 etapa3.py

Ele disparará pings para o endereço especificado em dest_addr e interpretará os pacotes recebidos, também reconstruindo-os.

## Etapa 4
Interpretação da Camada de Enlace

O código da Etapa 3 foi modificado e está sendo realizado o seguinte:

- Verificar se o endereço MAC de destino de cada quadro recebido é o MAC da sua placa de rede;
- Verificar se o protocolo encapsulado dentro do quadro recebido é o protocolo IP,
- Caso ambas as condições acima sejam satisfeitas, repassar o conteúdo encapsulado (datagrama IP) para uma função que lide com o processamento na camada de rede, por exemplo a função implementada na Etapa 3.

### Como usar
Executar através do comando:

    sudo python3 etapa4.py

## Etapa 5
Integração. Todas as etapas etapas foram interligadas.

### Como usar
Antes de usar, execute o seguinte comando para evitar que o Linux feche
as conexoes TCP abertas por este programa:

    sudo iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP

Executar através do comando:

    sudo python3 etapa5.py
    
O servidor HTTP será iniciado na porta 8080
