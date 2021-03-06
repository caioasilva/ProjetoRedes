# Stack TCP/IP + HTTP Básico em Python

Projeto para a disciplina de Redes de Computadores
CCO-130 / 21237 - DC/UFSCar


## Etapa Final
Integração de todas as camadas implementadas.

### Como usar
Primeiro, modifique as variáveis if_name, my_mac e src_ip no arquivo etapa5.py para corresponder aos valores de seu computador.

Depois, execute o seguinte comando para evitar que o Linux feche as conexoes TCP abertas por este programa:

    sudo iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP

Executar através do comando:

    sudo python3 etapa5.py
    
O servidor HTTP será iniciado na porta 8080.

Inicialmente foi utilizada uma imagem bastante pesada no plano de fundo da página web para testar o funcionamento da implementação. Porém, como o Autolab não suporta envios maiores que 1MB, o arquivo foi substituido por um menor. Entretanto, se for desejado realizar esse teste é necessário somente substituir o arquivo "image.jpg" na pasta "www" por um de maior resolução.

## Etapas anteriores

Para testar as etapas anteriores, recomendo utilizar a branch "etapa4", pois diversos arquivos foram modificados na integração final que devem impedir o funcionamento delas separadamente.

### Etapa 1
Implementação de uma camada de aplicação. 
Foi desenvolvido um servidor HTTP básico (somente GET), capaz de fornecer arquivos a partir de um diretório.

#### Como usar
Executar o script "etapa1.py"
O servidor HTTP sera iniciado na porta 8080

### Etapa 2
Implementar o protocolo TCP. Deverão ser implementados e exercitados (testar e comprovar que funcionam) os seguintes aspectos do protocolo TCP:
- Estabelecer conexão (handshake SYN, SYN+ACK, ACK) com número de sequência inicial aleatório.
- Transmitir e receber corretamente os segmentos.
- Retransmitir corretamente segmentos que forem perdidos ou corrompidos.
- Estimar o timeout para retransmissão de acordo com as recomendações do livro-texto (RFC 2988).
- Implementar a semântica para timeout e ACKs duplos de acordo com as recomendações do livro-texto.
- Tratar e informar corretamente o campo window size, implementando controle de fluxo.
- Realizar controle de congestionamento de acordo com as recomendações do livro-texto (RFC 5681).
- Fechar a conexão de forma limpa (lidando corretamente com a flag FIN).

#### Como usar
Antes de usar, execute o seguinte comando para evitar que o Linux feche
as conexoes TCP abertas por este programa:

    sudo iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP

Executar através do comando:

    sudo python3 etapa2.py
    
O servidor HTTP sera iniciado na porta 8080
È recomendada autilização do Wireshark para monitorar o tráfego de pacotes.

### Etapa 3
Implementação da camada de rede.
Foram exercitados os seguintes aspectos:
- Interpretação de cabeçalhos IP.
- Reconstrução de datagramas IP fragmentados.

#### Como usar
Executar através do comando:

    sudo python3 etapa3.py

Ele disparará pings para o endereço especificado em dest_addr e interpretará os pacotes recebidos, também reconstruindo-os.

### Etapa 4
Interpretação da Camada de Enlace

O código da Etapa 3 foi modificado e está sendo realizado o seguinte:

- Verificar se o endereço MAC de destino de cada quadro recebido é o MAC da sua placa de rede;
- Verificar se o protocolo encapsulado dentro do quadro recebido é o protocolo IP,
- Caso ambas as condições acima sejam satisfeitas, repassar o conteúdo encapsulado (datagrama IP) para uma função que lide com o processamento na camada de rede, por exemplo a função implementada na Etapa 3.

#### Como usar
Executar através do comando:

    sudo python3 etapa4.py