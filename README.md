# SRTP — Simple Reliable Transport Protocol

Implementação do protocolo SRTP sobre UDP para a disciplina de Laboratório de Redes de Computadores (PUCRS).  
Suporta três variantes: **Stop-and-Wait (SAW)**, **Go-Back-N (GBN)** e **Selective Repeat (SR)**.

---

## Requisitos

- Python 3.8 ou superior
- Sem dependências externas (apenas biblioteca padrão)

---

## Compilação / Execução

Não é necessária compilação. Execute diretamente com Python 3:

```bash
python3 srtp.py [opções]
```

---

## Argumentos de linha de comando

| Argumento   | Obrigatório | Descrição |
|-------------|-------------|-----------|
| `--port P`  | Sim | Porta base P. Receiver escuta em P; Sender usa P+1 para ACKs |
| `--file`    | Sim | Arquivo a enviar (sender) ou caminho para salvar (receiver) |
| `--listen`  | No receiver | Ativa modo receiver |
| `--host`    | No sender | IP do receiver (default: `127.0.0.1`) |
| `--mode`    | Não | `saw` \| `gbn` \| `sr` (default: `saw`) |
| `--window`  | Não | Tamanho de janela 1–255 (ignorado em SAW; default: `4`) |

---

## Exemplos de uso

### Stop-and-Wait

```bash
# Terminal 1 — Receiver
python3 srtp.py --listen --port 6000 --file recebido.bin --mode saw

# Terminal 2 — Sender
python3 srtp.py --host 192.168.1.10 --port 6000 --file enviar.bin --mode saw
```

### Go-Back-N com janela 16

```bash
python3 srtp.py --listen --port 6000 --file recebido.bin --mode gbn --window 16
python3 srtp.py --host 192.168.1.10 --port 6000 --file enviar.bin --mode gbn --window 16
```

### Selective Repeat com janela 4

```bash
python3 srtp.py --listen --port 6000 --file recebido.bin --mode sr --window 4
python3 srtp.py --host 192.168.1.10 --port 6000 --file enviar.bin --mode sr --window 4
```

---

## Modelo de portas

- O receiver **escuta na porta P**.
- O sender **liga na porta P+1** e envia pacotes para (receiver\_host, P).  
  ACKs e NACKs retornam do receiver para o sender na porta P+1.

---

## Formato do cabeçalho (9 bytes)

```
 0                   1                   2
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|S|F|         SEQ (14 bits)         |A|N|      ACK (14 bits)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Length (8 bits)    |              CRC32 (32 bits)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Campo    | Bits | Descrição |
|----------|------|-----------|
| SYN (S)  | 1    | Flag de estabelecimento de conexão |
| FIN (F)  | 1    | Flag de encerramento de conexão |
| SEQ      | 14   | Número de sequência (em pacotes; wrap em 16384) |
| ACK flag (A) | 1 | Indica que o campo ACK é válido |
| NACK (N) | 1    | Negative acknowledgement |
| ACK      | 14   | Número de acknowledgement |
| Length   | 8    | Tamanho do payload; durante handshake = janela proposta |
| CRC32    | 32   | Checksum sobre cabeçalho (CRC=0) + payload |

---

## Semântica do campo Length

| Valor    | Significado |
|----------|-------------|
| `255`    | Pacote intermediário; receiver bufferiza |
| `< 255`  | Último pacote do stream; receiver entrega o buffer completo |
| `0`      | Fim de stream sem payload (arquivo múltiplo exato de 255 bytes) |
| (handshake) | Tamanho de janela proposto |

---

## Comportamento dos modos

### Stop-and-Wait (SAW)
- Janela efetiva = 1 pacote
- Retransmite após timeout de 100 ms
- Pacotes com CRC inválido ou fora de ordem são descartados silenciosamente

### Go-Back-N (GBN)
- Janela de até N pacotes em trânsito
- ACKs cumulativos: `ACK(n)` confirma todos os pacotes até `n`
- Timeout ou NACK → retransmite toda a janela a partir do base
- Receiver descarta pacotes fora de ordem e envia `NACK(seq_esperado)`

### Selective Repeat (SR)
- Janela de até N pacotes em trânsito
- ACKs individuais: `ACK(n)` confirma apenas o pacote `n`
- Timeout individual por pacote → retransmite apenas o pacote vencido
- NACK → retransmite apenas o pacote solicitado
- Receiver bufferiza pacotes fora de ordem dentro da janela

---

## Verificação de integridade

O sender e o receiver exibem o MD5 do arquivo. Verifique manualmente:

```bash
md5sum arquivo_enviado.bin arquivo_recebido.bin
```

---

## Estrutura dos arquivos entregues

```
t2-labredes/
├── srtp.py          # Implementação completa (SAW + GBN + SR)
├── README.md        # Este arquivo
└── capturas/        # Capturas Wireshark (.pcapng) por cenário
    ├── saw_L0.pcapng
    ├── saw_L1.pcapng
    ...
```
