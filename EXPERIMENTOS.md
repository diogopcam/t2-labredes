# O que falta fazer

## Pré-requisitos

- Dois computadores em rede local (ou dois terminais no mesmo PC via 127.0.0.1)
- [Clumsy](https://jagt.github.io/clumsy/) instalado no Windows (para injetar latência/perda/reordenação)
- Wireshark instalado
- Arquivo de teste de ~1 MB (ex: `dd if=/dev/urandom of=test.bin bs=1M count=1`)

---

## Como rodar cada experimento

```bash
# Terminal 1 — Receiver
python3 srtp.py --listen --port 6000 --file out.bin --mode <saw|gbn|sr> --window <N>

# Terminal 2 — Sender
python3 srtp.py --host <IP_RECEIVER> --port 6000 --file test.bin --mode <saw|gbn|sr> --window <N>
```

O sender imprime ao final:
```
Transferência concluída em X.XX s
Throughput: XXXX.X kbps
Retransmissões: N
```

Anotar esses dois números para cada cenário. Salvar a captura Wireshark com o nome indicado.

---

## Tabela 1 — SAW sob latência

Configuração Clumsy: **Delay** (outbound, UDP porta 6000)

| Cenário | Clumsy | Captura | Throughput (kbps) | Retransmissões |
|---------|--------|---------|-------------------|----------------|
| L0 | sem Clumsy | saw_L0.pcapng | | |
| L1 | Delay = 50 ms | saw_L1.pcapng | | |
| L2 | Delay = 100 ms | saw_L2.pcapng | | |
| L3 | Delay = 150 ms | saw_L3.pcapng | | |

Anotar também o **RTT do cenário L0** via Wireshark (delta entre DATA e ACK) — necessário para calcular os valores teóricos da seção 2.1.

---

## Tabela 2 — SAW sob perda

Configuração Clumsy: **Drop** (outbound, UDP porta 6000)

| Cenário | Clumsy | Captura | Throughput (kbps) | Retransmissões |
|---------|--------|---------|-------------------|----------------|
| P0 | sem Clumsy | saw_P0.pcapng | | |
| P1 | Drop = 1% | saw_P1.pcapng | | |
| P2 | Drop = 5% | saw_P2.pcapng | | |
| P3 | Drop = 10% | saw_P3.pcapng | | |
| P4 | Drop = 25% | saw_P4.pcapng | | |

---

## Tabela 3 — Latência comparativa (SAW vs GBN vs SR, N=4)

Reaproveitar os valores de SAW da Tabela 1 (L0–L3).
Rodar GBN N=4 e SR N=4 com os mesmos cenários de latência.

| Cenário | Clumsy | GBN N=4 captura | GBN N=4 kbps | SR N=4 captura | SR N=4 kbps |
|---------|--------|-----------------|--------------|----------------|-------------|
| L0 | sem Clumsy | gbn_L0.pcapng | | sr_L0.pcapng | |
| L1 | Delay = 50 ms | gbn_L1.pcapng | | sr_L1.pcapng | |
| L2 | Delay = 100 ms | gbn_L2.pcapng | | sr_L2.pcapng | |
| L3 | Delay = 150 ms | gbn_L3.pcapng | | sr_L3.pcapng | |

---

## Tabela 4 — Perda comparativa (GBN vs SR, N=4 e N=16)

Configuração Clumsy: **Drop** (outbound, UDP porta 6000)

| Cenário | GBN N=4 kbps | GBN N=4 retx | GBN N=16 kbps | GBN N=16 retx | SR N=4 kbps | SR N=4 retx | SR N=16 kbps | SR N=16 retx |
|---------|--------------|--------------|---------------|---------------|-------------|-------------|--------------|--------------|
| P1 (1%) | | | | | | | | |
| P2 (5%) | | | | | | | | |
| P3 (10%) | | | | | | | | |
| P4 (25%) | | | | | | | | |

Capturas: `gbn_P1_N4.pcapng`, `gbn_P1_N16.pcapng`, `sr_P1_N4.pcapng`, `sr_P1_N16.pcapng`, etc.

---

## Tabela 5 — Reordenação comparativa (GBN vs SR, N=4 e N=16)

Configuração Clumsy: **Out of Order** (outbound, UDP porta 6000)

| Cenário | Clumsy | GBN N=4 kbps | GBN N=4 retx | GBN N=16 kbps | GBN N=16 retx | SR N=4 kbps | SR N=4 retx | SR N=16 kbps | SR N=16 retx |
|---------|--------|--------------|--------------|---------------|---------------|-------------|-------------|--------------|--------------|
| R0 | sem Clumsy | | | | | | | | |
| R1 | Reorder = 10% | | | | | | | | |
| R2 | Reorder = 25% | | | | | | | | |

Capturas: `gbn_R1_N4.pcapng`, `gbn_R2_N16.pcapng`, `sr_R1_N4.pcapng`, etc.

---

## Captura especial — CRC32

Rodar SAW com um pacote corrompido manualmente (ou usar Clumsy com
**Tamper** para corromper bytes do payload).

| Captura | O que mostrar |
|---------|---------------|
| saw_crc.pcapng | Gap de ~100 ms após pacote corrompido, sem ACK do receiver, seguido de retransmissão com o mesmo SEQ |

---

## Após os experimentos

1. Copiar os números para `relatorio.txt` (substituir os `[?]`)
2. Calcular os valores teóricos da seção 2.1 com o RTT medido do L0
3. Inserir os parágrafos de análise nos blocos `[INSERIR: ...]` restantes
4. Mover as capturas `.pcapng` para a pasta `capturas/`
5. Enviar `relatorio.txt` ao Gemini para formatação em Google Docs
6. Revisar e entregar via Moodle até **28/06/2026 às 23:59**

---

## Total de execuções

| Etapa | Execuções |
|-------|-----------|
| Tabela 1 (SAW latência) | 4 |
| Tabela 2 (SAW perda) | 5 |
| Tabela 3 (GBN+SR latência) | 8 |
| Tabela 4 (GBN+SR perda ×2 janelas) | 16 |
| Tabela 5 (GBN+SR reordenação ×2 janelas) | 12 |
| CRC32 | 1 |
| **Total** | **46** |

Com arquivo de teste de 1 MB cada execução leva ~30 segundos.
Tempo estimado para todos os experimentos: **~45 minutos**.
