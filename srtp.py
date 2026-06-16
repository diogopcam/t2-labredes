#!/usr/bin/env python3
"""
SRTP - Simple Reliable Transport Protocol
Protocolo de transporte confiável sobre UDP: Stop-and-Wait, Go-Back-N, Selective Repeat.

Uso:
  Receiver: python3 srtp.py --listen --port 6000 --file saida.bin [--mode saw|gbn|sr] [--window N]
  Sender:   python3 srtp.py --host 192.168.1.10 --port 6000 --file entrada.bin [--mode saw|gbn|sr] [--window N]
"""

import argparse
import socket
import struct
import zlib
import select
import time
import sys
import os
import hashlib

# ── Constantes ────────────────────────────────────────────────────────────────
MAX_PAYLOAD  = 255
TIMEOUT      = 0.1      # 100 ms (fixo conforme especificação)
MAX_SEQ      = 16384    # 2^14 — espaço de sequência de 14 bits
HEADER_SIZE  = 9        # bytes
MAX_WINDOW   = 255
FIN_WAIT     = 5.0      # segundos para aguardar FIN após dados completos

# ── Cabeçalho (9 bytes) ───────────────────────────────────────────────────────
#
#  0                   1                   2
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 ...
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |S|F|         SEQ (14 bits)         |A|N|      ACK (14 bits)    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Length (8 bits)    |              CRC32 (32 bits)           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Byte 0 : S(1) F(1) SEQ[13:8](6)
# Byte 1 : SEQ[7:0]
# Byte 2 : A(1) N(1) ACK[13:8](6)
# Byte 3 : ACK[7:0]
# Byte 4 : Length
# Bytes 5-8 : CRC32 big-endian

def _pack_hdr(syn, fin, seq, ack_flag, nack, ack, length, crc=0):
    b0 = ((syn & 1) << 7) | ((fin & 1) << 6) | ((seq >> 8) & 0x3F)
    b1 = seq & 0xFF
    b2 = ((ack_flag & 1) << 7) | ((nack & 1) << 6) | ((ack >> 8) & 0x3F)
    b3 = ack & 0xFF
    b4 = length & 0xFF
    return bytes([b0, b1, b2, b3, b4]) + struct.pack('!I', crc & 0xFFFFFFFF)


def make_packet(syn=0, fin=0, seq=0, ack_flag=0, nack=0, ack=0, length=0, payload=b''):
    """Monta pacote completo com CRC32 calculado automaticamente."""
    hdr0 = _pack_hdr(syn, fin, seq, ack_flag, nack, ack, length, 0)
    crc  = zlib.crc32(hdr0 + payload) & 0xFFFFFFFF
    return _pack_hdr(syn, fin, seq, ack_flag, nack, ack, length, crc) + payload


def parse_packet(data):
    """
    Verifica CRC32 e retorna (header_dict, payload) ou None se corrompido.
    Pacotes com CRC inválido são descartados silenciosamente (sem NACK),
    pois nenhum campo — incluindo SEQ — é confiável.
    """
    if len(data) < HEADER_SIZE:
        return None
    b0, b1, b2, b3, b4 = data[0], data[1], data[2], data[3], data[4]
    crc_recv = struct.unpack('!I', data[5:9])[0]
    payload  = data[HEADER_SIZE:]
    h = dict(
        syn      = (b0 >> 7) & 1,
        fin      = (b0 >> 6) & 1,
        seq      = ((b0 & 0x3F) << 8) | b1,
        ack_flag = (b2 >> 7) & 1,
        nack     = (b2 >> 6) & 1,
        ack      = ((b2 & 0x3F) << 8) | b3,
        length   = b4,
        crc      = crc_recv,
    )
    hdr0 = _pack_hdr(h['syn'], h['fin'], h['seq'],
                     h['ack_flag'], h['nack'], h['ack'], h['length'], 0)
    if (zlib.crc32(hdr0 + payload) & 0xFFFFFFFF) != crc_recv:
        return None
    return h, payload


# ── Chunking ──────────────────────────────────────────────────────────────────

def chunk_data(data):
    """
    Divide dados em chunks de até 255 bytes.
    • Último chunk tem len < 255  →  sinaliza fim de stream (push).
    • Se len(data) é múltiplo exato de 255, adiciona chunk vazio (length=0)
      como sentinela de fim de stream.
    • Arquivo vazio: retorna [b''] (length=0).
    """
    if len(data) == 0:
        return [b'']
    chunks = [data[i:i + MAX_PAYLOAD] for i in range(0, len(data), MAX_PAYLOAD)]
    if len(chunks[-1]) == MAX_PAYLOAD:
        chunks.append(b'')
    return chunks


def recv_one(sock, timeout=30.0):
    """Aguarda um pacote válido. Retorna (h, payload, addr) ou (None, None, None) no timeout."""
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None, None, None
        ready, _, _ = select.select([sock], [], [], min(remaining, 1.0))
        if not ready:
            if time.time() >= deadline:
                return None, None, None
            continue
        try:
            raw, addr = sock.recvfrom(HEADER_SIZE + MAX_PAYLOAD)
        except OSError:
            return None, None, None
        r = parse_packet(raw)
        if r is None:
            continue   # CRC inválido: descarta silenciosamente
        return r[0], r[1], addr


# ── Handshake (three-way) ─────────────────────────────────────────────────────

def handshake_sender(sock, dest, my_window):
    """Envia SYN → aguarda SYN+ACK → envia ACK. Retorna janela efetiva."""
    syn_pkt = make_packet(syn=1, length=my_window)
    while True:
        sock.sendto(syn_pkt, dest)
        ready, _, _ = select.select([sock], [], [], TIMEOUT)
        if not ready:
            continue
        try:
            raw, _ = sock.recvfrom(HEADER_SIZE + MAX_PAYLOAD)
        except OSError:
            continue
        r = parse_packet(raw)
        if not r:
            continue
        h, _ = r
        if h['syn'] and h['ack_flag']:
            rcv_wnd = h['length'] if h['length'] > 0 else my_window
            eff     = min(my_window, rcv_wnd)
            sock.sendto(make_packet(ack_flag=1), dest)
            print(f"[INFO] Handshake completo — janela efetiva={eff}", file=sys.stderr)
            return eff


def handshake_receiver(sock, my_window):
    """Aguarda SYN → SYN+ACK → ACK. Retorna (sender_addr, janela efetiva)."""
    while True:
        h, _, addr = recv_one(sock, timeout=3600)
        if h is None:
            continue
        if not h['syn']:
            continue
        snd_wnd = h['length'] if h['length'] > 0 else my_window
        eff     = min(my_window, snd_wnd)
        sock.sendto(make_packet(syn=1, ack_flag=1, length=my_window), addr)
        # Aguarda ACK final (tolerante a perda: se não chegar, sender reenvia SYN)
        ready, _, _ = select.select([sock], [], [], TIMEOUT * 3)
        if ready:
            try:
                raw2, _ = sock.recvfrom(HEADER_SIZE + MAX_PAYLOAD)
            except OSError:
                raw2 = None
            if raw2:
                r2 = parse_packet(raw2)
                if r2 and r2[0]['ack_flag'] and not r2[0]['syn']:
                    print(f"[INFO] Conexão de {addr} — janela efetiva={eff}", file=sys.stderr)
                    return addr, eff
        # ACK perdido: sender reenviará SYN → continua o loop


# ── Encerramento (two-way) ────────────────────────────────────────────────────

def close_sender(sock, dest):
    """Envia FIN e aguarda FIN+ACK. Tolerante a falhas de rede."""
    fin_pkt = make_packet(fin=1)
    attempts = 0
    while attempts < 20:
        try:
            sock.sendto(fin_pkt, dest)
        except OSError:
            break
        ready, _, _ = select.select([sock], [], [], TIMEOUT)
        if not ready:
            attempts += 1
            continue
        try:
            raw, _ = sock.recvfrom(HEADER_SIZE)
        except OSError:
            attempts += 1
            continue
        r = parse_packet(raw)
        if r and r[0]['fin'] and r[0]['ack_flag']:
            return


def close_receiver(sock, addr):
    """Responde FIN+ACK."""
    try:
        sock.sendto(make_packet(fin=1, ack_flag=1), addr)
    except OSError:
        pass


# ── Stop-and-Wait ─────────────────────────────────────────────────────────────

def tx_saw(chunks, sock, dest):
    """
    Sender stop-and-wait.
    • Transmite um pacote por vez.
    • Aguarda ACK antes do próximo; retransmite após timeout de 100ms.
    Retorna (retransmissoes, tempo_total).
    """
    retx = 0
    t0   = time.time()
    for i, chunk in enumerate(chunks):
        seq = i % MAX_SEQ
        pkt = make_packet(seq=seq, length=len(chunk), payload=chunk)
        while True:
            try:
                sock.sendto(pkt, dest)
            except OSError:
                break
            ready, _, _ = select.select([sock], [], [], TIMEOUT)
            if not ready:
                retx += 1
                continue
            try:
                raw, _ = sock.recvfrom(HEADER_SIZE)
            except OSError:
                retx += 1
                continue
            r = parse_packet(raw)
            if not r:
                retx += 1
                continue
            h, _ = r
            if h['ack_flag'] and not h['nack'] and h['ack'] == seq:
                break
            retx += 1
    return retx, time.time() - t0


def rx_saw(sock, out_path, sender_addr):
    """
    Receiver stop-and-wait.
    Bufferiza dados em ordem e aguarda FIN do sender após último pacote.
    """
    expected  = 0
    buf       = bytearray()
    data_done = False

    while True:
        h, payload, addr = recv_one(sock, timeout=FIN_WAIT if data_done else 30.0)
        if h is None:
            if data_done:
                # FIN não chegou, mas dados foram recebidos — encerra assim mesmo
                _save(buf, out_path)
                return True
            print("[WARN] rx_saw: timeout aguardando dados", file=sys.stderr)
            return False

        if h['fin']:
            close_receiver(sock, addr)
            if not data_done:
                _save(buf, out_path)
            return True

        if data_done:
            # Stray packet após último dado: só ACK, ignora conteúdo
            continue

        if h['seq'] != expected:
            # Fora de ordem: descarta silenciosamente
            continue

        buf += payload
        try:
            sock.sendto(make_packet(ack_flag=1, ack=h['seq']), addr)
        except OSError:
            pass

        if h['length'] < MAX_PAYLOAD:
            data_done = True
            _save(buf, out_path)
            # Não retorna ainda: continua aguardando FIN
            continue

        expected = (expected + 1) % MAX_SEQ


# ── Go-Back-N ─────────────────────────────────────────────────────────────────

def tx_gbn(chunks, sock, dest, wnd):
    """
    Sender GBN.
    • Janela de até wnd pacotes em trânsito.
    • ACKs cumulativos: ACK(n) confirma todos os pacotes até n.
    • Timeout ou NACK: retransmite toda a janela a partir de base.
    Retorna (retransmissoes, tempo_total).
    """
    n            = len(chunks)
    base         = 0
    nxt          = 0
    retx         = 0
    timer_start  = None
    t0           = time.time()

    def _send(i):
        pkt = make_packet(seq=i % MAX_SEQ, length=len(chunks[i]), payload=chunks[i])
        try:
            sock.sendto(pkt, dest)
        except OSError:
            pass

    while base < n:
        # Envia novos pacotes dentro da janela
        while nxt < n and nxt < base + wnd:
            _send(nxt)
            if nxt == base:
                timer_start = time.time()
            nxt += 1

        # Tempo restante até o timeout do pacote mais antigo
        elapsed = (time.time() - timer_start) if timer_start else TIMEOUT
        wait    = max(0.0, TIMEOUT - elapsed)

        ready, _, _ = select.select([sock], [], [], wait)

        if ready:
            # Drena todos os ACKs disponíveis sem bloquear
            while True:
                r2, _, _ = select.select([sock], [], [], 0)
                if not r2:
                    break
                try:
                    raw, _ = sock.recvfrom(HEADER_SIZE)
                except OSError:
                    break
                r = parse_packet(raw)
                if not r:
                    continue
                h, _ = r
                if not h['ack_flag']:
                    continue

                if h['nack']:
                    # NACK recebido: retransmite janela inteira a partir de base
                    in_flight = min(nxt, base + wnd) - base
                    retx     += max(in_flight, 0)
                    nxt       = base
                    timer_start = None
                    break

                # ACK cumulativo: avança base
                ack_seq = h['ack']
                for i in range(base, min(base + wnd + 1, n)):
                    if i % MAX_SEQ == ack_seq:
                        base        = i + 1
                        timer_start = time.time() if base < n else None
                        break
        else:
            # Timeout: retransmite janela inteira
            in_flight = min(nxt, base + wnd) - base
            retx     += max(in_flight, 0)
            nxt       = base
            timer_start = None

    return retx, time.time() - t0


def rx_gbn(sock, out_path, wnd):
    """
    Receiver GBN.
    • Aceita apenas pacotes na ordem esperada.
    • Pacotes fora de ordem: descarta e envia NACK com SEQ esperado.
    • ACKs cumulativos.
    """
    expected  = 0
    buf       = bytearray()
    data_done = False

    while True:
        h, payload, addr = recv_one(sock, timeout=FIN_WAIT if data_done else 30.0)
        if h is None:
            if data_done:
                return True
            print("[WARN] rx_gbn: timeout aguardando dados", file=sys.stderr)
            return False

        if h['fin']:
            close_receiver(sock, addr)
            if not data_done:
                _save(buf, out_path)
            return True

        if data_done:
            continue

        if h['seq'] == expected:
            buf += payload
            try:
                sock.sendto(make_packet(ack_flag=1, ack=h['seq']), addr)
            except OSError:
                pass

            if h['length'] < MAX_PAYLOAD:
                data_done = True
                _save(buf, out_path)
                continue

            expected = (expected + 1) % MAX_SEQ
        else:
            # Fora de ordem: envia NACK com o SEQ esperado
            try:
                sock.sendto(make_packet(ack_flag=1, nack=1, ack=expected), addr)
            except OSError:
                pass


# ── Selective Repeat ───────────────────────────────────────────────────────────

def tx_sr(chunks, sock, dest, wnd):
    """
    Sender SR.
    • Janela de até wnd pacotes em trânsito.
    • ACKs individuais: ACK(n) confirma apenas o pacote n.
    • NACK: retransmite apenas o pacote faltante.
    • Timeout individual por pacote.
    Retorna (retransmissoes, tempo_total).
    """
    n         = len(chunks)
    base      = 0
    nxt       = 0
    acked     = [False] * n
    sent_time = {}          # índice absoluto → tempo do último envio
    retx      = 0
    t0        = time.time()

    def _send(i):
        pkt = make_packet(seq=i % MAX_SEQ, length=len(chunks[i]), payload=chunks[i])
        try:
            sock.sendto(pkt, dest)
        except OSError:
            pass
        sent_time[i] = time.time()

    while base < n:
        # Envia novos pacotes dentro da janela
        while nxt < n and nxt < base + wnd:
            if not acked[nxt]:
                _send(nxt)
            nxt += 1

        # Calcula espera = menor tempo até o próximo timeout individual
        now  = time.time()
        wait = TIMEOUT
        for i in range(base, min(base + wnd, n)):
            if not acked[i] and i in sent_time:
                rem  = TIMEOUT - (now - sent_time[i])
                wait = min(wait, max(0.0, rem))

        ready, _, _ = select.select([sock], [], [], wait)

        if ready:
            # Drena todos os ACKs disponíveis
            while True:
                r2, _, _ = select.select([sock], [], [], 0)
                if not r2:
                    break
                try:
                    raw, _ = sock.recvfrom(HEADER_SIZE)
                except OSError:
                    break
                r = parse_packet(raw)
                if not r:
                    continue
                h, _ = r
                if not h['ack_flag']:
                    continue

                if h['nack']:
                    # Retransmite o pacote específico solicitado
                    ns = h['ack']
                    for i in range(base, min(base + wnd, n)):
                        if i % MAX_SEQ == ns and not acked[i]:
                            _send(i)
                            retx += 1
                            break
                else:
                    # ACK individual
                    as_ = h['ack']
                    for i in range(base, min(base + wnd, n)):
                        if i % MAX_SEQ == as_ and not acked[i]:
                            acked[i] = True
                            sent_time.pop(i, None)
                            break
                    # Avança base
                    while base < n and acked[base]:
                        base += 1

        # Verifica timeouts individuais de cada pacote na janela
        now = time.time()
        for i in range(base, min(base + wnd, n)):
            if not acked[i] and i in sent_time:
                if now - sent_time[i] > TIMEOUT:
                    _send(i)
                    retx += 1

    return retx, time.time() - t0


def rx_sr(sock, out_path, wnd):
    """
    Receiver SR com bufferização de pacotes fora de ordem.
    • Aceita e bufferiza pacotes dentro da janela [recv_base, recv_base+wnd-1].
    • ACKs individuais para cada pacote aceito.
    • NACK para o pacote faltante quando detecta lacuna.
    • Entrega em ordem assim que a sequência está contínua.
    """
    recv_base = 0       # índice absoluto do próximo pacote esperado
    buf       = {}      # índice absoluto → (length, payload)
    assembled = bytearray()
    data_done = False

    while True:
        h, payload, addr = recv_one(sock, timeout=FIN_WAIT if data_done else 30.0)
        if h is None:
            if data_done:
                return True
            print("[WARN] rx_sr: timeout aguardando dados", file=sys.stderr)
            return False

        if h['fin']:
            close_receiver(sock, addr)
            if not data_done:
                _save(assembled, out_path)
            return True

        if data_done:
            # Após dados completos: só responde ACKs antigos para não travar o sender
            if h['ack_flag'] == 0:
                try:
                    sock.sendto(make_packet(ack_flag=1, ack=h['seq']), addr)
                except OSError:
                    pass
            continue

        seq      = h['seq']
        base_seq = recv_base % MAX_SEQ
        diff     = (seq - base_seq) % MAX_SEQ

        if diff < wnd:
            # Dentro da janela do receiver: aceita e bufferiza
            idx = recv_base + diff
            if idx not in buf:
                buf[idx] = (h['length'], bytes(payload))

            # ACK individual
            try:
                sock.sendto(make_packet(ack_flag=1, ack=seq), addr)
            except OSError:
                pass

            # Se há lacuna antes do pacote recebido, envia NACK para o base faltante
            if diff > 0 and recv_base not in buf:
                try:
                    sock.sendto(make_packet(ack_flag=1, nack=1, ack=base_seq), addr)
                except OSError:
                    pass

            # Entrega pacotes em ordem enquanto o base estiver disponível
            while recv_base in buf:
                ln, pld = buf.pop(recv_base)
                assembled += pld
                if ln < MAX_PAYLOAD:
                    data_done = True
                    _save(assembled, out_path)
                    # Não retorna: aguarda FIN
                    recv_base += 1
                    break
                recv_base += 1

        elif diff < MAX_SEQ // 2:
            # Pacote já entregue (fora da janela à esquerda): reenvia ACK
            try:
                sock.sendto(make_packet(ack_flag=1, ack=seq), addr)
            except OSError:
                pass
        # else: completamente fora da janela — descarta silenciosamente


# ── Utilitários ───────────────────────────────────────────────────────────────

def _save(data, path):
    with open(path, 'wb') as f:
        f.write(data)
    print(f"[INFO] Arquivo salvo: {path} ({len(data)} bytes)", file=sys.stderr)


def _md5(path):
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


# ── Ponto de entrada ──────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='SRTP — Simple Reliable Transport Protocol sobre UDP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  # Stop-and-Wait
  python3 srtp.py --listen --port 6000 --file recebido.bin --mode saw
  python3 srtp.py --host 192.168.1.10 --port 6000 --file enviar.bin --mode saw

  # Go-Back-N com janela 16
  python3 srtp.py --listen --port 6000 --file recebido.bin --mode gbn --window 16
  python3 srtp.py --host 192.168.1.10 --port 6000 --file enviar.bin --mode gbn --window 16

  # Selective Repeat com janela 4
  python3 srtp.py --listen --port 6000 --file recebido.bin --mode sr --window 4
  python3 srtp.py --host 192.168.1.10 --port 6000 --file enviar.bin --mode sr --window 4
        """
    )
    ap.add_argument('--listen', action='store_true',
                    help='Modo receiver (aguarda conexão na porta P)')
    ap.add_argument('--host',   default='127.0.0.1',
                    help='IP do receiver (usado apenas no modo sender)')
    ap.add_argument('--port',   type=int, required=True,
                    help='Porta base P (receiver escuta em P; sender usa P+1)')
    ap.add_argument('--file',   required=True,
                    help='Arquivo a enviar (sender) ou caminho para salvar (receiver)')
    ap.add_argument('--mode',   choices=['saw', 'gbn', 'sr'], default='saw',
                    help='Protocolo: saw (stop-and-wait) | gbn (Go-Back-N) | sr (Selective Repeat)')
    ap.add_argument('--window', type=int, default=4,
                    help='Tamanho de janela 1-255 (ignorado em saw, default=4)')
    args = ap.parse_args()

    wnd = max(1, min(MAX_WINDOW, args.window))
    if args.mode == 'saw':
        wnd = 1

    if args.listen:
        # ── RECEIVER ────────────────────────────────────────────────────────
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', args.port))
        print(f"[INFO] Aguardando conexão na porta {args.port} (modo={args.mode})",
              file=sys.stderr)

        sender_addr, eff_wnd = handshake_receiver(sock, wnd)

        t_start = time.time()
        if args.mode == 'saw':
            ok = rx_saw(sock, args.file, sender_addr)
        elif args.mode == 'gbn':
            ok = rx_gbn(sock, args.file, eff_wnd)
        else:
            ok = rx_sr(sock, args.file, eff_wnd)
        elapsed = time.time() - t_start

        sock.close()

        if ok and os.path.exists(args.file):
            size = os.path.getsize(args.file)
            tp   = size / elapsed if elapsed > 0 else 0
            print(f"[INFO] Throughput: {tp:.0f} B/s  ({tp * 8 / 1000:.1f} kbps)",
                  file=sys.stderr)
            print(f"[INFO] MD5: {_md5(args.file)}", file=sys.stderr)
        else:
            print("[ERRO] Transferência falhou", file=sys.stderr)
            sys.exit(1)

    else:
        # ── SENDER ──────────────────────────────────────────────────────────
        if not os.path.exists(args.file):
            print(f"[ERRO] Arquivo não encontrado: {args.file}", file=sys.stderr)
            sys.exit(1)

        with open(args.file, 'rb') as f:
            data = f.read()

        chunks = chunk_data(data)
        print(f"[INFO] {len(data)} bytes → {len(chunks)} pacotes"
              f" (modo={args.mode}, janela={wnd})", file=sys.stderr)
        print(f"[INFO] MD5 origem: {hashlib.md5(data).hexdigest()}", file=sys.stderr)

        # Sender liga na porta P+1; envia para (receiver_host, P); recebe ACKs em P+1
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', args.port + 1))

        dest = (args.host, args.port)
        print(f"[INFO] Conectando a {dest}...", file=sys.stderr)
        eff_wnd = handshake_sender(sock, dest, wnd)

        t_start = time.time()
        if args.mode == 'saw':
            retx, elapsed = tx_saw(chunks, sock, dest)
        elif args.mode == 'gbn':
            retx, elapsed = tx_gbn(chunks, sock, dest, eff_wnd)
        else:
            retx, elapsed = tx_sr(chunks, sock, dest, eff_wnd)

        close_sender(sock, dest)
        sock.close()

        total = time.time() - t_start
        tp    = len(data) / total if total > 0 else 0
        print(f"[INFO] Concluído em {total:.3f}s", file=sys.stderr)
        print(f"[INFO] Throughput: {tp:.0f} B/s  ({tp * 8 / 1000:.1f} kbps)",
              file=sys.stderr)
        print(f"[INFO] Retransmissões: {retx}", file=sys.stderr)


if __name__ == '__main__':
    main()
