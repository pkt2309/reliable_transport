import sys
import socket
import select
import time
import struct
import zlib

START = 0
END = 1
DATA = 2
ACK = 3
MAX_PACKET_SIZE = 1472
HEADER_SIZE = 16
CHUNK_SIZE = MAX_PACKET_SIZE - HEADER_SIZE
TIMEOUT = 0.5 

def create_packet(pkt_type, seq_num, data=b''):
    length = len(data)
    header_no_checksum = struct.pack('!III', pkt_type, seq_num, length)
    checksum = zlib.crc32(header_no_checksum + data) & 0xffffffff
    return struct.pack('!IIII', pkt_type, seq_num, length, checksum) + data

def extract_ack(packet):
    if len(packet) < HEADER_SIZE: return None, None
    pkt_type, seq_num, length, checksum = struct.unpack('!IIII', packet[:HEADER_SIZE])
    return pkt_type, seq_num

def main():
    if len(sys.argv) != 4: sys.exit(1)
    dest = (sys.argv[1], int(sys.argv[2]))
    window_size = int(sys.argv[3])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    message = sys.stdin.buffer.read()
    chunks = [message[i:i + CHUNK_SIZE] for i in range(0, len(message), CHUNK_SIZE)] or [b'']
    total_packets = len(chunks)

    sock.sendto(create_packet(START, 0), dest)
    while True:
        if select.select([sock], [], [], TIMEOUT)[0]:
            ack_data, _ = sock.recvfrom(2048)
            if extract_ack(ack_data) == (ACK, 1): break 
        else: sock.sendto(create_packet(START, 0), dest)

    base, next_seq, acked_packets = 1, 1, set()
    while base <= total_packets:
        while next_seq < base + window_size and next_seq <= total_packets:
            if next_seq not in acked_packets:
                sock.sendto(create_packet(DATA, next_seq, chunks[next_seq - 1]), dest)
            next_seq += 1

        if select.select([sock], [], [], TIMEOUT)[0]:
            ack_type, ack_seq = extract_ack(sock.recvfrom(2048)[0])
            if ack_type == ACK:
                acked_packets.add(ack_seq)
                while base in acked_packets:
                    acked_packets.remove(base)
                    base += 1
        else:
            for seq in range(base, next_seq):
                if seq not in acked_packets:
                    sock.sendto(create_packet(DATA, seq, chunks[seq - 1]), dest)

    end_seq = total_packets + 1
    sock.sendto(create_packet(END, end_seq), dest)
    start_time = time.time()
    while time.time() - start_time < TIMEOUT:
        if select.select([sock], [], [], TIMEOUT - (time.time() - start_time))[0]:
            if extract_ack(sock.recvfrom(2048)[0]) == (ACK, end_seq + 1): break
        else: break
    sock.close()

if __name__ == "__main__":
    main()
