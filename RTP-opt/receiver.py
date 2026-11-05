import sys
import socket
import struct
import zlib

START = 0
END = 1
DATA = 2
ACK = 3
HEADER_SIZE = 16

def verify_packet(packet):
    if len(packet) < HEADER_SIZE: return False, None, None, None, None
    header, data = packet[:HEADER_SIZE], packet[HEADER_SIZE:]
    pkt_type, seq_num, length, checksum_received = struct.unpack('!IIII', header)
    checksum_calculated = zlib.crc32(struct.pack('!III', pkt_type, seq_num, length) + data) & 0xffffffff
    if checksum_calculated != checksum_received: return False, None, None, None, None
    return True, pkt_type, seq_num, length, data

def create_ack(ack_seq):
    return struct.pack('!IIII', ACK, ack_seq, 0, zlib.crc32(struct.pack('!III', ACK, ack_seq, 0)) & 0xffffffff)

def main():
    if len(sys.argv) != 4: sys.exit(1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((sys.argv[1], int(sys.argv[2])))
    window_size = int(sys.argv[3])
    
    expected_seq, buffer, started = 1, {}, False
    while True:
        packet, addr = sock.recvfrom(2048)
        is_valid, pkt_type, seq_num, length, data = verify_packet(packet)
        if not is_valid: continue

        if pkt_type == START:
            started = True
            sock.sendto(create_ack(1), addr)
        elif pkt_type == DATA and started:
            if seq_num < expected_seq + window_size and seq_num >= expected_seq:
                buffer[seq_num] = data
                sock.sendto(create_ack(seq_num), addr) 
            while expected_seq in buffer:
                sys.stdout.buffer.write(buffer[expected_seq])
                sys.stdout.flush()
                del buffer[expected_seq]
                expected_seq += 1
        elif pkt_type == END and started:
            sock.sendto(create_ack(seq_num + 1), addr)
            break
    sock.close()

if __name__ == "__main__":
    main()
