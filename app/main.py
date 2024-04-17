import json
import sys
import bencodepy
import hashlib
import requests 
import binascii
import socket

CHOKE_ID = 0
UNCHOKE_ID = 1
INTERESTED_ID = 2
NOT_INTERESTED_ID = 3
HAVE_ID = 4
BITFIELD_ID = 5
REQUEST_ID = 6
PIECE_ID = 7
CANCEL_ID = 8
BLOCK_SIZE = 2**14 # 16KB

class PeerMessage:
    def __init__(self, message_id: bytes, payload: bytes):
        self.message_id = message_id
        self.payload = payload
        self.message_length_prefix = len(message_id + payload).to_bytes(4, byteorder="big")

    def get_decoded(self):
        return {
            "message_length_prefix": self.message_length_prefix.hex(),
            "message_id": self.message_id.hex(),
            "payload": self.payload.hex(),
        }
    
    def get_encoded(self):
        return self.message_length_prefix + self.message_id + self.payload


class PeerComm:
    def __init__(self, sock):
        self.sock = sock
    """
    The choke message is used to notify the peer that the client is not interested in downloading pieces from the peer.
    The choke message has the following format:
    <length><message_id>
    length: 4 bytes for length of the message
    message_id: 1 byte for message identifier
    """
    def choke(self):
        message_id = CHOKE_ID.to_bytes(1, byteorder = 'big')
        payload = b''
        peer_message = PeerMessage(message_id, payload)
        self.sock.sendall(peer_message.get_encoded())
    """
    The unchoke message is used to notify the peer that the client is ready to download pieces from the peer.
    The unchoke message has the following format:
    <length><message_id>
    length: 4 bytes for length of the message
    message_id: 1 byte for message identifier
    """
    def unchoke(self):
        message_id = UNCHOKE_ID.to_bytes(1, byteorder = 'big')
        payload = b''
        peer_message = PeerMessage(message_id, payload)
        self.sock.sendall(peer_message.get_encoded())

    def listen_unchoke(self):
        response = self.sock.recv(5)
        message_id = response[4]

        if message_id != UNCHOKE_ID:
            raise ValueError(f'Invalid message id: {message_id} for unchoke message')
    """
    The interested message is used to notify the peer that the client is interested in downloading pieces from the peer.
    The interested message has the following format:
    <length><message_id>
    length: 4 bytes for length of the message
    message_id: 1 byte for message identifier
    """
    def interested(self):
        message_id = INTERESTED_ID.to_bytes(1, byteorder = 'big')
        payload = b''
        peer_message = PeerMessage(message_id, payload)
        self.sock.sendall(peer_message.get_encoded())
    """
    The not interested message is used to notify the peer that the client is not interested in downloading pieces from the peer.
    The not interested message has the following format:
    <length><message_id>
    length: 4 bytes for length of the message
    message_id: 1 byte for message identifier
    """
    def not_interested(self):
        message_id = NOT_INTERESTED_ID.to_bytes(1, byteorder = 'big')
        payload = b''
        peer_message = PeerMessage(message_id, payload)
        self.sock.sendall(peer_message.get_encoded())

    """
    The have message is used to notify the peer that the client has downloaded a piece.
    The have message has the following format:
    <length><message_id><payload>
    length: 4 bytes for length of the message
    message_id: 1 byte for message identifier
    payload: 4 bytes for the zero-based piece index
    """
    def have(self):
        message_id = HAVE_ID.to_bytes(1, byteorder = 'big')
        payload = b''
        peer_message = PeerMessage(message_id, payload)
        self.sock.sendall(peer_message.get_encoded())     
    """"
    The bitfield message is used to specify which pieces the peer has.
    The bitfield message has the following format:
    <length><message_id><payload>
    length: 4 bytes for length of the message ie. message id and payload
    message_id: 1 byte for message identifier
    payload: variable length payload representing the pieces
    """
    def bitfield_listen(self) -> list[int]:
        # receive length prefix and message id
        response = self.socket.recv(5)
        length = int.from_bytes(response[0:4], byteorder="big")
        message_id = response[4]
        if message_id != BITFIELD_ID:
            raise ValueError(f"Invalid message id: {message_id} for bitfield message")
        # receive the remaining message of length -1 (1 accounting for message id which is already received)
    
        payload = self.socket.recv(length - 1)
        
        payload_str = "".join(format(x, "08b") for x in payload)
        # print(payload_str)
        indexes_of_pieces = [i for i, bit in enumerate(payload_str) if bit == "1"]
        return indexes_of_pieces
    #     first_colon_index = bencoded_value.find(b":")
    """
    The request message is used to request a piece from the peer.
    The request message has the following format:
    <length><message_id><payload>
    length: 4 bytes for length of the message
    message_id: 1 byte for message identifier
    payload: 12 bytes payload representing the index, begin, and length
    """
    def request_send(self, piece_index: int, piece_length: int) -> bytes:
        message_id = REQUEST_ID.to_bytes(1, byteorder="big")
        full_block = b""
        for offset in range(0, piece_length, BLOCK_SIZE):
            print("-----Requesting Block-----")
            print(f"Offset: {offset} - Length: {piece_length}")
            # to ensure that the unusual size of last block is considered
            block_length = min(BLOCK_SIZE, piece_length - offset)
            payload = piece_index.to_bytes(4, byteorder="big")
            payload += offset.to_bytes(4, byteorder="big")
            payload += block_length.to_bytes(4, byteorder="big")
            peer_message = PeerMessage(message_id, payload)
            # send the request message
            self.socket.sendall(peer_message.get_encoded())
            _, begin, block = self.piece_listen()  # listen for the piece message
            full_block += block
            print(f"Recieved {len(full_block)} bytes")
        return full_block


def decode_bencode(bencoded_value):
    # if chr(bencoded_value[0]).isdigit():
    #     first_colon_index = bencoded_value.find(b":")
    #     if first_colon_index == -1:
    #         raise ValueError("Invalid encoded value")
    #     return bencoded_value[first_colon_index+1:]
    # elif chr(bencoded_value[0]) == "i":
    #     endIndex = bencoded_value[1:].find(b"e") +1
    #     return int(bencoded_value[1:endIndex])
    # elif chr(bencoded_value[0]) == "l":
    #     if 
    # else:
    #     raise NotImplementedError("Only strings and integers are supported at the moment")
    return bencodepy.decode(bencoded_value)


def decode_torrent(sysarg):
    torrent_file_path = "test files/" + sysarg
    with open(torrent_file_path,  'rb') as f:
        data = f.read()
    decoded_data =decode_bencode(data)
    return decoded_data


def info(decoded_data):
    piece_list = []
    tracker_url = decoded_data[b"announce"]
    length = decoded_data[b"info"][b"length"]
    piece_length = decoded_data[b"info"][b"piece length"]
    pieces = decoded_data[b"info"][b"pieces"]
    info = decoded_data[b"info"]
    binfo = bencodepy.encode(info)
    hinfo = hashlib.sha1(binfo).hexdigest()    

    for i in range(len(pieces)//20):
        piece = pieces[i*20 : (i+1)*20]
        piece_list.append(piece.hex())
    return tracker_url, hinfo, length, piece_list


def peer_info(decoded_data):
    tracker_url, hinfo, length, piece_list = info(decoded_data)
    # converting hexdigest which is of 40 characters long (each byte is represented as two hex characters) 
    # to a 20 byte binary representation digest
    info_hash_byte = bytes.fromhex(hinfo)
    params = {
            'info_hash' : info_hash_byte,
            'peer_id' : '99112233445566778899',
            'port' : 6881,
            'uploaded' : 0,
            'downloaded' : 0,
            'left' : length,
            'compact' : 1
    }
    response = requests.get(tracker_url, params = params)
    if response.status_code == 200:
        
        
        #print('[SUCCESS] IP address and port of peers:  ')
        # response.content has binary representation of response and response.text has text representation
        decoded_response = bencodepy.decode(response.content)
        peers = decoded_response[b'peers']
        # every 6 byte contains IP address and port
        # first 4 bytes are IP address, rest are port eg: 192.150.20.11:34501
        peers_ip = []
        # for item in peers:
        #     peer_ip.append
        for i in range(0,len(peers), 6):
            # port number are stored in big-endian format so, higher byte*256 + lower byte gives the port address
            peers_ip.append(f"{peers[i]}.{peers[i+1]}.{peers[i+2]}.{peers[i+3]}:{peers[i+4]*256 +peers[i+5]}")
    else:
            print( 'Error:', response.status_code)
    
    return peers_ip     


def perform_handshake(sysargv2):
    decoded_data =decode_torrent(sysargv2)
    peers_ip = peer_info(decoded_data)
    _,hinfo,*_ = info(decoded_data)
    info_hash_byte = bytes.fromhex(hinfo)
    peer_ip, peer_port = peers_ip[1].split(":")
    
    # peer_ip, peer_port = '165.232.33.77', '51467'
    peer_port = int(peer_port)
    sock = socket.create_connection((peer_ip, peer_port))

    bt_protocol = b'BitTorrent protocol'
    protocol_length = len(bt_protocol).to_bytes(1, byteorder="big")
    reserved = b'\x00' * 8  # 8 bytes reserved x00 is hex representation and \ to escape
    peer_id = b'00112233445566778899'
    
    payload = protocol_length + bt_protocol + reserved + info_hash_byte + peer_id
    sock.send(payload)
    received = sock.recv(68)
    return received
    # [SUCCESS] IP address and port of peers:  
    # 165.232.33.77:20111
    # 178.62.85.20:20133
    # 178.62.82.89:200248
    
# def download_piece(sysargv2):
#     # 
#     _ = perform_handshake(sysargv2)
    

#     return 

def main():
    command = sys.argv[1]

    # print("Logs")

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))

    elif command == "decodetorrent":
        decoded_data =decode_torrent(sys.argv[2])
        print(decoded_data)

    elif command == "info":
        decoded_data =decode_torrent(sys.argv[2])
        tracker_url, hinfo, length, piece_list = info(decoded_data)
        print(f"Tracker URL: {tracker_url.decode()}")
        print(f"Info hash: {hinfo}")
        print(f"Length: {length}")
        print(f"Pieces: ")
        for piece in piece_list:
            print(piece)

    elif command == "peers":
        decoded_data =decode_torrent(sys.argv[2])
        peers_ip = peer_info(decoded_data)
        for item in peers_ip:
            print(item)        

    elif command == "handshake":
        received = perform_handshake(sys.argv[2])
        received_peer_id = received[48:]
        print(f'[HANDSHAKE SUCCESS] Received Peer ID: {received_peer_id.hex()}')


    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
