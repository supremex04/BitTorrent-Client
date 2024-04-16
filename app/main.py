import json
import sys
import bencodepy
import hashlib
import requests 
import binascii
import socket


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
        
        
        print('[SUCCESS] IP address and port of peers:  ')
        # response.content has binary representation of response and response.text has text representation
        decoded_response = bencodepy.decode(response.content)
        peers = decoded_response[b'peers']
        print(decoded_response[b'interval'])
        print(peers)
        # every 6 byte contains IP address and port
        # first 4 bytes are IP address, rest are port eg: 192.150.20.11:34501
        peers_ip = []
        # for item in peers:
        #     peer_ip.append
        for i in range(0,len(peers), 6):
            peers_ip.append(f"{peers[i]}.{peers[i+1]}.{peers[i+2]}.{peers[i+3]}:{peers[i+4]*256 +peers[i+5]}")
    else:
            print( 'Error:', response.status_code)
    
    return peers_ip     

def perform_handshake(peers_ip ,info_hash_byte):
    peer_ip, peer_port = peers_ip[1].split(":")
    #peer_ip, peer_port = '165.232.33.77', '51467'
    peer_port = int(peer_port)
    print(peer_ip)
    print(peer_port)
    sock = socket.create_connection((peer_ip, peer_port))
    print("works")
    bt_protocol = b'BitTorrent protocol'
    protocol_length = len(bt_protocol).to_bytes(1, byteorder="big")
    reserved = b'\x00' * 8  #8 bytes reserved x00 is hex representation and \ to escape
    peer_id = b'00112233445566778899'
    payload = protocol_length + bt_protocol + reserved + info_hash_byte + peer_id
    sock.send(payload)
    print('works')
    received = sock.recv(68)
    return received
    # [SUCCESS] IP address and port of peers:  
    # 165.232.33.77:20111
    # 178.62.85.20:20133
    # 178.62.82.89:200248
    


def main():
    command = sys.argv[1]

    #print("Logs")

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))

    elif command == "decodetorrent":
        torrent_file = "test files/" +sys.argv[2]
        f = open(torrent_file, "rb")
        data = f.read()
        decoded_data =decode_bencode(data)
        f.close()
        print(decoded_data)

    elif command == "info":
        torrent_file = "test files/" +sys.argv[2]
        f = open(torrent_file, "rb")
        data = f.read()
        decoded_data =decode_bencode(data)
        f.close()
        tracker_url, hinfo, length, piece_list = info(decoded_data)
        print(f"Tracker URL: {tracker_url.decode()}")
        print(f"Info hash: {hinfo}")
        print(f"Length: {length}")
        print(f"Pieces: ")
        for piece in piece_list:
            print(piece)

    elif command == "peers":
        torrent_file = "test files/" +sys.argv[2]
        f = open(torrent_file, "rb")
        data = f.read()
        decoded_data =decode_bencode(data)
        f.close()
        peers_ip = peer_info(decoded_data)
        for item in peers_ip:
            print(item)        
    elif command == "handshake":
        torrent_file = "test files/" +sys.argv[2]
        with open(torrent_file, "rb") as f:
            data = f.read()
            decoded_data =decode_bencode(data)
        peers_ip = peer_info(decoded_data)
        _,hinfo,*_ = info(decoded_data)
        info_hash_byte = bytes.fromhex(hinfo)
        received = perform_handshake(peers_ip, info_hash_byte)
        received_peer_id = received[48:]
        print(f'[HANDSHAKE SUCCESS] Received Peer ID: {received_peer_id.hex()}')


    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
