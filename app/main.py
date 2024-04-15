import json
import sys
import bencodepy
import hashlib
import requests 
import binascii

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
        tracker_url, hinfo, length, piece_list = info(decoded_data)
        info_hash_byte = bytes.fromhex(hinfo)
        params = {
            'info_hash' : info_hash_byte,
            'peer_id' : '18495285910374614278',
            'port' : 6881,
            'uploaded' : 0,
            'downloaded' : 0,
            'left' : length,
            'compact' : 1
        }
        response = requests.get(tracker_url, params = params)
        if response.status_code == 200:
            
            
            print('Success: ')
            decoded_response = bencodepy.decode(response.content)
            print(decoded_response)
        else:
            print( 'Error:', response.status_code)

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
