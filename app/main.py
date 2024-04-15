import json
import sys
import bencodepy

# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
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


def main():
    command = sys.argv[1]

    #print("Logs")

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        # Uncomment this block to pass the first stage
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "decodetorrent":
        torrent_file = sys.argv[2]
        f = open(torrent_file, "rb")
        data = f.read()
        decoded_data =decode_bencode(data)
        f.close()
        print(decoded_data)
    elif command == "info":
        torrent_file = sys.argv[2]
        f = open(torrent_file, "rb")
        data = f.read()
        decoded_data =decode_bencode(data)
        f.close()
        tracker_url = decoded_data[b"announce"]
        length = decoded_data[b"info"][b"length"]
        print(f"Tracker URL: {tracker_url.decode()}")
        print(f"Length: {length}")
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
