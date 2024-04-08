from bencoding import Decoder
with open('test files/test.txt', 'rb') as f:
    meta_info = f.read()
torrent = Decoder(meta_info).decode()
print(torrent[1])