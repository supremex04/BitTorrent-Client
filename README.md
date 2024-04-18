- torrent file must be in "test files" folder
- run format for decoding/parsing
``` 
./bittorrent.sh {command} {bencode/file}
```
commands: 

- decode: decoding simple bencode
- decodetorrent: decoding torrent file
- info: to extract annouce and length
- peers: gets IP and port of peers
- handshake: handshakes with the peer on 0th index (you may change according to your preference)

To download a piece:
```
./bittorrent.sh download_piece {torrent file} -o downloaded_files/{piece_name} 0
```