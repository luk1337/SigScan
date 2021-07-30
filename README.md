## SigScan

SigScan is a really basic signature scanner that takes file path and IDA style code pattern and outputs offsets for each
match.

### Usage

```shell
$ ./SigScan -h
  -h [ --help ]         print usage message
  -f [ --file ] arg     path to file
  -p [ --pattern ] arg  IDA style code pattern
  -m [ --max ] arg      maximum number of matches
```

### Examples

```shell
$ ./SigScan -f client_client.so -p "81 27 ?? ?? ?? FF 55 31 C0"
0x1270640
$ ./SigScan -f client_client.so -p "F6 05 ?? ?? ?? ?? ?? 74" -m 3
0xA65DD9
0xA6A3CC
0xA7385B
```
