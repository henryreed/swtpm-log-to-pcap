# swtpm log to PCAP

This Python script converts a `swtpm` log file or `swtpm` stdout to a PCAP file. 
This allows system administrators and security researchers to view the `swtpm` raw 
hex data in a human-readable format using Wireshark's TPM dissector.

## Usage

```
./swtpm-log-to-pcap.py --help
usage: swtpm-log-to-pcap.py [-h] log pcap

Given an swtpm log file, create a PCAP that can be analyzed by Wireshark's TPM dissector

positional arguments:
  log         Path to the swtpm log file
  pcap        Path to where the PCAP file will be written to

options:
  -h, --help  show this help message and exit
```

## Installation

Clone this repository and navigate to the root directory.

It is recommended to use a virtual environment, rather than 
installing requirements directly on the host operating system:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Technical Details

### Log compatibility

This script assumes there are five types of lines in the log file:

**Ctrl Cmd**

`Ctrl Cmd: length 4`

**Ctrl Rsp**

`Ctrl Rsp: length 4`

**SWTPM_IO_READ**

`SWTPM_IO_Read: length 14`

**SWTPM_IO_Write**

`SWTPM_IO_Write: length 10`

**IO Buffer**

`C0 FF EE DE AD BE EF 00 FF 00 FF`

It attempts to ignore anything prepended to these lines; e.g., the
line `[id=12345678]  SWTPM_IO_Read: length 14` and `SWTPM_IO_Read: length 14`
are identical. This is because some swtpm logs may have an ident prepended
to each line, while other logs might be from swtpm stdout which does
not have this ident. 

### TCP

The Wireshark TPM dissector requires all TPM traffic to occur in a TCP
connection. As such, this script generates a TCP handshake, encapsulates all
TPM traffic in TCP Push-Acks, and generates a TCP teardown in order to 
avoid any Wireshark warnings and to allow Wireshark to automatically 
identify TPM traffic.

## License

This software uses Scapy, which is licensed under GPL 2.0 only, and is therefore
licensed under GPL 2.0 only. 
