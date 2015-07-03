watershell
==========
This will allow you to run commands through iptables or other linux packet filters.

It is essentially a sniffer. It sniffs for udp datagrams to a specified port and then runs a command if a keyword is found

The two keywords right now are run:(command) and status
- run will run the command that comes after the colon as root
- status will send a reply packet with the exit code of the last command run

Status will not work if the port is not filtered, block ICMP port unreachable messages somehow and it should reply fine if it really is listening

Configuring
-----------
You can hard code values at the top of watershell.c or you can use command line arguments when you launch it. There are three options:
- PORT: this defines the port to check for, -p flag, default 12345
- IFACE: the interface to sniff on, -l flag, default eth0
- PROMISC: whether to sniff all traffic or not, -p flag, default false

If promiscuous mode is on any traffic that goes over the network that is UDP and matches the spectfied port will trigger the program, for example sending UDP traffic with a payload of run:reboot to 8.8.8.8 will reboot the listening machine if it is on the same network as the originator. This is useful if you don't want to make direct contact with the machine but still want to send it commands. The status reply will have a spoofed source of the destination host you specified.
