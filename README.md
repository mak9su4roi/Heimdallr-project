# Heimdallr-project
### Description & details
> Just a simple Firewall on BPF :) <br>
[Project-page](https://www.notion.so/Heimdallr-project-7307e47c13cd47a785983d0ca4843f4a)
---
### Requirements
Python:
* pandas
* ifaddr

Linux:
* libbpf
* glibc
---
### How to test
```bash
$ git clone https://github.com/m-shiroi/Heimdallr-project .
$ make
$ cd prg
$ python3 util.py
$ sudo su
# python3 util.py --set <index of your active network interface>
# python3 util.py --launch
```
### Block single IPv4
```bash
# python3 util.py --block 8.8.8.8
```
### Check sing IPv4
```
# ping 8.8.8.8
# python3 util.py --help
```

