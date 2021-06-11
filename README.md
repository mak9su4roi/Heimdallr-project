# Heimdallr-project
## Description & details
> Just a simple Firewall on BPF :) <br>
[Project-page](https://www.notion.so/Heimdallr-project-7307e47c13cd47a785983d0ca4843f4a)
---
## Requirements
Linux:
* libbpf
* glibc
---
## Clone && Build
```bash
$ git clone https://github.com/m-shiroi/Heimdallr-project .
$ make
$ sudo su
```
---
## SetUp environment
* create new virtualenv
```bash
virtualenv .venv
```

* activate virtualenv
```bash
source .venv/bin/activate
```

* load dependencies
```bash
pip install -r requirements.txt
```
---
## Test

### Set networking device
```bash
python3 hmdl.py -s 2
```

### Attach firewall
```bash
python3 hmdl.py -A
```

### Block single IPv4
```bash
python3 hmdl.py -d 8.8.8.8
```
### Check sing IPv4
```bash
ping 8.8.8.8
```
### Check short command description
```bash
python3 hmdl.py --help
```
...
### Detach
```bash
python3 hmdl.py -D
```


