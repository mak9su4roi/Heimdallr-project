# Heimdallr-project
## Description & details
> Just a simple Firewall on BPF :) 
---
## Requirements
Linux:
* libbpf
* glibc
---
## Clone && Build
```bash
git clone https://github.com/m-shiroi/Heimdallr-project .
```
```bash
make
```
```bash
sudo su
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
---
## Benchmarking
### Latency test
```bash
python3 bench.py
```
### Bandwidth test
```bash
python3 hmdl.py -B
```
* Open other terminal window and run:
```bash
python3 iperf.py
```



