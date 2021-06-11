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
### Test configuration
```json
{
	"old_name": "former", #name for file to store firewall former rules in
	"rules": [10, 100, 1000, 10000], #number of rules to test
	"ping_ip": "www.facebook.com", #address fro latency test
	"ping_interval": 0.001, #ping -i flag
	"device": 2, #networking device
	"ping_rate": 10, #ping -c flag
	"iterations": 10, #number of iterations
	"mask_distribution": "20:0.001,22:0.001,24:0.02,27:0.05,29:0.1,30:0.3,31:0.4", #distribution of randomly generated ips
	"first_octet": "200", #firs harcoded octet of randomly generated ips
	"test_dir": "other", #name for directory to save benchmarking data in
	"other_name": "other.dat"
}
```

### Latency test
```bash
python3 bench.py
```
### Bandwidth test
```bash
python3 bench.py -B
```
* Open other terminal window and run:
```bash
python3 iperf.py <your IPv4 address>
```



