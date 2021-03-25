# Heimdallr-project
### Description & details 
> Just a simple Firewall on BPF :)

[1]: https://www.notion.so/Heimdallr-project-7307e47c13cd47a785983d0ca4843f4a

[![git](media/heimdallr_s.png)][1]
<br>
---
## Reqiremnts:
---
* `python3`
* `pandas`
(installed as root) 
```bash
# pip3 install pandas
```
* `libbpf`
---
### Installation
---
```bash
$ mkdir firewall
$ cd firewall
$ git https://github.com/m-shiroi/Heimdallr-project.git .
$ git checkout devel
$ python3 install.py
```
(close console) <br>
---
### Test
---
```bash
$ ping www.facebook.com #get ip address of facebook
$ hmdl -a <facebookIPv4> <your current networking interface>
```
After this command IPv4 www.facebook.com should be blocked <br>
You can check it with ping <br>
```bash
$ hmdl -d <facebookIPv4> <your current networking interface>
```
After this command IPv4 www.facebook.com should be unblocked <br>
You can check it with ping <br>
---
### Uninstallation
---
Move to ther root of project <br>
```bash
$ python3 uninstall.py
```
