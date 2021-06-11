import subprocess
from sys import argv
from time import sleep

while True:
    subprocess.run(f"iperf3 -c {argv[1]} -n 1G", shell=True)
    sleep(1)
