from datetime import datetime
from functools import reduce
from sys import argv
import subprocess
from string import Template
from os import chdir, path, remove, getenv
import pandas as pd
import re

TRUNCATE = None

BPF_NAME = "bpf_program"
PROJECT_NAME = "heimdallr"

DB_FILE = "data/db"
LOG_FILE = f"{PROJECT_NAME}_log.txt"
TPL_FILE = f"template/{BPF_NAME}.template"
SRC_FILE = f"src/{BPF_NAME}.c"
BPF_PRG = "./monitor-exec"

PRG_DIR = "prg"
DB_DIR = "data"
LIMIT = 100

IP4_VALIDATOR = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


get_db_file = lambda itf: f"{DB_FILE}_{itf}.csv"
convert_ip = lambda ip: reduce(lambda x, y: x | y,
                               [byte << shift * 8 for shift, byte in enumerate(map(int, ip.split(".")))])


def append_to_db(db, info):
    db.loc[len(db)] = [info["IP"], info["STR"], info["MASK"]]


def create_db(db_name):
    with open(db_name, mode="w", encoding="UTF-8") as db:
        db.write("IP, STR, MASK")


def load_db(db_name):
    if not path.exists(db_name):
        return pd.DataFrame(data={"IP": [], "STR": [], "MASK": []})
    else:
        return pd.read_csv(db_name, encoding="UTF-8")


def is_correct_interface(itf, ind):
    if argv[ind] not in itf:
        print(f"Wrong interface selected: {argv[ind]} (use: {', '.join(itf.keys())})")
        return False
    return True


def is_correct_ip(ind):
    if not IP4_VALIDATOR.match(argv[ind]):
        print(f"Wrong ip address: {argv[ind]}")
        return False
    return True


def show_blocked(itf):
    if len(argv) != 3:
        print("Wrong number of arguments (1 argument after -l expected)")
        return TRUNCATE

    if not is_correct_interface(itf, 2):
        return TRUNCATE

    interface = argv[2]
    db_file = get_db_file(interface)

    if not path.exists(db_file):
        print(f"There are no blocked addresses on: {interface}")
        return TRUNCATE

    print("\n".join([f"* {ip}" for ip in load_db(db_file)["STR"]]))
    return TRUNCATE


def clear(itf):
    if len(argv) != 3:
        print("Wrong number of arguments (1 argument after -c expected)")
        return TRUNCATE

    if not is_correct_interface(itf, 2):
        return TRUNCATE

    interface = argv[2]
    db_file = get_db_file(interface)

    if not path.exists(db_file):
        print(f"There is no xdp program running on: {interface}")
        return TRUNCATE

    remove(db_file)

    return {"db": None,
            "u_itf": {"name": interface, "id": itf[interface]},
            "launch": False}


def append(itf):
    if len(argv) != 4:
        print("Wrong number of arguments (2 arguments after -a flag expected)")
        return TRUNCATE

    if not is_correct_ip(2):
        return TRUNCATE

    if not is_correct_interface(itf, 3):
        return TRUNCATE

    interface = argv[3]
    db_file = get_db_file(interface)
    db = load_db(db_file)

    ip_str = argv[2]
    ip_dig = convert_ip(ip_str)

    if len(db) == LIMIT:
        print(f"Limit of IPv4 filter is {LIMIT}, please drop some address from filter to add new one")
        return TRUNCATE

    if ip_dig in set(db["IP"]):
        print(f"IPv4: {argv[2]} is already in filter list")
        return TRUNCATE

    append_to_db(db, {"IP": ip_dig, "STR": ip_str, "MASK": 32})
    db.to_csv(db_file, index=False)
    return {"db": db,
            "u_itf": {"name": interface, "id": itf[interface]},
            "launch": True}


def drop(itf):
    if len(argv) != 4:
        print("Wrong number of arguments (one argument after -d flag expected)")
        return TRUNCATE

    if not is_correct_ip(2):
        return TRUNCATE

    if not is_correct_interface(itf, 3):
        return TRUNCATE

    interface = argv[3]
    db_file = get_db_file(interface)
    db = load_db(db_file)

    ip_str = argv[2]
    ip_dig = 0

    for shift, byte in enumerate(map(int, reversed(ip_str.split(".")))):
        ip_dig |= byte << (3 - shift) * 8

    to_drop = list(db[db["IP"] == ip_dig].index)

    if not to_drop:
        print(f"IPv4: {argv[2]} is not in filter list")
        return TRUNCATE

    db = db.drop(to_drop[0])
    remove(db_file) if db.empty else db.to_csv(db_file, index=False)
    return {"db": None if db.empty else db,
            "u_itf": {"name": interface, "id": itf[interface]},
            "launch": not db.empty}


def run_with_sudo():
    if getenv("SUDO_USER") is None:
        print("Need sudo")
        return False
    return True


def main():
    if not run_with_sudo():
        return 0
    interfaces = {el.split(": ")[1]: int(el.split(": ")[0])
                  for el in re.findall(r'\d: [\w\d-]+', subprocess.check_output(["ip", "addr"]).decode("utf-8"))}

    chdir(path.dirname(__file__))
    procedure = {"-c": clear,
                 "-a": append,
                 "-d": drop,
                 "-l": show_blocked}.get(argv[1], lambda x: print(f"Invalid argument: {argv[1]}"))

    conf = procedure(interfaces)
    if conf is TRUNCATE:
        return 0

    if conf["db"] is not None:
        cell_template = Template("ips[$ind]=$ip;\n")
        forbidden_ips = "".join([cell_template.substitute(ind=ind, ip=ip)
                                 for ind, ip in enumerate(conf["db"]["IP"])])
    else:
        forbidden_ips = ""

    with open(TPL_FILE, mode="r", encoding="UTF-8") as tpp:
        bpf_template = Template("".join(tpp.readlines()))

    with open(SRC_FILE, mode="w", encoding="UTF-8") as src:
        src.write(bpf_template.substitute(forbidden_ips=forbidden_ips))

    log = f"{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n"

    itf_id = conf['u_itf']['id']
    inf_nm = conf['u_itf']['name']

    log += "make: " + subprocess.check_output(["make"]).decode("utf-8").strip() + "\n"
    log += "ip link set dev enp2s0 xdp off: " + \
           subprocess.check_output(["ip", "link", "set", "dev", inf_nm, "xdp", "off"]) \
                     .decode("utf-8").strip() + "\n"

    if conf['launch']:
        chdir(PRG_DIR)
        log += f"{BPF_PRG} {itf_id}: " + subprocess.check_output([BPF_PRG, str(itf_id)]).decode("utf-8").strip()
        chdir(path.dirname(__file__))

    with open(LOG_FILE, mode="a", encoding="UTF-8") as lg:
        lg.write(log)


if __name__ == "__main__":
    main()
