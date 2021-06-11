import subprocess
import argparse
from os import path, mkdir, chdir
from numpy import mean
from pkg import ip2csv, IPTables, XDP, ploter
from config import config
import json


def get_ping(firewall, ind, conf):
    firewall.load_rules(ind)
    get_avg = lambda res: float(res.stdout.decode("utf-8").split("/")[-3])
    command = f"ping {conf['ping_ip']} -i {conf['ping_interval']} -c {conf['ping_rate']}"
    kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "shell": True}
    pings = [get_avg(subprocess.run(command, **kwargs)) for _ in range(conf["iterations"])]
    padding = ' '*(len(str(conf['rules'][-1])) - len(str(conf['rules'][ind])))
    print(f"<> Ping for {conf['rules'][ind]}:{padding} {mean(pings)}")
    return mean(pings)


def get_bdw(firewall, ind, conf):
    firewall.load_rules(ind)
    get_avg = lambda res: print("<> Run client") or json.loads(res.stdout.decode("utf-8"))["end"]["sum_received"]["bits_per_second"]
    command = "iperf3 -s -1 -J"
    kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "shell": True}
    bdw = [get_avg(subprocess.run(command, **kwargs)) for _ in range(conf["iterations"])]
    return mean(bdw)/(1024**3)


def ping_benchmark(conf, res: dict):
    with XDP(conf["rules"], old=conf["old_name"]) as firewall:
        res[firewall.prefix] = {rule_num: get_ping(firewall, ind, conf) for ind, rule_num in enumerate(conf["rules"])}

    with IPTables(conf["rules"], old=conf["old_name"]) as firewall:
        res[firewall.prefix] = {rule_num: get_ping(firewall, ind, conf) for ind, rule_num in enumerate(conf["rules"])}


def bdw_benchmark(conf, res: dict):
    with IPTables(conf["rules"], old=conf["old_name"]) as firewall:
        res[firewall.prefix] = {rule_num: get_bdw(firewall, ind, conf) for ind, rule_num in enumerate(conf["rules"])}

    with XDP(conf["rules"], old=conf["old_name"]) as firewall:
        res[firewall.prefix] = {rule_num: get_bdw(firewall, ind, conf) for ind, rule_num in enumerate(conf["rules"])}


def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-B', '--bandwidth',   action="store_true")
    args = parser.parse_args()

    if path.isfile(config["test_dir"]):
        raise AssertionError
    if not path.exists(config["test_dir"]):
        mkdir(config["test_dir"])

    chdir(config["test_dir"])
    config["rules"] = sorted(list(set(config["rules"])))

    [ip2csv(f"{rule}.csv", dist=config["mask_distribution"], num=rule, octet=config["first_octet"]) for rule in config["rules"]]
    results = dict()

    if args.bandwidth:
        bdw_benchmark(config, results)
        data = [(pk, results[lbl][pk], lbl) for lbl in results for pk in results[lbl]]
        ploter.plotter("Bandwidth", data, ("xdp", "iptables", "Bandwidth Test", "Number of rules", "Bandwidth Gb", "Firewalls"))
    else:
        ping_benchmark(config, results)
        data = [(pk, results[lbl][pk], lbl) for lbl in results for pk in results[lbl]]
        ploter.plotter("Latency", data, ("xdp", "iptables", "Latency test", "Number of rules", "Ping time in ms", "Firewalls"))


if __name__ == "__main__":
    main()
