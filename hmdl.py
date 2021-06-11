import argparse
from config import f_config as conf, save_config
import pandas as pd
from re import match
from os import path
from functools import reduce
from subprocess import check_output, PIPE
from netifaces import interfaces


HEADER = ['IP', 'MASK', 'RULE', 'IFF']


class Data:
    def __init__(self, file):
        self.data_path = file
        if not path.exists(self.data_path):
            self.__touch_data()
        self.db = pd.read_csv(self.data_path)
        self.changed = False

    def __touch_data(self):
        empty = pd.DataFrame(data={el: [] for el in HEADER})
        empty.to_csv(self.data_path, index=False)

    def add(self, row):
        self.db = self.db.append(row.T, ignore_index=True)
        self.changed = True

    @staticmethod
    def __to_bin(addr):
        return reduce(lambda x, y: x + y,
                      [int(el) << (8 * ind) for ind, el in enumerate(reversed(addr.split('.')))])

    def get_duplicate(self, ipv4, iff, mask):
        df = self.db
        duplicate = df[(df["IFF"] == iff) & (df["IP"] == ipv4) & (df["MASK"] == mask)]
        return None if duplicate.empty else duplicate.iloc[0]["RULE"]

    def remove(self, items):
        items = to_df(items)
        if items.empty:
            return
        index = [ind for ind, sr in self.db.iterrows() for _, row in items.iterrows() if sr.eq(row).all()]
        self.db.drop(index, inplace=True)
        self.changed = True

    def __getitem__(self, iff):
        return self.db[self.db["IFF"] == iff]

    def save(self):
        if self.changed:
            self.db.to_csv(self.data_path, index=False)


class Conf:
    def __init__(self, config):
        self.data = config
        self.itf = {ind+1: device for ind, device in enumerate(interfaces())}

    def set_device(self, iff):
        self.data['device'] = iff
        self.save()

    def save(self):
        save_config(self.data)

    def __getitem__(self, key):
        return self.data[key]


def to_df(data):
    return data if isinstance(data, pd.DataFrame) else data.to_frame().T


class IPv4:
    filter = r'^(((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'\
                r'([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'\
                r'(((\/([4-9]|[12][0-9]|3[0-2]))?)|\s?-\s?'\
                r'((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'\
                r'([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))))($))'
    message = "Wrong IPv4"
    max_mask = 32

    def __init__(self, raw: str):
        failed = self.message if not match(self.filter, raw) else False
        if failed:
            raise argparse.ArgumentTypeError(failed)
        self.ip, self.mask = raw.split("/") if "/" in raw else (raw, self.max_mask)
        self.mask = int(self.mask)
        bin_mask = 2**self.mask-1 << 32-self.mask
        adj = sum([int(octet) << (3-ind)*8 for ind, octet in enumerate(self.ip.split("."))]) & bin_mask
        self.ip = ".".join([str(adj >> (3-ind)*8 & 0xFF) for ind in range(4)])


class Hmdl:
    rules = {"drop": 1, "pass": 0}

    def __init__(self, config):
        self.data = Data(config['data'])
        self.conf = config

    def show(self, *_):
        for ind, iff in self.conf.itf.items():
            print(f"{ind}: {iff} "
                  f"{'(+)'*(self.is_active() and ind == self.conf['device']) or '(-)'*(ind == self.conf['device'])}")
            rules = '\n'.join([f"<> {row['IP']}/{row['MASK']}:{'PASS' if row['RULE'] == self.rules['pass'] else 'DROP'}"
                               for _, row in self.data[ind].iterrows()])
            print(rules or "<> Nothing", "\n---")

    def set_dev(self, iff):
        self.conf.set_device(iff)

    def clear_cash(self):
        assert self.is_active(), "Error: Heimdallr is active, cannot clear cash"
        if not self.conf["cashed"]:
            return
        util = self.conf['util']
        device = str(self.conf['device'])
        check_output([util, device, 'c']).decode("utf-8").strip()

    def run(self, flag, *args):
        util = self.conf['util']
        iff = str(self.conf['device'])
        return check_output([util, iff, flag, *args]).decode("utf-8").strip()

    def add_rules(self, items):
        chunk = 9000
        df = to_df(items)
        args = [str(el) for _, sr in df.iterrows() for el in [sr['IP'], sr['MASK'], sr['RULE']]]
        if len(args) < chunk:
            self.run('a', *args)
            return
        delta = len(args)//chunk
        over = delta*chunk != len(args)
        [self.run('a', *args[ind*chunk: (ind+1)*chunk]) for ind in range(delta+over)]

    def remove_rules(self, items):
        chunk = 8000
        df = to_df(items)
        args = [str(el) for _, sr in df.iterrows() for el in [sr['IP'], sr['MASK']]]
        if len(args) < chunk:
            self.run('d', *args)
            return
        delta = len(args)//chunk
        over = delta*chunk != len(args)
        [self.run('d', *args[ind*chunk: (ind+1)*chunk]) for ind in range(delta+over)]

    def remove_rule(self, ipv4):
        self.check_invariants()
        assert self.is_active(), "Error: Heimdallr is not active"
        ip_sr = pd.Series([ipv4.ip, ipv4.mask, self.rules["pass"], self.conf["device"]], index=HEADER)
        duplicate = self.data.get_duplicate(ipv4.ip, self.conf["device"], ipv4.mask)

        if duplicate is None:
            print(f"There is no such rule: {ipv4.ip}/{ipv4.mask}")
            return

        ip_sr["RULE"] = duplicate

        self.data.remove(ip_sr)
        self.data.save()
        self.remove_rules(ip_sr)
        self.clear_cash()

    def insert_pass(self, ipv4):
        self.check_invariants()
        assert self.is_active(), "Error: Heimdallr is not active"
        ip_sr = pd.Series([ipv4.ip, ipv4.mask, self.rules["pass"], self.conf["device"]], index=HEADER)
        duplicate = self.data.get_duplicate(ipv4.ip, self.conf["device"], ipv4.mask)

        if duplicate == self.rules['drop']:
            print(f"Cannot insert new rule: have contradiction")
            return

        if duplicate == self.rules['pass']:
            print(f"Cannot insert new rule: have similar")
            return

        self.data.add(ip_sr)
        self.data.save()
        self.add_rules(ip_sr)
        self.clear_cash()

    def insert_drop(self, ipv4):
        self.check_invariants()
        assert self.is_active(), "Error: Heimdallr is not active"
        ip_sr = pd.Series([ipv4.ip, ipv4.mask, self.rules["drop"], self.conf["device"]], index=HEADER)
        duplicate = self.data.get_duplicate(ipv4.ip, self.conf["device"], ipv4.mask)

        if duplicate == self.rules['pass']:
            print(f"Cannot insert new rule: have contradiction")
            return

        if duplicate == self.rules['drop']:
            print(f"Cannot insert new rule: have similar")
            return

        self.data.add(ip_sr)
        self.data.save()
        self.add_rules(ip_sr)
        self.clear_cash()

    def detach(self):
        self.check_invariants()
        assert self.is_active(), "Error: Heimdallr is not active"
        if self.is_active():
            self.run('e')
            print(f"Heimdallr detached from device: {self.conf['device']}")
        else:
            print(f"Heimdallr already detached from device: {self.conf['device']}")

    def attach(self):
        self.check_invariants()
        launcher = self.conf['launcher']
        rules = self.data[self.conf['device']]
        iff = str(self.conf['device'])
        xdp = self.conf["xdp"]
        if not self.is_active():
            check_output([launcher, iff, xdp], stderr=PIPE).decode("utf-8").strip()
            self.add_rules(rules)
            print(f"Heimdallr attached to device: {iff}")
        else:
            print(f"Heimdallr already attached to device: {iff}")

    def is_active(self):
        return path.exists(self.conf["trie"])

    def check_invariants(self):
        assert self.conf["device"] != -1, "Please set one of available interfaces: " + \
                                          ', '.join(map(lambda el: f'{self.conf.itf[el]}: {str(el)}', self.conf.itf))

        assert self.conf["device"] in self.conf.itf, "Wrong interface, or not active one"


def get_device(x):
    iff = {ind+1: device for ind, device in enumerate(interfaces())}
    try:
        device = int(x)
    except:
        raise argparse.ArgumentTypeError(f"Interface should be integer: {iff}")
    if device not in iff:
        raise argparse.ArgumentTypeError(f"Interface should be integer: {iff}")
    return device


def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-p', '--PASS',   type=lambda x: IPv4(x))
    group.add_argument('-d', '--DROP',   type=lambda x: IPv4(x))
    group.add_argument('-r', '--REMOVE', type=lambda x: IPv4(x))
    group.add_argument('-s', '--SET',    type=get_device)
    group.add_argument('-L', '--list',   action="store_true")
    group.add_argument('-A', '--attach', action="store_true")
    group.add_argument('-D', '--detach', action="store_true")
    args = parser.parse_args()

    configuration = Conf(conf)
    app = Hmdl(configuration)

    msg = "Heimdallr-project by @m-shiroi"

    {args.PASS is not None: lambda: app.insert_pass(args.PASS),
     args.DROP is not None: lambda: app.insert_drop(args.DROP),
     args.REMOVE is not None: lambda: app.remove_rule(args.REMOVE),
     args.SET is not None: lambda: app.set_dev(args.SET),
     args.list is True: lambda: app.show(),
     args.detach is True: lambda: app.detach(),
     args.attach is True: lambda: app.attach()}.get(True, lambda: print(msg))()


if __name__ == "__main__":
    main()
