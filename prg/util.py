import pandas as pd
from re import match
from os import path, chdir
from functools import reduce
from sys import argv
from subprocess import check_output
from ifaddr import get_adapters

IP_LEN = 32
CONFIG_FILE = ".hmdl.json"
HEADER = ['IP', 'MASK', 'RULE']


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

    def get_inner(self, row):
        df, prefix, mask, rule = self.db, self.__to_bin(row['IP']) >> (32 - row['MASK']), row['MASK'], row['RULE']
        if df.empty:
            return df
        return df[((df['MASK'] > mask) | ((df['MASK'] == mask) & (df['RULE'] != rule))) &
                  (df['IP'].apply(lambda addr: self.__to_bin(addr) >> (32 - mask)) == prefix)]

    def get_outer(self, row):
        df = self.db
        if df.empty:
            return df
        ip, mask, rule = row.values
        outer = df[(df['MASK'] < mask) & (df['IP'].apply(lambda addr: self.__to_bin(addr) >> (32 - df['MASK'][0]))
                                          == self.__to_bin(ip) >> (32 - df['MASK'][0]))].reset_index()
        return outer if outer.empty else outer.iloc[outer['MASK'].idxmax()]

    def has_alike(self, row):
        df, prefix, mask, rule = self.db, self.__to_bin(row['IP']) >> (32 - row['MASK']), row['MASK'], row['RULE']
        if df.empty:
            return True
        return df[(df['MASK'] == mask) & (df['RULE'] == rule) &
                  (df['IP'].apply(lambda addr: self.__to_bin(addr) >> (32 - mask)) == prefix)].empty

    def has_duplicate(self, row):
        df = self.db
        return any([sr.eq(row).all() for _, sr in df.iterrows()])

    def remove(self, items):
        items = to_df(items)
        if items.empty:
            return
        index = [ind for ind, sr in self.db.iterrows() for _, row in items.iterrows() if sr.eq(row).all()]
        self.db.drop(index, inplace=True)
        self.changed = True

    def exists(self, row):
        df = pd.DataFrame([row], columns=HEADER)
        return any([df.eq(el).all(axis=1)[0] for _, el in self.db.iterrows()])

    def save(self):
        if self.changed:
            self.db.to_csv(self.data_path, index=False)


class Conf:
    def __init__(self, file):
        assert path.exists(file), f"No configuration file, {file}"
        self.name = file
        self.data = pd.read_json(file)
        self.itf = {device.index: device.name for device in get_adapters()}

    def set_device(self, args):
        self.data['device'] = int(args[0])
        self.save()

    def save(self):
        self.data.to_json(self.name, orient="records")

    def __getitem__(self, key):
        return self.data[key][0]


def to_df(data):
    return data if isinstance(data, pd.DataFrame) else data.to_frame().T


class Hmdl:
    itf = {device.index: device.name for device in get_adapters()}
    filters = {
        'ip': {'filter': r'^(((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'
                         r'([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
                         r'(((\/([4-9]|[12][0-9]|3[0-2]))?)|\s?-\s?'
                         r'((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'
                         r'([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))))($))',
               'message': "Wrong IP"},
        'device': {'filter': '|'.join([f'^{ind}$' for ind in itf]),
                   'message': "Index should correspond to one of the devices: " +
                              ', '.join([f'{el}: {key}' for key, el in itf.items()])
                   }
    }
    flags = {
        '--set': {'args': ['device'], 'desc': "Set network interface; args: <dev> "},
        '--pass': {'args': ['ip'], 'desc': "Add passing rule; args: <ip>[/<mask>]"},
        '--drop': {'args': ['ip'], 'desc': "Add dropping rule; args: <ip>[/<mask>]"},
        '--allow': {'args': ['ip'], 'desc': "Rewrite previous rules in a such a way that specified passing rule has no "
                                            "nested rules associated; args: <ip>[/<mask>]"},
        '--block': {'args': ['ip'], 'desc': "Rewrite previous rules in a such a way that specified dropping rule has "
                                            "no nested rules associated; args: <ip>[/<mask>]"},
        '--remove': {'args': ['ip'], 'desc': "Remove passing/dropping rule; args: <ip>[/<mask>]"},
        '--detach': {'args': [], 'desc': "Detach Heimdallr from network interface"},
        '--launch': {'args': [], 'desc': "Attach Heimdallr to network interface"},
        '--list': {'args': [], 'desc': "List all the rules"},
        '--help': {'args': [], 'desc': "Help"},
    }
    rules = {
        'drop': 1,
        'pass': 0,
    }

    def __init__(self, config):
        self.data = Data(config['data'])
        self.conf = config

    def check(self, flag, args):
        exp_args = self.flags[flag]['args']
        failed = [self.filters[arg]['message'] for ind, arg in enumerate(exp_args)
                  if not match(self.filters[arg]['filter'], args[ind])]
        assert not failed, '\n'.join(failed)

    def funcs(self, flag, args):
        self.check(flag, args)
        {
            '--list': self.show,
            '--allow': self.allow,
            '--block': self.block,
            '--pass': self.insert_pass,
            '--drop': self.insert_drop,
            '--remove': self.remove_rule,
            '--launch': self.launch,
            '--detach': self.detach,
            '--help': self.help,
            '--set': self.set_dev,
        }[flag](args)

    def show(self, *_):
        rules = '\n'.join([f"<> {row['IP']}/{row['MASK']}:{'PASS' if row['RULE'] == self.rules['pass'] else 'DROP'}"
                           for _, row in self.data.db.iterrows()])
        print(rules or "Nothing")

    def set_dev(self, args):
        assert not self.is_active(), "Error: Heimdallr is active, cannot change device"
        self.conf.set_device(args)

    def clear_cash(self):
        assert self.is_active(), "Error: Heimdallr is active, cannot clear cash"
        util = self.conf['util']
        device = str(self.conf['device'])
        check_output([util, device, 'c']).decode("utf-8").strip()

    def run(self, flag, args):
        util = self.conf['util']
        device = str(self.conf['device'])
        return check_output([util, device, flag, *args]).decode("utf-8").strip()

    def add_rules(self, items):
        df = to_df(items)
        args = [str(el) for _, sr in df.iterrows() for el in [sr['IP'], sr['MASK'], sr['RULE']]]
        self.run('a', args)

    def remove_rules(self, items):
        df = to_df(items)
        args = [str(el) for _, sr in df.iterrows() for el in [sr['IP'], sr['MASK']]]
        self.run('d', args)

    def remove_rule(self, args):
        self.check_invariants()
        assert self.is_active(), "Error: Heimdallr is not active"

        ip, mask, *_ = args[0].split('/') + [IP_LEN]
        mask = int(mask)

        ip_sr = pd.Series([ip, mask, self.rules['pass']], index=HEADER)

        if not self.data.has_duplicate(ip_sr):
            ip_sr = pd.Series([ip, mask, self.rules['drop']], index=HEADER)

        if not self.data.has_duplicate(ip_sr):
            print(f"There is no such rule: {ip}/{mask}")
            return

        self.data.remove(ip_sr)
        self.data.save()
        self.remove_rules(ip_sr)
        self.clear_cash()

    def insert_pass(self, args):
        self.check_invariants()
        assert self.is_active(), "Error: Heimdallr is not active"

        ip, mask, *_ = args[0].split('/') + [IP_LEN]
        mask, rule = int(mask), self.rules['pass']

        ip_sr = pd.Series([ip, mask, rule], index=HEADER)

        inner = self.data.get_inner(ip_sr)
        alike = self.data.has_alike(ip_sr)

        ctr = inner[(inner['MASK'] == mask) & (inner['IP'] == ip)]
        ctr = ctr if ctr.empty else ctr.reset_index().iloc[0]

        if not ctr.empty:
            print(f"Cannot insert new rule: have contradiction -- {ctr['IP']}/{ctr['MASK']}:DROP")
            return

        if not alike:
            print(f"Cannot insert new rule: similar rule already exists")
            return

        self.data.add(ip_sr)
        self.data.save()
        self.add_rules(ip_sr)
        self.clear_cash()

    def insert_drop(self, args):
        self.check_invariants()
        assert self.is_active(), "Error: Heimdallr is not active"

        ip, mask, *_ = args[0].split('/') + [IP_LEN]
        mask, rule = int(mask), self.rules['drop']

        ip_sr = pd.Series([ip, mask, rule], index=HEADER)

        inner = self.data.get_inner(ip_sr)
        alike = self.data.has_alike(ip_sr)

        ctr = inner[(inner['MASK'] == mask) & (inner['IP'] == ip)]
        ctr = ctr if ctr.empty else ctr.reset_index().iloc[0]

        if not ctr.empty:
            print(f"Cannot insert new rule: have contradiction -- {ctr['IP']}/{ctr['MASK']}:PASS")
            return

        if not alike:
            print(f"Cannot insert new rule: similar rule already exists")
            return

        self.data.add(ip_sr)
        self.data.save()
        self.add_rules(ip_sr)
        self.clear_cash()

    def allow(self, args):
        self.check_invariants()
        assert self.is_active(), "Error: Heimdallr is not active"

        ip, mask, *_ = args[0].split('/') + [IP_LEN]
        mask, rule = int(mask), self.rules['pass']

        ip_sr = pd.Series([ip, mask, rule], index=HEADER)

        outer = self.data.get_outer(ip_sr)
        inner = self.data.get_inner(ip_sr)
        alike = self.data.has_alike(ip_sr)

        [print(f"Removing {'contradicting' if rule != el['RULE'] else 'excessive'} rule: {el['IP']}/{el['MASK']}") for
         _, el in inner.iterrows()]

        self.remove_rules(inner)
        self.data.remove(inner)

        if not alike:
            print(f"There is similar rule")
        elif not outer.empty and outer['RULE'] == rule:
            print(f"No need to add {ip}/{mask} as long as {outer['IP']}/{outer['MASK']} is allowed")
        else:
            self.data.add(ip_sr)
            self.add_rules(ip_sr)

        if self.data.changed:
            self.clear_cash()
            self.data.save()

    def detach(self, *_):
        self.check_invariants()
        assert self.is_active(), "Error: Heimdallr is not active"
        if self.is_active():
            self.run('e', [])
            print(f"Heimdallr detached from device: {self.conf['device']}")
        else:
            print(f"Heimdallr already detached from device: {self.conf['device']}")

    def help(self, *_):
        msg = '\n'.join([f"{flag} == {self.flags[flag]['desc']}" for flag in self.flags])
        print(msg)

    def block(self, args):
        self.check_invariants()
        assert self.is_active(), "Error: Heimdallr is not active"

        ip, mask, *_ = args[0].split('/') + [IP_LEN]
        mask, rule = int(mask), self.rules['drop']

        ip_sr = pd.Series([ip, mask, rule], index=HEADER)

        outer = self.data.get_outer(ip_sr)
        inner = self.data.get_inner(ip_sr)
        alike = self.data.has_alike(ip_sr)

        [print(f"Removing {'contradicting' if rule != el['RULE'] else 'excessive'} rule: {el['IP']}/{el['MASK']}") for
         _, el in inner.iterrows()]
        self.remove_rules(inner)
        self.data.remove(inner)

        if not alike:
            print(f"There is similar rule")
        elif not outer.empty and outer['RULE'] == rule:
            print(f"No need to add {ip}/{mask} as long as {outer['IP']}/{outer['MASK']} is allowed")
        else:
            self.data.add(ip_sr)
            self.add_rules(ip_sr)

        if self.data.changed:
            self.clear_cash()
            self.data.save()

    def is_active(self):
        return path.exists(self.conf["trie"])

    def launch(self, *_):
        self.check_invariants()
        launcher = self.conf['launcher']
        device = str(self.conf['device'])
        if not self.is_active():
            check_output([launcher, device]).decode("utf-8").strip()
            self.add_rules(self.data.db)
            print(f"Heimdallr attached to device: {device}")
        else:
            print(f"Heimdallr already attached to device: {device}")

    def check_invariants(self):
        assert self.conf["device"] != -1, "Please set one of available interfaces: " + \
                                          ', '.join(map(lambda el: f'{self.conf.itf[el]}: {str(el)}', self.conf.itf))
        assert self.conf["device"] in self.conf.itf, "Wrong interface, or not active one"


def parse_cmd(args):
    if not args:
        return None, None
    return {'-' in args[0] and bool(args[1:]): (args[0], args[1:]),
            '-' in args[0] and bool(not args[1:]): (args[0], [])}.get(True, (None, None))


def try_exec(obj, flag, args):
    assert flag in obj.flags, f"Unknown flag: {flag}"
    assert len(args) == len(obj.flags[flag]['args']), f"Wrong number of arguments for option {flag}, " \
                                                      f"should be {len(obj.flags[flag]['args'])}"
    obj.funcs(flag, args)


def main():
    abspath = path.abspath(__file__)
    dir_name = path.dirname(abspath)
    chdir(dir_name)

    configuration = Conf(CONFIG_FILE)
    flag, args = parse_cmd(argv[1:])

    if flag is None:
        print("Heimdallr-project by @m-shiroi")
        return

    app = Hmdl(configuration)
    try_exec(app, flag, args)


if __name__ == "__main__":
    main()