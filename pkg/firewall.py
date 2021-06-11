from string import Template
import subprocess
import pandas as pd
import hmdl


class Firewall:
    test_ext = ".csv"
    test_header = "IPv4"

    def __init__(self, test_sizes: list, **kwargs):
        self.test_sizes = test_sizes[:]
        self.test_names = [f"{size}{self.test_ext}" for size in test_sizes]
        self.new_rules = [f"{kwargs['prefix']}{size}{kwargs['rule_ext']}" for size in test_sizes]
        self.old_rules = f"{kwargs['prefix']}{kwargs['old']}{kwargs['rule_ext']}"

    def __enter__(self):
        self._start()
        self._save_rules()
        return self

    def _read_test(self, ind: int):
        return pd.read_csv(self.test_names[ind])[self.test_header]

    def _save_rules(self):
        pass

    def _restore_rules(self):
        pass

    def load_rules(self, ind: int):
        pass

    def _ip2rules(self, ind: int):
        pass

    def _start(self):
        pass

    def __exit__(self, exc_type, exc_value, traceback):
        self._restore_rules()
        self._stop()

    def _stop(self):
        pass


class IPTables(Firewall):
    ruleFormat = "-A INPUT -s ${ip} -m comment --comment \"benchmark\" -j DROP\n"
    prefix = "iptables"
    rule_ext = ".dat"

    def __init__(self, ips: list, **kwargs):
        super().__init__(ips, **kwargs, prefix=self.prefix, rule_ext=self.rule_ext)

    def _save_rules(self):
        subprocess.run(f"iptables-save > {self.old_rules}", shell=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)

    def _restore_rules(self):
        subprocess.run(f"iptables-restore < {self.old_rules}", shell=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)

    def load_rules(self, ind: int):
        self._ip2rules(ind)
        subprocess.run(f"iptables-restore < {self.new_rules[ind]}", shell=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
        return self.test_sizes[ind]

    def _ip2rules(self, ind):
        ip_set = self._read_test(ind)
        new_rule = self.new_rules[ind]
        template = Template(self.ruleFormat)
        with open(new_rule, mode="w", encoding="utf-8") as rule:
            rule.write("*filter\n")
            [rule.write(template.substitute(ip=ipv4)) for ipv4 in ip_set]
            rule.write("COMMIT\n")

    def _start(self):
        subprocess.run("service iptables start", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def _stop(self):
        subprocess.run("service iptables stop", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class XDP(Firewall):
    ruleFormat = "-A INPUT -s ${ip} -m comment --comment \"benchmark\" -j DROP\n"
    prefix = "xdp"
    rule_ext = ".csv"

    def __init__(self, ips: list, **kwargs):
        super().__init__(ips, **kwargs, prefix=self.prefix, rule_ext=self.rule_ext)
        self.config = hmdl.conf
        self.xdp = hmdl.Hmdl(hmdl.Conf(self.config))

    def _save_rules(self):
        self.xdp.data.db.to_csv(self.old_rules, index=False)

    def _restore_rules(self):
        self.xdp.remove_rules(self.xdp.data.db)
        rules = pd.read_csv(self.old_rules)
        self.xdp.add_rules(rules)

    def load_rules(self, ind: int):
        self._ip2rules(ind)
        self.xdp.remove_rules(self.xdp.data.db)
        rules = pd.read_csv(self.new_rules[ind])
        self.xdp.add_rules(rules)
        self.xdp.data.db = rules

    def _ip2rules(self, ind):
        df = self._read_test(ind)
        new_rule = self.new_rules[ind]
        df_ip = df.apply(lambda x: x.split("/")[0])
        df_mask = df.apply(lambda x: x.split("/")[1])
        df = pd.DataFrame({"IP": df_ip, "MASK": df_mask, "RULE": [1]*len(df_mask), "IFF": [2]*len(df_mask)})
        df.to_csv(new_rule, index=False)

    def _start(self):
        self.xdp.attach()

    def _stop(self):
        self.xdp.detach()
