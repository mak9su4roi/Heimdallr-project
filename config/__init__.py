import json
from string import Template

loc = __file__.strip("__init__.py")

with open(f"{loc}config.json", mode="r", encoding="utf-8") as file:
    config = json.load(file)

with open(f"{loc}.hmdl.json", mode="r", encoding="utf-8") as file:
    f_config = json.load(file)
    iff = f_config["device"]
    imm = {"hash": {"iff": iff}, "trie": {"iff": iff}, "cash": {"iff": iff},
           "data": {"loc": loc}, "util": {"loc": loc}, "launcher": {"loc": loc}, "xdp": {"loc": loc}}
    templates = {k: v for k, v in f_config.items() if k in imm}
    f_config = {k: (Template(v).substitute(**imm[k]) if k in imm else v)
                for k, v in f_config.items()}


def save_config(conf):
    with open(f"{loc}.hmdl.json", mode="w", encoding="utf-8") as saved:
        json.dump({**{k: v for k, v in conf.items() if k not in templates}, **templates}, saved, indent=4)
