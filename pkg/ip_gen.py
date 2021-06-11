import argparse
from random import randint
import pandas as pd


def positive_int(arg):
    arg = int(arg)
    if arg <= 0:
        raise argparse.ArgumentTypeError("Argument should be positive integer")
    return arg


def octet(arg):
    arg = positive_int(arg)
    if arg > 255:
        raise argparse.ArgumentTypeError("Argument should be smaller le than 255")
    return arg


def proportion(arg):
    arg = arg.split(",")
    arg = {int(mask): float(prp)
           for mask, prp in [el.split(":") for el in arg]
           if 8 <= int(mask) <= 32}
    num = sum(float(el) for el in arg.values())
    if num > 1:
        raise argparse.ArgumentTypeError("Wrong proportion")
    if 32 not in arg:
        arg[32] = 0
    if num < 1:
        arg[32] += 1 - num
    return arg


def gen_ip(old, mask):
    mask -= 8
    mask = 2**mask-1
    while True:
        adr = randint(1, mask)
        if adr not in old:
            old.add(adr)
            break
    return f"{adr&0xFF}.{(adr>>8)&0xFF}.{(adr>>16)&0xFF}"


def ip2csv(fname, **conf):
    dist = proportion(conf["dist"])
    num = positive_int(conf["num"])
    first_oct = octet(conf["octet"])

    dist = {IPv4: int(num * prp) for IPv4, prp in dist.items()}
    dist[32] += num - sum(dist.values())

    ip_seq = set()

    ips = [f"{first_oct}.{gen_ip(ip_seq, mask)}/{mask}"
           for mask, num in dist.items() for _ in range(num)]
    df = pd.DataFrame(columns=["IPv4"], data=ips)
    df.to_csv(fname, index=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("n", help="number of IPv4 to generate",
                        type=positive_int)
    parser.add_argument("b", help="first octet",
                        type=octet)
    parser.add_argument("-p", "--proportion",
                        type=proportion)
    args = parser.parse_args()
    args.proportion = {IPv4: int(args.n * prp) for IPv4, prp in args.proportion.items()}
    args.proportion[32] += args.n - sum(args.proportion.values())

    ip_seq = set()

    ips = [f"{args.b}.{gen_ip(ip_seq, mask)}/{mask}"
           for mask, num in args.proportion.items() for _ in range(num)]
    df = pd.DataFrame(columns=["IPv4"], data=ips)
    df.to_csv("ip.csv", index=False)


if __name__ == "__main__":
    main()
