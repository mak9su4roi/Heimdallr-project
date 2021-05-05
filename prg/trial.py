import pandas as pd
from functools import reduce
import ifaddr

# to_bin = lambda ip: reduce(lambda x, y: x+y, [int(el) << (8*ind) for ind, el in enumerate(reversed(ip.split(".")))])
# d = {'addr':  ["1.1.128.1", "1.1.2.1", "1.2.1.1"],
#      'mask': [20, 24, 24]}
# df = pd.DataFrame(data=d)
# length = 17
# ip = "1.1.200.1"
# etalon = to_bin(ip) >> (32-length)
#
#
# print(df[(df['mask'] >= length) & (df['addr'].apply(lambda ip: to_bin(ip) >> (32-length)) == etalon)])

d = {'addr':  ["1.1.128.1","1.1.128.1","1.1.128.1"],
     'mask': [20,20,20],
     'misk': [0, 0, 0]}
df = pd.DataFrame(data=d)
d2, d1 = df.iloc[0:2][['addr', 'mask']].T.values
print(d2)
