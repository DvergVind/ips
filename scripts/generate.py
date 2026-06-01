import bisect as _B
import ipaddress as _I
import time as _T
import urllib.request as _R

_D = bytes.fromhex
_U = [
    _D("68747470733a2f2f616e746966696c7465722e646f776e6c6f61642f6c6973742f69702e6c7374").decode(),
    _D("68747470733a2f2f616e746966696c7465722e646f776e6c6f61642f6c6973742f7375626e65742e6c7374").decode(),
]
_AU = _D("68747470733a2f2f7261772e67697468756275736572636f6e74656e742e636f6d2f697076657273652f61732d69702d626c6f636b732f6d61737465722f61732f7b61736e7d2f697076342d616767726567617465642e747874").decode()
_H = {
    _D("557365722d4167656e74").decode(): _D("4d6f7a696c6c612f352e302028636f6d70617469626c653b2069702d757064617465722f312e3029").decode(),
    _D("416363657074").decode(): _D("746578742f706c61696e").decode(),
}
_AL = [(0x3417, "cloudflare"), (0x407d, "amazon"), (0x8e6b, "github")]


def _F(_u, _t=0x78, _r=0x3):
    _q = _R.Request(_u, headers=_H)
    for _i in range(0x1, _r + 0x1):
        try:
            with _R.urlopen(_q, timeout=_t) as _z:
                return _z.read()
        except Exception as _e:
            if _i == _r:
                raise
            _T.sleep(0x5 * _i)


def _P(_n):
    _c = _F(_AU.format(asn=_n)).decode("utf-8")
    _v = []
    for _l in _c.splitlines():
        _l = _l.strip()
        if not _l or _l.startswith("#"):
            continue
        try:
            _v.append(_I.ip_network(_l, strict=False))
        except ValueError:
            pass
    return list(_I.collapse_addresses(_v))


def _G():
    _v = []
    for _u in _U:
        _c = _F(_u).decode("utf-8")
        for _l in _c.splitlines():
            _l = _l.strip()
            if not _l or _l.startswith("#"):
                continue
            try:
                _v.append(_I.ip_network(_l, strict=False))
            except ValueError:
                pass
    return list(_I.collapse_addresses(_v))


def _X(_s, _a):
    _sa = sorted(_a, key=lambda _n: _n.network_address)
    _ss = [int(_n.network_address) for _n in _sa]
    _se = [int(_n.broadcast_address) for _n in _sa]
    _o = []
    for _b in _s:
        _bs = int(_b.network_address)
        _be = int(_b.broadcast_address)
        _lo = _B.bisect_left(_se, _bs)
        _hi = _B.bisect_right(_ss, _be)
        for _i in range(_lo, _hi):
            _st = max(_bs, _ss[_i])
            _en = min(_be, _se[_i])
            if _st <= _en:
                _o.extend(_I.summarize_address_range(_I.IPv4Address(_st), _I.IPv4Address(_en)))
    return list(_I.collapse_addresses(_o))


def _W1(_p, _n):
    _k = _D("49502d434944522c").decode()
    with open(_p, "w") as _o:
        for _v in _n:
            _o.write(_k + str(_v) + "\n")


def _W2(_p, _n):
    _h = _D("20202d20").decode()
    with open(_p, "w") as _o:
        _o.write(_D("7061796c6f61643a0a").decode())
        for _v in _n:
            _o.write(_h + str(_v) + "\n")


def _M():
    _i = _G()
    for _an, _nm in _AL:
        _pr = _P(_an)
        _ns = _X(_i, _pr)
        _W1(_D("72756c65732f536861646f77726f636b65742f").decode() + _nm + _D("2e6c697374").decode(), _ns)
        _W2(_D("72756c65732f4d69686f6d6f2f").decode() + _nm + _D("2e79616d6c").decode(), _ns)


if __name__ == "__main__":
    _M()
