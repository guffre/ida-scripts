import idc
import idaapi
import time

CALL_API_COLOR = 0x407070
CALL_COLOR     = 0x313191
XOR_COLOR      = 0x007138
addr           = 0

def IsAPICall(addr):
    for xref in XrefsFrom(addr):
        flags = GetFunctionFlags(xref.to)
        if (flags & FUNC_LIB) or (flags & FUNC_THUNK):
            return 1
    return 0

while addr != BADADDR:
    addr = NextHead(addr)
    mnem = GetMnem(addr)
    if mnem == "call":
        if IsAPICall(addr):
            SetColor(addr, CIC_ITEM, CALL_API_COLOR)
        else:
            SetColor(addr, CIC_ITEM, CALL_COLOR)
    elif mnem == "xor":
        if GetOpnd(addr,0) != GetOpnd(addr,1):
            SetColor(addr, CIC_ITEM, XOR_COLOR)

print("IDA Autohighlight Script has finished!")
