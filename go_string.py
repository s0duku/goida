import idaapi
import idautils
import ida_search
import idc
import ida_bytes

# 部分恢复 go 二进制的字符串
# 基于 字符串 加载的指令特征 
# lea REG MEM;xxx;mov REG STR_LEN
# mov REG OFFSET;xxx;mov REG STR_LEN

# 保守恢复字符串，太激进的用这种代码特征有时候把一些 IDA 识别的 golang 原型给恢复掉了
def check_possible_string(ea,size):
    test_chars = [c for c in range(ord('a'),ord('z'))]
    test_chars += [c for c in range(ord('A'),ord('Z'))]
    test_chars += [c for c in range(ord('0'),ord('9'))]
    test_chars += [ord(c) for c in ["\n","\r"," ","_","-","/","\\",".",",",":",";","?","!","@","#","$","%","^","&","*","(",")","+","=","{","}","[","]","|","<",">","~","`","'","\""]]
    for i in range(size):
        c = idc.get_bytes(ea+i,1)
        if not ord(c) in test_chars:
            return False
    return True


def create_go_string(ins):
    # 判断是否是 golang 的 load string 特征
    # 获取 intel 指令名
    insname = ins.get_canon_mnem()
    str_addr = None
    size = None
    
    while True:
        if insname == 'lea':
            if ins.Op1.type == idaapi.o_reg and ins.Op2.type == idaapi.o_mem:
                str_addr = ins.Op2.addr
                if idc.get_segm_name(str_addr) == '.rodata':
                    break
        elif insname == 'mov':
            if ins.Op1.type == idaapi.o_reg and ins.Op2.type == idaapi.o_imm:
                str_addr = ins.Op2.value
                if idc.get_segm_name(str_addr) == '.rodata':
                    break

        return ida_search.find_code(ins.ea, ida_search.SEARCH_DOWN)

    # 获取下两条指令
    ins_addr = ida_search.find_code(ida_search.find_code(ins.ea, ida_search.SEARCH_DOWN),ida_search.SEARCH_DOWN)
    ins_ = idautils.DecodeInstruction(ins_addr)
    if ins_ and ins_.get_canon_mnem() == 'mov' and ins_.Op2.type == idaapi.o_imm:
        size = ins_.Op2.value
        if size > 0 and check_possible_string(str_addr,size):
            print(hex(ins.ea),hex(str_addr),size)
            # 删除原始定义
            ida_bytes.del_items(str_addr)
            ida_bytes.create_strlit(str_addr, size, idc.STRTYPE_C)
            return ida_search.find_code(ins_.ea, ida_search.SEARCH_DOWN)

    return ida_search.find_code(ins.ea, ida_search.SEARCH_DOWN)



def stringfy(ea):
    ida_func = idaapi.get_func(ea)
    pos = ida_func.start_ea
    while pos < ida_func.end_ea:
        ins = idautils.DecodeInstruction(pos)
        if not ins:
            break
        # 尝试每条指令
        pos = create_go_string(ins)


def stringfy_all_function():
    for func in idautils.Functions():
        stringfy(func)


if __name__ == '__main__':
    stringfy_all_function()