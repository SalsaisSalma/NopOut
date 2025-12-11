from capstone import *
from capstone.x86 import *
import sys
from elftools.elf.elffile import ELFFile
import pefile
from pwn import ELF

def get_arch_and_mode(bin_path):
    with open(bin_path, 'rb') as fp:
        magic = fp.read(5)

    if magic.startswith(b"MZ"): # if is pe
        file_format = "pe"
        pe = pefile.PE(bin_path)
        if pe.FILE_HEADER.Machine == 0x8664: # amd64 (64 bit)
            arch = CS_ARCH_X86
            mode = CS_MODE_64
            print("PE x86_64")
        elif pe.FILE_HEADER.Machine == 0x014c: # i386 (32 bit)
            arch = CS_ARCH_X86
            mode = CS_MODE_32
            print("PE x86_32")
        else:
            print("not a valid pe header")
            exit(1)
        
    elif magic.startswith(b'\x7fELF'):
        file_format = "elf"
        with open(bin_path, 'rb') as f:
            elf = ELFFile(f)
            arch = elf.header['e_machine']
            
            match arch:
                case 'EM_X86_64':
                    arch = CS_ARCH_X86
                    mode = CS_MODE_64
                    print("ELF x86_64")
                case 'EM_386': 
                    arch = CS_ARCH_X86
                    mode = CS_MODE_32
                    print("ELF x86_32")
                    '''
                case 'EM_ARM': # arm 32 bit
                    arch = CS_ARCH_ARM
                    mode = CS_MODE_ARM
                
                case 'EM_AARCH64': # arm 64 bit
                    arch = CS_ARCH_ARM64
                    mode = CS_MODE_ARM
                    '''
                case _:
                    print("didn't recognise architecture")
                    exit(1)

    else:
        print("could not identify header")
        exit(1)
    return file_format, arch, mode

def get_elf_code(bin_path):
    with open(bin_path, "rb") as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name('.text')
        
        ops = text.data()
        addr = text['sh_addr']
        
        return ops, addr


def get_pe_code(bin_path):
    exe = pefile.PE(bin_path)

    for s in exe.sections:
        if b".text" in s.Name:
            code = s.get_data()
            rva = s.VirtualAddress
            return code, rva


def patch_elf(bin_path, md):
    code, addr = get_elf_code(bin_path)

    elf = ELF(bin_path)
    # print(hex(elf.plt['ptrace']))
        
    try: 
        # patch call ptrace in .text
        ptrace = elf.plt['ptrace']
        for i in md.disasm(code, addr):
            if i.id == X86_INS_CALL:
                if i.operands[0].type == X86_OP_IMM:
                    if i.operands[0].imm == ptrace:
                        print(f"ptrace present at {hex(ptrace)}")
                        print(f"{hex(i.address)}:\t{i.mnemonic}\t{i.op_str}")
    
    except:
        #TODO test
        prev = None
        for i in md.disasm(code, addr):
            if i.id == X86_INS_SYSCALL:
                if prev.id == X86_INS_MOV:
                    if len(prev.operands) == 2:
                        if prev.operands[0] == X86_REG_RAX and prev.operands[1].type == X86_OP_IMM:
                            if prev.operands[1].imm == 26:
                                print(f"syscall 101 found at {hex(prev.address)}")
                                print(f"{hex(prev.address)}:\t{prev.mnemonic}\t{prev.op_str}")
                                print(f"{hex(i.address)}:\t{i.mnemonic}\t{i.op_str}")
                
            if i.id == X86_INS_INT:
                if prev.id == X86_INS_MOV:
                    if len(prev.operands) == 2:
                        if prev.operands[0] == X86_REG_EAX and prev.operands[1].type == X86_OP_IMM:
                            if prev.operands[1].imm == 101:
                                print(f"syscall 101 found at {hex(prev.address)}")
                                print(f"{hex(prev.address)}:\t{prev.mnemonic}\t{prev.op_str}")
                                print(f"{hex(i.address)}:\t{i.mnemonic}\t{i.op_str}")

            prev = i
    
    


def patch_pe(bin_path, md):
    code, addr = get_pe_code(bin_path)
    for i in md.disasm(code, addr):
        print(f"{hex(i.address)}:\t{i.mnemonic}\t{i.op_str}")



def main():
    if len(sys.argv) != 2:
        print("Usage: python nopout.py <<path_to_your_binary>>")
        exit(1)
    bin_path = sys.argv[1]
    file_format, arch, mode = get_arch_and_mode(bin_path)

    print(f"file format: {file_format}\narch: {arch}\nmode: {mode}")
    
    md = Cs(arch, mode)
    md.detail = True
    
    

    match file_format:
        case "elf":
            patch_elf(bin_path, md)
            
        case "pe":
            patch_pe(bin_path, md)
            
        case _:
            print("architechture not supported")
            exit(1)

    
if __name__ == "__main__":
    main()
