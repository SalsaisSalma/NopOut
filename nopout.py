from capstone import *
import sys
from elftools.elf.elffile import ELFFile
import pefile


def get_arch_and_mode(bin_path):
    with open(bin_path, 'rb') as fp:
        magic = fp.read(5)

    if magic.startswith(b"MZ"): # if is pe
        file_format = "pe"
        pe = pefile.PE(bin_path)
        if pe.FILE_HEADER.Machine == 0x8664: # amd64 (64 bit)
            arch = CS_ARCH_X86
            mode = CS_MODE_64
        elif pe.FILE_HEADER.Machine == 0x014c: # i386 (32 bit)
            arch = CS_ARCH_X86
            mode = CS_MODE_32
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
                
                case 'EM_386': 
                    arch = CS_ARCH_X86
                    mode = CS_MODE_32
                
                case 'EM_ARM': # arm 32 bit
                    arch = CS_ARCH_ARM
                    mode = CS_MODE_ARM
                
                case 'EM_AARCH64': # arm 64 bit
                    arch = CS_ARCH_ARM64
                    mode = CS_MODE_ARM
    
                case _:
                    print("binary can only be 64 or 32 bit")
                    exit(1)

    else:
        print("could not identify header")
        exit(1)
    return file_format, arch, mode

def get_elf_code(bin_path):
    pass

def get_pe_code(bin_path):
    pass


def main():
    if len(sys.argv) != 2:
        print("Usage: python nopout.py <<path_to_your_binary>>")
        exit(1)
    bin_path = sys.argv[1]
    file_format, arch, mode = get_arch_and_mode(bin_path)

    match file_format:
        case "elf":
            code = get_elf_code(bin_path)
        case "pe":
            code = get_pe_code(bin_path)
        case _:
            print("architechture not supported")
            exit(1)

    print(f"file format: {file_format}\narch: {arch}\nmode: {mode}")
    md = Cs(arch, mode)
    md.detail = True

if __name__ == "__main__":
    main()
