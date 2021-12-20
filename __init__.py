from binaryninja import *
import lief
from tempfile import NamedTemporaryFile
import platform

def generate_c(bv, liefbin):
    
    c_code = """
    int main (int argc, char** argv) {

    }
    """
    pass

def generate_so(bv, new_filename):
    tempbin = NamedTemporaryFile()
    bv.save(tempbin.name)
    liefbin = lief.parse(tempbin.name)

    print(len(liefbin.exported_functions))
    for func in liefbin.exported_functions:
        print(f'{func.name} {hex(func.address)}')

    print("")
    liefbin_exported_names = list(map(lambda x: x.name, liefbin.exported_functions))

    print(liefbin_exported_names)


    for func in set(bv.functions):
        # Check if function is already in elif exported functions
        if func.name not in liefbin_exported_names:
            if func.symbol.type == SymbolType.FunctionSymbol:
                liefbin.add_exported_function(func.start, func.name)
            
    print("")
    print(len(liefbin.exported_functions))
    for func in liefbin.exported_functions:
        print(f'{func.name} {hex(func.address)}')
    
    # Check if it uses glibc >= 2.29. You have to patch or else you will get dlopen error: cannot dynamically load position-independent executable
    # Read more on https://lief-project.github.io/doc/latest/tutdlopen%20error:%20cannot%20dynamically%20load%20position-independent%20executableorials/08_elf_bin2lib.html
    if float(platform.libc_ver(tempbin.name)[1]) >= 2.29:
        liefbin[lief.ELF.DYNAMIC_TAGS.FLAGS_1].remove(lief.ELF.DYNAMIC_FLAGS_1.PIE)

    liefbin.write(new_filename + '.so')

    

def main(bv):
    org_filename = bv.file.original_filename.split('/')[-1]
    new_filename = get_save_filename_input("filename:", None, org_filename)
    generate_so(bv, new_filename)


PluginCommand.register('binlief', 'Converts Elf into Library File', main)

