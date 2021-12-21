from binaryninja import *
import lief
from tempfile import NamedTemporaryFile
import platform


def generate_c(exported_func, liefbin, org_filename, new_directory):
    # Write the main code
    main_code = fr"""#include "{org_filename}.h"

int main (int argc, char** argv) {{
    void* handler = dlopen("./{org_filename}.so", RTLD_LAZY);
    if (!handler) {{
        printf("dlopen failed: %s\n", dlerror());
        return 1;
    }}

    resolve_sym(handler);
}}
    """

    with open(f"{new_directory}/main.c", "w") as f:
        f.write(main_code)

    # Write the header
    ## Generate typedef
    typedef_codes = ""
    for func in exported_func:
        function_proto = (
            "".join(map(lambda x: str(x), func.type_tokens))
            .replace("(", " ")
            .replace(")", "")
            .split(" ")
        )
        # remove things like __noreturn
        function_proto = [f for f in function_proto if "__" not in f]
        ret_type = function_proto.pop(0)
        func_name = function_proto.pop(0)
        func_args = function_proto

        typedef_codes += (
            f"typedef {ret_type} (*{func_name}_t)({' '.join(func_args)});\n"
        )

    ## extern variables
    extern_codes = ""
    for func in exported_func:
        extern_codes += f"extern {func.name}_t {func.name};\n"

    ## Generate function prototypes
    header_code = fr"""#ifndef {org_filename.upper()}_H
#define {org_filename.upper()}_H
#include <stdio.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

{typedef_codes}

{extern_codes}

void resolve_sym(void *handle);
#endif
    """

    with open(f"{new_directory}/{org_filename}.h", "w") as f:
        f.write(header_code)

    # Write resolve file
    global_func_var_codes = ""

    for func in exported_func:
        global_func_var_codes += f"{func.name}_t {func.name};\n"

    resolved_func_codes = ""
    for fun in exported_func:
        resolved_func_codes += f'\t{fun.name} = dlsym(handle, "{fun.name}");\n'

    resolve_code = fr"""#include "{org_filename}.h"
{global_func_var_codes}

void resolve_sym(void *handle) {{
{resolved_func_codes}
}}
    """
    with open(f"{new_directory}/{org_filename}.c", "w") as f:
        f.write(resolve_code)

    makefile_code = fr"""CC=gcc

all: {org_filename}

{org_filename}: main.c {org_filename}.c
	$(CC) main.c {org_filename}.c -o {org_filename} -ldl"""

    with open(f"{new_directory}/Makefile", "w") as f:
        f.write(makefile_code)


def generate_so(bv, org_filename, new_directory):
    tempbin = NamedTemporaryFile()
    bv.save(tempbin.name)
    liefbin = lief.parse(tempbin.name)
    liefbin_exported_names = list(map(lambda x: x.name, liefbin.exported_functions))
    exported_bv_func = []
    for func in set(bv.functions):
        # Check if function is already in elif exported functions
        if func.name not in liefbin_exported_names:
            if func.symbol.type == SymbolType.FunctionSymbol:
                if func.name != "main" and (not func.name.startswith("_")):
                    liefbin.add_exported_function(func.start, func.name)
                    print(func.name)
                    exported_bv_func.append(func)

    # Check if it uses glibc >= 2.29. You have to patch or else you will get dlopen error: cannot dynamically load position-independent executable
    # Read more on https://lief-project.github.io/doc/latest/tutdlopen%20error:%20cannot%20dynamically%20load%20position-independent%20executableorials/08_elf_bin2lib.html
    if float(platform.libc_ver(tempbin.name)[1]) >= 2.29:
        liefbin[lief.ELF.DYNAMIC_TAGS.FLAGS_1].remove(lief.ELF.DYNAMIC_FLAGS_1.PIE)

    liefbin.write(f"{new_directory}/{org_filename}.so")
    generate_c(exported_bv_func, liefbin, org_filename, new_directory)


def main(bv):
    org_filename = bv.file.original_filename.split("/")[-1]
    new_directory = get_directory_name_input("Directory:")
    generate_so(bv, org_filename, new_directory)


PluginCommand.register("binlief", "Converts Elf into Library File", main)
