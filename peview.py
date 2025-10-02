#!/usr/bin/env python3
# Usage: python peview.py <filename>

import sys
import os
import datetime as dt

import pefile
import colorama

colorama.init(autoreset=True)

def human_ts(ts):
    try:
        return dt.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)

def main():
    if len(sys.argv) != 2:
        print(colorama.Fore.RED + f"Usage: {sys.argv[0]} <file>", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.isfile(path):
        print(colorama.Fore.RED + "Error: File not found!", file=sys.stderr)
        sys.exit(2)

    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError as e:
        print(colorama.Fore.RED + f"Invalid PE: {e}", file=sys.stderr)
        sys.exit(3)

    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER

    print(colorama.Fore.MAGENTA + "=== General Information ===")
    print(f"{colorama.Fore.CYAN}File:{colorama.Fore.GREEN}           {os.path.basename(path)}")
    print(f"{colorama.Fore.CYAN}Machine:{colorama.Fore.GREEN}        0x{fh.Machine:04X}")
    print(f"{colorama.Fore.CYAN}PE Type:{colorama.Fore.GREEN}        {'PE32+' if oh.Magic == 0x20B else 'PE32' if oh.Magic == 0x10B else hex(oh.Magic)}")
    print(f"{colorama.Fore.CYAN}Entry Point:{colorama.Fore.GREEN}    0x{oh.AddressOfEntryPoint:08X}")
    print(f"{colorama.Fore.CYAN}ImageBase:{colorama.Fore.GREEN}      0x{oh.ImageBase:X}")
    print(f"{colorama.Fore.CYAN}Subsystem:{colorama.Fore.GREEN}      {oh.Subsystem}")
    print(f"{colorama.Fore.CYAN}Timestamp:{colorama.Fore.GREEN}      {fh.TimeDateStamp} ({human_ts(fh.TimeDateStamp)})")
    print(f"{colorama.Fore.CYAN}Section Count:{colorama.Fore.GREEN}  {fh.NumberOfSections}")
    print()

    print(colorama.Fore.MAGENTA + "=== Sections ===")
    print(f"{colorama.Fore.CYAN}{'Name':<12} {'VirtAddr':>10} {'VirtSize':>10} {'RawPtr':>10} {'RawSize':>10}")
    for s in pe.sections:
        name = s.Name.decode(errors="ignore").rstrip("\x00")
        print(f"{colorama.Fore.GREEN}{name:<12} {colorama.Fore.YELLOW}0x{s.VirtualAddress:08X} {s.Misc_VirtualSize:10} {colorama.Fore.YELLOW}0x{s.PointerToRawData:08X} {s.SizeOfRawData:10}")
    print()

    print(colorama.Fore.MAGENTA + "=== Imports ===")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="ignore")
            print(f"{colorama.Fore.CYAN}[{colorama.Fore.GREEN}{dll}{colorama.Fore.CYAN}]")
            for imp in entry.imports:
                name = imp.name.decode(errors="ignore") if imp.name else f"ord#{imp.ordinal}"
                print(f"  {colorama.Fore.YELLOW}0x{imp.address:08X}  {colorama.Fore.GREEN}{name}")
    else:
        print(colorama.Fore.YELLOW + "(None)")
    print()

    print(colorama.Fore.MAGENTA + "=== Exports ===")
    try:
        dir_export = pe.DIRECTORY_ENTRY_EXPORT
        if dir_export and dir_export.symbols:
            for sym in dir_export.symbols:
                name = sym.name.decode(errors="ignore") if sym.name else ""
                print(f"  {colorama.Fore.CYAN}ord {sym.ordinal:<4} {colorama.Fore.YELLOW}RVA 0x{sym.address:08X}  {colorama.Fore.GREEN}{name}")
        else:
            print(colorama.Fore.YELLOW + "(None)")
    except AttributeError:
        print(colorama.Fore.YELLOW + "(None)")

if __name__ == "__main__":
    main()
