import argparse
import json
import subprocess
import os
import sys
import struct
from typing import List, Dict, Union

# --- CONFIGURATION ---
# Check your C struct! 
# We assume: CPU (4 bytes), PAD (4 bytes), TSC (8 bytes), TIME_NS (8 bytes), ADDR (8 bytes)
# If your binary is 32-bit, the last 'Q' might need to be 'I'.
RECORD_FMT = "<IIQQQ"  
RECORD_SIZE = struct.calcsize(RECORD_FMT)

def symbolize(addr2line_bin: str, binary: str, addrs_abs: List[int], base: Union[int, None], trim_path: bool) -> Dict[str, str]:
    """Runs addr2line to resolve addresses to names."""
    unique_addrs = sorted(set(addrs_abs))
    if not unique_addrs:
        return {}

    offsets = [(a - base) if base is not None else a for a in unique_addrs]
    
    if not os.path.isfile(binary):
        print(f"Error: Binary not found at {binary}")
        sys.exit(1)

    cmd = [addr2line_bin, "-f", "-C", "-e", binary]
    input_data = "\n".join([f"0x{x:x}" for x in offsets])

    print(f"[*] Resolving {len(unique_addrs)} unique addresses...")
    
    try:
        process = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        out, err = process.communicate(input=input_data)
        if process.returncode != 0:
            raise RuntimeError(f"addr2line error: {err}")
    except FileNotFoundError:
        print("Error: 'addr2line' not installed or not in PATH.")
        sys.exit(1)

    lines = out.splitlines()
    mapping = {}
    
    idx = 0
    for abs_addr in unique_addrs:
        if idx + 1 >= len(lines):
            break
            
        func = lines[idx].strip()
        loc = lines[idx+1].strip()
        idx += 2
        
        if trim_path and ":" in loc:
            try:
                path, linenum = loc.rsplit(":", 1)
                loc = f"{os.path.basename(path)}:{linenum}"
            except ValueError:
                pass

        label = loc if func == "??" else f"{func}\n{loc}"
        mapping[str(abs_addr)] = label

    return mapping

def read_trace_bin(filename):
    """Reads the binary trace file and returns a list of addresses."""
    addresses = []
    
    try:
        file_size = os.path.getsize(filename)
        print(f"[*] Opening binary trace: {filename} ({file_size} bytes)")
        
        # NOTE: "rb" is crucial here to avoid the 'utf-8' error
        with open(filename, "rb") as f:
            while True:
                data = f.read(RECORD_SIZE)
                if not data or len(data) < RECORD_SIZE:
                    break

                # Unpack: cpu, pad, tsc, time_ns, value
                unpacked = struct.unpack(RECORD_FMT, data)
                
                # We assume 'value' (the address) is the 5th item (index 4)
                address = unpacked[4]
                addresses.append(address)
                
    except OSError as e:
        print(f"Error opening {filename}: {e}")
        sys.exit(1)
    except struct.error as e:
        print(f"Struct unpacking error. Is RECORD_FMT correct? Error: {e}")
        sys.exit(1)
        
    return addresses

def main():
    parser = argparse.ArgumentParser(description="Generate symbol map from binary trace.")
    parser.add_argument("--binary", required=True, help="Path to the executable binary")
    parser.add_argument("--input", required=True, help="Path to the binary trace file (.bin)")
    parser.add_argument("--output", default="symbols.json", help="Output JSON file")
    parser.add_argument("--addr2line", default="addr2line", help="Path to addr2line binary")
    parser.add_argument("--base", type=lambda x: int(x,0), help="Base address offset (if PIE/ASLR)")
    parser.add_argument("--no-trim", action="store_true", help="Do not shorten file paths")

    args = parser.parse_args()

    # 1. READ BINARY (The fix is ensuring we call this function)
    addrs = read_trace_bin(args.input)

    if not addrs:
        print("No addresses found in trace file.")
        sys.exit(1)
        
    print(f"[*] Read {len(addrs)} records. Found {len(set(addrs))} unique addresses.")

    # 2. RESOLVE
    mapping = symbolize(
        args.addr2line, 
        args.binary, 
        addrs, 
        args.base, 
        not args.no_trim
    )

    # 3. SAVE
    with open(args.output, 'w') as f:
        json.dump(mapping, f, indent=2)
    
    print(f"[+] Saved symbol map to {args.output}")

if __name__ == "__main__":
    main()

# python3 generate_symbols.py --binary ./example-program2 --input trace.bin --output symbols.json
# python3 generate_symbols.py --binary ~/Codes/cpu2017/benchspec/CPU/505.mcf_r/run/run_base_refrate_ali-test1-m64.0000/mcf_r_base.ali-test1-m64 --input trace.bin --output symbols.json