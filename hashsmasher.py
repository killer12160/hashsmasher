#!/usr/bin/env python3
import subprocess
import os
import sys
import argparse
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""{Fore.RED}
 ▄  █ ██      ▄▄▄▄▄    ▄  █    ▄▄▄▄▄   █▀▄▀█ ██      ▄▄▄▄▄    ▄  █ ▄███▄   █▄▄▄▄ 
█   █ █ █    █     ▀▄ █   █   █     ▀▄ █ █ █ █ █    █     ▀▄ █   █ █▀   ▀  █  ▄▀ 
██▀▀█ █▄▄█ ▄  ▀▀▀▀▄   ██▀▀█ ▄  ▀▀▀▀▄   █ ▄ █ █▄▄█ ▄  ▀▀▀▀▄   ██▀▀█ ██▄▄    █▀▀▌  
█   █ █  █  ▀▄▄▄▄▀    █   █  ▀▄▄▄▄▀    █   █ █  █  ▀▄▄▄▄▀    █   █ █▄   ▄▀ █  █  
   █     █               █                █     █               █  ▀███▀     █   
  ▀     █               ▀                ▀     █               ▀            ▀    
       ▀                                      ▀                                                               

{Style.RESET_ALL}{Fore.CYAN}             ⚡ Fast GPU/CPU Hash Cracker ⚡{Style.RESET_ALL}
"""

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BINARY_PATH = os.path.join(SCRIPT_DIR, "rust_hash_cracker/target/release/rust_hash_cracker")

def build_rust_binary():
    """Builds the Rust project if the binary is missing."""
    print(f"{Fore.YELLOW}[!] Rust binary not found. Building with cargo...{Style.RESET_ALL}")
    try:
        subprocess.run(
            ["cargo", "build", "--release"],
            cwd=os.path.join(SCRIPT_DIR, "rust_hash_cracker"),
            check=True
        )
        print(f"{Fore.GREEN}[+] Build complete!{Style.RESET_ALL}\n")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[!] Failed to build Rust binary. Is cargo installed?{Style.RESET_ALL}")
        sys.exit(1)

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="HashSmasher 🔨 - Fast GPU/CPU Hash Cracker"
    )
    parser.add_argument(
        "-H", "--hash",
        help="Target hash (MD5, SHA1, SHA256)"
    )
    parser.add_argument(
        "-w", "--wordlist",
        help="Path to wordlist file"
    )

    args = parser.parse_args()

    
    if not os.path.exists(BINARY_PATH):
        build_rust_binary()

    
    if not args.hash:
        args.hash = input(f"{Fore.CYAN}[?]{Style.RESET_ALL} Enter hash: ").strip()
    if not args.wordlist:
        args.wordlist = input(f"{Fore.CYAN}[?]{Style.RESET_ALL} Enter wordlist path: ").strip()

    
    args.wordlist = os.path.expanduser(args.wordlist)

    
    cmd = [
        BINARY_PATH,
        "--hash", args.hash,
        "--wordlist", args.wordlist
    ]

    print(f"\n{Fore.GREEN}[+] Running HashSmasher...{Style.RESET_ALL}\n")
    subprocess.run(cmd)

if __name__ == "__main__":
    main()

