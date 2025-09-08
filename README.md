# HashSmasher 🔨

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge\&logo=rust\&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge\&logo=python\&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

```
 ▄  █ ██      ▄▄▄▄▄    ▄  █    ▄▄▄▄▄   █▀▄▀█ ██      ▄▄▄▄▄    ▄  █ ▄███▄   █▄▄▄▄ 
█   █ █ █    █     ▀▄ █   █   █     ▀▄ █ █ █ █ █    █     ▀▄ █   █ █▀   ▀  █  ▄▀ 
██▀▀█ █▄▄█ ▄  ▀▀▀▀▄   ██▀▀█ ▄  ▀▀▀▀▄   █ ▄ █ █▄▄█ ▄  ▀▀▀▀▄   ██▀▀█ ██▄▄    █▀▀▌  
█   █ █  █  ▀▄▄▄▄▀    █   █  ▀▄▄▄▄▀    █   █ █  █  ▀▄▄▄▄▀    █   █ █▄   ▄▀ █  █  
   █     █               █                █     █               █  ▀███▀     █   
  ▀     █               ▀                ▀     █               ▀            ▀    
       ▀                                      ▀                                                               
```

⚡ **Fast GPU/CPU Hash Cracker** built with Rust (core) + Python (interface).
HashSmasher is designed to be **simple, fast, and user-friendly** with GPU acceleration (OpenCL) and automatic CPU fallback.

---

## ✨ Features

* Crack **MD5 / SHA1 / SHA256** hashes
* **GPU acceleration** via OpenCL (with CPU fallback)
* **Python CLI**
* Two usage modes:

  * Interactive prompts (`./hashsmasher.py`)
  * Command-line arguments (`./hashsmasher.py -H <hash> -w <wordlist>`)

---

## ⚙️ Installation

### 1. Install Rust + Cargo

Most Linux distros don’t ship Rust by default. Install it with:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

Verify installation:

```bash
rustc --version
cargo --version
```

### 2. Install Python dependencies

Make sure you have Python 3.8+ installed. Then install:

```bash
pip install colorama
```

### 3. Clone and build HashSmasher

```bash
git clone https://github.com/killer12160/hashsmasher.git
cd hashsmasher
chmod +x hashsmasher.py
cargo build --release --manifest-path rust_hash_cracker/Cargo.toml
```

This will generate the optimized binary at:

```
rust_hash_cracker/target/release/rust_hash_cracker
```

---

## 🚀 Usage

### Interactive mode

```bash
./hashsmasher.py
```

You’ll be prompted for the hash and wordlist path.

---

### Direct CLI mode

```bash
./hashsmasher.py -H <hash> -w <wordlist>
```



## 🛠 Dependencies

* Rust (`cargo`, `rustc`)
* Python 3.8+
* Python `colorama` package
* OpenCL runtime (GPU drivers installed)

---

## 📝 License

MIT License — feel free to fork, hack, and improve 🚀

---
