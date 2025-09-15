use anyhow::{anyhow, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use opencl3::command_queue::CommandQueue;
use opencl3::context::Context;
use opencl3::device::{get_all_devices, Device, CL_DEVICE_TYPE_ALL};
use opencl3::kernel::{ExecuteKernel, Kernel};
use opencl3::memory::{Buffer, CL_MEM_COPY_HOST_PTR, CL_MEM_READ_ONLY, CL_MEM_READ_WRITE};
use opencl3::program::Program;
use opencl3::types::{cl_int, CL_BLOCKING};
use rayon::prelude::*;
use std::ffi::c_void;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Instant;

use md5;
use sha1::Sha1;
use sha2::Sha256;
use sha1::Digest as Sha1DigestTrait;
use sha2::Digest as Sha2DigestTrait;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long)]
    hash: Option<String>,
    #[arg(long)]
    wpa: Option<String>,
    #[arg(long)]
    wordlist: String,
}

#[derive(Debug, Clone, Copy)]
enum Algo {
    MD5,
    SHA1,
    SHA256,
}

fn detect_algo(hash: &str) -> Result<Algo> {
    match hash.len() {
        32 => Ok(Algo::MD5),
        40 => Ok(Algo::SHA1),
        64 => Ok(Algo::SHA256),
        _ => Err(anyhow!("Unsupported hash length: {}", hash.len())),
    }
}

fn read_wordlist(path: &str) -> Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(reader.lines().filter_map(Result::ok).collect())
}

struct WpaData {
    ssid: String,
    mic: String,
}

fn parse_wpa_file(path: &str) -> Result<WpaData> {
    let content = std::fs::read_to_string(path)?;
    let first_line = content
        .lines()
        .next()
        .ok_or_else(|| anyhow!("Empty WPA file"))?;
    let parts: Vec<&str> = first_line.split(':').collect();
    if parts.len() < 4 {
        return Err(anyhow!("Invalid .22000 format"));
    }
    Ok(WpaData {
        ssid: parts[3].to_string(),
        mic: parts[0].to_string(),
    })
}

fn kernel_path(file: &str) -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(release_dir) = exe.parent() {
            if let Some(target_dir) = release_dir.parent() {
                if let Some(project_dir) = target_dir.parent() {
                    let candidate = project_dir.join("kernels").join(file);
                    if candidate.exists() {
                        return candidate;
                    }
                }
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        let candidate = cwd.join("rust_hash_cracker").join("kernels").join(file);
        if candidate.exists() {
            return candidate;
        }
        let candidate2 = cwd.join("kernels").join(file);
        if candidate2.exists() {
            return candidate2;
        }
    }
    PathBuf::from(file)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let words = read_wordlist(&args.wordlist)?;
    println!("[*] Loaded {} words from {}", words.len(), args.wordlist);

    println!("[*] Initializing OpenCL device...");
    let devices = match get_all_devices(CL_DEVICE_TYPE_ALL) {
        Ok(devs) => devs,
        Err(e) => {
            eprintln!("[!] OpenCL runtime unavailable: {:#}", e);
            println!("[!] Falling back to CPU mode...");
            return cpu_fallback(&args, &words);
        }
    };

    if devices.is_empty() {
        println!("[!] No OpenCL device found → using CPU fallback");
        return cpu_fallback(&args, &words);
    }

    let device_id = devices[0];
    let device = Device::new(device_id);
    let context = match Context::from_device(&device) {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("[!] Failed to create OpenCL context: {:#}", e);
            println!("[!] Falling back to CPU mode...");
            return cpu_fallback(&args, &words);
        }
    };

    let queue = match unsafe { CommandQueue::create_with_properties(&context, device_id, 0, 0) } {
        Ok(q) => q,
        Err(e) => {
            eprintln!("[!] Failed to create command queue: {:#}", e);
            println!("[!] Falling back to CPU mode...");
            return cpu_fallback(&args, &words);
        }
    };

    if let Some(hash) = args.hash.clone() {
        let target_hash = hash.trim().to_lowercase();
        let algo = detect_algo(&target_hash)?;
        println!("[*] Detected algo: {:?}", algo);

        let kernel_file = match algo {
            Algo::MD5 => kernel_path("md5.cl"),
            Algo::SHA1 => kernel_path("sha1.cl"),
            Algo::SHA256 => kernel_path("sha256.cl"),
        };

        println!("[*] Loading kernel from {:?}...", kernel_file);
        let kernel_source = match std::fs::read_to_string(&kernel_file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[!] Failed to read kernel file {:?}: {}", kernel_file, e);
                println!("[!] Falling back to CPU mode...");
                return cpu_fallback(&args, &words);
            }
        };

        let mut program = Program::create_from_source(&context, &kernel_source)?;
        if let Err(_) = program.build(&[device_id], "") {
            if let Ok(log) = program.get_build_log(device_id) {
                eprintln!("❌ Kernel build failed:\n{}", log);
            }
            println!("[!] Falling back to CPU mode...");
            return cpu_fallback(&args, &words);
        }

        let kernel = Kernel::create(&program, "crack")?;
        crack_wordlist(&words, &target_hash, fixed_word_len(), &context, &queue, &kernel)?;
    } else if let Some(wpa_file) = args.wpa.clone() {
        println!("[*] WPA mode selected");
        let wpa = parse_wpa_file(&wpa_file)?;
        println!("[*] SSID: {}", wpa.ssid);

        let kernel_file = kernel_path("wpa.cl");
        println!("[*] Loading kernel from {:?}...", kernel_file);
        let kernel_source = match std::fs::read_to_string(&kernel_file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[!] Failed to read WPA kernel file {:?}: {}", kernel_file, e);
                println!("[!] Falling back to CPU mode...");
                return cpu_fallback(&args, &words);
            }
        };

        let mut program = Program::create_from_source(&context, &kernel_source)?;
        if let Err(_) = program.build(&[device_id], "") {
            if let Ok(log) = program.get_build_log(device_id) {
                eprintln!("❌ WPA Kernel build failed:\n{}", log);
            }
            println!("[!] Falling back to CPU mode...");
            return cpu_fallback(&args, &words);
        }

        let kernel = Kernel::create(&program, "wpa_crack")?;
        crack_wordlist(&words, &wpa.mic, fixed_word_len(), &context, &queue, &kernel)?;
    } else {
        return Err(anyhow!("Must provide either --hash or --wpa"));
    }

    Ok(())
}

fn fixed_word_len() -> usize {
    64
}

fn crack_wordlist(
    words: &[String],
    target_hash: &str,
    fixed_word_len: usize,
    context: &Context,
    queue: &CommandQueue,
    kernel: &Kernel,
) -> Result<()> {
    const BATCH_SIZE: usize = 1_048_576;
    let mut found_password: Option<String> = None;
    let start_time = Instant::now();

    let pb = ProgressBar::new(words.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) H/s: {per_sec}",
        )?
        .progress_chars("=>-"),
    );

    for batch in words.chunks(BATCH_SIZE) {
        let mut word_data: Vec<u8> = Vec::with_capacity(batch.len() * fixed_word_len);
        for word in batch {
            let mut bytes = word.as_bytes().to_vec();
            bytes.resize(fixed_word_len, 0);
            word_data.extend_from_slice(&bytes);
        }

        let words_buffer = unsafe {
            Buffer::<u8>::create(
                context,
                CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                word_data.len(),
                word_data.as_ptr() as *mut c_void,
            )?
        };

        let hash_buffer = unsafe {
            Buffer::<u8>::create(
                context,
                CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                target_hash.len(),
                target_hash.as_ptr() as *mut c_void,
            )?
        };

        let mut result_index: [cl_int; 1] = [-1];
        let result_buffer = unsafe {
            Buffer::<cl_int>::create(
                context,
                CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
                1,
                result_index.as_mut_ptr() as *mut c_void,
            )?
        };

        let kernel_event = unsafe {
            ExecuteKernel::new(kernel)
                .set_arg(&words_buffer)
                .set_arg(&(fixed_word_len as cl_int))
                .set_arg(&hash_buffer)
                .set_arg(&result_buffer)
                .set_global_work_size(batch.len())
                .enqueue_nd_range(queue)?
        };
        kernel_event.wait()?;

        unsafe {
            queue.enqueue_read_buffer(&result_buffer, CL_BLOCKING, 0, &mut result_index, &[])?.wait()?;
        }

        pb.inc(batch.len() as u64);

        if result_index[0] != -1 {
            let idx = result_index[0] as usize;
            found_password = Some(batch[idx].to_string());
            break;
        }
    }

    pb.finish_with_message("Done");
    let duration = start_time.elapsed();

    match found_password {
        Some(password) => println!("\n[+] Password found: {}", password),
        None => println!("\n[-] Password not found in wordlist."),
    }
    println!("[*] Total time: {:.2?}", duration);
    println!("[*] Speed: {:.2} H/s", words.len() as f64 / duration.as_secs_f64());

    Ok(())
}

fn cpu_fallback(args: &Args, words: &[String]) -> Result<()> {
    if let Some(hash) = &args.hash {
        let target_hash = hash.trim().to_lowercase();
        let algo = detect_algo(&target_hash)?;
        println!("[*] CPU fallback → {:?}", algo);

        let start = Instant::now();

        let pb = ProgressBar::new(words.len() as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) H/s: {per_sec}",
            )?
            .progress_chars("=>-"),
        );

        let found = words.par_iter().find_any(|word| {
            let computed = match algo {
                Algo::MD5 => format!("{:x}", md5::compute(word.as_bytes())),
                Algo::SHA1 => {
                    let mut hasher = Sha1::new();
                    hasher.update(word.as_bytes());
                    format!("{:x}", hasher.finalize())
                }
                Algo::SHA256 => {
                    let mut hasher = Sha256::new();
                    hasher.update(word.as_bytes());
                    format!("{:x}", hasher.finalize())
                }
            };
            pb.inc(1);
            computed == target_hash
        });

        pb.finish_with_message("CPU Done");

        match found {
            Some(word) => println!("\n[+] Password found (CPU): {}", word),
            None => println!("\n[-] Password not found (CPU)."),
        }

        let dur = start.elapsed();
        println!("[*] CPU elapsed: {:.2?}", dur);
    } else {
        println!("[!] CPU fallback for WPA not implemented yet.");
    }

    Ok(())
}