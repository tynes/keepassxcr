//! Testing only: exposes the emulated FIDO2 authenticator on stdin/stdout so
//! `tests/test_fido2_python.py` can drive it with Yubico's python-fido2.
//!
//! Each input line is `<CTAPHID command hex> <data hex>`; each output line is
//! `K` for a keepalive asking for a touch, or `R <command hex> <data hex>`.

use std::io::{self, BufRead, Write};

use keepassxcr::fido2::ctaphid::{
    Assembler, BROADCAST_CID, CMD_INIT, CMD_KEEPALIVE, Transport, frame,
};
use keepassxcr::fido2::emulator::EmulatedAuthenticator;

fn exchange(key: &mut EmulatedAuthenticator, cid: [u8; 4], cmd: u8, data: &[u8]) -> (u8, Vec<u8>) {
    for packet in frame(cid, cmd, data).expect("frame") {
        key.write_packet(&packet).expect("write");
    }
    let mut out = io::stdout().lock();
    loop {
        let packet = key.read_packet(0).expect("read").expect("an answer");
        let mut assembler = Assembler::start(&packet).expect("init packet");
        while !assembler.is_complete() {
            let next = key.read_packet(0).expect("read").expect("continuation");
            assembler.push(&next).expect("sequence");
        }
        let (cmd, data) = assembler.finish();
        if cmd == CMD_KEEPALIVE {
            writeln!(out, "K").expect("stdout");
            continue;
        }
        return (cmd, data);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let secret = hex::decode(&args[1]).expect("hex secret");
    let pin = args.get(2).map(String::as_str).filter(|p| !p.is_empty());
    let legacy = args.get(3).is_some_and(|a| a == "v1");
    let mut key = EmulatedAuthenticator::new(&secret, pin, legacy);
    let (_, init) = exchange(&mut key, BROADCAST_CID, CMD_INIT, &[0u8; 8]);
    let mut cid = [0u8; 4];
    cid.copy_from_slice(&init[8..12]);
    for line in io::stdin().lock().lines() {
        let line = line.expect("stdin");
        let (cmd, data) = line.split_once(' ').unwrap_or((&line, ""));
        let cmd = u8::from_str_radix(cmd, 16).expect("command");
        let data = hex::decode(data).expect("data");
        let (cmd, answer) = exchange(&mut key, cid, cmd, &data);
        let mut out = io::stdout().lock();
        writeln!(out, "R {cmd:02x} {}", hex::encode(answer)).expect("stdout");
        out.flush().expect("stdout");
    }
}
