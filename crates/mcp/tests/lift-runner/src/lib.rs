//! The host of the program tests/lift.rs lifts: it runs one lifted function on its arguments
//! and prints the EAX it returned. The program imports nothing, so a call to the host is a bug.
//!
//!     lifted <exe> <function> [argument...]   addresses and arguments in hex, as 0x1f

use std::path::Path;

use recore_machine::{Cpu, Frame, Host, Lifted, image::Image, install, regs};

/// The top of the stack each run starts with, below the image.
const STACK: u32 = 0x0030_0000;

struct NoImports;

impl Host for NoImports {
    fn call(&mut self, _: &mut Cpu, addr: u32, _: Frame) -> Option<u32> {
        panic!("a call to the host at {addr:#x}")
    }

    fn import(&mut self, _: &mut Cpu, name: &str, _: Frame) -> Option<u32> {
        panic!("a call to the import {name}")
    }
}

fn number(text: &str) -> u32 {
    u32::from_str_radix(text.trim_start_matches("0x"), 16).unwrap_or_else(|_| panic!("{text} is not a hex number"))
}

pub fn run(functions: Vec<(u32, Lifted)>) {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [exe, function, rest @ ..] = args.as_slice() else { panic!("usage: lifted <exe> <function> [argument...]") };
    let image = Image::load(Path::new(exe)).unwrap();
    let low = functions.iter().map(|f| f.0).min().unwrap_or(0);
    let high = functions.iter().map(|f| f.0).max().unwrap_or(0);
    install(functions, low..high + 1);
    let mut c = Cpu::new(Some(image), None, Box::new(NoImports), false).unwrap();
    c.set_reg(regs::ESP, STACK);
    let eax = c.call(number(function), None, &rest.iter().map(|a| number(a)).collect::<Vec<_>>());
    println!("{eax:#x}");
}
