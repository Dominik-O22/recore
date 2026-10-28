//! `wsprintfA` and `wvsprintfA`: printf formatting as user32 does it, without floats. A
//! conversion is `%[-][#][0][width][.precision][h|l]type` with type d, i, u, x, X, c, s or %.

use recore_machine::Cpu;

/// The bytes of the zero-terminated string at `at`, without the zero.
pub fn c_bytes(c: &mut Cpu, at: u32) -> Vec<u8> {
    (at..).map(|a| c.ld_u8(a)).take_while(|&b| b != 0).take(0x10000).collect()
}

/// `fmt` formatted with the 4-byte arguments that start at `args` in game memory. Strings are
/// bytes, as the game's code page keeps them.
pub fn format(c: &mut Cpu, fmt: &[u8], mut args: u32) -> Vec<u8> {
    let mut next = |c: &mut Cpu| {
        let v = c.u32_at(args);
        args += 4;
        v
    };
    let mut out = Vec::new();
    let mut chars = fmt.iter().map(|&b| char::from(b)).collect::<Vec<char>>().into_iter().peekable();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            out.push(ch as u8);
            continue;
        }
        let (mut left, mut zero, mut alt) = (false, false, false);
        while let Some(&f) = chars.peek() {
            match f {
                '-' => left = true,
                '0' => zero = true,
                '#' => alt = true,
                _ => break,
            }
            chars.next();
        }
        let number = |chars: &mut std::iter::Peekable<std::vec::IntoIter<char>>| {
            let mut n = None;
            while let Some(d) = chars.peek().and_then(|d| d.to_digit(10)) {
                n = Some(n.unwrap_or(0) * 10 + d as usize);
                chars.next();
            }
            n
        };
        let width = number(&mut chars).unwrap_or(0);
        let precision = if chars.peek() == Some(&'.') {
            chars.next();
            Some(number(&mut chars).unwrap_or(0))
        } else {
            None
        };
        while matches!(chars.peek(), Some('h' | 'l')) {
            chars.next();
        }
        let Some(kind) = chars.next() else { break };
        let digits = |s: String| match precision {
            Some(p) if s.len() < p => format!("{}{s}", "0".repeat(p - s.len())).into_bytes(),
            _ => s.into_bytes(),
        };
        let text = match kind {
            'd' | 'i' => {
                let v = next(c) as i32;
                let s = digits(v.unsigned_abs().to_string());
                if v < 0 { [b"-".as_slice(), &s].concat() } else { s }
            }
            'u' => digits(next(c).to_string()),
            'x' => [if alt { b"0x".as_slice() } else { b"" }, &digits(format!("{:x}", next(c)))].concat(),
            'X' => [if alt { b"0X".as_slice() } else { b"" }, &digits(format!("{:X}", next(c)))].concat(),
            'c' => vec![next(c) as u8],
            's' => {
                let at = next(c);
                let s = if at == 0 { b"(null)".to_vec() } else { c_bytes(c, at) };
                s.into_iter().take(precision.unwrap_or(usize::MAX)).collect()
            }
            other => vec![other as u8],
        };
        let pad = width.saturating_sub(text.len());
        if left {
            out.extend(&text);
            out.extend(std::iter::repeat_n(b' ', pad));
        } else if zero && precision.is_none() && kind != 's' {
            let (sign, rest) = text.strip_prefix(b"-").map_or((&b""[..], &text[..]), |r| (&b"-"[..], r));
            out.extend(sign);
            out.extend(std::iter::repeat_n(b'0', pad));
            out.extend(rest);
        } else {
            out.extend(std::iter::repeat_n(b' ', pad));
            out.extend(&text);
        }
    }
    out
}
