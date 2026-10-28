//! gdi32.dll and user32's DrawText: the game draws its text with GDI into DIB sections and turns
//! those into textures. Fonts, device contexts and DIB sections are host objects by handle.

use std::collections::HashMap;

use recore_machine::{Cpu, Frame};

use crate::Win32;

#[derive(Clone, Debug)]
pub struct Font {
    pub height: i32,
    pub weight: u32,
    pub face: String,
}

#[derive(Clone, Debug)]
pub struct Dib {
    pub width: i32,
    /// Negative for rows top-down, as BITMAPINFOHEADER says.
    pub height: i32,
    pub bits: u32,
    pub bpp: u16,
}

#[derive(Clone, Debug, Default)]
pub struct Dc {
    pub font: u32,
    pub bitmap: u32,
    pub text_color: u32,
    pub bk_color: u32,
    pub bk_mode: u32,
}

pub enum Object {
    Font(Font),
    Dib(Dib),
    Dc(Dc),
}

#[derive(Default)]
pub struct Gdi {
    pub objects: HashMap<u32, Object>,
    next: u32,
}

impl Gdi {
    pub fn add(&mut self, o: Object) -> u32 {
        self.next += 4;
        let h = 0x0300_0000 + self.next;
        self.objects.insert(h, o);
        h
    }

    fn font_of(&self, dc: u32) -> Font {
        let font = match self.objects.get(&dc) {
            Some(Object::Dc(d)) => d.font,
            _ => 0,
        };
        match self.objects.get(&font) {
            Some(Object::Font(f)) => f.clone(),
            _ => Font { height: 16, weight: 400, face: "Arial".into() },
        }
    }
}

pub fn run(w: &mut Win32, c: &mut Cpu, name: &str, f: Frame) -> bool {
    let a = |c: &mut Cpu, n| c.arg(f, n);
    match name {
        "CreateFontA" => {
            let (height, weight, face) = (a(c, 0) as i32, a(c, 4), a(c, 13));
            let face = if face == 0 { String::new() } else { c.mem.c_str(face) };
            let h = w.gdi.add(Object::Font(Font { height, weight, face }));
            c.ret(f, Some(h), 14);
        }
        "CreateFontIndirectA" => {
            let lf = a(c, 0);
            let (height, weight) = (c.u32_at(lf) as i32, c.u32_at(lf + 16));
            let face = c.mem.c_str(lf + 28);
            let h = w.gdi.add(Object::Font(Font { height, weight, face }));
            c.ret(f, Some(h), 1);
        }
        // GetDeviceCaps: HORZRES 8, VERTRES 10, BITSPIXEL 12, PLANES 14, VREFRESH 116.
        "GetDeviceCaps" => {
            let v = match a(c, 1) {
                8 => w.user.screen.0,
                10 => w.user.screen.1,
                12 => w.dd.mode.2,
                14 => 1,
                116 => 60,
                _ => 0,
            };
            c.ret(f, Some(v), 2);
        }
        "GetStockObject" => {
            let n = a(c, 0);
            c.ret(f, Some(0x0400_0000 + n), 1);
        }
        "BitBlt" => c.ret(f, Some(1), 9),
        "CreateCompatibleDC" => {
            let h = w.gdi.add(Object::Dc(Dc { bk_mode: 2, bk_color: 0xffffff, ..Dc::default() }));
            c.ret(f, Some(h), 1);
        }
        "DeleteDC" | "DeleteObject" => {
            let h = a(c, 0);
            w.gdi.objects.remove(&h);
            c.ret(f, Some(1), 1);
        }
        // BITMAPINFOHEADER: size, width, height, planes, bit count, ...
        "CreateDIBSection" => {
            let (bmi, bits_out) = (a(c, 1), a(c, 3));
            let (width, height, bpp) = (c.u32_at(bmi + 4) as i32, c.u32_at(bmi + 8) as i32, c.ld(bmi + 14, 2) as u16);
            let stride = ((width * i32::from(bpp) + 31) / 32 * 4) as u32;
            let bits = w.alloc(stride * height.unsigned_abs());
            c.set_u32(bits_out, bits);
            let h = w.gdi.add(Object::Dib(Dib { width, height, bits, bpp }));
            c.ret(f, Some(h), 6);
        }
        "SelectObject" => {
            let (dc, obj) = (a(c, 0), a(c, 1));
            let kind = match w.gdi.objects.get(&obj) {
                Some(Object::Font(_)) => 1,
                Some(Object::Dib(_)) => 2,
                _ => 0,
            };
            let old = match w.gdi.objects.get_mut(&dc) {
                Some(Object::Dc(d)) if kind == 1 => std::mem::replace(&mut d.font, obj),
                Some(Object::Dc(d)) if kind == 2 => std::mem::replace(&mut d.bitmap, obj),
                _ => 0,
            };
            c.ret(f, Some(old), 2);
        }
        "SetTextColor" | "SetBkColor" | "SetBkMode" => {
            let (dc, v) = (a(c, 0), a(c, 1));
            let old = match w.gdi.objects.get_mut(&dc) {
                Some(Object::Dc(d)) => {
                    let field = match name {
                        "SetTextColor" => &mut d.text_color,
                        "SetBkColor" => &mut d.bk_color,
                        _ => &mut d.bk_mode,
                    };
                    std::mem::replace(field, v)
                }
                _ => 0,
            };
            c.ret(f, Some(old), 2);
        }
        "GetTextFaceA" => {
            let (dc, size, buf) = (a(c, 0), a(c, 1), a(c, 2));
            let face = w.gdi.font_of(dc).face;
            let len = w.put_str(c, buf, size, &face);
            c.ret(f, Some(len), 3);
        }
        // TEXTMETRICA from the font's height: height, ascent, descent, internal and external
        // leading, average and maximum width, weight.
        "GetTextMetricsA" => {
            let (dc, tm) = (a(c, 0), a(c, 1));
            let font = w.gdi.font_of(dc);
            let h = font.height.unsigned_abs().max(1);
            let ascent = h * 4 / 5;
            c.mem.poke(tm, &[0; 56]);
            for (i, v) in [h, ascent, h - ascent, 0, 0, h / 2, h, font.weight].into_iter().enumerate() {
                c.set_u32(tm + 4 * i as u32, v);
            }
            c.st(tm + 44, 1, 0x20);
            c.st(tm + 45, 1, 0xff);
            c.ret(f, Some(1), 2);
        }
        "GetObjectA" => {
            let (h, size, buf) = (a(c, 0), a(c, 1), a(c, 2));
            let written = match w.gdi.objects.get(&h) {
                Some(Object::Dib(d)) => {
                    let stride = ((d.width * i32::from(d.bpp) + 31) / 32 * 4) as u32;
                    let fields = [0u32, d.width as u32, d.height.unsigned_abs(), stride, u32::from(d.bpp) << 16 | 1, d.bits];
                    for (i, v) in fields.into_iter().enumerate().take(size as usize / 4) {
                        c.set_u32(buf + 4 * i as u32, v);
                    }
                    24
                }
                Some(Object::Font(font)) => {
                    let font = font.clone();
                    c.mem.poke(buf, &[0; 60]);
                    c.set_u32(buf, font.height as u32);
                    c.set_u32(buf + 16, font.weight);
                    w.put_str(c, buf + 28, 32, &font.face);
                    60
                }
                _ => 0,
            };
            c.ret(f, Some(written.min(size.max(written))), 3);
        }
        "DrawTextA" | "DrawTextW" => {
            let (dc, text, len) = (a(c, 0), a(c, 1), a(c, 2) as i32);
            let s = if name == "DrawTextA" {
                let t = c.mem.c_str(text);
                if len >= 0 { t.chars().take(len as usize).collect() } else { t }
            } else {
                String::new()
            };
            let height = w.gdi.font_of(dc).height.unsigned_abs();
            if w.trace {
                eprintln!("host: DrawText {s:?} is not drawn yet");
            }
            c.ret(f, Some(height), 5);
        }
        _ => return false,
    }
    true
}
