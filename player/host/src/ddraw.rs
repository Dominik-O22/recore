//! DirectDraw: a game of this time draws every pixel itself into surfaces it locks, so DirectDraw
//! here is memory, blits between it and flips that copy. A surface's pixels live in game memory; the screen is the
//! primary surface's, handed to the window as one texture on each flip or blit to the primary.
//! The display is 16 bits a pixel, 5-6-5, unless the game sets a mode of 8.

use std::collections::HashMap;

use recore_machine::Cpu;

use crate::{
    Win32,
    com::{Args, Iface},
};

const OK: u32 = 0;
/// DDERR_UNSUPPORTED.
const UNSUPPORTED: u32 = 0x8000_4001;

/// DDSURFACEDESC flags.
const SD_CAPS: u32 = 0x1;
const SD_HEIGHT: u32 = 0x2;
const SD_WIDTH: u32 = 0x4;
const SD_PITCH: u32 = 0x8;
const SD_BACKBUFFERCOUNT: u32 = 0x20;
const SD_LPSURFACE: u32 = 0x800;
const SD_PIXELFORMAT: u32 = 0x1000;
/// DDSCAPS bits.
const CAPS_BACKBUFFER: u32 = 0x4;
const CAPS_FRONTBUFFER: u32 = 0x20;
const CAPS_PRIMARY: u32 = 0x200;
const CAPS_SYSTEMMEMORY: u32 = 0x800;
/// DDBLT flags.
const BLT_COLORFILL: u32 = 0x400;
const BLT_KEYSRC: u32 = 0x8000;
/// DDBLTFAST_SRCCOLORKEY.
const BLTFAST_SRCCOLORKEY: u32 = 0x1;
/// DDCKEY_SRCBLT.
const CKEY_SRCBLT: u32 = 0x8;

pub struct Surface {
    pub width: u32,
    pub height: u32,
    pub bpp: u32,
    pub pitch: u32,
    /// The pixels, in game memory.
    pub bits: u32,
    pub caps: u32,
    /// The back buffer of a flipping primary, by id.
    pub back: Option<u32>,
    pub palette: Option<u32>,
    /// The source color key, as DDCKEY_SRCBLT sets it.
    pub key: Option<u32>,
}

pub struct DirectDraw {
    pub surfaces: HashMap<u32, Surface>,
    /// Palettes by id: 256 PALETTEENTRYs, red, green, blue and flags.
    pub palettes: HashMap<u32, [u8; 1024]>,
    next: u32,
    /// Width, height and bits a pixel of the display.
    pub mode: (u32, u32, u32),
    pub primary: Option<u32>,
}

impl Default for DirectDraw {
    fn default() -> DirectDraw {
        DirectDraw { surfaces: HashMap::new(), palettes: HashMap::new(), next: 0, mode: (640, 480, 16), primary: None }
    }
}

/// The display modes EnumDisplayModes offers.
const MODES: [(u32, u32, u32); 8] = [(640, 480, 8), (640, 480, 16), (800, 600, 8), (800, 600, 16), (864, 480, 8), (864, 480, 16), (1024, 768, 8), (1024, 768, 16)];

/// A rectangle as RECT keeps it: left, top, right, bottom.
#[derive(Clone, Copy, Debug)]
struct Rect {
    x0: i32,
    y0: i32,
    x1: i32,
    y1: i32,
}

impl Rect {
    fn of(c: &mut Cpu, at: u32, whole: Rect) -> Rect {
        if at == 0 {
            return whole;
        }
        Rect { x0: c.u32_at(at) as i32, y0: c.u32_at(at + 4) as i32, x1: c.u32_at(at + 8) as i32, y1: c.u32_at(at + 12) as i32 }
    }

    fn w(self) -> i32 {
        self.x1 - self.x0
    }

    fn h(self) -> i32 {
        self.y1 - self.y0
    }
}

impl Surface {
    fn whole(&self) -> Rect {
        Rect { x0: 0, y0: 0, x1: self.width as i32, y1: self.height as i32 }
    }

    fn bytes(&self) -> u32 {
        self.bpp / 8
    }
}

impl DirectDraw {
    fn id(&mut self) -> u32 {
        self.next += 1;
        self.next
    }

    /// The front buffer as a picture, if there is a primary surface.
    pub fn screen(&self, c: &mut Cpu) -> Option<recore_window::Frame> {
        let s = self.surfaces.get(&self.primary?)?;
        let (width, height) = (s.width.min(self.mode.0), s.height.min(self.mode.1));
        let bytes = c.mem.bytes(s.bits, (s.pitch * s.height) as usize);
        let palette = s.palette.and_then(|p| self.palettes.get(&p));
        let mut pixels = Vec::with_capacity((width * height) as usize);
        for y in 0..height as usize {
            let row = &bytes[y * s.pitch as usize..];
            for x in 0..width as usize {
                let (r, g, b) = match s.bpp {
                    8 => {
                        let i = 4 * row[x] as usize;
                        palette.map_or((row[x], row[x], row[x]), |p| (p[i], p[i + 1], p[i + 2]))
                    }
                    _ => {
                        let p = u16::from_le_bytes([row[2 * x], row[2 * x + 1]]);
                        let scale = |v: u16, max: u16| (u32::from(v) * 255 / u32::from(max)) as u8;
                        (scale(p >> 11, 31), scale((p >> 5) & 63, 63), scale(p & 31, 31))
                    }
                };
                pixels.push(u32::from(r) << 16 | u32::from(g) << 8 | u32::from(b));
            }
        }
        Some(recore_window::Frame { width, height, pixels })
    }
}

/// Writes a DDPIXELFORMAT for `bpp` bits a pixel at `at`.
fn pixel_format(c: &mut Cpu, at: u32, bpp: u32) {
    c.mem.poke(at, &[0; 32]);
    c.set_u32(at, 32);
    if bpp == 8 {
        // DDPF_RGB | DDPF_PALETTEINDEXED8.
        c.set_u32(at + 4, 0x60);
        c.set_u32(at + 12, 8);
    } else {
        c.set_u32(at + 4, 0x40);
        c.set_u32(at + 12, 16);
        for (i, mask) in [0xf800u32, 0x07e0, 0x001f].into_iter().enumerate() {
            c.set_u32(at + 16 + 4 * i as u32, mask);
        }
    }
}

/// Fills a DDSURFACEDESC or DDSURFACEDESC2 (by its dwSize) for a surface.
fn describe(c: &mut Cpu, desc: u32, s: &Surface) {
    let size = c.u32_at(desc).max(108);
    c.mem.poke(desc + 4, &vec![0; size as usize - 4]);
    c.set_u32(desc + 4, SD_CAPS | SD_HEIGHT | SD_WIDTH | SD_PITCH | SD_PIXELFORMAT | SD_LPSURFACE);
    c.set_u32(desc + 8, s.height);
    c.set_u32(desc + 12, s.width);
    c.set_u32(desc + 16, s.pitch);
    c.set_u32(desc + 36, s.bits);
    pixel_format(c, desc + 72, s.bpp);
    c.set_u32(desc + 104, s.caps);
}

/// The id of the surface an object pointer names.
fn surface_of(c: &mut Cpu, object: u32) -> Option<u32> {
    (object != 0).then(|| c.u32_at(object + 4))
}

pub fn method(w: &mut Win32, c: &mut Cpu, iface: Iface, name: &str, a: &Args) -> Option<u32> {
    match iface {
        Iface::DirectDraw | Iface::DirectDraw2 | Iface::DirectDraw4 => direct_draw(w, c, iface, name, a),
        Iface::Surface | Iface::Surface3 | Iface::Surface4 => surface(w, c, iface, name, a),
        Iface::Palette => palette(w, c, name, a),
        Iface::Clipper => match name {
            "SetHWnd" | "SetClipList" | "Initialize" => Some(OK),
            _ => None,
        },
        _ => None,
    }
}

fn direct_draw(w: &mut Win32, c: &mut Cpu, iface: Iface, name: &str, a: &Args) -> Option<u32> {
    let surface_iface = match iface {
        Iface::DirectDraw4 => Iface::Surface4,
        _ => Iface::Surface,
    };
    let v = match name {
        "SetCooperativeLevel" | "RestoreDisplayMode" | "FlipToGDISurface" | "TestCooperativeLevel" | "Compact" | "Initialize" => OK,
        "WaitForVerticalBlank" => OK,
        "SetDisplayMode" => {
            let mode = (a.get(c, 0), a.get(c, 1), a.get(c, 2));
            eprintln!("host: display mode {}x{} at {} bits", mode.0, mode.1, mode.2);
            w.dd.mode = mode;
            OK
        }
        "GetDisplayMode" => {
            let desc = a.get(c, 0);
            let (width, height, bpp) = w.dd.mode;
            let s = Surface { width, height, bpp, pitch: width * bpp / 8, bits: 0, caps: 0, back: None, palette: None, key: None };
            describe(c, desc, &s);
            OK
        }
        "GetMonitorFrequency" => {
            let out = a.get(c, 0);
            c.set_u32(out, 60);
            OK
        }
        // DDCAPS: its size and nothing more, for the driver and for the emulation layer.
        "GetCaps" => {
            for n in 0..2 {
                let caps = a.get(c, n);
                if caps != 0 {
                    let size = c.u32_at(caps);
                    c.mem.poke(caps + 4, &vec![0; size.saturating_sub(4) as usize]);
                }
            }
            OK
        }
        "GetAvailableVidMem" => {
            let (total, free) = (a.get(c, 1), a.get(c, 2));
            for out in [total, free].into_iter().filter(|&o| o != 0) {
                c.set_u32(out, 32 << 20);
            }
            OK
        }
        // DDDEVICEIDENTIFIER: driver and description strings, then version and ids, all zero.
        "GetDeviceIdentifier" => {
            let ident = a.get(c, 0);
            c.mem.poke(ident, &[0; 1072]);
            w.put_str(c, ident, 512, "display");
            w.put_str(c, ident + 512, 512, "recore host display");
            OK
        }
        "EnumDisplayModes" => {
            let (context, callback) = (a.get(c, 2), a.get(c, 3));
            let size = if iface == Iface::DirectDraw4 { 124 } else { 108 };
            let calls: Vec<Vec<u32>> = MODES
                .iter()
                .map(|&(width, height, bpp)| {
                    let desc = w.alloc(size);
                    c.set_u32(desc, size);
                    describe(c, desc, &Surface { width, height, bpp, pitch: width * bpp / 8, bits: 0, caps: 0, back: None, palette: None, key: None });
                    c.set_u32(desc + 4, SD_HEIGHT | SD_WIDTH | SD_PITCH | SD_PIXELFORMAT);
                    vec![desc, context]
                })
                .collect();
            w.call_each(c, a.frame, a.taken, callback, &calls, OK);
            OK
        }
        "CreateSurface" => {
            let (desc, out) = (a.get(c, 0), a.get(c, 1));
            let flags = c.u32_at(desc + 4);
            let caps = if flags & SD_CAPS != 0 { c.u32_at(desc + 104) } else { 0 };
            let (mw, mh, mbpp) = w.dd.mode;
            let primary = caps & CAPS_PRIMARY != 0;
            let (width, height) = if primary { (mw, mh) } else { (c.u32_at(desc + 12), c.u32_at(desc + 8)) };
            let bpp = if flags & SD_PIXELFORMAT != 0 && !primary { c.u32_at(desc + 72 + 12) } else { mbpp };
            let back_count = if flags & SD_BACKBUFFERCOUNT != 0 { c.u32_at(desc + 20) } else { 0 };
            let new = |w: &mut Win32, caps: u32| {
                let pitch = (width * bpp / 8 + 3) & !3;
                let bits = w.alloc_pages(pitch * height);
                let id = w.dd.id();
                w.dd.surfaces.insert(id, Surface { width, height, bpp, pitch, bits, caps: caps | CAPS_SYSTEMMEMORY, back: None, palette: None, key: None });
                id
            };
            let id = new(w, if back_count > 0 { caps | CAPS_FRONTBUFFER } else { caps });
            if back_count > 0 {
                let back = new(w, (caps & !(CAPS_PRIMARY | CAPS_FRONTBUFFER)) | CAPS_BACKBUFFER);
                w.dd.surfaces.get_mut(&id).expect("made").back = Some(back);
            }
            if primary {
                w.dd.primary = Some(id);
            }
            eprintln!("host: surface {id} {width}x{height} at {bpp} bits, caps {caps:#x}, {back_count} back buffers");
            let object = w.new_object(c, surface_iface, id);
            c.set_u32(out, object);
            OK
        }
        "CreatePalette" => {
            let (entries, out) = (a.get(c, 1), a.get(c, 2));
            let mut colors = [0u8; 1024];
            colors.copy_from_slice(&c.mem.bytes(entries, 1024));
            let id = w.dd.id();
            w.dd.palettes.insert(id, colors);
            let object = w.new_object(c, Iface::Palette, id);
            c.set_u32(out, object);
            OK
        }
        "CreateClipper" => {
            let out = a.get(c, 1);
            let object = w.new_object(c, Iface::Clipper, 0);
            c.set_u32(out, object);
            OK
        }
        _ => return None,
    };
    Some(v)
}

fn surface(w: &mut Win32, c: &mut Cpu, iface: Iface, name: &str, a: &Args) -> Option<u32> {
    let id = a.id;
    let v = match name {
        "IsLost" | "Restore" | "Unlock" | "GetBltStatus" | "GetFlipStatus" | "SetClipper" | "PageLock" | "PageUnlock" | "Initialize" => OK,
        "Lock" => {
            let (rect, desc) = (a.get(c, 0), a.get(c, 1));
            let s = w.dd.surfaces.get(&id)?;
            describe(c, desc, s);
            if rect != 0 {
                let r = Rect::of(c, rect, s.whole());
                c.set_u32(desc + 36, s.bits + r.y0 as u32 * s.pitch + r.x0 as u32 * s.bytes());
            }
            OK
        }
        "GetSurfaceDesc" => {
            let desc = a.get(c, 0);
            describe(c, desc, w.dd.surfaces.get(&id)?);
            OK
        }
        "GetPixelFormat" => {
            let pf = a.get(c, 0);
            let bpp = w.dd.surfaces.get(&id)?.bpp;
            pixel_format(c, pf, bpp);
            OK
        }
        "GetCaps" => {
            let caps = a.get(c, 0);
            let v = w.dd.surfaces.get(&id)?.caps;
            c.set_u32(caps, v);
            OK
        }
        "GetAttachedSurface" => {
            let out = a.get(c, 1);
            let back = w.dd.surfaces.get(&id)?.back;
            match back {
                Some(back) => {
                    let object = w.new_object(c, iface, back);
                    c.set_u32(out, object);
                    OK
                }
                None => 0x8876_00ff,
            }
        }
        "SetPalette" => {
            let object = a.get(c, 0);
            let palette = surface_of(c, object);
            w.dd.surfaces.get_mut(&id)?.palette = palette;
            OK
        }
        "SetColorKey" => {
            let (flags, key) = (a.get(c, 0), a.get(c, 1));
            let low = (key != 0).then(|| c.u32_at(key));
            if flags & CKEY_SRCBLT != 0 {
                w.dd.surfaces.get_mut(&id)?.key = low;
            }
            OK
        }
        // A flip copies the back buffer to the front and shows it; the back buffer keeps its
        // pixels and its address. A game that asks for its flipping chain in system memory (caps
        // 0xa18) may redraw only what changed since the last frame and keep the back buffer's
        // address after unlocking it, so swapping the two buffers' memory would leave every other
        // frame's changes behind.
        "Flip" => {
            let back = w.dd.surfaces.get(&id)?.back?;
            let (front, back) = (w.dd.surfaces.get(&id)?, w.dd.surfaces.get(&back)?);
            let pixels = c.mem.bytes(back.bits, (back.pitch * back.height) as usize);
            c.mem.poke(front.bits, &pixels);
            w.present(c);
            OK
        }
        "Blt" => {
            let (dest_rect, src, src_rect, flags, fx) = (a.get(c, 0), a.get(c, 1), a.get(c, 2), a.get(c, 3), a.get(c, 4));
            let dest_whole = w.dd.surfaces.get(&id)?.whole();
            let dr = Rect::of(c, dest_rect, dest_whole);
            if flags & BLT_COLORFILL != 0 {
                // DDBLTFX: dwSize, dwDDFX, ROP, DDROP, rotation angle, ZBufferOpCode, ZBufferLow,
                // ZBufferHigh, ZBufferBaseDest, ZDestConstBitDepth, ZDestConst, ZSrcConstBitDepth,
                // ZSrcConst, alpha bit depths and constants (6 words), then dwFillColor at 80.
                let color = c.u32_at(fx + 80);
                fill(w, c, id, dr, color);
            } else {
                let src = surface_of(c, src)?;
                let src_whole = w.dd.surfaces.get(&src)?.whole();
                let sr = Rect::of(c, src_rect, src_whole);
                let key = if flags & BLT_KEYSRC != 0 { w.dd.surfaces.get(&src)?.key } else { None };
                copy(w, c, src, sr, id, dr, key);
            }
            if Some(id) == w.dd.primary {
                w.present(c);
            }
            OK
        }
        "BltFast" => {
            let (x, y, src, src_rect, trans) = (a.get(c, 0) as i32, a.get(c, 1) as i32, a.get(c, 2), a.get(c, 3), a.get(c, 4));
            let src = surface_of(c, src)?;
            let src_whole = w.dd.surfaces.get(&src)?.whole();
            let sr = Rect::of(c, src_rect, src_whole);
            let key = if trans & BLTFAST_SRCCOLORKEY != 0 { w.dd.surfaces.get(&src)?.key } else { None };
            copy(w, c, src, sr, id, Rect { x0: x, y0: y, x1: x + sr.w(), y1: y + sr.h() }, key);
            if Some(id) == w.dd.primary {
                w.present(c);
            }
            OK
        }
        "GetDC" => UNSUPPORTED,
        _ => return None,
    };
    Some(v)
}

fn palette(w: &mut Win32, c: &mut Cpu, name: &str, a: &Args) -> Option<u32> {
    let (start, count, entries) = (a.get(c, 1), a.get(c, 2), a.get(c, 3));
    let range = 4 * start.min(256) as usize..4 * (start + count).min(256) as usize;
    let p = w.dd.palettes.get_mut(&a.id)?;
    match name {
        "SetEntries" => p[range.clone()].copy_from_slice(&c.mem.bytes(entries, range.len())),
        "GetEntries" => c.mem.poke(entries, &p[range]),
        _ => return None,
    }
    Some(OK)
}

/// Fills `r` of a surface with `color`, clipped to the surface.
fn fill(w: &Win32, c: &mut Cpu, id: u32, r: Rect, color: u32) {
    let Some(s) = w.dd.surfaces.get(&id) else { return };
    let (x0, y0, x1, y1) = (r.x0.max(0), r.y0.max(0), r.x1.min(s.width as i32), r.y1.min(s.height as i32));
    if x0 >= x1 || y0 >= y1 {
        return;
    }
    let b = s.bytes() as usize;
    let row: Vec<u8> = (x0..x1).flat_map(|_| color.to_le_bytes().into_iter().take(b)).collect();
    for y in y0..y1 {
        c.mem.poke(s.bits + y as u32 * s.pitch + x0 as u32 * b as u32, &row);
    }
}

/// Copies `sr` of `src` to `dr` of `dest`, scaled to fit when the sizes differ, skipping source
/// pixels equal to `key`, clipped to both surfaces.
fn copy(w: &Win32, c: &mut Cpu, src: u32, sr: Rect, dest: u32, dr: Rect, key: Option<u32>) {
    let (Some(s), Some(d)) = (w.dd.surfaces.get(&src), w.dd.surfaces.get(&dest)) else { return };
    if sr.w() <= 0 || sr.h() <= 0 || dr.w() <= 0 || dr.h() <= 0 || s.bpp != d.bpp {
        return;
    }
    let b = s.bytes() as usize;
    let pixels = c.mem.bytes(s.bits, (s.pitch * s.height) as usize);
    let mask = if b == 1 { 0xff } else { 0xffff };
    for dy in dr.y0.max(0)..dr.y1.min(d.height as i32) {
        let sy = sr.y0 + (dy - dr.y0) * sr.h() / dr.h();
        if sy < 0 || sy >= s.height as i32 {
            continue;
        }
        let at = d.bits + dy as u32 * d.pitch;
        let (x0, x1) = (dr.x0.max(0), dr.x1.min(d.width as i32));
        if x0 >= x1 {
            continue;
        }
        let mut row = c.mem.bytes(at + x0 as u32 * b as u32, (x1 - x0) as usize * b);
        for dx in x0..x1 {
            let sx = sr.x0 + (dx - dr.x0) * sr.w() / dr.w();
            if sx < 0 || sx >= s.width as i32 {
                continue;
            }
            let from = sy as usize * s.pitch as usize + sx as usize * b;
            let px = &pixels[from..from + b];
            let value = px.iter().rev().fold(0u32, |v, &p| v << 8 | u32::from(p));
            if key.is_some_and(|k| k & mask == value) {
                continue;
            }
            row[(dx - x0) as usize * b..][..b].copy_from_slice(px);
        }
        c.mem.poke(at + x0 as u32 * b as u32, &row);
    }
}
