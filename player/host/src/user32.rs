//! user32.dll: one window, its messages, the cursor and the keyboard. The window and input
//! come from the host's display when it has one; without one the game runs headless.

use std::collections::VecDeque;

use recore_machine::{Cpu, Frame};

use crate::Win32;

pub const HWND: u32 = 0x0001_0001;

/// A window message for the game's window procedure.
#[derive(Clone, Copy, Debug)]
pub struct Message {
    pub msg: u32,
    pub wparam: u32,
    pub lparam: u32,
}

pub struct User {
    pub wndproc: u32,
    pub queue: VecDeque<Message>,
    pub cursor: (i32, i32),
    pub screen: (u32, u32),
    pub keys: [u8; 256],
    /// Whether the window was activated, which showing it does once.
    active: bool,
    /// ShowCursor's count. The window never shows the system's pointer: the game draws its own.
    cursor_shown: i32,
    /// The handle `SetCursor` last set.
    cursor_set: u32,
}

impl User {
    pub fn new() -> User {
        User { wndproc: 0, queue: VecDeque::new(), cursor: (320, 240), screen: (640, 480), keys: [0; 256], active: false, cursor_shown: 0, cursor_set: 0 }
    }
}

pub fn run(w: &mut Win32, c: &mut Cpu, name: &str, f: Frame) -> bool {
    let a = |c: &mut Cpu, n| c.arg(f, n);
    match name {
        "RegisterClassExA" => {
            let class = a(c, 0);
            w.user.wndproc = c.u32_at(class + 8);
            c.ret(f, Some(0xc001), 1);
        }
        // WNDCLASSA: style, lpfnWndProc, ...
        "RegisterClassA" => {
            let class = a(c, 0);
            w.user.wndproc = c.u32_at(class + 4);
            c.ret(f, Some(0xc001), 1);
        }
        "UnregisterClassA" => c.ret(f, Some(1), 2),
        "FindWindowA" => c.ret(f, Some(0), 2),
        "GetDC" => {
            let dc = w.gdi.add(crate::gdi32::Object::Dc(crate::gdi32::Dc { bk_mode: 2, bk_color: 0xffffff, ..Default::default() }));
            c.ret(f, Some(dc), 1);
        }
        "ReleaseDC" => {
            let dc = a(c, 1);
            w.gdi.objects.remove(&dc);
            c.ret(f, Some(1), 2);
        }
        // Bitmaps from resources are not loaded yet: a game goes on without the picture.
        "LoadImageA" => {
            eprintln!("host: LoadImageA answers 0");
            c.ret(f, Some(0), 6);
        }
        "GetDesktopWindow" => c.ret(f, Some(0x0001_0002), 0),
        "BringWindowToTop" | "UpdateWindow" | "LockWindowUpdate" => c.ret(f, Some(1), 1),
        "SetWindowPos" => c.ret(f, Some(1), 7),
        "SetWindowTextA" => c.ret(f, Some(1), 2),
        "AdjustWindowRectEx" => c.ret(f, Some(1), 4),
        "GetWindowLongA" => c.ret(f, Some(0), 2),
        "ClientToScreen" => c.ret(f, Some(1), 2),
        "SystemParametersInfoA" => c.ret(f, Some(1), 4),
        "SwapMouseButton" => c.ret(f, Some(0), 1),
        "SetRect" => {
            let rect = a(c, 0);
            for i in 0..4 {
                let v = a(c, 1 + i);
                c.set_u32(rect + 4 * i, v);
            }
            c.ret(f, Some(1), 5);
        }
        "GetClientRect" => {
            let rect = a(c, 1);
            let (sw, sh) = w.user.screen;
            for (i, v) in [0, 0, sw, sh].into_iter().enumerate() {
                c.set_u32(rect + 4 * i as u32, v);
            }
            c.ret(f, Some(1), 2);
        }
        // The mouse buttons are virtual keys too: VK_LBUTTON 1, VK_RBUTTON 2, VK_MBUTTON 4. The game
        // reads its buttons so and its pointer with GetCursorPos.
        "GetKeyState" | "GetAsyncKeyState" => {
            w.sync_input();
            let vk = a(c, 0) & 0xff;
            let down = match vk {
                1 => w.input.buttons[0],
                2 => w.input.buttons[1],
                4 => w.input.buttons[2],
                _ => w.user.keys[vk as usize] & 0x80 != 0,
            };
            c.ret(f, Some(if down { 0xffff_ff80 } else { 0 }), 1);
        }
        // WM_QUIT.
        "PostQuitMessage" => {
            let code = a(c, 0);
            w.user.queue.push_back(Message { msg: 0x12, wparam: code, lparam: 0 });
            c.ret(f, None, 1);
        }
        // Waits are short: without a message after 10 ms, GetMessageA answers WM_NULL.
        "GetMessageA" => {
            w.sync_input();
            let msg = a(c, 0);
            if w.user.queue.is_empty() {
                w.clock.sleep(10);
            }
            let m = w.user.queue.pop_front().unwrap_or(Message { msg: 0, wparam: 0, lparam: 0 });
            for (i, v) in [HWND, m.msg, m.wparam, m.lparam, 0, w.user.cursor.0 as u32, w.user.cursor.1 as u32].into_iter().enumerate() {
                c.set_u32(msg + 4 * i as u32, v);
            }
            w.answer_after_timers(c, f, 4, Some(u32::from(m.msg != 0x12)));
        }
        "WaitMessage" => {
            w.sync_input();
            if w.user.queue.is_empty() {
                w.clock.sleep(10);
            }
            w.answer_after_timers(c, f, 0, Some(1));
        }
        // WAIT_OBJECT_0 + count when a message waits, else WAIT_TIMEOUT after at most 10 ms.
        "MsgWaitForMultipleObjects" => {
            w.sync_input();
            let (count, ms) = (a(c, 0), a(c, 3));
            let result = if w.user.queue.is_empty() {
                w.clock.sleep(ms.min(10));
                0x102
            } else {
                count
            };
            w.answer_after_timers(c, f, 5, Some(result));
        }
        "MessageBoxW" => {
            eprintln!("host: MessageBoxW");
            c.ret(f, Some(1), 4);
        }
        // LoadStringA(instance, id, buffer, size) from the executable's string table.
        "LoadStringA" => {
            let (id, buf, size) = (a(c, 1), a(c, 2), a(c, 3));
            let text = w.strings.get(&id).cloned().unwrap_or_default();
            let len = w.put_bytes(c, buf, size, &text);
            c.ret(f, Some(len), 4);
        }
        // wsprintfA is cdecl: the caller takes its arguments off.
        "wsprintfA" => {
            let (buf, fmt) = (a(c, 0), a(c, 1));
            let sp = c.reg(recore_machine::regs::ESP) + if f == Frame::Called { 4 } else { 0 };
            let pattern = crate::fmt::c_bytes(c, fmt);
            let text = crate::fmt::format(c, &pattern, sp + 8);
            let len = w.put_bytes(c, buf, 1025, &text);
            c.ret(f, Some(len), 0);
        }
        "wvsprintfA" => {
            let (buf, fmt, args) = (a(c, 0), a(c, 1), a(c, 2));
            let pattern = crate::fmt::c_bytes(c, fmt);
            let text = crate::fmt::format(c, &pattern, args);
            let len = w.put_bytes(c, buf, 1025, &text);
            c.ret(f, Some(len), 3);
        }
        "CreateWindowExA" => {
            let (x, y, width, height) = (a(c, 4), a(c, 5), a(c, 6), a(c, 7));
            if w.trace {
                eprintln!("host: CreateWindowExA at {x},{y} size {width}x{height}");
            }
            c.ret(f, Some(HWND), 12);
        }
        "DestroyWindow" => c.ret(f, Some(1), 1),
        // Showing the window activates it, as Windows does: WM_ACTIVATEAPP, WM_ACTIVATE (WA_ACTIVE)
        // and WM_SETFOCUS. Games wait in their message loop until WM_ACTIVATEAPP.
        "ShowWindow" => {
            let shown = a(c, 1) != 0;
            if shown && !w.user.active {
                w.user.active = true;
                for msg in [0x1c, 0x6, 0x7] {
                    w.user.queue.push_back(Message { msg, wparam: 1, lparam: 0 });
                }
            }
            c.ret(f, Some(0), 2);
        }
        "SetWindowLongA" => c.ret(f, Some(0), 3),
        "AdjustWindowRect" => c.ret(f, Some(1), 3),
        "GetWindowRect" => {
            let rect = a(c, 1);
            let (sw, sh) = w.user.screen;
            for (i, v) in [0, 0, sw, sh].into_iter().enumerate() {
                c.set_u32(rect + 4 * i as u32, v);
            }
            c.ret(f, Some(1), 2);
        }
        "GetForegroundWindow" => c.ret(f, Some(HWND), 0),
        "SetFocus" => c.ret(f, Some(HWND), 1),
        "GetSystemMetrics" => {
            let (sw, sh) = w.user.screen;
            let v = match a(c, 0) {
                0 => sw,
                1 => sh,
                _ => 0,
            };
            c.ret(f, Some(v), 1);
        }
        "EnumDisplayDevicesA" => {
            let (index, dev) = (a(c, 1), a(c, 2));
            let found = index == 0;
            if found {
                w.put_str(c, dev + 4, 32, "\\\\.\\DISPLAY1");
                w.put_str(c, dev + 36, 128, "display");
                c.set_u32(dev + 164, 5);
            }
            c.ret(f, Some(u32::from(found)), 4);
        }
        // MSG: hwnd, message, wParam, lParam, time, pt.
        "PeekMessageA" => {
            w.sync_input();
            let (msg, remove) = (a(c, 0), a(c, 4));
            let next = if remove & 1 != 0 { w.user.queue.pop_front() } else { w.user.queue.front().copied() };
            if let Some(m) = next {
                for (i, v) in [HWND, m.msg, m.wparam, m.lparam, 0, w.user.cursor.0 as u32, w.user.cursor.1 as u32].into_iter().enumerate() {
                    c.set_u32(msg + 4 * i as u32, v);
                }
            }
            w.answer_after_timers(c, f, 5, Some(u32::from(next.is_some())));
        }
        "TranslateMessage" => c.ret(f, Some(0), 1),
        // The window procedure runs in DispatchMessageA's place and its result is the answer.
        "DispatchMessageA" => {
            let msg = a(c, 0);
            let args = [HWND, c.u32_at(msg + 4), c.u32_at(msg + 8), c.u32_at(msg + 12)];
            if w.user.wndproc == 0 {
                c.ret(f, Some(0), 1);
            } else {
                c.redirect(f, 1, &args);
                w.next = Some(w.user.wndproc);
            }
        }
        "PostMessageA" => {
            let (msg, wparam, lparam) = (a(c, 1), a(c, 2), a(c, 3));
            w.user.queue.push_back(Message { msg, wparam, lparam });
            c.ret(f, Some(1), 4);
        }
        "DefWindowProcA" => c.ret(f, Some(0), 4),
        "MessageBoxA" => {
            let (text, caption) = (a(c, 1), a(c, 2));
            eprintln!("host: MessageBox {:?}: {:?}", c.mem.c_str(caption), c.mem.c_str(text));
            c.ret(f, Some(1), 4);
        }
        "LoadCursorA" | "LoadIconA" => c.ret(f, Some(0x0002_0001), 2),
        "LoadCursorFromFileA" => c.ret(f, Some(0x0003_0000), 1),
        "SetCursor" => {
            let previous = std::mem::replace(&mut w.user.cursor_set, a(c, 0));
            c.ret(f, Some(previous), 1);
        }
        "ShowCursor" => {
            w.user.cursor_shown += if a(c, 0) != 0 { 1 } else { -1 };
            c.ret(f, Some(w.user.cursor_shown as u32), 1);
        }
        "GetCursorPos" => {
            w.sync_input();
            let pt = a(c, 0);
            c.set_u32(pt, w.user.cursor.0 as u32);
            c.set_u32(pt + 4, w.user.cursor.1 as u32);
            c.ret(f, Some(1), 1);
        }
        "SetCursorPos" => {
            w.user.cursor = (a(c, 0) as i32, a(c, 1) as i32);
            c.ret(f, Some(1), 2);
        }
        "ScreenToClient" => c.ret(f, Some(1), 2),
        "SetCapture" => c.ret(f, Some(0), 1),
        "ReleaseCapture" => c.ret(f, Some(1), 0),
        "GetDoubleClickTime" => c.ret(f, Some(500), 0),
        "GetKeyboardState" => {
            let buf = a(c, 0);
            let keys = w.user.keys;
            c.mem.poke(buf, &keys);
            c.ret(f, Some(1), 1);
        }
        "ToAscii" => {
            let (vk, out) = (a(c, 0), a(c, 3));
            let ch = if (0x20..0x7f).contains(&vk) { vk } else { 0 };
            if ch != 0 {
                c.st(out, 2, u128::from(ch));
            }
            c.ret(f, Some(u32::from(ch != 0)), 5);
        }
        "VkKeyScanA" => {
            let ch = a(c, 0) as u8;
            c.ret(f, Some(u32::from(ch.to_ascii_uppercase())), 1);
        }
        "keybd_event" => c.ret(f, None, 4),
        "CharNextExA" => {
            let p = a(c, 1);
            let next = if c.ld(p, 1) != 0 { p + 1 } else { p };
            c.ret(f, Some(next), 3);
        }
        "CharPrevExA" => {
            let (start, p) = (a(c, 1), a(c, 2));
            c.ret(f, Some(if p > start { p - 1 } else { start }), 4);
        }
        "OpenClipboard" | "GetClipboardData" => c.ret(f, Some(0), 1),
        "EmptyClipboard" | "CloseClipboard" => c.ret(f, Some(1), 0),
        "SetClipboardData" => c.ret(f, Some(0), 2),
        "DestroyMenu" => c.ret(f, Some(1), 1),
        "SetMenu" => c.ret(f, Some(1), 2),
        "EnableMenuItem" | "CheckMenuItem" => c.ret(f, Some(0), 3),
        "GetMenuStringA" => c.ret(f, Some(0), 5),
        _ => return false,
    }
    true
}
