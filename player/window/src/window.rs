//! The native window. The game thread sends one [`Frame`] per flip, which the main thread scales
//! into the window with its aspect ratio kept, nearest neighbour, in software. Input goes back
//! through [`Input`].

use std::{
    num::NonZeroU32,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    time::{Duration, Instant},
};

use winit::{
    application::ApplicationHandler,
    event::{DeviceEvent, DeviceId, ElementState, MouseButton, MouseScrollDelta, WindowEvent},
    event_loop::{ActiveEventLoop, EventLoop, EventLoopProxy},
    keyboard::{Key, PhysicalKey},
    window::{CursorGrabMode, Window, WindowId},
};

use crate::{Frame, Input, Link, Out, on_game_stack};

/// The game thread's end of the window.
pub struct Sender {
    frames: SyncSender<Frame>,
    proxy: EventLoopProxy<()>,
    captured: Arc<AtomicBool>,
    /// The next refresh, for `wait_for_refresh`.
    next: Instant,
}

/// The time between frames: a flip waits for the display's vertical blank, 60 a second.
const FRAME: Duration = Duration::from_nanos(1_000_000_000 / 60);

impl Sender {
    /// Waits for the next refresh, as a flip waits for the display.
    pub fn wait_for_refresh(&mut self) {
        let now = Instant::now();
        if now < self.next {
            std::thread::sleep(self.next - now);
        }
        // The next refresh after this one; a frame that missed some waits for the one after.
        let now = Instant::now();
        while self.next <= now {
            self.next += FRAME;
        }
    }

    /// Hands a frame to the window; waits while the previous one is still being drawn.
    pub fn present(&self, frame: Frame) {
        if self.frames.send(frame).is_ok() {
            let _ = self.proxy.send_event(());
        }
    }

    pub fn capture(&self, on: bool) {
        if self.captured.swap(on, Ordering::Relaxed) != on {
            let _ = self.proxy.send_event(());
        }
    }
}

/// Runs the window on this thread and `game` on its own, until the window closes.
pub fn run(title: &str, game: impl FnOnce(Link) + Send + 'static) -> anyhow::Result<()> {
    let event_loop = EventLoop::<()>::with_user_event().build()?;
    let (frames, received) = sync_channel(1);
    let (input, captured) = (Arc::new(Mutex::new(Input::default())), Arc::new(AtomicBool::new(false)));
    let link = Link::new(Out::Window(Sender { frames, proxy: event_loop.create_proxy(), captured: captured.clone(), next: Instant::now() }), input.clone());
    std::thread::spawn(move || on_game_stack(move || game(link)));
    let mut app = App { title: title.to_string(), window: None, surface: None, frames: received, frame: None, input, captured, locked: false, focused: false, rest: (0.0, 0.0) };
    event_loop.run_app(&mut app)?;
    Ok(())
}

struct App {
    title: String,
    window: Option<Arc<Window>>,
    surface: Option<softbuffer::Surface<Arc<Window>, Arc<Window>>>,
    frames: Receiver<Frame>,
    /// The last frame, drawn again when the window needs it.
    frame: Option<Frame>,
    input: Arc<Mutex<Input>>,
    /// Whether the game holds the mouse, and whether the pointer is locked for it.
    captured: Arc<AtomicBool>,
    locked: bool,
    focused: bool,
    /// Motion not yet whole game pixels.
    rest: (f64, f64),
}

impl App {
    fn game_size(&self) -> (u32, u32) {
        self.frame.as_ref().map_or((640, 480), |f| (f.width, f.height))
    }

    /// Where the picture sits in the window: x, y, width, height.
    fn picture(&self) -> (f64, f64, f64, f64) {
        let Some(window) = &self.window else { return (0.0, 0.0, 1.0, 1.0) };
        let size = window.inner_size();
        let (ww, wh) = (f64::from(size.width), f64::from(size.height));
        let (gw, gh) = self.game_size();
        let scale = (ww / f64::from(gw)).min(wh / f64::from(gh));
        let (w, h) = (f64::from(gw) * scale, f64::from(gh) * scale);
        ((ww - w) / 2.0, (wh - h) / 2.0, w, h)
    }

    /// Locks the pointer while the game holds the mouse and the window has focus, and frees it
    /// otherwise. Wayland locks it; where that is not supported it is confined to the window.
    fn apply_capture(&mut self) {
        let want = self.focused && self.captured.load(Ordering::Relaxed);
        let Some(window) = &self.window else { return };
        if want == self.locked {
            return;
        }
        let result = if want { window.set_cursor_grab(CursorGrabMode::Locked).or_else(|_| window.set_cursor_grab(CursorGrabMode::Confined)) } else { window.set_cursor_grab(CursorGrabMode::None) };
        if let Err(e) = result {
            eprintln!("window: pointer grab failed: {e}");
        }
        self.locked = want;
        self.rest = (0.0, 0.0);
    }

    fn draw(&mut self) {
        let (px, py, pw, ph) = self.picture();
        let (Some(window), Some(surface), Some(frame)) = (&self.window, &mut self.surface, &self.frame) else { return };
        let size = window.inner_size();
        let (Some(w), Some(h)) = (NonZeroU32::new(size.width), NonZeroU32::new(size.height)) else { return };
        if surface.resize(w, h).is_err() {
            return;
        }
        let Ok(mut buffer) = surface.buffer_mut() else { return };
        let (ww, wh) = (size.width as usize, size.height as usize);
        // The source column of each window column, or none outside the picture.
        let columns: Vec<Option<usize>> = (0..ww).map(|x| ((x as f64 + 0.5 - px) / pw * f64::from(frame.width)).floor()).map(|c| (c >= 0.0 && c < f64::from(frame.width)).then_some(c as usize)).collect();
        for y in 0..wh {
            let row = ((y as f64 + 0.5 - py) / ph * f64::from(frame.height)).floor();
            let out = &mut buffer[y * ww..(y + 1) * ww];
            if row < 0.0 || row >= f64::from(frame.height) {
                out.fill(0);
                continue;
            }
            let src = &frame.pixels[row as usize * frame.width as usize..][..frame.width as usize];
            for (pixel, column) in out.iter_mut().zip(&columns) {
                *pixel = column.map_or(0, |c| src[c]);
            }
        }
        let _ = buffer.present();
    }
}

impl ApplicationHandler for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        let attributes = Window::default_attributes().with_title(&self.title).with_inner_size(winit::dpi::LogicalSize::new(1280.0, 960.0));
        let window = Arc::new(event_loop.create_window(attributes).expect("a window"));
        window.set_cursor_visible(false);
        let context = softbuffer::Context::new(window.clone()).expect("a display");
        self.surface = Some(softbuffer::Surface::new(&context, window.clone()).expect("a surface"));
        self.window = Some(window);
    }

    fn user_event(&mut self, _event_loop: &ActiveEventLoop, _event: ()) {
        if let Some(frame) = self.frames.try_iter().last() {
            self.frame = Some(frame);
            if let Some(window) = &self.window {
                window.request_redraw();
            }
        }
        self.apply_capture();
    }

    fn device_event(&mut self, _event_loop: &ActiveEventLoop, _id: DeviceId, event: DeviceEvent) {
        let DeviceEvent::MouseMotion { delta } = event else { return };
        if !self.locked {
            return;
        }
        // A screen pixel of motion is as many game pixels as the picture is scaled down, so the
        // game's pointer moves as fast as the system's would over the same picture.
        let scale = f64::from(self.game_size().0) / self.picture().2;
        let (x, y) = (self.rest.0 + delta.0 * scale, self.rest.1 + delta.1 * scale);
        let (dx, dy) = (x.trunc(), y.trunc());
        self.rest = (x - dx, y - dy);
        let mut input = self.input.lock().expect("input");
        input.moved.0 += dx as i32;
        input.moved.1 += dy as i32;
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        match event {
            WindowEvent::Focused(focused) => {
                self.focused = focused;
                self.apply_capture();
            }
            WindowEvent::CloseRequested => {
                self.input.lock().expect("input").quit = true;
                event_loop.exit();
            }
            WindowEvent::Resized(_) | WindowEvent::RedrawRequested => self.draw(),
            WindowEvent::CursorMoved { position, .. } => {
                let (x, y, w, h) = self.picture();
                let (gw, gh) = self.game_size();
                let gx = (((position.x - x) / w * f64::from(gw)) as i32).clamp(0, gw as i32 - 1);
                let gy = (((position.y - y) / h * f64::from(gh)) as i32).clamp(0, gh as i32 - 1);
                self.input.lock().expect("input").move_to(gx, gy);
            }
            WindowEvent::MouseInput { state, button, .. } => {
                let index = match button {
                    MouseButton::Left => 0,
                    MouseButton::Right => 1,
                    MouseButton::Middle => 2,
                    _ => return,
                };
                self.input.lock().expect("input").button(index, state == ElementState::Pressed);
            }
            WindowEvent::MouseWheel { delta, .. } => {
                let notches = match delta {
                    MouseScrollDelta::LineDelta(_, y) => y,
                    MouseScrollDelta::PixelDelta(p) => (p.y / 40.0) as f32,
                };
                self.input.lock().expect("input").moved.2 += (notches * 120.0) as i32;
            }
            WindowEvent::KeyboardInput { event, .. } => {
                let PhysicalKey::Code(code) = event.physical_key else { return };
                let label = match &event.logical_key {
                    Key::Character(text) => text.chars().next(),
                    _ => None,
                };
                let typed = event.text.as_ref().and_then(|t| t.chars().next()).or(label.filter(char::is_ascii_alphabetic));
                self.input.lock().expect("input").key(&format!("{code:?}"), typed, event.state == ElementState::Pressed);
            }
            _ => {}
        }
    }
}
