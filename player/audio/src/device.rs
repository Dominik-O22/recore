//! The default output device, through cpal, on a thread of its own.

use std::sync::mpsc::{Receiver, Sender, channel};

use cpal::{
    FromSample, SizedSample,
    traits::{DeviceTrait, HostTrait, StreamTrait},
};

use crate::{Command, Mixer};

pub struct Audio {
    commands: Sender<Command>,
}

impl Audio {
    /// The default output device, or none when there is no sound to be had; the reason goes to
    /// stderr. The stream lives on a thread of its own.
    pub fn open() -> Option<Audio> {
        let (commands, received) = channel();
        let (ready, opened) = channel();
        std::thread::Builder::new()
            .name("audio".into())
            .spawn(move || {
                let stream = match stream(received) {
                    Ok(stream) => stream,
                    Err(e) => {
                        let _ = ready.send(Err(e));
                        return;
                    }
                };
                let _ = ready.send(Ok(()));
                // The stream plays while this thread holds it, until the host is gone.
                std::thread::park();
                drop(stream);
            })
            .ok()?;
        match opened.recv() {
            Ok(Ok(())) => Some(Audio { commands }),
            Ok(Err(e)) => {
                eprintln!("audio: no sound: {e}");
                None
            }
            Err(_) => None,
        }
    }

    pub fn send(&mut self, command: Command) {
        let _ = self.commands.send(command);
    }

    /// Nothing to do: the device's thread mixes as it plays.
    pub fn pump(&mut self) {}
}

fn stream(commands: Receiver<Command>) -> Result<cpal::Stream, String> {
    let device = cpal::default_host().default_output_device().ok_or("no output device")?;
    let supported = device.default_output_config().map_err(|e| e.to_string())?;
    let config: cpal::StreamConfig = supported.config();
    let mixer = Mixer::new(config.sample_rate, usize::from(config.channels));
    let stream = match supported.sample_format() {
        cpal::SampleFormat::F32 => build::<f32>(&device, config, mixer, commands),
        cpal::SampleFormat::I16 => build::<i16>(&device, config, mixer, commands),
        cpal::SampleFormat::I32 => build::<i32>(&device, config, mixer, commands),
        cpal::SampleFormat::U16 => build::<u16>(&device, config, mixer, commands),
        other => return Err(format!("unsupported sample format {other:?}")),
    }?;
    stream.play().map_err(|e| e.to_string())?;
    eprintln!("audio: {} Hz, {} channels", config.sample_rate, config.channels);
    Ok(stream)
}

fn build<T: SizedSample + FromSample<f32>>(device: &cpal::Device, config: cpal::StreamConfig, mut mixer: Mixer, commands: Receiver<Command>) -> Result<cpal::Stream, String> {
    let mut mixed = Vec::new();
    device
        .build_output_stream(
            config,
            move |out: &mut [T], _: &cpal::OutputCallbackInfo| {
                while let Ok(command) = commands.try_recv() {
                    mixer.command(command);
                }
                mixed.clear();
                mixed.resize(out.len(), 0.0);
                mixer.mix(&mut mixed);
                for (o, v) in out.iter_mut().zip(&mixed) {
                    *o = T::from_sample(*v);
                }
            },
            |e| eprintln!("audio: {e}"),
            None,
        )
        .map_err(|e| e.to_string())
}

