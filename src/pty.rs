use portable_pty::{native_pty_system, CommandBuilder, PtyPair, PtySize};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::info;

pub enum PtyCommand {
    Input(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Pause,
    Resume,
    Kill { sig_code: i32 },
}

pub enum PtyEvent {
    Output(Vec<u8>),
    Exit(i32),
}

pub struct PtyHandle {
    pub cmd_tx: mpsc::Sender<PtyCommand>,
}

pub fn spawn_pty(
    argv: Vec<String>,
    envp: Vec<(String, String)>,
    cwd: Option<String>,
    cols: u16,
    rows: u16,
    read_buf_size: usize,
    event_tx: mpsc::Sender<PtyEvent>,
) -> anyhow::Result<PtyHandle> {
    let pty_system = native_pty_system();

    let size = PtySize {
        cols,
        rows,
        pixel_width: 0,
        pixel_height: 0,
    };
    let PtyPair { master, slave } = pty_system.openpty(size)?;

    // Get reader/writer before moving master into Arc<Mutex> for resize
    let mut writer = master.take_writer()?;
    let mut reader = master.try_clone_reader()?;
    let master_arc = Arc::new(Mutex::new(master));

    let mut cmd = CommandBuilder::new(&argv[0]);
    for arg in argv.iter().skip(1) {
        cmd.arg(arg);
    }
    for (k, v) in &envp {
        cmd.env(k, v);
    }
    if let Some(dir) = cwd {
        cmd.cwd(dir);
    }

    let mut child = slave.spawn_command(cmd)?;
    let child_pid = child.process_id().unwrap_or(0);
    info!("started process, pid: {}", child_pid);

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<PtyCommand>(64);

    // Dedicated stdin-write thread (sync I/O)
    let (write_tx, write_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        while let Ok(data) = write_rx.recv() {
            if writer.write_all(&data).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    });

    // kill_flag: shared between command task and child-wait thread
    let kill_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let kill_flag_wait = Arc::clone(&kill_flag);
    let kill_sig = Arc::new(std::sync::atomic::AtomicI32::new(15));
    let kill_sig_wait = Arc::clone(&kill_sig);
    let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let paused_read = Arc::clone(&paused);

    // Async command dispatch task
    let master_for_resize = Arc::clone(&master_arc);
    tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                PtyCommand::Input(data) => {
                    let _ = write_tx.send(data);
                }
                PtyCommand::Resize { cols, rows } => {
                    if let Ok(m) = master_for_resize.lock() {
                        let _ = m.resize(PtySize {
                            cols,
                            rows,
                            pixel_width: 0,
                            pixel_height: 0,
                        });
                    }
                }
                PtyCommand::Pause => paused.store(true, std::sync::atomic::Ordering::SeqCst),
                PtyCommand::Resume => paused.store(false, std::sync::atomic::Ordering::SeqCst),
                PtyCommand::Kill { sig_code } => {
                    kill_sig.store(sig_code, std::sync::atomic::Ordering::SeqCst);
                    kill_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    break;
                }
            }
        }
        drop(master_for_resize);
    });

    // Blocking PTY read thread
    let event_tx_read = event_tx.clone();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; read_buf_size.max(128)];
        loop {
            if paused_read.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(20));
                continue;
            }
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if event_tx_read
                        .blocking_send(PtyEvent::Output(buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    // Child wait thread — polls try_wait so kill_flag can be checked
    std::thread::spawn(move || {
        let mut killed = false;
        loop {
            if kill_flag_wait.load(std::sync::atomic::Ordering::SeqCst) && !killed {
                killed = true;
                let _sig_code = kill_sig_wait.load(std::sync::atomic::Ordering::SeqCst);
                #[cfg(unix)]
                unsafe {
                    libc::kill(-(child_pid as libc::pid_t), _sig_code);
                }
                #[cfg(windows)]
                {
                    let _ = child.kill();
                }
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    let code = if status.success() {
                        0i32
                    } else {
                        status.exit_code() as i32
                    };
                    info!("process exited with code {}", code);
                    let _ = event_tx.blocking_send(PtyEvent::Exit(code));
                    break;
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
                Err(_) => break,
            }
        }
    });

    Ok(PtyHandle { cmd_tx })
}
