use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::Line,
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph},
};
use serde_json::{Value, json};

const STEP_COUNT: usize = 6;

#[derive(Clone, Copy, Debug)]
enum StepState {
    NotRun,
    Success,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Focus {
    SocketPath,
    EnableLogging,
    LogPath,
    KernelImage,
    KernelArgs,
    Rootfs,
    IfaceId,
    GuestMac,
    HostDevName,
    BtnPing,
    BtnLogger,
    BtnBootSource,
    BtnRootfs,
    BtnNetwork,
    BtnStartVm,
    BtnRunAll,
}

const FOCUS_ORDER: [Focus; 16] = [
    Focus::SocketPath,
    Focus::EnableLogging,
    Focus::LogPath,
    Focus::KernelImage,
    Focus::KernelArgs,
    Focus::Rootfs,
    Focus::IfaceId,
    Focus::GuestMac,
    Focus::HostDevName,
    Focus::BtnPing,
    Focus::BtnLogger,
    Focus::BtnBootSource,
    Focus::BtnRootfs,
    Focus::BtnNetwork,
    Focus::BtnStartVm,
    Focus::BtnRunAll,
];

struct App {
    socket_path: String,
    enable_logging: bool,
    log_path: String,
    kernel_image: String,
    kernel_args: String,
    rootfs_path: String,
    iface_id: String,
    guest_mac: String,
    host_dev_name: String,
    focus: Focus,
    steps: [StepState; STEP_COUNT],
    status_lines: Vec<String>,
    path_completions: Vec<String>,
    selected_completion: usize,
}

impl Default for App {
    fn default() -> Self {
        Self {
            socket_path: "/tmp/firecracker.socket".to_string(),
            enable_logging: false,
            log_path: "/tmp/firecracker.log".to_string(),
            kernel_image: String::new(),
            kernel_args: "console=ttyS0 reboot=k panic=1 pci=off".to_string(),
            rootfs_path: String::new(),
            iface_id: "eth0".to_string(),
            guest_mac: "06:00:AC:10:00:02".to_string(),
            host_dev_name: "tap0".to_string(),
            focus: Focus::SocketPath,
            steps: [StepState::NotRun; STEP_COUNT],
            status_lines: vec![
                "Ready. Use Tab/Shift+Tab to navigate, Enter to run action, Ctrl+C to quit."
                    .to_string(),
            ],
            path_completions: Vec::new(),
            selected_completion: 0,
        }
    }
}

impl App {
    fn is_path_focus(&self) -> bool {
        matches!(
            self.focus,
            Focus::SocketPath | Focus::LogPath | Focus::KernelImage | Focus::Rootfs
        )
    }

    fn focused_value(&self) -> Option<&str> {
        match self.focus {
            Focus::SocketPath => Some(&self.socket_path),
            Focus::LogPath => Some(&self.log_path),
            Focus::KernelImage => Some(&self.kernel_image),
            Focus::KernelArgs => Some(&self.kernel_args),
            Focus::Rootfs => Some(&self.rootfs_path),
            Focus::IfaceId => Some(&self.iface_id),
            Focus::GuestMac => Some(&self.guest_mac),
            Focus::HostDevName => Some(&self.host_dev_name),
            _ => None,
        }
    }

    fn focused_value_mut(&mut self) -> Option<&mut String> {
        match self.focus {
            Focus::SocketPath => Some(&mut self.socket_path),
            Focus::LogPath => Some(&mut self.log_path),
            Focus::KernelImage => Some(&mut self.kernel_image),
            Focus::KernelArgs => Some(&mut self.kernel_args),
            Focus::Rootfs => Some(&mut self.rootfs_path),
            Focus::IfaceId => Some(&mut self.iface_id),
            Focus::GuestMac => Some(&mut self.guest_mac),
            Focus::HostDevName => Some(&mut self.host_dev_name),
            _ => None,
        }
    }

    fn has_visible_completions(&self) -> bool {
        self.is_path_focus() && !self.path_completions.is_empty()
    }

    fn completion_base_and_prefix(input: &str) -> (PathBuf, String) {
        if input.is_empty() {
            return (PathBuf::from("."), String::new());
        }

        if input.ends_with('/') {
            return (PathBuf::from(input), String::new());
        }

        let path = Path::new(input);
        match (path.parent(), path.file_name()) {
            (Some(parent), Some(file_name)) if !parent.as_os_str().is_empty() => (
                parent.to_path_buf(),
                file_name.to_string_lossy().to_string(),
            ),
            _ => (PathBuf::from("."), input.to_string()),
        }
    }

    fn update_path_completions(&mut self) {
        self.path_completions.clear();
        self.selected_completion = 0;

        if !self.is_path_focus() {
            return;
        }

        let Some(current_value) = self.focused_value() else {
            return;
        };

        let (base_dir, prefix) = Self::completion_base_and_prefix(current_value);
        let dir_for_scan = if base_dir.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            base_dir.clone()
        };

        let Ok(entries) = std::fs::read_dir(&dir_for_scan) else {
            return;
        };

        let mut results = Vec::new();
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name().to_string_lossy().to_string();

            if !prefix.is_empty() && !name.starts_with(&prefix) {
                continue;
            }

            let mut candidate = if base_dir == Path::new(".") {
                name
            } else {
                let base_str = base_dir.display().to_string();
                if base_str.ends_with('/') {
                    format!("{}{}", base_str, name)
                } else {
                    format!("{}/{}", base_str, name)
                }
            };

            if file_type.is_dir() {
                candidate.push('/');
            }

            results.push(candidate);
        }

        results.sort();
        self.path_completions = results;
    }

    fn select_next_completion(&mut self) {
        if self.path_completions.is_empty() {
            return;
        }
        self.selected_completion = (self.selected_completion + 1) % self.path_completions.len();
    }

    fn select_prev_completion(&mut self) {
        if self.path_completions.is_empty() {
            return;
        }
        self.selected_completion = if self.selected_completion == 0 {
            self.path_completions.len() - 1
        } else {
            self.selected_completion - 1
        };
    }

    fn apply_selected_completion(&mut self) {
        let Some(selected) = self.path_completions.get(self.selected_completion).cloned() else {
            return;
        };

        if let Some(current) = self.focused_value_mut() {
            *current = selected;
        }
        self.update_path_completions();
    }

    fn push_status(&mut self, message: impl Into<String>) {
        self.status_lines.push(message.into());
        if self.status_lines.len() > 200 {
            let trim = self.status_lines.len() - 200;
            self.status_lines.drain(0..trim);
        }
    }

    fn move_focus(&mut self, forward: bool) {
        let current_idx = FOCUS_ORDER
            .iter()
            .position(|f| *f == self.focus)
            .unwrap_or(0);
        let next_idx = if forward {
            (current_idx + 1) % FOCUS_ORDER.len()
        } else if current_idx == 0 {
            FOCUS_ORDER.len() - 1
        } else {
            current_idx - 1
        };
        self.focus = FOCUS_ORDER[next_idx];
    }

    fn can_run_step(&self, step_idx: usize) -> bool {
        self.steps
            .iter()
            .take(step_idx)
            .all(|s| matches!(s, StepState::Success))
    }

    fn set_step_result(&mut self, step_idx: usize, success: bool) {
        self.steps[step_idx] = if success {
            StepState::Success
        } else {
            StepState::Failed
        };

        if !success {
            for later in self.steps.iter_mut().skip(step_idx + 1) {
                *later = StepState::NotRun;
            }
        }
    }

    fn run_step(&mut self, step_idx: usize) {
        if !self.can_run_step(step_idx) {
            self.push_status(format!(
                "Step {} blocked: previous step must succeed first.",
                step_idx + 1
            ));
            return;
        }

        let result = match step_idx {
            0 => self.step_ping(),
            1 => self.step_logger(),
            2 => self.step_boot_source(),
            3 => self.step_rootfs(),
            4 => self.step_network(),
            5 => self.step_start_vm(),
            _ => Err("Invalid step index".to_string()),
        };

        match result {
            Ok(msg) => {
                self.set_step_result(step_idx, true);
                self.push_status(format!("Step {} success: {msg}", step_idx + 1));
            }
            Err(err) => {
                self.set_step_result(step_idx, false);
                self.push_status(format!("Step {} failed: {err}", step_idx + 1));
            }
        }
    }

    fn run_all_steps(&mut self) {
        self.push_status("Running all steps in order...");
        for step_idx in 0..STEP_COUNT {
            if !self.can_run_step(step_idx) {
                self.push_status(format!(
                    "Run-all stopped at step {}: dependency failed.",
                    step_idx + 1
                ));
                break;
            }
            let before = self.steps[step_idx];
            self.run_step(step_idx);
            if !matches!(self.steps[step_idx], StepState::Success)
                && !matches!(before, StepState::Success)
            {
                self.push_status(format!(
                    "Run-all terminated because step {} failed.",
                    step_idx + 1
                ));
                break;
            }
        }
    }

    fn step_ping(&self) -> Result<String, String> {
        let response = send_json_request(&self.socket_path, "GET", "/", None)?;
        Ok(format!("Firecracker ping responded: {response}"))
    }

    fn step_logger(&self) -> Result<String, String> {
        if !self.enable_logging {
            return Ok("logging disabled, skipping logger configuration".to_string());
        }
        if self.log_path.is_empty() {
            return Err("log path is required when logging is enabled".to_string());
        }

        let payload = json!({
            "log_path": self.log_path,
            "level": "Info",
            "show_level": true,
            "show_log_origin": false,
        });

        let _ = send_json_request(&self.socket_path, "PUT", "/logger", Some(payload))?;
        Ok("logger configured".to_string())
    }

    fn step_boot_source(&self) -> Result<String, String> {
        if self.kernel_image.is_empty() {
            return Err("kernel image path is required".to_string());
        }

        let payload = json!({
            "kernel_image_path": self.kernel_image,
            "boot_args": self.kernel_args,
        });

        let _ = send_json_request(&self.socket_path, "PUT", "/boot-source", Some(payload))?;
        Ok("boot source configured".to_string())
    }

    fn step_rootfs(&self) -> Result<String, String> {
        if self.rootfs_path.is_empty() {
            return Err("rootfs path is required".to_string());
        }

        let payload = json!({
            "drive_id": "rootfs",
            "path_on_host": self.rootfs_path,
            "is_root_device": true,
            "is_read_only": false,
        });

        let _ = send_json_request(&self.socket_path, "PUT", "/drives/rootfs", Some(payload))?;
        Ok("rootfs drive configured".to_string())
    }

    fn step_network(&self) -> Result<String, String> {
        if self.iface_id.is_empty() {
            return Err("iface_id is required".to_string());
        }
        if self.guest_mac.is_empty() {
            return Err("guest_mac is required".to_string());
        }
        if self.host_dev_name.is_empty() {
            return Err("host_dev_name is required".to_string());
        }

        let payload = json!({
            "iface_id": self.iface_id,
            "guest_mac": self.guest_mac,
            "host_dev_name": self.host_dev_name,
        });

        let path = format!("/network-interfaces/{}", self.iface_id);
        let _ = send_json_request(&self.socket_path, "PUT", &path, Some(payload))?;
        Ok("network interface configured".to_string())
    }

    fn step_start_vm(&self) -> Result<String, String> {
        let payload = json!({ "action_type": "InstanceStart" });
        let _ = send_json_request(&self.socket_path, "PUT", "/actions", Some(payload))?;
        Ok("VM start requested".to_string())
    }
}

fn send_json_request(
    socket_path: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<String, String> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("failed to connect to socket '{socket_path}': {e}"))?;

    let body_str = body.map(|v| v.to_string()).unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body_str.len(),
        body_str
    );

    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("failed to write request: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("failed to flush request: {e}"))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("failed to read response: {e}"))?;

    let mut lines = response.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| "malformed HTTP response: missing status line".to_string())?;

    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| "malformed HTTP response: missing status code".to_string())?
        .parse::<u16>()
        .map_err(|e| format!("failed parsing status code: {e}"))?;

    let body_part = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("");

    if (200..300).contains(&status_code) {
        Ok(if body_part.trim().is_empty() {
            "OK".to_string()
        } else {
            body_part.trim().to_string()
        })
    } else {
        Err(format!("HTTP {status_code}: {}", body_part.trim()))
    }
}

fn ui(frame: &mut ratatui::Frame, app: &App) {
    let area = frame.area();

    if app.has_visible_completions() {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Length(25),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Min(3),
                Constraint::Length(1),
            ])
            .split(area);

        frame.render_widget(
            Paragraph::new("Firecracker TUI")
                .style(Style::default().fg(Color::Cyan).bold())
                .block(Block::default().borders(Borders::BOTTOM)),
            chunks[0],
        );
        render_form(frame, chunks[1], app);
        render_steps(frame, chunks[2], app);
        render_path_completion(frame, chunks[3], app);
        render_status(frame, chunks[4], app);
        frame.render_widget(
            Paragraph::new(
                "Ctrl+C: quit | Tab/Shift+Tab: focus | Enter: action/accept | Up/Down: completion | Space: toggle checkbox",
            ),
            chunks[5],
        );
    } else {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Length(25),
                Constraint::Length(8),
                Constraint::Min(6),
                Constraint::Length(1),
            ])
            .split(area);

        frame.render_widget(
            Paragraph::new("Firecracker TUI")
                .style(Style::default().fg(Color::Cyan).bold())
                .block(Block::default().borders(Borders::BOTTOM)),
            chunks[0],
        );
        render_form(frame, chunks[1], app);
        render_steps(frame, chunks[2], app);
        render_status(frame, chunks[3], app);
        frame.render_widget(
            Paragraph::new(
                "Ctrl+C: quit | Tab/Shift+Tab: focus | Enter: action | Space: toggle checkbox",
            ),
            chunks[4],
        );
    }
}

fn render_form(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .split(area);

    render_input(
        frame,
        rows[0],
        "Socket Path",
        &app.socket_path,
        app.focus == Focus::SocketPath,
    );

    let checkbox = if app.enable_logging { "[x]" } else { "[ ]" };
    let logging_line = Line::from(vec![
        if app.focus == Focus::EnableLogging {
            "Enable Logging ".bold().fg(Color::Yellow)
        } else {
            "Enable Logging ".into()
        },
        format!("{checkbox} (toggle with Enter or Space)").into(),
    ]);
    frame.render_widget(
        Paragraph::new(logging_line).block(Block::default().borders(Borders::ALL)),
        rows[1],
    );

    render_input(
        frame,
        rows[2],
        "Log Path",
        &app.log_path,
        app.focus == Focus::LogPath,
    );
    render_input(
        frame,
        rows[3],
        "Kernel Image Path",
        &app.kernel_image,
        app.focus == Focus::KernelImage,
    );
    render_input(
        frame,
        rows[4],
        "Kernel Arguments",
        &app.kernel_args,
        app.focus == Focus::KernelArgs,
    );
    render_input(
        frame,
        rows[5],
        "Rootfs Path",
        &app.rootfs_path,
        app.focus == Focus::Rootfs,
    );
    render_input(
        frame,
        rows[6],
        "Network iface_id",
        &app.iface_id,
        app.focus == Focus::IfaceId,
    );

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[7]);

    render_input(
        frame,
        bottom[0],
        "Network guest_mac",
        &app.guest_mac,
        app.focus == Focus::GuestMac,
    );
    render_input(
        frame,
        bottom[1],
        "Network host_dev_name",
        &app.host_dev_name,
        app.focus == Focus::HostDevName,
    );
}

fn render_steps(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let buttons = [
        (Focus::BtnPing, "Step 1: Ping Firecracker", 0),
        (Focus::BtnLogger, "Step 2: Configure Logger", 1),
        (Focus::BtnBootSource, "Step 3: Configure Boot Source", 2),
        (Focus::BtnRootfs, "Step 4: Configure Rootfs", 3),
        (Focus::BtnNetwork, "Step 5: Configure Network", 4),
        (Focus::BtnStartVm, "Step 6: Start VM", 5),
    ];

    let mut items = Vec::with_capacity(buttons.len() + 1);
    for (focus, label, idx) in buttons {
        let step_state = match app.steps[idx] {
            StepState::NotRun => "Not run",
            StepState::Success => "Success",
            StepState::Failed => "Failed",
        };

        let prefix = if app.focus == focus { ">" } else { " " };
        items.push(ListItem::new(format!("{prefix} [{label}] - {step_state}")));
    }
    let run_all_prefix = if app.focus == Focus::BtnRunAll {
        ">"
    } else {
        " "
    };
    items.push(ListItem::new(format!(
        "{run_all_prefix} [Run All Steps Sequentially]"
    )));

    frame.render_widget(
        List::new(items).block(
            Block::default()
                .title("Actions")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        area,
    );
}

fn render_path_completion(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let cwd = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .display()
        .to_string();

    let visible_count = area.height.saturating_sub(2) as usize;
    let start = app
        .selected_completion
        .saturating_sub(visible_count.saturating_sub(1));

    let mut items = Vec::new();
    for (idx, path) in app
        .path_completions
        .iter()
        .enumerate()
        .skip(start)
        .take(visible_count)
    {
        let item = if idx == app.selected_completion {
            ListItem::new(format!("> {path}"))
                .style(Style::default().fg(Color::Yellow).bg(Color::DarkGray))
        } else {
            ListItem::new(format!("  {path}"))
        };
        items.push(item);
    }

    frame.render_widget(
        List::new(items).block(
            Block::default()
                .title(format!("Path Completion (cwd: {cwd})"))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Magenta)),
        ),
        area,
    );
}

fn render_status(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let mut lines: Vec<ListItem> = app
        .status_lines
        .iter()
        .rev()
        .take((area.height.saturating_sub(2)) as usize)
        .map(|line| ListItem::new(line.clone()))
        .collect();
    lines.reverse();

    frame.render_widget(Clear, area);
    frame.render_widget(
        List::new(lines).block(
            Block::default()
                .title("Step Output")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        ),
        area,
    );
}

fn render_input(frame: &mut ratatui::Frame, area: Rect, title: &str, value: &str, focused: bool) {
    let border_style = if focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    frame.render_widget(
        Paragraph::new(value.to_string()).block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(border_style),
        ),
        area,
    );

    if focused {
        // Keep the cursor on the visible content row inside the bordered input.
        let max_inner_width = area.width.saturating_sub(3) as usize;
        let visible_len = value.chars().count().min(max_inner_width) as u16;
        let cursor_x = area.x.saturating_add(1).saturating_add(visible_len);
        let cursor_y = area.y.saturating_add(1);
        frame.set_cursor_position((cursor_x, cursor_y));
    }
}

fn run_app() -> Result<(), String> {
    enable_raw_mode().map_err(|e| format!("failed to enable raw mode: {e}"))?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)
        .map_err(|e| format!("failed to enter alternate screen: {e}"))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| format!("terminal init failed: {e}"))?;

    let mut app = App::default();
    app.update_path_completions();
    let tick_rate = Duration::from_millis(250);
    let mut last_tick = Instant::now();

    let result = loop {
        terminal
            .draw(|f| ui(f, &app))
            .map_err(|e| format!("draw failed: {e}"))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout).map_err(|e| format!("event poll failed: {e}"))?
            && let Event::Key(key) = event::read().map_err(|e| format!("event read failed: {e}"))?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            match key.code {
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break Ok(()),
                KeyCode::Tab => {
                    app.move_focus(true);
                    app.update_path_completions();
                }
                KeyCode::BackTab => {
                    app.move_focus(false);
                    app.update_path_completions();
                }
                KeyCode::Up if app.has_visible_completions() => app.select_prev_completion(),
                KeyCode::Down if app.has_visible_completions() => app.select_next_completion(),
                KeyCode::Enter if app.has_visible_completions() => {
                    app.apply_selected_completion();
                }
                KeyCode::Enter => match app.focus {
                    Focus::EnableLogging => {
                        app.enable_logging = !app.enable_logging;
                        app.push_status(format!("Logging enabled: {}", app.enable_logging));
                    }
                    Focus::BtnPing => app.run_step(0),
                    Focus::BtnLogger => app.run_step(1),
                    Focus::BtnBootSource => app.run_step(2),
                    Focus::BtnRootfs => app.run_step(3),
                    Focus::BtnNetwork => app.run_step(4),
                    Focus::BtnStartVm => app.run_step(5),
                    Focus::BtnRunAll => app.run_all_steps(),
                    _ => {}
                },
                KeyCode::Char(' ')
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        || key.modifiers.contains(KeyModifiers::SUPER) =>
                {
                    app.update_path_completions();
                }
                KeyCode::Char(' ') if app.focus == Focus::EnableLogging => {
                    app.enable_logging = !app.enable_logging;
                    app.push_status(format!("Logging enabled: {}", app.enable_logging));
                }
                KeyCode::Backspace => {
                    if let Some(current) = app.focused_value_mut() {
                        current.pop();
                        app.update_path_completions();
                    }
                }
                KeyCode::Char(c) => {
                    if let Some(current) = app.focused_value_mut() {
                        current.push(c);
                        app.update_path_completions();
                    }
                }
                _ => {}
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    };

    disable_raw_mode().map_err(|e| format!("failed to disable raw mode: {e}"))?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .map_err(|e| format!("failed to leave alternate screen: {e}"))?;
    terminal
        .show_cursor()
        .map_err(|e| format!("failed to show cursor: {e}"))?;
    result
}

fn main() {
    if let Err(err) = run_app() {
        eprintln!("Error: {err}");
    }
}
