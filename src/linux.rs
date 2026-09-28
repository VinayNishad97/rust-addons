// Linux port of the Windows overlay/hidden-window detector.
//
// IMPORTANT CAVEAT (read before trusting this file's output):
// X11 and Wayland have NO standard, cross-desktop equivalent of
// WDA_EXCLUDEFROMCAPTURE / kCGWindowSharingNone. There is no window property
// that universally means "hidden from screen capture" the way the Windows
// display-affinity flag or macOS's window-sharing-state do. Individual
// compositors (KWin, Mutter, wlroots-based ones) have their own private,
// non-standardized mechanisms for their screen-recording pipelines, but
// nothing a normal client can query back for an arbitrary window.
//
// So this port does two different things honestly rather than one fake thing:
//   1. Click-through detection has a SOLID native equivalent: the XFixes
//      "input shape" region. A window whose input shape is empty receives no
//      pointer events at all -- this is exactly what WS_EX_TRANSPARENT means.
//   2. Capture-exclusion is approximated with a labeled HEURISTIC based on
//      window-manager hints that stealthy/hidden overlays commonly (ab)use:
//      override_redirect + _NET_WM_STATE_SKIP_TASKBAR + _NET_WM_STATE_SKIP_PAGER.
//      This is weaker evidence than the Windows/macOS checks -- treat it as
//      such in any downstream scoring.
//
// Also note: Wayland-native windows are not enumerable at all by design (the
// compositor security model deliberately prevents one client from listing
// another's surfaces). Under Wayland, this code only sees XWayland windows.
//
// Cargo.toml additions:
//   x11rb = { version = "0.13", features = ["shape"] }
//
// Process name/path use plain /proc, no extra native libs needed.

use crate::common::{codepoint_dump, Finding, ProtectedProcessInfo};
use std::collections::HashSet;
use std::fs;

use x11rb::connection::Connection;
use x11rb::protocol::shape::{ConnectionExt as ShapeConnectionExt, SK};
use x11rb::protocol::xproto::{AtomEnum, ConnectionExt, Window};
use x11rb::rust_connection::RustConnection;

type Atom = u32;

struct Atoms {
    net_client_list: Atom,
    net_wm_pid: Atom,
    net_wm_name: Atom,
    utf8_string: Atom,
    net_wm_state: Atom,
    net_wm_state_skip_taskbar: Atom,
    net_wm_state_skip_pager: Atom,
}

fn intern(conn: &RustConnection, name: &str) -> Atom {
    conn.intern_atom(false, name.as_bytes())
        .ok()
        .and_then(|c| c.reply().ok())
        .map(|r| r.atom)
        .unwrap_or(0)
}

fn load_atoms(conn: &RustConnection) -> Atoms {
    Atoms {
        net_client_list: intern(conn, "_NET_CLIENT_LIST"),
        net_wm_pid: intern(conn, "_NET_WM_PID"),
        net_wm_name: intern(conn, "_NET_WM_NAME"),
        utf8_string: intern(conn, "UTF8_STRING"),
        net_wm_state: intern(conn, "_NET_WM_STATE"),
        net_wm_state_skip_taskbar: intern(conn, "_NET_WM_STATE_SKIP_TASKBAR"),
        net_wm_state_skip_pager: intern(conn, "_NET_WM_STATE_SKIP_PAGER"),
    }
}

fn get_property_u32s(conn: &RustConnection, win: Window, atom: Atom, atype: AtomEnum) -> Vec<u32> {
    match conn
        .get_property(false, win, atom, atype, 0, u32::MAX)
        .ok()
        .and_then(|c| c.reply().ok())
    {
        Some(reply) => reply.value32().map(|v| v.collect()).unwrap_or_default(),
        None => Vec::new(),
    }
}

fn get_property_string(
    conn: &RustConnection,
    win: Window,
    atom: Atom,
    utf8_string: Atom,
) -> Option<String> {
    let reply = conn
        .get_property(false, win, atom, utf8_string, 0, u32::MAX)
        .ok()?
        .reply()
        .ok()?;
    if reply.value.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&reply.value).into_owned())
}

fn window_bounds(conn: &RustConnection, win: Window) -> (i64, i64, i64, i64) {
    match conn.get_geometry(win).ok().and_then(|c| c.reply().ok()) {
        Some(g) => (
            g.x as i64,
            g.y as i64,
            g.x as i64 + g.width as i64,
            g.y as i64 + g.height as i64,
        ),
        None => (0, 0, 0, 0),
    }
}

fn window_override_redirect(conn: &RustConnection, win: Window) -> bool {
    conn.get_window_attributes(win)
        .ok()
        .and_then(|c| c.reply().ok())
        .map(|a| a.override_redirect)
        .unwrap_or(false)
}

/// Click-through detection via the XFixes "input shape". A window whose
/// input shape region is empty receives no pointer events at all -- the
/// direct native analog of WS_EX_TRANSPARENT.
fn window_is_click_through(conn: &RustConnection, win: Window) -> bool {
    match conn
        .shape_get_rectangles(win, SK::INPUT)
        .ok()
        .and_then(|c| c.reply().ok())
    {
        Some(reply) => reply.rectangles.is_empty(),
        None => false,
    }
}

fn window_has_skip_hints(conn: &RustConnection, win: Window, atoms: &Atoms) -> bool {
    let states = get_property_u32s(conn, win, atoms.net_wm_state, AtomEnum::ATOM);
    states.contains(&atoms.net_wm_state_skip_taskbar) && states.contains(&atoms.net_wm_state_skip_pager)
}

fn pid_for_window(conn: &RustConnection, win: Window, atoms: &Atoms) -> Option<u32> {
    get_property_u32s(conn, win, atoms.net_wm_pid, AtomEnum::CARDINAL)
        .into_iter()
        .next()
}

fn proc_name(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim_end().to_string())
}

fn proc_exe_path(pid: u32) -> Option<String> {
    fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

fn list_top_level_windows(conn: &RustConnection, root: Window, atoms: &Atoms) -> Vec<Window> {
    // _NET_CLIENT_LIST is maintained by any EWMH-compliant window manager
    // (GNOME, KDE, XFCE, i3 w/ EWMH support, etc.) and is the native,
    // idiomatic way to enumerate top-level application windows -- the X11
    // analog of Windows' EnumWindows over top-level HWNDs.
    get_property_u32s(conn, root, atoms.net_client_list, AtomEnum::WINDOW)
}

pub fn get_hidden_processes() -> Vec<ProtectedProcessInfo> {
    let (conn, screen_num) = match x11rb::connect(None) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let root = conn.setup().roots[screen_num].root;
    let atoms = load_atoms(&conn);

    let mut seen: HashSet<u32> = HashSet::new();
    let mut results = Vec::new();

    for win in list_top_level_windows(&conn, root, &atoms) {
        // See module doc comment: heuristic stand-in, not a true
        // capture-exclusion flag.
        let looks_hidden =
            window_override_redirect(&conn, win) && window_has_skip_hints(&conn, win, &atoms);
        if !looks_hidden {
            continue;
        }

        let pid = match pid_for_window(&conn, win, &atoms) {
            Some(p) => p,
            None => continue,
        };
        if !seen.insert(pid) {
            continue;
        }

        let name = proc_name(pid).unwrap_or_else(|| "<unknown>".into());
        let full_path = proc_exe_path(pid);

        results.push(ProtectedProcessInfo {
            pid,
            name_debug: format!("{:?}", name),
            codepoints: codepoint_dump(&name),
            path_codepoints: full_path.as_ref().map(|p| codepoint_dump(p)),
            name,
            full_path,
        });
    }

    results
}

pub fn get_suspicious_process() -> Vec<Finding> {
    println!("=== overlay_detector (Linux/X11): scanning _NET_CLIENT_LIST ===\n");
    println!(
        "Note: X11 has no equivalent of WDA_EXCLUDEFROMCAPTURE. 'excluded_from_capture'\n\
         below is a HEURISTIC (override_redirect + skip-taskbar + skip-pager hints),\n\
         NOT a guarantee the window is actually hidden from screen capture.\n\
         Click-through detection (XFixes input shape) IS a solid native equivalent.\n\
         Wayland-native surfaces are invisible to this tool entirely.\n"
    );

    let (conn, screen_num) = match x11rb::connect(None) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let root = conn.setup().roots[screen_num].root;
    let atoms = load_atoms(&conn);

    let mut findings: Vec<Finding> = Vec::new();

    for win in list_top_level_windows(&conn, root, &atoms) {
        let excluded_from_capture =
            window_override_redirect(&conn, win) && window_has_skip_hints(&conn, win, &atoms);
        let click_through = window_is_click_through(&conn, win);

        if !excluded_from_capture && !click_through {
            continue;
        }

        let title = get_property_string(&conn, win, atoms.net_wm_name, atoms.utf8_string)
            .unwrap_or_default();
        let pid = pid_for_window(&conn, win, &atoms).unwrap_or(0);
        let process_path = proc_exe_path(pid)
            .unwrap_or_else(|| format!("<pid {pid}: could not resolve /proc/{pid}/exe>"));
        let rect64 = window_bounds(&conn, win);
        let rect = (
            rect64.0 as i32,
            rect64.1 as i32,
            rect64.2 as i32,
            rect64.3 as i32,
        );

        findings.push(Finding {
            hwnd: win as i64,
            title,
            pid,
            process_path,
            excluded_from_capture,
            excluded_kind: if excluded_from_capture {
                "override_redirect+skip_taskbar+skip_pager (heuristic)".to_string()
            } else {
                String::new()
            },
            click_through,
            rect,
        });
    }

    findings.sort_by(|a, b| b.score().cmp(&a.score()));

    let mut suspicious_count = 0;
    let mut seen_processes = HashSet::new();

    for f in &findings {
        if !f.is_suspicious() {
            continue;
        }
        suspicious_count += 1;
        seen_processes.insert(f.process_path.clone());

        println!("--------------------------------------------------------");
        println!("Suspicion score : {}", f.score());
        println!(
            "Title           : {:?}",
            if f.title.is_empty() { "<none>" } else { &f.title }
        );
        println!("PID             : {}", f.pid);
        println!("Process path    : {}", f.process_path);
        println!(
            "Rect (L,T,R,B)  : {:?}  size {}x{}",
            f.rect,
            f.rect.2 - f.rect.0,
            f.rect.3 - f.rect.1
        );
        if f.excluded_from_capture {
            println!(">> HEURISTIC CAPTURE-EXCLUSION MATCH ({})", f.excluded_kind);
        }
        if f.click_through {
            println!(">> Empty XFixes input shape (click-through)");
        }
    }

    println!("\n=== Summary ===");
    println!("Suspicious windows found : {}", suspicious_count);
    println!("Distinct processes flagged:");
    for p in &seen_processes {
        println!("  - {p}");
    }
    if suspicious_count == 0 {
        println!("No windows matched the click-through or heuristic capture-exclusion signals.");
    }

    findings
}