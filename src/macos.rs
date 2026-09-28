// macOS port of the Windows overlay/hidden-window detector.
//
// Windows concept                                  -> macOS equivalent
// -----------------------------------------------------------------------
// GetWindowDisplayAffinity == WDA_EXCLUDEFROMCAPTURE -> CGWindowListCopyWindowInfo
//                                                        entry's kCGWindowSharingState
//                                                        == kCGWindowSharingNone
//                                                        (this is a *direct*, near-exact
//                                                        analog -- both are explicit,
//                                                        OS-level "hide from screen
//                                                        capture/recording" flags)
// WS_EX_TRANSPARENT (click-through)                  -> NO public, cross-process
//                                                        equivalent. NSWindow's
//                                                        ignoresMouseEvents is only
//                                                        readable from inside the owning
//                                                        process. Left as `false` below,
//                                                        clearly labeled.
// EnumWindows + GetWindowThreadProcessId             -> CGWindowListCopyWindowInfo already
//                                                        returns kCGWindowOwnerPID per
//                                                        window; no separate enumeration
//                                                        + lookup pass needed.
// Toolhelp32Snapshot / Process32First/NextW          -> not needed -- PID comes from the
//                                                        CG window dictionary directly.
// QueryFullProcessImageNameW                        -> proc_pidpath() (libproc.h)
//
// Cargo.toml additions:
//   core-foundation = "0.9"
//
// Build requires linking the CoreGraphics framework (handled by the #[link] attribute
// below) and normal libSystem, which is linked by default and provides proc_pidpath.

use crate::common::{codepoint_dump, Finding, ProtectedProcessInfo};
use std::collections::HashSet;
use std::ffi::c_void;
use std::os::raw::{c_char, c_int};

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;

const K_CG_WINDOW_LIST_OPTION_ALL: u32 = 0;
const K_CG_NULL_WINDOW_ID: u32 = 0;

// CGWindow.h: kCGWindowSharingNone
const K_CG_WINDOW_SHARING_NONE: i64 = 0;

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGWindowListCopyWindowInfo(option: u32, relative_to_window: u32) -> *const c_void;
}

// libproc.h -- part of libSystem, no extra linker flags needed.
extern "C" {
    fn proc_pidpath(pid: c_int, buffer: *mut c_char, buffersize: u32) -> c_int;
}

const PROC_PIDPATHINFO_MAXSIZE: usize = 4 * 1024;

fn pid_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
    let ret = unsafe { proc_pidpath(pid, buf.as_mut_ptr() as *mut c_char, buf.len() as u32) };
    if ret <= 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..ret as usize]).into_owned())
}

fn pid_name(pid: i32) -> Option<String> {
    // proc_pidpath gives the full path; derive the executable name from it,
    // mirroring the "szExeFile" field from the Windows Toolhelp snapshot.
    pid_path(pid).map(|p| p.rsplit('/').next().unwrap_or(&p).to_string())
}

struct WindowRecord {
    pid: i32,
    window_id: u32,
    owner_name: Option<String>,
    window_name: Option<String>,
    sharing_state: i64,
    is_onscreen: bool,
    bounds: (i64, i64, i64, i64), // left, top, right, bottom
}

fn get_number(dict: &CFDictionary<CFString, CFType>, key: &str) -> Option<i64> {
    dict.find(CFString::new(key))
        .and_then(|v| v.downcast::<CFNumber>())
        .and_then(|n| n.to_i64())
}

fn get_double(dict: &CFDictionary<CFString, CFType>, key: &str) -> Option<f64> {
    dict.find(CFString::new(key))
        .and_then(|v| v.downcast::<CFNumber>())
        .and_then(|n| n.to_f64())
}

fn get_bool(dict: &CFDictionary<CFString, CFType>, key: &str) -> bool {
    get_number(dict, key).map(|n| n != 0).unwrap_or(false)
}

fn get_string(dict: &CFDictionary<CFString, CFType>, key: &str) -> Option<String> {
    dict.find(CFString::new(key))
        .and_then(|v| v.downcast::<CFString>())
        .map(|s| s.to_string())
}

fn list_windows() -> Vec<WindowRecord> {
    let mut out = Vec::new();

    unsafe {
        let cf_array_ref =
            CGWindowListCopyWindowInfo(K_CG_WINDOW_LIST_OPTION_ALL, K_CG_NULL_WINDOW_ID);
        if cf_array_ref.is_null() {
            return out;
        }

        let array: CFArray<CFType> = TCFType::wrap_under_create_rule(cf_array_ref as *const _);

        for item in array.iter() {
            let dict = match item.downcast::<CFDictionary<CFString, CFType>>() {
                Some(d) => d,
                None => continue,
            };

            let pid = match get_number(&dict, "kCGWindowOwnerPID") {
                Some(p) => p as i32,
                None => continue,
            };

            let window_id = get_number(&dict, "kCGWindowNumber").unwrap_or(0) as u32;

            let bounds_dict = dict
                .find(CFString::new("kCGWindowBounds"))
                .and_then(|v| v.downcast::<CFDictionary<CFString, CFType>>());

            let (x, y, w, h) = if let Some(b) = bounds_dict {
                (
                    get_double(&b, "X").unwrap_or(0.0) as i64,
                    get_double(&b, "Y").unwrap_or(0.0) as i64,
                    get_double(&b, "Width").unwrap_or(0.0) as i64,
                    get_double(&b, "Height").unwrap_or(0.0) as i64,
                )
            } else {
                (0, 0, 0, 0)
            };

            out.push(WindowRecord {
                pid,
                window_id,
                owner_name: get_string(&dict, "kCGWindowOwnerName"),
                window_name: get_string(&dict, "kCGWindowName"),
                sharing_state: get_number(&dict, "kCGWindowSharingState").unwrap_or(1),
                is_onscreen: get_bool(&dict, "kCGWindowIsOnscreen"),
                bounds: (x, y, x + w, y + h),
            });
        }
    }

    out
}

pub fn get_hidden_processes() -> Vec<ProtectedProcessInfo> {
    let windows = list_windows();
    let mut seen: HashSet<i32> = HashSet::new();
    let mut results = Vec::new();

    for w in windows {
        if w.sharing_state != K_CG_WINDOW_SHARING_NONE {
            continue;
        }
        if !seen.insert(w.pid) {
            continue;
        }

        let name = pid_name(w.pid)
            .or(w.owner_name.clone())
            .unwrap_or_else(|| "<unknown>".into());
        let full_path = pid_path(w.pid);

        results.push(ProtectedProcessInfo {
            pid: w.pid as u32,
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
    println!("=== overlay_detector (macOS): scanning ===\n");

    let windows = list_windows();
    let mut findings: Vec<Finding> = Vec::new();

    for w in windows {
        let excluded_from_capture = w.sharing_state == K_CG_WINDOW_SHARING_NONE;
        if !excluded_from_capture {
            continue;
        }

        // No public, cross-process way to read NSWindow.ignoresMouseEvents on macOS,
        // so click-through cannot be detected the way WS_EX_TRANSPARENT allows on
        // Windows. Field kept for structural parity with the other platforms.
        let click_through = false;

        let full_path =
            pid_path(w.pid).unwrap_or_else(|| format!("<pid {}: could not resolve path>", w.pid));

        findings.push(Finding {
            hwnd: w.window_id as i64, // CGWindowID, not an NSWindow/HWND handle
            title: w.window_name.unwrap_or_default(),
            pid: w.pid as u32,
            process_path: full_path,
            excluded_from_capture,
            excluded_kind: "kCGWindowSharingNone".to_string(),
            click_through,
            rect: w.bounds,
        });

        let _ = w.is_onscreen; // available if you want to filter offscreen windows out
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
        println!(">> EXCLUDED FROM SCREEN CAPTURE  ({})", f.excluded_kind);
    }

    println!("\n=== Summary ===");
    println!("Suspicious windows found : {}", suspicious_count);
    println!("Distinct processes flagged:");
    for p in &seen_processes {
        println!("  - {p}");
    }
    if suspicious_count == 0 {
        println!("No windows matched kCGWindowSharingNone.");
    } else {
        println!(
            "\nNote: kCGWindowSharingNone is macOS's near-exact analog of \n\
             WDA_EXCLUDEFROMCAPTURE -- apps opt into it explicitly (e.g. via \n\
             NSWindow.sharingType = .none) to hide a window from screen recording/\n\
             sharing. There is no public API to detect click-through overlays \n\
             belonging to another process on macOS, so that signal is unavailable here."
        );
    }

    findings
}