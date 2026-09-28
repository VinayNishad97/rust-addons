use crate::common::{codepoint_dump, ProtectedProcessInfo,Finding};

use std::collections::{HashMap, HashSet};

use windows::core::PWSTR;
use windows::Win32::Foundation::{
    BOOL, CloseHandle, HANDLE, HWND, LPARAM, MAX_PATH,RECT
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot,
    Process32FirstW,
    Process32NextW,
    PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess,
    QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
     PROCESS_VM_READ,
};
///////////////

use windows::Win32::System::ProcessStatus::K32GetModuleFileNameExW;

use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowDisplayAffinity, GetWindowLongPtrW, GetWindowRect, GetWindowTextW,
    GetWindowThreadProcessId, GWL_EXSTYLE, WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR, WDA_NONE,
    WS_EX_TRANSPARENT,
};

///////////

struct EnumState {
    protected_processes: HashSet<u32>,
}

extern "system" fn enum_windows_proc(
    hwnd: HWND,
    lparam: LPARAM,
) -> BOOL {
    let state = unsafe { &mut *(lparam.0 as *mut EnumState) };

    let mut affinity: u32 = 0;

    let ok = unsafe {
        GetWindowDisplayAffinity(hwnd, &mut affinity)
    };

    if ok.is_ok() && affinity == WDA_EXCLUDEFROMCAPTURE.0 {
        let mut pid = 0;

        unsafe {
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
        }

        state.protected_processes.insert(pid);
    }

    BOOL::from(true)
}

fn find_capture_excluded_processes() -> HashSet<u32> {
    let mut state = EnumState {
        protected_processes: HashSet::new(),
    };

    unsafe {
        let _ = EnumWindows(
            Some(enum_windows_proc),
            LPARAM(&mut state as *mut _ as isize),
        );
    }

    state.protected_processes
}

fn build_process_name_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();

    unsafe {
        let snapshot =
            match CreateToolhelp32Snapshot(
                TH32CS_SNAPPROCESS,
                0,
            ) {
                Ok(h) => h,
                Err(_) => return map,
            };

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let end = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());

                map.insert(
                    entry.th32ProcessID,
                    String::from_utf16_lossy(
                        &entry.szExeFile[..end],
                    ),
                );

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    map
}

fn get_process_full_path(pid: u32) -> Option<String> {
    unsafe {
        let handle: HANDLE =
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid,
            )
            .ok()?;

        let mut buffer =
            [0u16; MAX_PATH as usize];

        let mut size = buffer.len() as u32;

        let result = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        );

        let _ = CloseHandle(handle);

        if result.is_ok() {
            Some(
                String::from_utf16_lossy(
                    &buffer[..size as usize],
                ),
            )
        } else {
            None
        }
    }
}

pub fn get_hidden_processes() -> Vec<ProtectedProcessInfo> {
    let protected = find_capture_excluded_processes();
    let names = build_process_name_map();

    let mut results = Vec::new();

    for pid in protected {
        let name = names
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| "<unknown>".into());

        let full_path = get_process_full_path(pid);

        results.push(ProtectedProcessInfo {
            pid,
            name_debug: format!("{:?}", name),
            codepoints: codepoint_dump(&name),
            path_codepoints: full_path
                .as_ref()
                .map(|p| codepoint_dump(p)),
            name,
            full_path,
        });
    }

    results
}

pub fn get_suspicious_process()->Vec<Finding>{
     println!("=== overlay_detector: scanning all top-level windows ===\n");
    let mut findings: Vec<Finding> = Vec::new();
    unsafe {
        let _ = EnumWindows(
            Some(enum_proc),
            LPARAM(&mut findings as *mut _ as isize),
        );
    }
    findings.sort_by(|a, b| b.score().cmp(&a.score()));

    let mut seen_processes = HashSet::new();
    let mut suspicious_count = 0;

    for f in &findings {
        if !f.is_suspicious() {
            continue;
        }
        suspicious_count += 1;
        seen_processes.insert(f.process_path.clone());

        println!("--------------------------------------------------------");
        println!("Suspicion score : {}", f.score());
        println!("HWND            : 0x{:X}", f.hwnd);
        println!("Title           : {:?}", if f.title.is_empty() { "<none>" } else { &f.title });
        println!("PID             : {}", f.pid);
        println!("Process path    : {}", f.process_path);
        println!(
            "Rect (L,T,R,B)  : {:?}  size {}x{}",
            f.rect,
            f.rect.2 - f.rect.0,
            f.rect.3 - f.rect.1
        );
        if f.excluded_from_capture {
            println!(">> EXCLUDED FROM SCREEN CAPTURE  ({})", f.excluded_kind);
        }
        if f.click_through {
            println!(">> WS_EX_TRANSPARENT (click-through)");
        }
    }

    println!("\n=== Summary ===");
    println!("Suspicious windows found : {}", suspicious_count);
    println!("Distinct processes flagged:");
    for p in &seen_processes {
        println!("  - {p}");
    }
    if suspicious_count == 0 {
        println!("No windows matched capture-exclusion or click-through fingerprints.");
    } else {
        println!(
            "\nNote: WDA_EXCLUDEFROMCAPTURE alone is near-definitive. WS_EX_TRANSPARENT\n\
             alone is weaker -- some legitimate overlays (OSDs, tooltips) use it too.\n\
             Review the flagged process paths above and judge case by case."
        );
    }
    return findings
}
///////////////////////////////////////////////////////////////////////////
impl Finding {
    fn is_suspicious(&self) -> bool {
        self.excluded_from_capture || self.click_through
    }

    fn score(&self) -> u32 {
        let mut s = 0;
        if self.excluded_from_capture {
            s += 5; // near-definitive: explicitly hidden from screenshots/recording
        }
        if self.click_through {
            s += 1; // weak alone, but relevant combined with capture exclusion
        }
        s
    }
}

fn get_window_title(hwnd: HWND) -> String {
    let mut buf = [0u16; 512];
    let len = unsafe { GetWindowTextW(hwnd, &mut buf) };
    if len > 0 {
        String::from_utf16_lossy(&buf[..len as usize])
    } else {
        String::new()
    }
}

fn get_process_path(pid: u32) -> String {
    unsafe {
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid) {
            Ok(handle) => {
                let mut buf = [0u16; 1024];
                let len = K32GetModuleFileNameExW(handle, None, &mut buf);
                let _ = CloseHandle(handle);
                if len > 0 {
                    String::from_utf16_lossy(&buf[..len as usize])
                } else {
                    format!("<pid {pid}: access denied or exited>")
                }
            }
            Err(_) => format!("<pid {pid}: could not open process>"),
        }
    }
}

fn check_display_affinity(hwnd: HWND) -> (bool, &'static str) {
    let mut affinity: u32 = WDA_NONE.0;
    let ok = unsafe { GetWindowDisplayAffinity(hwnd, &mut affinity) };
    if ok.is_ok() {
        if affinity == WDA_EXCLUDEFROMCAPTURE.0 {
            return (true, "WDA_EXCLUDEFROMCAPTURE");
        }
        if affinity == WDA_MONITOR.0 {
            return (true, "WDA_MONITOR");
        }
    }
    (false, "")
}

fn check_click_through(hwnd: HWND) -> bool {
    let ex_style = unsafe { GetWindowLongPtrW(hwnd, GWL_EXSTYLE) } as u32;
    (ex_style & WS_EX_TRANSPARENT.0 as u32) != 0
}

extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let findings = unsafe { &mut *(lparam.0 as *mut Vec<Finding>) };

    let (excluded_from_capture, excluded_kind) = check_display_affinity(hwnd);
    let click_through = check_click_through(hwnd);

    // Skip windows that match neither signal -- there are thousands of
    // ordinary windows and they're just noise for this tool's purpose.
    if !excluded_from_capture && !click_through {
        return true.into();
    }

    let title = get_window_title(hwnd);

    let mut rect = RECT::default();
    let _ = unsafe { GetWindowRect(hwnd, &mut rect) };

    let mut pid: u32 = 0;
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    let process_path = get_process_path(pid);

    findings.push(Finding {
        hwnd: hwnd.0 as i64,
        title,
        pid,
        process_path,
        excluded_from_capture,
        excluded_kind : excluded_kind.to_string(),
        click_through,
        rect: (rect.left, rect.top, rect.right, rect.bottom),
    });

    true.into()
}