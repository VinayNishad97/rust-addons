use napi_derive::napi;

#[napi(object)]
pub struct ProtectedProcessInfo {
    pub pid: u32,
    pub name: String,
    pub name_debug: String,
    pub codepoints: String,
    pub full_path: Option<String>,
    pub path_codepoints: Option<String>,
}

#[napi(object)]
pub struct Finding {
    pub hwnd: i64, // changed from isize
    pub title: String,
    pub pid: u32,
    pub process_path: String,
    pub excluded_from_capture: bool,
    pub excluded_kind: String,
    pub click_through: bool,
    pub rect: (i32, i32, i32, i32),
}
impl Finding {
    pub fn score(&self) -> u32 {
        let mut score = 0;

        if self.excluded_from_capture {
            score += 50;
        }

        if self.click_through {
            score += 50;
        }

        score
    }

    pub fn is_suspicious(&self) -> bool {
        self.score() > 0
    }
}

pub fn codepoint_dump(s: &str) -> String {
    s.chars()
        .map(|c| format!("U+{:04X}", c as u32))
        .collect::<Vec<String>>()
        .join(" ")
}