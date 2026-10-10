//! Colors. Themes live in ~/.chatui/themes/<name>.json, the active theme's name in
//! ~/.chatui/theme. The TUI rereads both every second, so edits made through
//! `chatui mcp` show up live.
use crate::*;
use ratatui::style::Color;
use serde_json::{Map, Value};
use std::sync::RwLock;

macro_rules! theme {
    ($($field:ident = $default:expr, $desc:literal;)*) => {
        #[derive(Clone, Copy, PartialEq, Debug)]
        pub struct Theme {
            $(pub $field: Color,)*
            /// People's names in chats, picked by hashing the name.
            pub names: [Color; 6],
        }

        pub const DEFAULT: Theme = Theme {
            $($field: $default,)*
            names: [
                Color::Magenta,
                Color::Yellow,
                Color::LightBlue,
                Color::LightRed,
                Color::Green,
                Color::LightMagenta,
            ],
        };

        /// (key, what it colors), for the MCP tool schema.
        pub const FIELDS: &[(&str, &str)] = &[$((stringify!($field), $desc),)*];

        impl Theme {
            fn field(&mut self, k: &str) -> Option<&mut Color> {
                match k {
                    $(stringify!($field) => Some(&mut self.$field),)*
                    _ => None,
                }
            }

            pub fn to_json(self) -> Map<String, Value> {
                let mut m = Map::new();
                $(m.insert(stringify!($field).into(), self.$field.to_string().into());)*
                m.insert("names".into(), self.names.iter().map(|c| c.to_string()).collect());
                m
            }
        }
    };
}

theme! {
    accent = Color::Cyan, "highlights: focused borders, keys in hints, your own name, the header badge";
    dim = Color::DarkGray, "secondary text: timestamps, placeholders, hints, unfocused borders";
    text = Color::Reset, "normal text";
    muted = Color::Gray, "less important text: chat previews, labels, help text";
    bright = Color::White, "emphasis: unread chat names, help headings";
    bg = Color::Reset, "background of the whole app";
    selected_bg = Color::Indexed(236), "background of the selected row in lists";
    field_bg = Color::Indexed(235), "background of text input fields";
    on_accent = Color::Black, "text drawn on an accent background: header badge, unread counts";
    ok = Color::Green, "success: the online dot, confirmation toasts";
    error = Color::LightRed, "errors: the offline dot, error toasts";
    warn = Color::Yellow, "in-progress status like 'connecting…'";
    mention = Color::LightYellow, "@mentions of you, and the badge for unread mentions";
}

/// Shipped themes, in the same format as theme files. Their names are reserved.
const BUILTIN: &[(&str, &str)] = &[
    (
        "dracula",
        r##"{"bg": "#282a36", "text": "#f8f8f2", "muted": "#c0c4d6", "dim": "#6272a4",
        "bright": "#ffffff", "accent": "#bd93f9", "on_accent": "#282a36", "selected_bg": "#44475a",
        "field_bg": "#343746", "ok": "#50fa7b", "error": "#ff5555", "warn": "#f1fa8c",
        "mention": "#ffb86c",
        "names": ["#ff79c6", "#8be9fd", "#50fa7b", "#ffb86c", "#f1fa8c", "#bd93f9"]}"##,
    ),
    (
        "gruvbox",
        r##"{"bg": "#282828", "text": "#ebdbb2", "muted": "#bdae93", "dim": "#7c6f64",
        "bright": "#fbf1c7", "accent": "#fabd2f", "on_accent": "#282828", "selected_bg": "#3c3836",
        "field_bg": "#32302f", "ok": "#b8bb26", "error": "#fb4934", "warn": "#fe8019",
        "mention": "#83a598",
        "names": ["#d3869b", "#8ec07c", "#83a598", "#fe8019", "#b8bb26", "#fb4934"]}"##,
    ),
    (
        "nord",
        r##"{"bg": "#2e3440", "text": "#d8dee9", "muted": "#a5afc0", "dim": "#616e88",
        "bright": "#eceff4", "accent": "#88c0d0", "on_accent": "#2e3440", "selected_bg": "#3b4252",
        "field_bg": "#353b48", "ok": "#a3be8c", "error": "#bf616a", "warn": "#ebcb8b",
        "mention": "#d08770",
        "names": ["#b48ead", "#8fbcbb", "#a3be8c", "#ebcb8b", "#d08770", "#81a1c1"]}"##,
    ),
    (
        "solarized",
        r##"{"bg": "#fdf6e3", "text": "#586e75", "muted": "#657b83", "dim": "#93a1a1",
        "bright": "#073642", "accent": "#268bd2", "on_accent": "#fdf6e3", "selected_bg": "#eee8d5",
        "field_bg": "#eee8d5", "ok": "#859900", "error": "#dc322f", "warn": "#b58900",
        "mention": "#d33682",
        "names": ["#d33682", "#2aa198", "#6c71c4", "#cb4b16", "#859900", "#b58900"]}"##,
    ),
    (
        "synthwave",
        r##"{"bg": "#1a1028", "text": "#f4e9ff", "muted": "#b9a3d6", "dim": "#6c5a8a",
        "bright": "#ffffff", "accent": "#ff4fd8", "on_accent": "#1a1028", "selected_bg": "#2d1b45",
        "field_bg": "#24163a", "ok": "#5af78e", "error": "#ff5c8a", "warn": "#ffd166",
        "mention": "#00e5ff",
        "names": ["#00e5ff", "#ffd166", "#5af78e", "#ff9e64", "#c792ea", "#7aa2f7"]}"##,
    ),
];

fn reserved(name: &str) -> bool {
    name == "default" || BUILTIN.iter().any(|(n, _)| *n == name)
}

static CURRENT: RwLock<Theme> = RwLock::new(DEFAULT);

pub fn th() -> Theme {
    *CURRENT.read().unwrap()
}

pub fn set(t: Theme) {
    *CURRENT.write().unwrap() = t;
}

/// A theme file: any subset of the fields (the rest stay default), plus an
/// optional "description". Every bad key or color is reported, not just the first.
pub fn parse(v: &Value) -> Result<Theme, String> {
    let obj = v.as_object().ok_or("a theme is a JSON object")?;
    let mut t = DEFAULT;
    let mut errs = vec![];
    let color = |k: &str, v: &Value| {
        v.as_str()
            .and_then(|s| s.parse::<Color>().ok())
            .ok_or_else(|| {
                format!("{k}: {v} isn't a color (#rrggbb, a name like cyan, 0-255, or reset)")
            })
    };
    for (k, v) in obj {
        match k.as_str() {
            "description" => {}
            "names" => match v.as_array() {
                Some(a) if (1..=6).contains(&a.len()) => {
                    match a
                        .iter()
                        .map(|c| color("names", c))
                        .collect::<Result<Vec<_>, _>>()
                    {
                        // fewer than 6 colors: repeat them
                        Ok(cs) => t.names = std::array::from_fn(|i| cs[i % cs.len()]),
                        Err(e) => errs.push(e),
                    }
                }
                _ => errs.push("names: a list of 1-6 colors".into()),
            },
            _ => match (t.field(k), color(k, v)) {
                (None, _) => errs.push(format!("unknown key {k}")),
                (Some(f), Ok(c)) => *f = c,
                (Some(_), Err(e)) => errs.push(e),
            },
        }
    }
    if errs.is_empty() {
        Ok(t)
    } else {
        Err(errs.join("; "))
    }
}

fn file(dir: &Path, name: &str) -> PathBuf {
    dir.join("themes").join(format!("{name}.json"))
}

pub fn active_name(dir: &Path) -> String {
    fs::read_to_string(dir.join("theme"))
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "default".into())
}

pub fn load(dir: &Path, name: &str) -> Result<Theme, String> {
    if name == "default" {
        return Ok(DEFAULT);
    }
    if let Some((_, spec)) = BUILTIN.iter().find(|(n, _)| *n == name) {
        return parse(&serde_json::from_str(spec).unwrap());
    }
    let b = fs::read(file(dir, name)).map_err(|e| format!("theme {name}: {e}"))?;
    let v = serde_json::from_slice(&b).map_err(|e| format!("theme {name}: {e}"))?;
    parse(&v).map_err(|e| format!("theme {name}: {e}"))
}

/// "default", the built-in themes, then saved ones A-Z.
pub fn list(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir.join("themes"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_str()?
                .strip_suffix(".json")
                .map(String::from)
        })
        .filter(|n| valid_name(n) && !reserved(n))
        .collect();
    names.sort();
    let shipped = std::iter::once("default").chain(BUILTIN.iter().map(|(n, _)| *n));
    shipped.map(String::from).chain(names).collect()
}

/// Validates, then writes the theme with every field filled in.
pub fn save(dir: &Path, name: &str, spec: &Value) -> Result<(), String> {
    if !valid_name(name) {
        return Err("theme names are 1-20 characters: a-z 0-9 _ -".into());
    }
    if reserved(name) {
        return Err(format!(
            "{name} is a built-in theme; save your version under another name"
        ));
    }
    let mut out = parse(spec)?.to_json();
    if let Some(d) = spec.get("description").and_then(Value::as_str) {
        out.insert("description".into(), d.into());
    }
    fs::create_dir_all(dir.join("themes")).map_err(|e| e.to_string())?;
    write_private(&file(dir, name), &serde_json::to_vec_pretty(&out).unwrap())
        .map_err(|e| e.to_string())
}

pub fn activate(dir: &Path, name: &str) -> Result<Theme, String> {
    let t = load(dir, name)?;
    write_private(&dir.join("theme"), name.as_bytes()).map_err(|e| e.to_string())?;
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_and_roundtrip() {
        let t = parse(&json!({
            "description": "ignored",
            "accent": "#ff79c6",
            "bg": "235",
            "dim": "dark gray",
            "names": ["red", "blue"],
        }))
        .unwrap();
        assert_eq!(
            (t.accent, t.bg, t.dim, t.text),
            (
                Color::Rgb(255, 121, 198),
                Color::Indexed(235),
                Color::DarkGray,
                Color::Reset
            )
        );
        assert_eq!(t.names[2], Color::Red);
        assert_eq!(parse(&Value::Object(t.to_json())).unwrap(), t);
        assert_eq!(parse(&Value::Object(DEFAULT.to_json())).unwrap(), DEFAULT);

        let e = parse(&json!({"accent": "nope", "font": "x", "names": []})).unwrap_err();
        assert!(e.contains("accent") && e.contains("unknown key font") && e.contains("names"));
    }

    #[test]
    fn files() {
        let dir = std::env::temp_dir().join(format!("chatui-theme-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(active_name(&dir), "default");
        save(
            &dir,
            "night",
            &json!({"accent": "magenta", "description": "dark"}),
        )
        .unwrap();
        assert!(save(&dir, "default", &json!({})).is_err());
        assert!(save(&dir, "nord", &json!({})).is_err());
        assert!(save(&dir, "../x", &json!({})).is_err());
        assert_eq!(
            list(&dir),
            [
                "default",
                "dracula",
                "gruvbox",
                "nord",
                "solarized",
                "synthwave",
                "night"
            ]
        );
        // every built-in parses, and none is just the default
        for (n, _) in BUILTIN {
            assert_ne!(load(&dir, n).unwrap(), DEFAULT, "{n}");
        }
        assert_eq!(activate(&dir, "night").unwrap().accent, Color::Magenta);
        assert_eq!(active_name(&dir), "night");
        assert!(
            fs::read_to_string(file(&dir, "night"))
                .unwrap()
                .contains("\"dark\"")
        );
        fs::remove_dir_all(dir).ok();
    }
}
