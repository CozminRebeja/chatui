//! `chatui mcp`: a Model Context Protocol server on stdio, so an AI assistant can
//! design themes. Add it with `claude mcp add chatui -- chatui mcp`.
use crate::theme;
use crate::*;
use serde_json::{Map, Value, json};
use std::io::BufRead;

const INSTRUCTIONS: &str = "chatui is an end-to-end encrypted terminal chat app. These tools \
design its color themes. Pick a cohesive palette with readable contrast: text, muted and dim \
against bg, and on_accent against accent. bg \"reset\" keeps the user's terminal background; \
if you set bg, also set text, selected_bg and field_bg to suit it. A running chatui switches \
to a newly activated theme within a second.";

pub fn run() -> Result<(), String> {
    let dir = home();
    let mut out = io::stdout();
    for line in io::stdin().lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(resp) = handle(&dir, &line) {
            writeln!(out, "{resp}")
                .and_then(|_| out.flush())
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// One JSON-RPC message in, at most one out (notifications get no reply).
fn handle(dir: &Path, line: &str) -> Option<Value> {
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return Some(json!({"jsonrpc": "2.0", "id": null,
                "error": {"code": -32700, "message": e.to_string()}}));
        }
    };
    let id = req.get("id")?.clone();
    let params = &req["params"];
    let result = match req["method"].as_str().unwrap_or_default() {
        "initialize" => Ok(json!({
            "protocolVersion": params["protocolVersion"].as_str().unwrap_or("2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "chatui", "version": env!("CARGO_PKG_VERSION")},
            "instructions": INSTRUCTIONS,
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools()})),
        "tools/call" => Ok(
            match call(
                dir,
                params["name"].as_str().unwrap_or_default(),
                &params["arguments"],
            ) {
                Ok(text) => json!({"content": [{"type": "text", "text": text}]}),
                Err(e) => json!({"content": [{"type": "text", "text": e}], "isError": true}),
            },
        ),
        m => Err(format!("unknown method {m}")),
    };
    Some(match result {
        Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
        Err(e) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": e}}),
    })
}

fn tools() -> Value {
    let name = json!({"type": "string", "description": "theme name: 1-20 characters, a-z 0-9 _ -"});
    let mut props = Map::new();
    props.insert("name".into(), name.clone());
    props.insert(
        "description".into(),
        json!({"type": "string", "description": "one line describing the look"}),
    );
    for (k, d) in theme::FIELDS {
        props.insert(
            (*k).into(),
            json!({"type": "string", "description": format!(
                "{d}. A color: #rrggbb, a terminal color name (cyan, light blue, dark gray…), 0-255, or reset")}),
        );
    }
    props.insert(
        "names".into(),
        json!({"type": "array", "items": {"type": "string"}, "maxItems": 6, "description":
            "1-6 colors for people's names in chats; distinct from each other and readable on bg"}),
    );
    props.insert(
        "activate".into(),
        json!({"type": "boolean", "description": "switch chatui to this theme now (default true)"}),
    );
    json!([
        {
            "name": "list_themes",
            "description": "List chatui's themes and which one is active.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "get_theme",
            "description": "Get every color of a theme, e.g. to tweak it. Defaults to the active theme.",
            "inputSchema": {"type": "object", "properties": {"name": name}},
        },
        {
            "name": "create_theme",
            "description": "Create or overwrite a chatui color theme. Colors you leave out keep the default theme's value.",
            "inputSchema": {"type": "object", "properties": props, "required": ["name"]},
        },
        {
            "name": "set_theme",
            "description": "Switch chatui to an existing theme (\"default\" is the built-in one).",
            "inputSchema": {"type": "object", "properties": {"name": name}, "required": ["name"]},
        },
    ])
}

fn call(dir: &Path, tool: &str, args: &Value) -> Result<String, String> {
    let name = args["name"].as_str();
    match tool {
        "list_themes" => Ok(format!(
            "active: {}\nthemes: {}",
            theme::active_name(dir),
            theme::list(dir).join(", ")
        )),
        "get_theme" => {
            let name = name.map_or_else(|| theme::active_name(dir), String::from);
            let t = theme::load(dir, &name)?;
            Ok(serde_json::to_string_pretty(&t.to_json()).unwrap())
        }
        "create_theme" => {
            let name = name.ok_or("name is required")?;
            let mut spec = args.as_object().cloned().unwrap_or_default();
            spec.remove("name");
            let activate = spec.remove("activate").and_then(|v| v.as_bool()) != Some(false);
            theme::save(dir, name, &Value::Object(spec))?;
            if activate {
                theme::activate(dir, name)?;
                Ok(format!("Saved theme {name} and switched chatui to it."))
            } else {
                Ok(format!(
                    "Saved theme {name}. Switch with set_theme or t in chatui."
                ))
            }
        }
        "set_theme" => {
            let name = name.ok_or("name is required")?;
            theme::activate(dir, name)?;
            Ok(format!("chatui now uses {name}."))
        }
        _ => Err(format!("unknown tool {tool}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rpc(dir: &Path, method: &str, params: Value) -> Value {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        handle(dir, &req.to_string()).unwrap()
    }

    #[test]
    fn theme_tools() {
        let dir = std::env::temp_dir().join(format!("chatui-mcp-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let init = rpc(&dir, "initialize", json!({"protocolVersion": "2025-06-18"}));
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        assert!(
            handle(
                &dir,
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
            )
            .is_none()
        );
        let tools = rpc(&dir, "tools/list", json!({}));
        assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 4);

        let r = rpc(
            &dir,
            "tools/call",
            json!({"name": "create_theme", "arguments":
            {"name": "synth", "accent": "#ff00ff", "bg": "#1a1025", "names": ["cyan"]}}),
        );
        assert_eq!(r["result"].get("isError"), None, "{r}");
        assert_eq!(theme::active_name(&dir), "synth");
        let r = rpc(
            &dir,
            "tools/call",
            json!({"name": "get_theme", "arguments": {}}),
        );
        assert!(
            r["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("#FF00FF")
        );

        let r = rpc(
            &dir,
            "tools/call",
            json!({"name": "create_theme", "arguments":
            {"name": "bad", "accent": "blurple"}}),
        );
        assert_eq!(r["result"]["isError"], true);
        let r = rpc(
            &dir,
            "tools/call",
            json!({"name": "set_theme", "arguments": {"name": "nope"}}),
        );
        assert_eq!(r["result"]["isError"], true);
        assert_eq!(rpc(&dir, "bogus", json!({}))["error"]["code"], -32601);
        fs::remove_dir_all(dir).ok();
    }
}
