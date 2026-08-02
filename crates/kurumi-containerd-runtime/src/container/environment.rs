use std::{
    collections::BTreeMap, env, ffi::CString, fmt::Write, fs, os::unix::fs::symlink, path::Path,
};

use anyhow::{Context, Result};
use kurumi_containerd_config::AndroidConfig;

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub(crate) fn container_environment(
    configured: &BTreeMap<String, String>,
    android: &AndroidConfig,
) -> Result<Vec<CString>> {
    let term = env::var("TERM")
        .ok()
        .filter(|value| !value.is_empty() && !value.contains('.') && !value.starts_with("bg"))
        .unwrap_or_else(|| "xterm-256color".to_owned());
    let mut environment = BTreeMap::from([
        ("PATH".to_owned(), DEFAULT_PATH.to_owned()),
        ("TERM".to_owned(), term),
        ("HOME".to_owned(), "/root".to_owned()),
        ("container".to_owned(), "kurumi-containerd".to_owned()),
        ("LANG".to_owned(), "en_US.UTF-8".to_owned()),
    ]);
    if android.termux_x11 {
        environment.insert("DISPLAY".to_owned(), ":5".to_owned());
    }
    if android.virgl {
        environment.insert("GALLIUM_DRIVER".to_owned(), "virpipe".to_owned());
    }
    if android.pulse_audio {
        environment.insert(
            "PULSE_SERVER".to_owned(),
            "unix:/tmp/.pulse-socket".to_owned(),
        );
    }
    environment.extend(configured.clone());
    environment
        .iter()
        .map(|(key, value)| variable(key, value))
        .collect()
}

pub(crate) fn session_environment(
    configured: &BTreeMap<String, String>,
    android: &AndroidConfig,
) -> Result<Vec<CString>> {
    let source = match fs::read_to_string("/etc/environment") {
        Ok(source) => source,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error).context("failed to read /etc/environment"),
    };
    session_environment_from(&source, configured, android)
}

fn session_environment_from(
    source: &str,
    configured: &BTreeMap<String, String>,
    android: &AndroidConfig,
) -> Result<Vec<CString>> {
    let mut environment = kurumi_containerd_config::parse_environment(source)?;
    environment.extend(configured.clone());
    container_environment(&environment, android)
}

pub(crate) fn write_profile_environment(
    configured: &BTreeMap<String, String>,
    android: &AndroidConfig,
) -> Result<()> {
    let mut environment = configured.clone();
    if android.termux_x11 {
        environment
            .entry("DISPLAY".to_owned())
            .or_insert(":5".to_owned());
    }
    if android.virgl {
        environment
            .entry("GALLIUM_DRIVER".to_owned())
            .or_insert("virpipe".to_owned());
    }
    if android.pulse_audio {
        environment
            .entry("PULSE_SERVER".to_owned())
            .or_insert("unix:/tmp/.pulse-socket".to_owned());
    }
    let contents = render_profile_environment(&environment);
    fs::write("/run/kurumi-containerd.env", contents)
        .context("failed to write /run/kurumi-containerd.env")?;
    if Path::new("/etc/profile.d").is_dir() {
        let link = Path::new("/etc/profile.d/kurumi_containerd_env.sh");
        match fs::remove_file(link) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("failed to replace profile environment link"),
        }
        symlink("/run/kurumi-containerd.env", link)
            .context("failed to create profile environment link")?;
    }
    Ok(())
}

fn render_profile_environment(environment: &BTreeMap<String, String>) -> String {
    environment
        .iter()
        .fold(String::new(), |mut output, (key, value)| {
            writeln!(output, "export {key}='{}'", value.replace('\'', "'\\''"))
                .expect("writing to a String cannot fail");
            output
        })
}

fn variable(key: &str, value: &str) -> Result<CString> {
    CString::new(format!("{key}={value}"))
        .with_context(|| format!("invalid NUL byte in environment variable {key}"))
}

#[cfg(test)]
mod tests {
    use kurumi_containerd_config::Config;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn applies_defaults_and_user_overrides() {
        let mut configured = BTreeMap::new();
        configured.insert("LANG".to_owned(), "C.UTF-8".to_owned());
        configured.insert("APP_MODE".to_owned(), "test".to_owned());
        let environment = container_environment(&configured, &AndroidConfig::default()).unwrap();
        let environment = environment
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert!(
            environment
                .contains(&"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        );
        assert!(environment.contains(&"container=kurumi-containerd"));
        assert!(environment.contains(&"LANG=C.UTF-8"));
        assert_eq!(
            environment
                .iter()
                .filter(|entry| entry.starts_with("LANG="))
                .count(),
            1
        );
        assert!(environment.contains(&"APP_MODE=test"));
    }

    #[test]
    fn quotes_profile_values_for_shell() {
        let mut configured = BTreeMap::new();
        configured.insert("VALUE".to_owned(), "it's safe".to_owned());
        let rendered = render_profile_environment(&configured);
        assert_eq!(rendered, "export VALUE='it'\\''s safe'\n");
    }

    #[test]
    fn configured_environment_overrides_session_environment() {
        let configured = BTreeMap::from([("LANG".to_owned(), "configured".to_owned())]);
        let environment = session_environment_from(
            "LANG=image\nIMAGE_ONLY=yes\n",
            &configured,
            &AndroidConfig::default(),
        )
        .unwrap();
        let environment = environment
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();

        assert!(environment.contains(&"LANG=configured"));
        assert!(environment.contains(&"IMAGE_ONLY=yes"));
        assert!(!environment.contains(&"LANG=image"));
    }

    #[test]
    fn injects_environment_key_from_config() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("rootfs/sbin")).unwrap();
        fs::write(dir.path().join("rootfs/sbin/init"), "").unwrap();
        let path = dir.path().join("kurumi-containerd.toml");
        fs::write(
            &path,
            "[runtime]\n[container]\nname='test'\nrootfs='rootfs'\n[container.environment]\nMY_KEY='my-value'\n",
        )
        .unwrap();

        let config = Config::load(&path).unwrap();
        let environment =
            container_environment(&config.container.environment, &config.container.android)
                .unwrap();

        assert!(
            environment
                .iter()
                .any(|value| value.to_bytes() == b"MY_KEY=my-value")
        );
    }
}
