//! Operating-system launcher registration for browser-to-connector handoff.
//!
//! The public URI contains only an action. The Tokenmaxxing server origin is
//! pinned in the local registration command and is never accepted from a web
//! page, which prevents another site from selecting an upload destination.

use anyhow::{bail, Result};
use std::path::Path;
use url::Url;

/// An action accepted from the `tokenmaxxing` URL protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherAction {
    /// Start or resume the local connection flow.
    Connect,
}

/// Parse a browser launcher URI using a deliberately tiny allowlist.
pub fn parse_uri(uri: &Url) -> Result<LauncherAction> {
    let valid_path = uri.path().is_empty() || uri.path() == "/";
    if uri.scheme() != "tokenmaxxing"
        || uri.host_str() != Some("connect")
        || !valid_path
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.port().is_some()
        || uri.query().is_some()
        || uri.fragment().is_some()
    {
        bail!("unsupported Tokenmaxxing launcher URI");
    }
    Ok(LauncherAction::Connect)
}

/// Register the current connector executable as the per-user URL handler.
pub fn install(executable: &Path, server_url: &Url, config_root: Option<&Path>) -> Result<()> {
    validate_pinned_server(server_url)?;
    if !executable.is_absolute() {
        bail!("launcher executable path must be absolute");
    }
    if config_root.is_some_and(|root| !root.is_absolute()) {
        bail!("launcher config root must be absolute");
    }
    platform::install(executable, server_url, config_root)
}

/// Return whether a per-user Tokenmaxxing URL handler is registered.
pub fn is_installed() -> Result<bool> {
    platform::is_installed()
}

/// Remove the per-user Tokenmaxxing URL handler if it exists.
pub fn uninstall() -> Result<bool> {
    platform::uninstall()
}

fn validate_pinned_server(url: &Url) -> Result<()> {
    if url.cannot_be_a_base() || url.host_str().is_none() {
        bail!("launcher server URL must be an absolute origin");
    }
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if url.scheme() != "https" && !(local && url.scheme() == "http") {
        bail!("launcher server URL must use HTTPS outside localhost");
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("launcher server URL must not contain credentials, query, or fragment");
    }
    Ok(())
}

#[cfg(windows)]
mod platform {
    use super::{bail, Path, Result, Url};
    use anyhow::Context;
    use std::ffi::{OsStr, OsString};
    use std::fmt::Write as _;
    use std::process::{Command, Output};

    const PROTOCOL_KEY: &str = r"HKCU\Software\Classes\tokenmaxxing";
    const COMMAND_KEY: &str = r"HKCU\Software\Classes\tokenmaxxing\shell\open\command";

    pub(super) fn install(
        executable: &Path,
        server_url: &Url,
        config_root: Option<&Path>,
    ) -> Result<()> {
        let executable_text = path_text(executable, "launcher executable")?;
        let icon = format!("{executable_text},0");
        let command = registration_command(executable, server_url, config_root)?;

        reg_add_default(PROTOCOL_KEY, "URL:Tokenmaxxing Protocol")?;
        reg_add_named(PROTOCOL_KEY, "URL Protocol", "")?;
        reg_add_default(&format!(r"{PROTOCOL_KEY}\DefaultIcon"), &icon)?;
        // Write the open command last so partially completed registration is
        // never reported as an installed, callable handler.
        reg_add_default(COMMAND_KEY, &command)?;
        Ok(())
    }

    pub(super) fn is_installed() -> Result<bool> {
        let output = run_reg([
            OsString::from("QUERY"),
            OsString::from(COMMAND_KEY),
            OsString::from("/ve"),
        ])?;
        if output.status.success() {
            return Ok(true);
        }
        if output.status.code() == Some(1) {
            return Ok(false);
        }
        bail!(
            "query Tokenmaxxing URL handler failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }

    pub(super) fn uninstall() -> Result<bool> {
        if !is_installed()? {
            return Ok(false);
        }
        let output = run_reg([
            OsString::from("DELETE"),
            OsString::from(PROTOCOL_KEY),
            OsString::from("/f"),
        ])?;
        if !output.status.success() {
            bail!(
                "remove Tokenmaxxing URL handler failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(true)
    }

    fn registration_command(
        executable: &Path,
        server_url: &Url,
        config_root: Option<&Path>,
    ) -> Result<String> {
        let executable = path_text(executable, "launcher executable")?;
        // Keep the URI before pinned options. If Windows ever passes a
        // malformed value containing argument separators, clap either rejects
        // the duplicate option or the locally pinned option remains last.
        let mut command = format!("\"{executable}\" launch \"%1\" --server \"{server_url}\"");
        if let Some(root) = config_root {
            let root = path_text(root, "launcher config root")?;
            write!(&mut command, " --config-root \"{root}\"")?;
        }
        Ok(command)
    }

    fn path_text<'a>(path: &'a Path, label: &str) -> Result<&'a str> {
        let value = path
            .to_str()
            .with_context(|| format!("{label} was not valid Unicode"))?;
        if value.contains('"') {
            bail!("{label} contained an unsupported quote");
        }
        Ok(value)
    }

    fn reg_add_default(key: &str, data: &str) -> Result<()> {
        reg_add(key, None, data)
    }

    fn reg_add_named(key: &str, name: &str, data: &str) -> Result<()> {
        reg_add(key, Some(name), data)
    }

    fn reg_add(key: &str, name: Option<&str>, data: &str) -> Result<()> {
        let mut args = vec![OsString::from("ADD"), OsString::from(key)];
        match name {
            Some(name) => {
                args.push(OsString::from("/v"));
                args.push(OsString::from(name));
            }
            None => args.push(OsString::from("/ve")),
        }
        args.extend([
            OsString::from("/t"),
            OsString::from("REG_SZ"),
            OsString::from("/d"),
            OsString::from(data),
            OsString::from("/f"),
        ]);
        let output = run_reg(args)?;
        if !output.status.success() {
            bail!(
                "register Tokenmaxxing URL handler failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    fn run_reg<I, S>(args: I) -> Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        Command::new("reg.exe")
            .args(args)
            .output()
            .context("run Windows per-user protocol registration")
    }

    #[cfg(test)]
    mod tests {
        use super::{registration_command, Path, Result, Url};

        #[test]
        fn handler_command_pins_server_and_forwards_only_the_uri() -> Result<()> {
            let executable = Path::new(r"C:\Program Files\Tokenmaxxing\tokenmaxxing.exe");
            let root = Path::new(r"C:\Tokenmaxxing Test");
            let server = Url::parse("http://localhost:3000/")?;
            let command = registration_command(executable, &server, Some(root))?;
            assert_eq!(
                command,
                r#""C:\Program Files\Tokenmaxxing\tokenmaxxing.exe" launch "%1" --server "http://localhost:3000/" --config-root "C:\Tokenmaxxing Test""#
            );
            Ok(())
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{bail, Path, Result, Url};

    pub(super) fn install(_: &Path, _: &Url, _: Option<&Path>) -> Result<()> {
        bail!("automatic URL-handler registration is currently available on Windows only")
    }

    // Match the fallible Windows platform interface used by the public API.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn is_installed() -> Result<bool> {
        Ok(false)
    }

    // Match the fallible Windows platform interface used by the public API.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn uninstall() -> Result<bool> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::{install, parse_uri, LauncherAction, Result, Url};

    #[test]
    fn accepts_only_the_exact_connect_action() -> Result<()> {
        assert_eq!(
            parse_uri(&Url::parse("tokenmaxxing://connect")?)?,
            LauncherAction::Connect
        );
        assert_eq!(
            parse_uri(&Url::parse("tokenmaxxing://connect/")?)?,
            LauncherAction::Connect
        );
        for invalid in [
            "tokenmaxxing:connect",
            "tokenmaxxing://sync",
            "tokenmaxxing://connect/extra",
            "tokenmaxxing://connect?server=https://evil.example",
            "tokenmaxxing://connect#fragment",
            "tokenmaxxing://user@connect",
            "https://connect",
        ] {
            assert!(parse_uri(&Url::parse(invalid)?).is_err(), "{invalid}");
        }
        Ok(())
    }

    #[test]
    fn rejects_an_insecure_remote_registration_origin() -> Result<()> {
        let executable = std::env::current_exe()?;
        let server = Url::parse("http://evil.example")?;
        assert!(install(&executable, &server, None).is_err());
        Ok(())
    }
}
