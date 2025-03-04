//! Comprehensive debug logging for Russh
//! 
//! This module provides utilities for initializing and using debug logging
//! within Russh. It offers various levels of verbosity and specialized
//! logging for SSH-specific operations.
//!
//! # Examples
//!
//! Basic initialization:
//! ```
//! // Initialize with environment variables (RUST_LOG)
//! russh::debug::init_from_env();
//!
//! // Or set a specific level
//! russh::debug::init_with_level(log::LevelFilter::Debug);
//! ```
//!
//! SSH-specific logging:
//! ```
//! // Log SSH packet data
//! russh::debug::log_packet(SSHPacketType::Transport, "RECV", &packet_data);
//!
//! // Log key exchange event
//! russh::debug::log_kex_event("curve25519-sha256", "start", None);
//! ```

use log::{debug, error, info, trace, warn, LevelFilter};
use std::fmt::Write;
use std::sync::Once;

/// SSH packet types for specialized logging
#[derive(Debug, Clone, Copy)]
pub enum SSHPacketType {
    Transport,
    Kex,
    Userauth,
    Connection,
    Unknown,
}

impl std::fmt::Display for SSHPacketType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SSHPacketType::Transport => write!(f, "TRANSPORT"),
            SSHPacketType::Kex => write!(f, "KEX"),
            SSHPacketType::Userauth => write!(f, "USERAUTH"),
            SSHPacketType::Connection => write!(f, "CONNECTION"),
            SSHPacketType::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

// Used to ensure init functions only run once
static INIT: Once = Once::new();

/// Initialize logging with a specific log level
///
/// # Arguments
///
/// * `level` - The log level filter to apply
///
/// # Examples
///
/// ```
/// russh::debug::init_with_level(log::LevelFilter::Debug);
/// ```
pub fn init_with_level(level: LevelFilter) {
    INIT.call_once(|| {
        env_logger::Builder::new()
            .filter_level(level)
            .format_timestamp_secs()
            .init();
        
        info!("Russh logging initialized with level: {}", level);
    });
}

/// Initialize logging from environment variables
///
/// Uses the RUST_LOG environment variable to determine log level.
/// Default level is INFO if RUST_LOG is not set.
///
/// # Examples
///
/// ```
/// russh::debug::init_from_env();
/// ```
pub fn init_from_env() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .format_timestamp_secs()
            .init();
        
        if let Ok(rust_log) = std::env::var("RUST_LOG") {
            info!("Russh logging initialized from environment with RUST_LOG={}", rust_log);
        } else {
            info!("Russh logging initialized from environment with default level");
        }
    });
}

/// Initialize logging with maximum verbosity for debugging
///
/// Sets the log level to TRACE and enables all diagnostic features.
///
/// # Examples
///
/// ```
/// russh::debug::init_for_debugging();
/// ```
pub fn init_for_debugging() {
    INIT.call_once(|| {
        env_logger::Builder::new()
            .filter_level(LevelFilter::Trace)
            .format_timestamp_millis()
            .init();
        
        info!("Russh debugging enabled with maximum verbosity");
    });
}

/// Initialize with the default log level (Info)
///
/// A convenience function for quick setup.
///
/// # Examples
///
/// ```
/// russh::debug::init_with_default_level();
/// ```
pub fn init_with_default_level() {
    init_with_level(LevelFilter::Info);
}

/// Format binary data as hexdump for debugging
///
/// # Arguments
///
/// * `data` - Binary data to format
/// * `max_len` - Maximum number of bytes to include (0 for all)
///
/// # Returns
///
/// A string with the formatted hexdump
///
/// # Examples
///
/// ```
/// let packet_data = vec![0x00, 0x01, 0x02, 0x03];
/// let formatted = russh::debug::hexdump(&packet_data, 0);
/// ```
pub fn hexdump(data: &[u8], max_len: usize) -> String {
    let mut result = String::new();
    let len = if max_len > 0 && data.len() > max_len {
        max_len
    } else {
        data.len()
    };

    for (i, chunk) in data[..len].chunks(16).enumerate() {
        write!(&mut result, "{:08x}  ", i * 16).unwrap();
        
        for (j, byte) in chunk.iter().enumerate() {
            write!(&mut result, "{:02x} ", byte).unwrap();
            if j == 7 {
                write!(&mut result, " ").unwrap();
            }
        }
        
        // Padding for incomplete lines
        if chunk.len() < 16 {
            let spaces = (16 - chunk.len()) * 3 + if chunk.len() <= 8 { 1 } else { 0 };
            for _ in 0..spaces {
                write!(&mut result, " ").unwrap();
            }
        }
        
        write!(&mut result, " |").unwrap();
        
        // ASCII representation
        for byte in chunk {
            let c = if *byte >= 32 && *byte <= 126 {
                *byte as char
            } else {
                '.'
            };
            write!(&mut result, "{}", c).unwrap();
        }
        
        writeln!(&mut result, "|").unwrap();
    }
    
    if max_len > 0 && data.len() > max_len {
        writeln!(&mut result, "... ({} bytes total)", data.len()).unwrap();
    }
    
    result
}

/// Check if packet-level logging is enabled
///
/// Checks the RUSSH_PACKET_LOG environment variable.
/// Returns true if the variable is set to "1", "true", or "yes".
pub fn is_packet_logging_enabled() -> bool {
    match std::env::var("RUSSH_PACKET_LOG") {
        Ok(val) => matches!(val.to_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => false,
    }
}

/// Determine if binary data should be logged in hexdump format
///
/// Checks the RUSSH_BINARY_LOG environment variable.
/// Returns true if the variable is set to "1", "true", or "yes".
pub fn use_binary_logging() -> bool {
    match std::env::var("RUSSH_BINARY_LOG") {
        Ok(val) => matches!(val.to_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => true, // Default to hexdump format
    }
}

/// Log SSH packet data with additional metadata
///
/// # Arguments
///
/// * `packet_type` - Type of SSH packet
/// * `direction` - Direction of the packet ("SEND" or "RECV")
/// * `data` - Packet binary data
///
/// # Examples
///
/// ```
/// russh::debug::log_packet(
///     russh::debug::SSHPacketType::Transport,
///     "RECV",
///     &packet_data
/// );
/// ```
pub fn log_packet(packet_type: SSHPacketType, direction: &str, data: &[u8]) {
    if log::log_enabled!(log::Level::Trace) && is_packet_logging_enabled() {
        if use_binary_logging() && !data.is_empty() {
            trace!(
                "SSH PACKET [{}] {}: \n{}",
                packet_type,
                direction,
                hexdump(data, 1024)
            );
        } else {
            trace!(
                "SSH PACKET [{}] {}: {} bytes",
                packet_type,
                direction,
                data.len()
            );
        }
    }
}

/// Log key exchange events
///
/// # Arguments
///
/// * `algorithm` - Name of the key exchange algorithm
/// * `event` - Description of the event (e.g., "start", "complete")
/// * `error` - Optional error message
///
/// # Examples
///
/// ```
/// russh::debug::log_kex_event("curve25519-sha256", "start", None);
/// ```
pub fn log_kex_event(algorithm: &str, event: &str, error: Option<&str>) {
    debug!("KEX [{}] {}", algorithm, event);
    if let Some(err) = error {
        error!("KEX [{}] error: {}", algorithm, err);
    }
}

/// Log connection-related events
///
/// # Arguments
///
/// * `address` - Connection address
/// * `event` - Description of the event
/// * `details` - Optional additional details
///
/// # Examples
///
/// ```
/// russh::debug::log_connection_event("192.168.1.1:22", "connected", None);
/// ```
pub fn log_connection_event(address: &str, event: &str, details: Option<&str>) {
    info!("CONNECTION [{}] {}", address, event);
    if let Some(details) = details {
        debug!("CONNECTION [{}] {} details: {}", address, event, details);
    }
}

/// Log authentication attempts
///
/// # Arguments
///
/// * `username` - Username being authenticated
/// * `method` - Authentication method (password, publickey, etc.)
/// * `result` - Result of the authentication attempt
///
/// # Examples
///
/// ```
/// russh::debug::log_auth_attempt("admin", "publickey", "success");
/// ```
pub fn log_auth_attempt(username: &str, method: &str, result: &str) {
    info!("AUTH [{}] method={} result={}", username, method, result);
}

/// Log channel-related events
///
/// # Arguments
///
/// * `channel_id` - Channel identifier
/// * `event` - Description of the event
/// * `details` - Optional additional details
///
/// # Examples
///
/// ```
/// russh::debug::log_channel_event(1, "open", Some("session"));
/// ```
pub fn log_channel_event(channel_id: u32, event: &str, details: Option<&str>) {
    debug!("CHANNEL [{}] {}", channel_id, event);
    if let Some(details) = details {
        debug!("CHANNEL [{}] {} details: {}", channel_id, event, details);
    }
}

/// Log SSH errors
///
/// # Arguments
///
/// * `context` - Context where the error occurred
/// * `error` - Error message or object
///
/// # Examples
///
/// ```
/// russh::debug::log_ssh_error("session_setup", &error);
/// ```
pub fn log_ssh_error(context: &str, error: &dyn std::fmt::Display) {
    error!("SSH ERROR [{}]: {}", context, error);
}

/// Log SSH command errors
///
/// # Arguments
///
/// * `command` - Command that failed
/// * `error` - Error message or object
///
/// # Examples
///
/// ```
/// russh::debug::log_ssh_command_error("ls -la", &error);
/// ```
pub fn log_ssh_command_error(command: &str, error: &dyn std::fmt::Display) {
    error!("SSH COMMAND ERROR [{}]: {}", command, error);
}

/// Log SSH channel errors
///
/// # Arguments
///
/// * `channel_id` - Channel identifier
/// * `error` - Error message or object
///
/// # Examples
///
/// ```
/// russh::debug::log_ssh_channel_error(1, &error);
/// ```
pub fn log_ssh_channel_error(channel_id: u32, error: &dyn std::fmt::Display) {
    error!("SSH CHANNEL ERROR [{}]: {}", channel_id, error);
}

/// Log authentication failures
///
/// # Arguments
///
/// * `username` - Username that failed authentication
/// * `method` - Authentication method that failed
/// * `reason` - Reason for the failure
///
/// # Examples
///
/// ```
/// russh::debug::log_auth_failure("user", "password", "incorrect password");
/// ```
pub fn log_auth_failure(username: &str, method: &str, reason: &str) {
    warn!("AUTH FAILURE [{}] method={} reason={}", username, method, reason);
}

/// Log command execution
///
/// # Arguments
///
/// * `channel_id` - Channel identifier
/// * `command` - Command being executed
/// * `exit_code` - Optional exit code
///
/// # Examples
///
/// ```
/// russh::debug::log_command_execution(1, "ls -la", Some(0));
/// ```
pub fn log_command_execution(channel_id: u32, command: &str, exit_code: Option<i32>) {
    info!("COMMAND [{}] executing: {}", channel_id, command);
    if let Some(code) = exit_code {
        debug!("COMMAND [{}] exit code: {}", channel_id, code);
    }
}

/// Log channel errors
///
/// # Arguments
///
/// * `channel_id` - Channel identifier
/// * `operation` - Operation that failed
/// * `error` - Error message or object
///
/// # Examples
///
/// ```
/// russh::debug::log_channel_error(1, "read", &error);
/// ```
pub fn log_channel_error(channel_id: u32, operation: &str, error: &dyn std::fmt::Display) {
    error!("CHANNEL ERROR [{}] {}: {}", channel_id, operation, error);
}

/// Log SSH server errors
///
/// # Arguments
///
/// * `address` - Client address
/// * `error` - Error message or object
///
/// # Examples
///
/// ```
/// russh::debug::log_ssh_server_error("192.168.1.1:54321", &error);
/// ```
pub fn log_ssh_server_error(address: &str, error: &dyn std::fmt::Display) {
    error!("SSH SERVER ERROR [{}]: {}", address, error);
}

/// Log general SSH events
///
/// # Arguments
///
/// * `component` - Component generating the event
/// * `event` - Description of the event
/// * `level` - Log level for the event
///
/// # Examples
///
/// ```
/// russh::debug::log_event("session", "handshake complete", log::Level::Info);
/// ```
pub fn log_event(component: &str, event: &str, level: log::Level) {
    match level {
        log::Level::Error => error!("{} {}", component, event),
        log::Level::Warn => warn!("{} {}", component, event),
        log::Level::Info => info!("{} {}", component, event),
        log::Level::Debug => debug!("{} {}", component, event),
        log::Level::Trace => trace!("{} {}", component, event),
    }
}
