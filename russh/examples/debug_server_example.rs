//! Debug Server Example
//!
//! This example demonstrates how to use the debug logging system with a Russh server.
//! It shows different ways to initialize logging and how to use specialized logging functions.
//!
//! # Running the example
//!
//! ## Basic usage:
//! ```
//! cargo run --example debug_server_example
//! ```
//!
//! ## With environment variables:
//! ```
//! RUSSH_LOG=debug RUSSH_PACKET_LOG=1 cargo run --example debug_server_example
//! ```

use log::{debug, error, info, trace, warn};
use russh::*;
use russh::server::{Auth, Config, Handler, Server, Session};
use std::env;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::net::TcpListener;
use futures::StreamExt;

/// This struct is used to configure our server
struct SshServer;

// Server implementation
impl server::Server for SshServer {
    type Handler = ServerHandler;
    
    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        // Log client connection using specialized logging function
        debug::log_connection_event(
            "New client connection", 
            peer_addr.map(|addr| addr.to_string().as_str())
        );
        
        ServerHandler
    }
}

// Server handler implementation
struct ServerHandler;

impl Handler for ServerHandler {
    type Error = std::io::Error;
    type FutureAuth = futures::future::Ready<Result<(Self, Auth), Self::Error>>;
    type FutureUnit = futures::future::Ready<Result<(Self, Session), Self::Error>>;
    type FutureBool = futures::future::Ready<Result<(Self, bool), Self::Error>>;

    // Handle authentication
    fn auth_password(self, user: &str, password: &str) -> Self::FutureAuth {
        // Log authentication attempt with specialized debug function
        debug::log_auth_attempt("password", user, if password == "password" { "success" } else { "failure" });
        
        // Regular logging
        info!("Password auth attempt for user: {}", user);
        
        // Specialized logging with context
        if password != "password" {
            debug::log_auth_failure(user, "password", "Invalid password");
        }
        
        let auth = if password == "password" {
            Auth::Accept
        } else {
            Auth::Reject
        };
        
        futures::future::ready(Ok((self, auth)))
    }

    fn auth_publickey(self, user: &str, public_key: &key::PublicKey) -> Self::FutureAuth {
        // Log publickey authentication with both regular and specialized logging
        debug!("Publickey auth attempt for user: {}", user);
        debug::log_auth_attempt("publickey", user, "verification");
        
        // Always reject in this example - this demonstrates logging auth rejection
        debug::log_auth_failure(user, "publickey", "Not implemented");
        warn!("Publickey authentication not implemented in this example");
        
        futures::future::ready(Ok((self, Auth::Reject)))
    }

    fn channel_open_session(self, channel: Channel<Msg>, session: Session) -> Self::FutureUnit {
        // Log session opening with specialized function
        debug::log_channel_event(&channel, "open-session", None);
        
        // Regular debug logging for channel ID
        debug!("Opening session on channel ID: {}", channel.id());
        
        futures::future::ready(Ok((self, session)))
    }

    fn channel_close(self, channel: Channel<Msg>, session: Session) -> Self::FutureUnit {
        // Log channel closing
        debug::log_channel_event(&channel, "close", None);
        info!("Closing channel ID: {}", channel.id());
        
        futures::future::ready(Ok((self, session)))
    }

    fn channel_eof(self, channel: Channel<Msg>, session: Session) -> Self::FutureUnit {
        // Log channel EOF
        debug::log_channel_event(&channel, "eof", None);
        debug!("EOF on channel ID: {}", channel.id());
        
        futures::future::ready(Ok((self, session)))
    }

    fn data(self, channel: Channel<Msg>, data: &[u8], session: Session) -> Self::FutureUnit {
        // Log data received on channel
        if debug::is_packet_logging_enabled() {
            // Only log packet data when packet logging is enabled (RUSSH_PACKET_LOG=1)
            debug::log_packet(debug::SSHPacketType::Channel, "RECV", data);
        } else {
            // Otherwise just log that data was received
            debug!("Received {} bytes on channel {}", data.len(), channel.id());
        }
        
        futures::future::ready(Ok((self, session)))
    }

    fn exec_request(
        self,
        channel: Channel<Msg>,
        data: &[u8],
        session: Session,
    ) -> Self::FutureUnit {
        // Convert data to string for logging command
        let command = String::from_utf8_lossy(data);
        info!("Exec request: {}", command);
        
        // Log command execution with specialized function
        debug::log_command_execution("<unknown>", &command, 0);
        
        // Log security-relevant commands specially
        if command.contains("rm") || command.contains("sudo") {
            warn!("Potentially sensitive command execution: {}", command);
            debug::log_event(log::Level::Warn, "security", &format!("Sensitive command: {}", command));
        }
        
        futures::future::ready(Ok((self, session)))
    }
}

fn main() {
    // SECTION 1: Different ways to initialize logging
    
    println!("=== Debug Server Example ===");
    println!("Demonstrating different logging initialization methods:");
    
    // Different initialization methods based on environment variables
    let log_method = env::var("LOG_METHOD").unwrap_or_default();
    
    match log_method.as_str() {
        "env" => {
            println!("Initializing logging from environment variables");
            debug::init_from_env();
        }
        "trace" => {
            println!("Initializing with Trace level");
            debug::init_with_level(log::LevelFilter::Trace);
        }
        "debug" => {
            println!("Initializing with Debug level");
            debug::init_with_level(log::LevelFilter::Debug);
        }
        "info" => {
            println!("Initializing with Info level");
            debug::init_with_level(log::LevelFilter::Info);
        }
        "full_debug" => {
            println!("Initializing with full debugging preset");
            debug::init_for_debugging();
        }
        _ => {
            println!("Initializing with default level");
            debug::init_with_default_level();
        }
    }
    
    // Print debug logging configuration information
    println!("\nLogging configuration:");
    println!("- Set RUSSH_LOG environment variable to control log level (trace, debug, info, warn, error)");
    println!("- Set RUSSH_PACKET_LOG=1 to enable detailed packet logging");
    println!("- Set RUSSH_BINARY_LOG=1 to enable hexdump format for binary data");
    println!("- Set LOG_METHOD to control initialization mode (env, trace, debug, info, full_debug)");
    
    // SECTION 2: Configure the server
    
    // Create a server configuration
    let config = Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(10)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        keys: vec![
            // Generate an in-memory key for this example
            key::KeyPair::generate_ed25519().unwrap(),
        ],
        ..Default::default()
    };
    
    // Log server configuration
    debug!("Server configured with {} keys", config.keys.len());
    debug::log_event(log::Level::Info, "server", "Server configuration complete");
    
    // SECTION 3: Start the server
    
    let config = Arc::new(config);
    let mut server = SshServer {};
    
    // Create a runtime to run our async SSH server
    let runtime = Runtime::new().unwrap();
    runtime.block_on(async move {
        // Log server startup
        info!("Starting SSH server on 0.0.0.0:2222");
        debug::log_event(log::Level::Info, "server", "Starting SSH server");
        
        //

