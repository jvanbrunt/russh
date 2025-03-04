//! Debug Client Example
//!
//! This example demonstrates how to use the debug logging system with a Russh client.
//! It shows different ways to initialize logging and how to use specialized logging functions.
//!
//! # Running the example
//!
//! ## Basic usage:
//! ```
//! cargo run --example debug_client_example
//! ```
//!
//! ## With environment variables:
//! ```
//! RUSSH_LOG=debug RUSSH_PACKET_LOG=1 cargo run --example debug_client_example
//! ```

use log::{debug, error, info, trace, warn};
use std::env;
use std::net::TcpStream;
use std::sync::Arc;
use tokio::runtime::Runtime;
use russh::*;
use russh::client::{Config, Handler, Session};
use std::io::Error;

// Create a simple client handler for this example
struct ClientHandler;

impl Handler for ClientHandler {
    type Error = Error;
    type FutureBool = futures::future::Ready<Result<(Self, bool), Error>>;
    type FutureUnit = futures::future::Ready<Result<(Self, Session), Error>>;

    fn finished_bool(self, b: bool) -> Self::FutureBool {
        futures::future::ready(Ok((self, b)))
    }

    fn finished(self, session: Session) -> Self::FutureUnit {
        // Log session establishment - demonstrates using regular log macros
        info!("Session established with server: {:?}", session);
        
        // Use specialized debug function for SSH-specific events
        debug::log_connection_event("Session established", None);
        
        futures::future::ready(Ok((self, session)))
    }

    fn check_server_key(self, server_public_key: &key::PublicKey) -> Self::FutureBool {
        // Log the key verification process - demonstrates debug logging for security events
        debug!("Checking server key: {:?}", server_public_key);
        
        // Use specialized function for key verification events
        debug::log_kex_event("server-key-check", "verification", Some("accepted"));
        
        self.finished_bool(true)
    }

    fn auth_keyboard_interactive(
        self,
        name: &str,
        instructions: &str,
        prompts: &[(String, bool)],
    ) -> futures::future::BoxFuture<'static, Result<(Self, Vec<String>), Error>> {
        // Log authentication attempt with debug module function
        debug::log_auth_attempt("keyboard-interactive", name, "attempt");
        
        Box::pin(futures::future::ready(Ok((
            self,
            vec!["password".to_string(); prompts.len()],
        ))))
    }
}

fn main() {
    // SECTION 1: Different ways to initialize logging
    
    println!("=== Debug Client Example ===");
    println!("Demonstrating different logging initialization methods:");
    
    // Method 1: Initialize with environment variables
    // You can set RUSSH_LOG=debug RUSSH_PACKET_LOG=1 before running the example
    if env::var("DEMO_METHOD").unwrap_or_default() == "1" {
        println!("Method 1: Initializing logging from environment variables");
        debug::init_from_env();
    }
    // Method 2: Initialize with specific log level
    else if env::var("DEMO_METHOD").unwrap_or_default() == "2" {
        println!("Method 2: Initializing with specific log level (Debug)");
        debug::init_with_level(log::LevelFilter::Debug);
    }
    // Method 3: Use debugging preset (maximum verbosity)
    else if env::var("DEMO_METHOD").unwrap_or_default() == "3" {
        println!("Method 3: Initializing with debugging preset (maximum verbosity)");
        debug::init_for_debugging();
    }
    // Method 4: Default initialization
    else {
        println!("Method 4: Initializing with default level (Info)");
        debug::init_with_default_level();
    }
    
    // SECTION 2: Configure the client
    
    let config = Config {
        // Log configuration settings
        debug!("Configuring client with 10 connection attempts", 10),
        connection_attempts: 10,
        ..Default::default()
    };
    
    // Create a client with this config
    let config = Arc::new(config);
    
    // SECTION 3: Run the client with different logging levels demonstrated
    
    // Create a runtime to run our async SSH client
    let runtime = Runtime::new().unwrap();
    runtime.block_on(async move {
        // Use regular log macros for general flow logging
        trace!("Starting SSH client connection attempt");
        
        // Demonstrate SSH-specific debug function for connection attempt
        debug::log_connection_event("Starting connection", Some("127.0.0.1:22"));
        
        // Simulate connection - in real code this would connect to a server
        info!("Connecting to SSH server at 127.0.0.1:22");
        
        // Simulate error handling with logging
        if let Err(e) = TcpStream::connect("127.0.0.1:22") {
            // Regular error logging
            error!("Failed to connect: {}", e);
            
            // SSH-specific error logging
            debug::log_ssh_error("Connection failed", &e.to_string());
            return;
        }
        
        // Simulate successful connection with more logging examples
        info!("Connection established successfully");
        
        // Demonstrate packet logging
        let sample_packet = b"SSH-2.0-OpenSSH_8.1";
        debug::log_packet(debug::SSHPacketType::Transport, "RECV", sample_packet);
        
        // Demonstrate key exchange logging
        debug::log_kex_event("curve25519-sha256", "negotiation", Some("success"));
        
        // Demonstrate authentication logging
        debug::log_auth_attempt("publickey", "user", "success");
        
        // Log warnings when appropriate
        warn!("Server using deprecated cipher: aes128-cbc");
        
        // Simulate command execution
        debug::log_command_execution("user", "ls -la", 0);
        
        // Log disconnection
        debug::log_connection_event("Disconnecting", None);
    });
    
    println!("\nExample complete! Try running with different environment variables:");
    println!("RUSSH_LOG=trace RUSSH_PACKET_LOG=1 cargo run --example debug_client_example");
    println!("DEMO_METHOD=3 cargo run --example debug_client_example");
}

