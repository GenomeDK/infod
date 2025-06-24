use std::env;
use std::net::ToSocketAddrs;
use std::{net::TcpStream, time::Duration};

use backoff::{retry, ExponentialBackoffBuilder};
use color_eyre::eyre::Result;
use eyre::{eyre, WrapErr};
use infod_common::{
    cipher_from_secret_key, read_config, Connection, DEFAULT_CONFIG_PATH,
};
use tracing::debug;

fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 || args[1] != "reload-state" {
        // TODO: print usage
        return Ok(());
    }

    let config_path = std::env::var("INFOD_CONFIG").unwrap_or(DEFAULT_CONFIG_PATH.to_string());
    let config = read_config(&config_path)
        .wrap_err_with(|| eyre!("Could not open config file at {}", &config_path))?;
    let cipher = cipher_from_secret_key(&config.secret_key);

    let host = config
        .client
        .server
        .to_socket_addrs()
        .wrap_err("Could not parse server address")?.find(|s| s.is_ipv4())
        .ok_or_else(|| eyre!("Could not find valid server address"))?;

    let backoff = ExponentialBackoffBuilder::new()
        .with_max_elapsed_time(Some(Duration::from_secs(60)))
        .build();

    let frame = {
        let op = || Ok(TcpStream::connect(host)?);
        let stream =
            retry(backoff, op).wrap_err_with(|| eyre!("Connect to server {} failed", host))?;

        let mut conn = Connection::new(cipher.clone(), stream)?;
        conn.send_frame(&infod_common::Frame::RequestStateReload)?;
        conn.read_frame()?
    };

    match frame {
        None => panic!("Invalid frame"),
        Some(frame) => match frame {
            infod_common::Frame::NewState(_, _) => {
                debug!("Successfully reloaded new state");
            }
            infod_common::Frame::NoChanges => {
                debug!("Successfully reloaded with no new state");
            },
            infod_common::Frame::CheckState(_) => panic!("Invalid frame: CheckState"),
            infod_common::Frame::RequestStateReload => panic!("Invalid frame: RequestStateReload"),
        },
    };

    Ok(())
}
