use std::fs;
use std::net::SocketAddr;
use std::net::TcpListener;

use color_eyre::eyre::Result;
use eyre::{eyre, WrapErr};
use infod_common::{cipher_from_secret_key, read_config, Connection, FileSpec, State, DEFAULT_CONFIG_PATH};
use tracing::info;

fn load_states(file_specs: &Vec<FileSpec>) -> Result<State>
{
    let mut files = Vec::new();
    for file_spec in file_specs.iter() {
        let contents = fs::read(&file_spec.src)?;
        files.push((file_spec.clone(), contents));
    }

    Ok(State { files })
}

fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();

    let config_path = std::env::var("INFOD_CONFIG").unwrap_or(DEFAULT_CONFIG_PATH.to_string());
    let config = read_config(&config_path)
        .wrap_err_with(|| eyre!("Could not open config file at {}", &config_path))?;
    let cipher = cipher_from_secret_key(&config.secret_key);

    let mut files = Vec::new();
    for file_spec in config.server.files.iter() {
        let contents = fs::read(&file_spec.src)?;
        files.push((file_spec.clone(), contents));
    }

    let mut state = load_states(&config.server.files)?;
    let mut id: u64 = rand::random();

    let listener = TcpListener::bind(
        config
            .server
            .listen_on
            .unwrap_or("0.0.0.0:9797".parse::<SocketAddr>()?),
    )?;
    let local_addr = listener.local_addr().unwrap();
    info!(
        "Listening for connections on {} port {}",
        local_addr.ip(),
        local_addr.port()
    );

    for stream in listener.incoming() {
        let mut conn = Connection::new(cipher.clone(), stream?)?;
        let response = match conn.read_frame()? {
            None => panic!("Invalid frame received"),
            Some(frame) => match frame {
                infod_common::Frame::CheckState(cid) if cid == id => infod_common::Frame::NoChanges,
                infod_common::Frame::CheckState(_) => {
                    infod_common::Frame::NewState(id, state.clone())
                }
                infod_common::Frame::RequestStateReload => {
                    let new_state = load_states(&config.server.files)?;
                    if state == new_state {
                        info!("Reloaded with no new state");
                        infod_common::Frame::NoChanges
                    } else {
                        info!("Reload with new state");
                        state = new_state;
                        id = rand::random();
                        infod_common::Frame::NewState(id, state.clone())
                    }
                }
                infod_common::Frame::NewState(_, _) => panic!("Invalid frame received: NewState"),
                infod_common::Frame::NoChanges => panic!("Invalid frame received: NoChanges"),
            },
        };
        conn.send_frame(&response)?;
    }

    Ok(())
}
