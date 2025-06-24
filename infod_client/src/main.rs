use std::fs;
use std::net::ToSocketAddrs;
use std::{net::TcpStream, thread, time::Duration};

use backoff::{retry, ExponentialBackoffBuilder};
use chacha20poly1305::XChaCha20Poly1305;
use color_eyre::eyre::Result;
use eyre::{eyre, WrapErr};
use infod_common::{
    cipher_from_secret_key, read_config, Config, Connection, State, StateId, DEFAULT_CONFIG_PATH,
};
use nix::sys::stat::{fchmodat, FchmodatFlags, Mode};
use tracing::{debug, error};

fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();

    let config_path = std::env::var("INFOD_CONFIG").unwrap_or(DEFAULT_CONFIG_PATH.to_string());
    let config = read_config(&config_path)
        .wrap_err_with(|| eyre!("Could not open config file at {}", &config_path))?;
    let cipher = cipher_from_secret_key(&config.secret_key);

    let mut state_id: StateId = 0;
    loop {
        if let Err(err) = start_client(&cipher, &mut state_id, &config) {
            error!("{:?}", err);
        };
        thread::sleep(Duration::from_secs_f64(
            config.client.update_interval.unwrap_or(1.0),
        ));
    }
}

fn start_client(cipher: &XChaCha20Poly1305, state_id: &mut StateId, config: &Config) -> Result<()> {
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
        conn.send_frame(&infod_common::Frame::CheckState(*state_id))?;
        conn.read_frame()?
    };

    match frame {
        None => panic!("Invalid frame"),
        Some(frame) => match frame {
            infod_common::Frame::NewState(new_state_id, state) => {
                *state_id = new_state_id;
                write_state(state).wrap_err("Could not write state to disk")?;
                debug!("Client state updated to version {}", state_id);
            }
            infod_common::Frame::NoChanges => (),
            infod_common::Frame::CheckState(_) => panic!("Invalid frame: CheckState"),
            infod_common::Frame::RequestStateReload => panic!("Invalid frame: RequestStateReload"),
        },
    };

    Ok(())
}

fn write_state(state: State) -> Result<()> {
    for (file_spec, contents) in state.files.iter() {
        let tmp_dest = file_spec.dest.with_extension("new");
        fs::write(&tmp_dest, contents)
            .wrap_err_with(|| eyre!("Could not write file {:?}", &tmp_dest))?;

        fchmodat(
            None,
            &tmp_dest,
            Mode::from_bits_truncate(file_spec.mode),
            FchmodatFlags::FollowSymlink,
        )?;

        fs::rename(&tmp_dest, &file_spec.dest)
            .wrap_err_with(|| eyre!("Could not move to file {:?}", &file_spec.dest))?;
    }
    Ok(())
}
