use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufWriter;
use std::net::ToSocketAddrs;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::{net::TcpStream, thread, time::Duration};

use backoff::{retry, ExponentialBackoffBuilder};
use chacha20poly1305::XChaCha20Poly1305;
use color_eyre::eyre::Result;
use eyre::{eyre, WrapErr};
use infod_common::{
    cipher_from_secret_key, read_config, write_groups, write_mounts, write_shadow, write_users,
    Config, Connection, Mount, State, StateId, DEFAULT_CONFIG_PATH,
};
use nix::sys::stat::{fchmod, Mode};
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
        .wrap_err("Could not parse server address")?
        .filter(|s| s.is_ipv4())
        .next()
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
                write_state(state, config).wrap_err("Could not write state to disk")?;
                debug!("Client state updated to version {}", state_id);
            }
            infod_common::Frame::NoChanges => (),
            infod_common::Frame::CheckState(_) => panic!("Invalid frame: CheckState"),
        },
    };

    Ok(())
}

fn write_state(state: State, config: &Config) -> Result<()> {
    let destination = config
        .client
        .destination
        .clone()
        .unwrap_or_else(|| PathBuf::from("/var/spool/infod"));

    let passwd_path = destination.join("passwd");
    let passwd_path_tmp = passwd_path.with_extension("new");

    let group_path = destination.join("group");
    let group_path_tmp = group_path.with_extension("new");

    let shadow_path = destination.join("shadow");
    let shadow_path_tmp = shadow_path.with_extension("new");

    let _ = std::fs::remove_file(&passwd_path_tmp);
    let _ = std::fs::remove_file(&group_path_tmp);
    let _ = std::fs::remove_file(&shadow_path_tmp);

    {
        let file = File::create(&passwd_path_tmp)?;
        fchmod(file.as_raw_fd(), Mode::S_IRUSR)?;
        write_users(&state.users, &mut BufWriter::new(file))?;

        let file = File::create(&shadow_path_tmp)?;
        fchmod(file.as_raw_fd(), Mode::S_IRUSR)?;
        write_shadow(&state.shadow, &mut BufWriter::new(file))?;

        let file = File::create(&group_path_tmp)?;
        fchmod(file.as_raw_fd(), Mode::S_IRUSR)?;
        write_groups(&state.groups, &mut BufWriter::new(file))?;
    }

    std::fs::rename(passwd_path_tmp, passwd_path)?;
    std::fs::rename(group_path_tmp, group_path)?;
    std::fs::rename(shadow_path_tmp, shadow_path)?;

    let mut mountpoints: BTreeMap<&str, Vec<Mount>> = BTreeMap::new();
    for mount in state.mounts.iter() {
        mountpoints
            .entry(&mount.mountpoint)
            .or_insert_with(|| Vec::new())
            .push(mount.clone());
    }

    for (mountpoint, mounts) in mountpoints.iter() {
        let path = destination.join(format!(
            "{}{}",
            config
                .client
                .mountpoint_prefix
                .clone()
                .unwrap_or(String::from("")),
            mountpoint,
        ));
        write_mounts(&mounts, &mut BufWriter::new(File::create(path)?))?;
    }

    Ok(())
}
