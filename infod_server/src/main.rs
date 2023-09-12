use std::fs::File;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::{io::BufReader, net::TcpListener};

use color_eyre::eyre::Result;
use eyre::{eyre, WrapErr};
use infod_common::{
    cipher_from_secret_key, read_config, read_groups, read_mounts, read_shadow, read_users,
    Connection, State, DEFAULT_CONFIG_PATH,
};
use rand;
use tracing::info;

fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();

    let spool_dir: PathBuf = PathBuf::from("/var/spool/infod");

    let config_path = std::env::var("INFOD_CONFIG").unwrap_or(DEFAULT_CONFIG_PATH.to_string());
    let config = read_config(&config_path)
        .wrap_err_with(|| eyre!("Could not open config file at {}", &config_path))?;
    let cipher = cipher_from_secret_key(&config.secret_key);

    let users = {
        let path = &config
            .server
            .passwd_file
            .unwrap_or(spool_dir.join("passwd"));
        let file = File::open(path).wrap_err_with(|| eyre!("Could not open file {:?}", path))?;
        read_users(BufReader::new(file)).wrap_err_with(|| eyre!("Could not read {:?}", path))?
    };

    let shadow = {
        let path = &config
            .server
            .shadow_file
            .unwrap_or(spool_dir.join("shadow"));
        let file = File::open(path).wrap_err_with(|| eyre!("Could not open file {:?}", path))?;
        read_shadow(BufReader::new(file)).wrap_err_with(|| eyre!("Could not read {:?}", path))?
    };

    let groups = {
        let path = &config.server.group_file.unwrap_or(spool_dir.join("group"));
        let file = File::open(path).wrap_err_with(|| eyre!("Could not open file {:?}", path))?;
        read_groups(BufReader::new(file)).wrap_err_with(|| eyre!("Could not read {:?}", path))?
    };

    let mounts = {
        let path = &config.server.mount_file.unwrap_or(spool_dir.join("mounts"));
        let file = File::open(path).wrap_err_with(|| eyre!("Could not open file {:?}", path))?;
        read_mounts(BufReader::new(file)).wrap_err_with(|| eyre!("Could not read {:?}", path))?
    };

    let state = State {
        users,
        shadow,
        groups,
        mounts,
    };

    let id: u64 = rand::random();

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
                infod_common::Frame::NewState(_, _) => panic!("Invalid frame received: NewState"),
                infod_common::Frame::NoChanges => panic!("Invalid frame received: NoChanges"),
            },
        };
        conn.send_frame(&response)?;
    }

    Ok(())
}
