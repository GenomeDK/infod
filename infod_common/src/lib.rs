use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    KeySizeUser, XChaCha20Poly1305, XNonce,
};
use eyre::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/infod/infod.toml";

#[derive(Deserialize)]
pub struct Config {
    pub secret_key: String,
    pub server: ServerConfig,
    pub client: ClientConfig,
}

#[derive(Deserialize)]
pub struct ServerConfig {
    pub passwd_file: Option<PathBuf>,
    pub group_file: Option<PathBuf>,
    pub shadow_file: Option<PathBuf>,
    pub mount_file: Option<PathBuf>,
    pub listen_on: Option<SocketAddr>,
}

#[derive(Deserialize)]
pub struct ClientConfig {
    pub mountpoint_prefix: Option<String>,
    pub destination: Option<PathBuf>,
    pub server: String,
    pub update_interval: Option<f64>,
}

pub fn read_config<P>(path: P) -> Result<Config>
where
    P: AsRef<Path>,
{
    let mut file = File::open(path)?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    let config: Config = toml::from_str(&buf)?;
    Ok(config)
}

pub fn cipher_from_secret_key(secret_key: &String) -> XChaCha20Poly1305 {
    let mut hasher = Sha512::new();
    hasher.update(secret_key.as_bytes());
    let result = hasher.finalize();
    XChaCha20Poly1305::new_from_slice(&result[0..XChaCha20Poly1305::key_size()]).unwrap()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub username: String,
    pub password: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Shadow {
    pub username: String, /* user login name */
    pub pwdp: String,     /* encrypted password */
    pub lstchg: String,   /* last password change */
    pub min: String,      /* days until change allowed. */
    pub max: String,      /* days before change required */
    pub warn: String,     /* days warning for expiration */
    pub inact: String,    /* days before account inactive */
    pub expire: String,   /* date when account expires */
    pub flag: String,     /* reserved for future use */
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Group {
    pub name: String,
    pub password: String,
    pub gid: u32,
    pub members: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Mount {
    pub mountpoint: String,
    pub key: String,
    pub params: String,
    pub location: String,
}

pub type StateId = u64;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct State {
    pub users: Vec<User>,
    pub shadow: Vec<Shadow>,
    pub groups: Vec<Group>,
    pub mounts: Vec<Mount>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Frame {
    CheckState(StateId),
    NewState(StateId, State),
    NoChanges,
}

pub struct Connection {
    cipher: XChaCha20Poly1305,
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>,
}

impl Connection {
    pub fn new(cipher: XChaCha20Poly1305, stream: TcpStream) -> Result<Self> {
        let reader = stream
            .try_clone()
            .expect("Could not clone stream for reader");

        let writer = stream
            .try_clone()
            .expect("Could not clone stream for writer");

        Ok(Self {
            cipher,
            reader: BufReader::new(reader),
            writer: BufWriter::new(writer),
        })
    }

    /// Read a frame from the connection.
    pub fn read_frame(&mut self) -> Result<Option<Frame>> {
        let mut length = [0; 8];
        self.reader.read_exact(&mut length)?;
        let length = u64::from_be_bytes(length);

        let mut nonce = [0; 24];
        self.reader.read_exact(&mut nonce)?;
        let nonce = XNonce::from_slice(&nonce);

        let mut ciphertext = vec![0u8; length as usize];
        self.reader.read_exact(ciphertext.as_mut_slice())?;

        let data = self.cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
        let frame = serde_json::from_slice(&data).wrap_err("Deserializing frame")?;

        Ok(Some(frame))
    }

    /// Send a frame to the connection.
    pub fn send_frame(&mut self, frame: &Frame) -> Result<()> {
        let data = serde_json::to_vec(frame).wrap_err("Encoding frame")?;

        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self.cipher.encrypt(&nonce, data.as_slice()).unwrap();

        let nonce = nonce.to_vec();

        let length: [u8; 8] = u64::to_be_bytes(ciphertext.len() as u64);
        let mut buf: Vec<u8> = Vec::new();
        buf.extend(length);
        buf.extend(nonce);
        buf.extend(ciphertext);

        self.writer.write_all(buf.as_slice())?;
        self.writer.flush()?;
        Ok(())
    }
}

pub fn read_key_from_file<P>(path: P) -> Result<[u8; 32]>
where
    P: AsRef<Path>,
{
    let mut buf = [0u8; 32];
    let _ = File::open(path)?.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn read_users<R>(reader: BufReader<R>) -> Result<Vec<User>>
where
    R: std::io::Read,
{
    let mut users = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let parts: Vec<_> = line.split(":").collect();
        users.push(User {
            username: parts[0].to_string(),
            password: parts[1].to_string(),
            uid: u32::from_str_radix(&parts[2], 10)?,
            gid: u32::from_str_radix(&parts[3], 10)?,
            gecos: parts[4].to_string(),
            home: parts[5].to_string(),
            shell: parts[6].to_string(),
        })
    }
    Ok(users)
}

pub fn write_users<W>(users: &Vec<User>, writer: &mut BufWriter<W>) -> Result<()>
where
    W: std::io::Write,
{
    for user in users.iter() {
        writer.write(
            format!(
                "{}:{}:{}:{}:{}:{}:{}\n",
                user.username, user.password, user.uid, user.gid, user.gecos, user.home, user.shell,
            )
            .as_bytes(),
        )?;
    }
    Ok(())
}

pub fn read_shadow<R>(reader: BufReader<R>) -> Result<Vec<Shadow>>
where
    R: std::io::Read,
{
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let parts: Vec<_> = line.split(":").collect();
        entries.push(Shadow {
            username: parts[0].to_string(),
            pwdp: parts[1].to_string(),
            lstchg: parts[2].to_string(),
            min: parts[3].to_string(),
            max: parts[4].to_string(),
            warn: parts[5].to_string(),
            inact: parts[6].to_string(),
            expire: parts[7].to_string(),
            flag: parts[8].to_string(),
        })
    }
    Ok(entries)
}

pub fn write_shadow<W>(shadow: &Vec<Shadow>, writer: &mut BufWriter<W>) -> Result<()>
where
    W: std::io::Write,
{
    for entry in shadow.iter() {
        writer.write(
            format!(
                "{}:{}:{}:{}:{}:{}:{}:{}:{}\n",
                entry.username,
                entry.pwdp,
                entry.lstchg,
                entry.min,
                entry.max,
                entry.warn,
                entry.inact,
                entry.expire,
                entry.flag,
            )
            .as_bytes(),
        )?;
    }
    Ok(())
}

pub fn read_groups<R>(reader: BufReader<R>) -> Result<Vec<Group>>
where
    R: std::io::Read,
{
    let mut groups = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let parts: Vec<_> = line.split(":").collect();
        groups.push(Group {
            name: parts[0].to_string(),
            password: parts[1].to_string(),
            gid: u32::from_str_radix(&parts[2], 10)?,
            members: parts[3]
                .split(",")
                .collect::<Vec<_>>()
                .iter()
                .map(|s| s.to_string())
                .collect(),
        })
    }
    Ok(groups)
}

pub fn write_groups<W>(groups: &Vec<Group>, writer: &mut BufWriter<W>) -> Result<()>
where
    W: std::io::Write,
{
    for group in groups.iter() {
        writer.write(
            format!(
                "{}:{}:{}:{}\n",
                group.name,
                group.password,
                group.gid,
                group.members.join(","),
            )
            .as_bytes(),
        )?;
    }
    Ok(())
}

pub fn read_mounts<R>(reader: BufReader<R>) -> Result<Vec<Mount>>
where
    R: std::io::Read,
{
    let mut mounts = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let parts: Vec<_> = line.split_whitespace().collect();
        mounts.push(Mount {
            mountpoint: parts[0].to_string(),
            key: parts[1].to_string(),
            params: parts[2].to_string(),
            location: parts[3].to_string(),
        })
    }
    Ok(mounts)
}

pub fn write_mounts<W>(mounts: &Vec<Mount>, writer: &mut BufWriter<W>) -> Result<()>
where
    W: std::io::Write,
{
    for mount in mounts.iter() {
        writer
            .write(format!("{}\t{}\t{}\n", mount.key, mount.params, mount.location).as_bytes())?;
    }
    Ok(())
}
