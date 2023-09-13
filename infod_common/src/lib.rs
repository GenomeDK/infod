use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    KeySizeUser, XChaCha20Poly1305, XNonce,
};
use eyre::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileSpec {
    pub src: PathBuf,
    pub dest: PathBuf,
    pub mode: u16,
}

#[derive(Deserialize)]
pub struct ServerConfig {
    pub listen_on: Option<SocketAddr>,
    pub files: Vec<FileSpec>,
}

#[derive(Deserialize)]
pub struct ClientConfig {
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

pub type StateId = u64;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct State {
    pub files: Vec<(FileSpec, Vec<u8>)>,
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
