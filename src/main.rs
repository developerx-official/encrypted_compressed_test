use bgzip::{BGZFWriter, Compression};
use libsw::Stopwatch;
use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};
use serde_encrypt::serialize::impls::BincodeSerializer;
use serde_encrypt::shared_key::SharedKey;
use serde_encrypt::traits::SerdeEncryptSharedKey;
use serde_encrypt::EncryptedMessage;
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read, Write};

const INPUT_FILE_PATH: &str = "input.file";
const OUTPUT_FILE_PATH: &str = "output.file";
const DECRYPTED_AND_DECOMPRESSED_FILE_PATH: &str = "output_decompressed.file";
const TEMPFILE_FILE_PATH: &str = "tempfile.file";
const KEY_PASSPHRASE: &str = "I_Like_Pizza!"; // DO NOT DO THIS IN THE REAL WORLD, THIS IS JUST FOR EXAMPLE

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedFile {
    content: Vec<u8>,
}

impl SerdeEncryptSharedKey for EncryptedFile {
    type S = BincodeSerializer<Self>;
}

fn main() -> Result<(), anyhow::Error> {
    println!("Compressing and encrypting...");
    let mut sw = Stopwatch::new();
    sw.start()?;
    let compressed_data = compress_data(get_bytes_from_file(INPUT_FILE_PATH.to_string())?)?;
    let encrypted_data = encrypt_data_from_struct(EncryptedFile {
        content: compressed_data,
    })?;
    let mut f = File::create(OUTPUT_FILE_PATH)?;
    f.write_all(encrypted_data.as_slice())?;
    sw.stop()?;
    println!(
        "Encrypted and compressed in {}ms!",
        sw.elapsed().as_millis()
    );

    println!("Decrypting and decompressing...");
    sw.reset();
    sw.start()?;
    let decrypted_data =
        decrypt_to_struct_from_data(get_bytes_from_file(OUTPUT_FILE_PATH.to_string())?)?;
    let decompressed_data = decompress_data(decrypted_data.content)?;
    let mut f2 = File::create(DECRYPTED_AND_DECOMPRESSED_FILE_PATH)?;
    f2.write_all(decompressed_data.as_slice())?;
    sw.stop()?;
    println!(
        "Decrypting and decompressing took {}ms!",
        sw.elapsed().as_millis()
    );
    Ok(())
}

fn get_bytes_from_file(path: String) -> Result<Vec<u8>, anyhow::Error> {
    let file = File::open(path)?;
    let mut file_reader = BufReader::new(file);
    let mut file_buffer = Vec::new();
    file_reader.read_to_end(&mut file_buffer)?;
    Ok(file_buffer)
}

fn compress_data(input: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
    let mut write_buffer = Vec::new();
    let mut writer = BGZFWriter::new(&mut write_buffer, bgzip::Compression::best());
    writer.write_all(input.as_slice())?;
    writer.close()?;
    Ok(write_buffer)
}

fn decompress_data(input: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
    let mut tmp_file = File::create(TEMPFILE_FILE_PATH)?;
    tmp_file.write_all(input.as_slice())?;
    tmp_file.flush()?;
    let mut x = File::open(TEMPFILE_FILE_PATH)?;
    let mut y = Vec::new();
    x.read_to_end(&mut y)?;
    let mut reader = flate2::bufread::MultiGzDecoder::new(Box::new(BufReader::new(File::open(
        TEMPFILE_FILE_PATH,
    )?)));
    let mut read_buffer = Vec::new();
    reader.read_to_end(&mut read_buffer)?;
    fs::remove_file(TEMPFILE_FILE_PATH)?;
    Ok(read_buffer)
}

fn string_to_hash(string: String) -> Result<Vec<u8>, anyhow::Error> {
    let mut context = Context::new(&SHA256);
    context.update(string.as_bytes());
    Ok(Vec::from(context.finish().as_ref()))
}

fn encrypt_data_from_struct(file: EncryptedFile) -> Result<Vec<u8>, anyhow::Error> {
    // let shared_key = SharedKey::new([0u8; 32]);
    let shared_key = SharedKey::new(
        string_to_hash(KEY_PASSPHRASE.to_string())?
            .as_slice()
            .try_into()?,
    );
    let encrypted_data = file.encrypt(&shared_key)?;
    let serialized_encrypted_message = encrypted_data.serialize();
    Ok(serialized_encrypted_message)
}

fn decrypt_to_struct_from_data(file: Vec<u8>) -> Result<EncryptedFile, anyhow::Error> {
    // let shared_key = SharedKey::new([0u8; 32]);
    let shared_key = SharedKey::new(
        string_to_hash(KEY_PASSPHRASE.to_string())?
            .as_slice()
            .try_into()?,
    );
    let encrypted_data = EncryptedMessage::deserialize(file)?;
    let decrypted_data = EncryptedFile::decrypt_owned(&encrypted_data, &shared_key)?;
    Ok(decrypted_data)
}
