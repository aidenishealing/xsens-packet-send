//! Send "Unreal LiveLink" network packets that were recorded from Xsens Animate
//! This should help bypass XSens ridiculous software.

use anyhow::Result as AnyhowResult;
use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::fs::File;
use std::time::Duration;
use tokio::net::UdpSocket;

const LOCAL_ADDR : &'static str = "0.0.0.0:8022";
const REMOTE_ADDR : &'static str = "192.168.50.31:9763";

#[tokio::main]
pub async fn main() -> AnyhowResult<()> {
  let socket = UdpSocket::bind(LOCAL_ADDR).await?;
  socket.connect(REMOTE_ADDR).await?;

  loop {
    play_legacy_pcap_file_format(&socket).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
  }

  Ok(())
}

pub async fn play_legacy_pcap_file_format(socket: &UdpSocket) -> AnyhowResult<()> {
  let path = "animation.pcap";
  let file = File::open(path)?;

  let mut num_blocks = 0;
  let mut reader = LegacyPcapReader::new(65536, file)?;

  loop {
    match reader.next() {
      Ok((offset, block)) => {
        num_blocks += 1;

        match block {
          PcapBlockOwned::LegacyHeader(header) => {
          },
          PcapBlockOwned::Legacy(block) => {
            // NB(brandon): The first 32 bytes seem to be the UDP packet metadata.
            let slice = &block.data[32..];
            let len = socket.send(slice).await?;
            //println!("Sent: {}", len);

            tokio::time::sleep(Duration::from_millis(5)).await;
          },
          PcapBlockOwned::NG(_) => unreachable!(),
        }
        reader.consume(offset);
      },
      Err(PcapError::Eof) => break,
      Err(PcapError::Incomplete) => {
        reader.refill().unwrap();
      },
      Err(e) => panic!("error while reading: {:?}", e),
    }
  }

  println!("num_blocks: {}", num_blocks);
  Ok(())
}
