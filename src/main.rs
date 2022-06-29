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
  old_format().await?;
  Ok(())
}

pub async fn old_format() -> AnyhowResult<()> {
  let path = "animation.pcap";
  let file = File::open(path)?;

  let mut num_blocks = 0;
  let mut reader = LegacyPcapReader::new(65536, file)?;

  let sock = UdpSocket::bind(LOCAL_ADDR).await?;

  sock.connect(REMOTE_ADDR).await?;

  loop {
    match reader.next() {
      Ok((offset, block)) => {
        //println!("got new block");
        num_blocks += 1;

        match block {
          PcapBlockOwned::LegacyHeader(header) => {
            // save hdr.network (linktype)
            println!("Header: {:?}", header)
          },
          PcapBlockOwned::Legacy(block) => {
            // use linktype to parse b.data()
            //println!("Block: {:?}", block);

            let slice = &block.data[32..];
            let len = sock.send(slice).await?;
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
