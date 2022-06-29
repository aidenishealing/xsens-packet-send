
use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::fs::File;
use tokio::net::UdpSocket;

use anyhow::Result as AnyhowResult;

#[tokio::main]
pub async fn main() -> AnyhowResult<()> {
  old_format().await?;

  Ok(())
}

pub async fn old_format() -> AnyhowResult<()> {

  let path = "anim.pcap";
  let file = File::open(path).unwrap();
  let mut num_blocks = 0;
  let mut reader = LegacyPcapReader::new(65536, file).expect("LegacyPcapReader");

  let sock = UdpSocket::bind("0.0.0.0:8022").await?;

  let remote_addr = "192.168.50.31:9763";
  sock.connect(remote_addr).await?;


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
            //println!("Block: {:?}", block)

            let len = sock.send(&block.data).await?;
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

pub fn new_format() {
  println!("Test");

  //let path = "anim.pcap";
  let path = "anim.pcapng";

  let file = File::open(path).unwrap();
  let mut num_blocks = 0;
  let capacity = 199999999;
  let mut reader = PcapNGReader::new(capacity, file).expect("PcapNGReader");
  let mut if_linktypes = Vec::new();
  loop {
    match reader.next() {
      Ok((offset, block)) => {
        println!("got new block");
        num_blocks += 1;
        match block {
          PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
            // starting a new section, clear known interfaces
            if_linktypes = Vec::new();
          },
          PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
            if_linktypes.push(idb.linktype);
          },
          PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
            assert!((epb.if_id as usize) < if_linktypes.len());
            let linktype = if_linktypes[epb.if_id as usize];
            #[cfg(feature="data")]
                let res = pcap_parser::data::get_packetdata(epb.data, linktype, epb.caplen as usize);
          },
          PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
            assert!(if_linktypes.len() > 0);
            let linktype = if_linktypes[0];
            let blen = (spb.block_len1 - 16) as usize;
            #[cfg(feature="data")]
                let res = pcap_parser::data::get_packetdata(spb.data, linktype, blen);
          },
          PcapBlockOwned::NG(_) => {
            // can be statistics (ISB), name resolution (NRB), etc.
            eprintln!("unsupported block");
          },
          PcapBlockOwned::Legacy(_)
          | PcapBlockOwned::LegacyHeader(_) => unreachable!(),
        }
        reader.consume(offset);
      },
      Err(PcapError::Eof) => break,
      Err(PcapError::Incomplete) => {
        eprintln!("Could not read complete data block.");
        eprintln!("Hint: the reader buffer size may be too small, or the input file nay be truncated.");
        break;
      },
      Err(e) => panic!("error while reading: {:?}", e),
    }
  }
  println!("num_blocks: {}", num_blocks);
}