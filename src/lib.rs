extern crate hex;
extern crate nom;
extern crate tls_parser;
extern crate json;

use wasm_bindgen::prelude::*;
use nom::{Err};
use tls_parser::parse_tls_plaintext;
use tls_parser::tls_extensions::parse_tls_extensions;

#[derive(Debug)]
struct JsonableTlsPlaintext<'a> (tls_parser::TlsPlaintext<'a>);

impl From<JsonableTlsPlaintext<'_>> for json::JsonValue {
  fn from(tlsplaintext: JsonableTlsPlaintext) -> json::JsonValue{
      let message: &tls_parser::TlsMessage = &tlsplaintext.0.msg[0];
      match message { 
          tls_parser::TlsMessage::Handshake(handshake) => {
              match handshake{
                  tls_parser::TlsMessageHandshake::ClientHello(clienthello) => {
                      let cipherlist: Vec<String>      = clienthello.ciphers.iter().map(|x| format!("{:?}",x)).collect();
                      let compressionlist: Vec<String> = clienthello.comp.iter().map(|x| format!("{:?}",x)).collect();
                      let random_data: Vec<String>     = clienthello.rand_time.to_be_bytes().iter().chain(clienthello.rand_data.iter()).map(|x| format!("{:#x}", *x)).collect();
                      let session_id: Vec<String>      = match clienthello.session_id {
                          Some(iddata) => iddata.iter().map(|x| format!("{:#x}", *x)).collect(),
                          _ => vec![]
                      };
                      let parsed_extensions: Vec<tls_parser::TlsExtension> = match clienthello.ext {
                          Some(exts) => {
                            let parseresult = parse_tls_extensions(exts);
                              match parseresult {
                                Ok((_,exts)) => exts,
                                Err(_) => vec![],  //TODO find the error value, return it.
                                }
                            }
                            _ => vec![]
                       };
                                    
                        let extensions: Vec<String> = parsed_extensions.iter().map(|x| format!("{:?}", x)).collect();
                        return json::object!{
                            "version"     => clienthello.version.to_string(),
                            "random_data" => random_data,
                            "session_id"  => session_id,
                            "cipherlist"  => cipherlist,
                            "compressionlist" => compressionlist,
                            "extensions" => extensions,
                        };
                  }
                  _ => {
                      return json::object!{
                          "version" => "HandshakeDefaultVersion"
                      }
                  }
              }
          }
          _ => {
              return json::object!{
                  "version" => "Defaultversion"
              }
          }
      }
  }
}

#[wasm_bindgen]
pub fn parse(bytes: &[u8]) -> Option<String> {
    let res = parse_tls_plaintext(&bytes);
    match res {
        Ok((_rem,record)) => {
            // rem is the remaining data (not parsed)
            // record is an object of type TlsRecord
            eprintln!("Result {:?}", record);
            return Some(json::stringify(JsonableTlsPlaintext(record)));
        }
        Err(Err::Incomplete(_needed)) => {
            eprintln!("Defragmentation required (TLS record)");
            return Some(json::stringify("Defragmentation required (TLS record)"));
        },
        Err(e) => { 
            eprintln!("parse_tls_plaintext failed: {:?}",e); 
            return Some(json::stringify(format!("parse_tls_plaintext failed: {:?}",e)));
            }
    }
}

#[wasm_bindgen]
pub fn parse_string(hexstring: String) -> Option<String> {
  match hex::decode(hexstring) {
      Ok(decoded) => {
          let passable: &[u8] = &decoded;
          return parse(passable);
      },
      Err(e) => return Some(json::stringify(format!("Hex-to-bytes failed: {:?}", e))),
  }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

 
    #[test]
    fn decode_example() {
        let result = super::parse_string("16030101400100013c03039f9342a6bfff1bc9fd917cbd44493513076c5aec3d5e70940b33793034b436a520b37db3b5a5c1bc158baa5f8f956c69e07315cea64d0ef1795d8fab1341ffc41000481302130313011304c02cc030cca9cca8c0adc02bc02fc0acc023c027c00ac014c009c013009dc09d009cc09c003d003c0035002f009fccaac09f009ec09e006b00670039003300ff010000ab0000001c001a0000176d61696c2e62696c6c796c69657572616e63652e6e6574000b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d00260024040305030603080708080809080a080b0804080508060401050106010303030102030201002b0009080304030303020301002d00020101003300260024001d0020addf9419097d03948c87e9df0386ce43d26fc5f7f4923959dfff13c01c09e84a".to_string());
        assert!(result.is_some());
        //assert_eq!(result.unwrap(), "Blah")
    }

}

