use tokio_proto::pipeline::{ClientProto, ServerProto};
use bytes::BytesMut;
use tokio_io::codec::length_delimited;
use futures::{future, Future, Sink, Stream};
use serde_cbor;
use tokio_uds::{UnixListener, UnixStream};
use tokio_core::reactor::Handle;
use nix;
use failure::{Error, ResultExt};

use std::{error, fmt, io};

use messages;

pub struct Proto {
    current_uid: nix::unistd::Uid,
}

impl Proto {
    pub fn new() -> Proto {
        Proto {
            current_uid: nix::unistd::Uid::current(),
        }
    }

    fn path(&self) -> String {
        format!("\0simple-crypt-{}", self.current_uid)
    }

    pub fn connect(&self, handle: &Handle) -> Result<UnixStream, Error> {
        Ok(UnixStream::connect(self.path(), &handle)
            .context("Could not connect to daemon. Is it running?")?)
    }

    pub fn bind(&self, handle: &Handle) -> Result<UnixListener, Error> {
        Ok(UnixListener::bind(self.path(), &handle)
            .context("Could not create listener. Is the daemon already running?")?)
    }
}

fn new_io_error<E>(err: E) -> io::Error
where
    E: Into<Box<error::Error + Send + Sync>> + fmt::Debug,
{
    println!("{:?}", err);
    io::Error::new(io::ErrorKind::Other, err)
}

impl ServerProto<UnixStream> for Proto {
    type Request = BytesMut;
    type Response = Vec<u8>;
    type Transport = length_delimited::Framed<UnixStream, Vec<u8>>;
    type BindTransport = Box<Future<Item = Self::Transport, Error = io::Error>>;

    fn bind_transport(&self, sock: UnixStream) -> Self::BindTransport {
        let valid_uid =
            nix::unistd::Uid::from_raw(sock.peer_cred().unwrap().uid) == self.current_uid;

        let transport = length_delimited::Builder::new()
            .length_field_length(2)
            .little_endian()
            .new_framed(sock);

        Box::new(
            transport
                .into_future()
                .map_err(|(e, _transport)| e)
                .and_then(move |(msg, transport)| {
                    let response = match msg.and_then(|msg| {
                        serde_cbor::from_slice::<messages::ClientHandshake>(&msg).ok()
                    }) {
                        Some(handshake) => {
                            if !valid_uid {
                                Ok(messages::ServerStatus::PermissionDenied)
                            } else if !handshake.is_current() {
                                Ok(messages::ServerStatus::BadVersion)
                            } else {
                                Ok(messages::ServerStatus::Ok)
                            }
                        }
                        None => Err(new_io_error("no handshake")),
                    };

                    future::result(response)
                        .and_then(|response| {
                            serde_cbor::to_vec(&messages::ServerHandshake::new(response))
                                .map_err(new_io_error)
                        })
                        .and_then(|msg| transport.send(msg))
                }),
        ) as Self::BindTransport
    }
}

impl ClientProto<UnixStream> for Proto {
    type Request = Vec<u8>;
    type Response = BytesMut;
    type Transport = length_delimited::Framed<UnixStream, Vec<u8>>;
    type BindTransport = Box<Future<Item = Self::Transport, Error = io::Error>>;

    fn bind_transport(&self, sock: UnixStream) -> Self::BindTransport {
        let transport = length_delimited::Builder::new()
            .length_field_length(2)
            .little_endian()
            .new_framed(sock);

        let handshake = messages::ClientHandshake {
            version: messages::CURRENT_VERSION,
        };
        Box::new(
            future::result(serde_cbor::to_vec(&handshake).map_err(new_io_error)).and_then(|msg| {
                transport
                    .send(msg)
                    .map(|transport| transport.into_future().map_err(|(e, _transport)| e))
                    .flatten()
                    .and_then(|(msg, transport)| {
                        match msg.and_then(|msg| {
                            serde_cbor::from_slice::<messages::ServerHandshake>(&msg).ok()
                        }) {
                            Some(handshake) => match handshake.status {
                                messages::ServerStatus::Ok => future::ok(transport),
                                messages::ServerStatus::BadVersion => {
                                    future::err(new_io_error(format!(
                                        "bad version, server version was {}",
                                        handshake.server_version
                                    )))
                                }
                                messages::ServerStatus::PermissionDenied => {
                                    future::err(new_io_error("permission denied"))
                                }
                            },
                            None => future::err(new_io_error(
                                "server did not present a valid handshake",
                            )),
                        }
                    })
            }),
        ) as Self::BindTransport
    }
}
