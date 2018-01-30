use failure::{Error, ResultExt};

use futures::sync::oneshot;
use futures::{Future, Stream};
use tokio_core::reactor::Core;
use tokio_proto::BindServer;
use std::rc::Rc;
use std::io;
use simple_crypt_util;
use sodiumoxide;
use daemonize;

use service_impl;
use proto;

pub fn serve() -> Result<(), Error> {
    let x: u32 = 1;
    sodiumoxide::init();

    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let service = Rc::new(service_impl::DaemonServiceImpl::new(shutdown_sender)?);
    let proto = proto::Proto::new();

    let listener = proto.bind(&handle)?;

    daemonize::Daemonize::new()
        .start()
        .context("could not daemonize")?;

    // lock 16k of stack below, and 1k above
    simple_crypt_util::memory_security::lock_memory(16 * 1024, 1024, &x)?;
    // lock down /proc and prevent core dumps
    simple_crypt_util::memory_security::set_no_dumpable()?;

    let server = listener.incoming().for_each(|(sock, _)| {
        proto.bind_server(&handle, sock, service.clone());
        Ok(())
    });

    core.run(
        server.select(shutdown_receiver.map_err(|err| io::Error::new(io::ErrorKind::Other, err))),
    ).map(|(v, _)| v)
        .map_err(|(e, _)| e)
        .expect("failure while running server");

    Ok(())
}
