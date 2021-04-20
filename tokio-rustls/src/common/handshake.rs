use crate::common::{Stream, TlsState};
use rustls::Connection;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{io, mem};
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) trait IoConnection {
    type Io;
    type Connection;

    fn skip_handshake(&self) -> bool;
    fn get_mut(&mut self) -> (&mut TlsState, &mut Self::Io, &mut Self::Connection);
    fn into_io(self) -> Self::Io;
}

pub(crate) enum MidHandshake<IC>
where
    IC: IoConnection
{
    Handshaking(Result<IC, (IC::Io, rustls::Error)>),
    End,
}

impl<IC> Future for MidHandshake<IC>
where
    IC: IoConnection + Unpin,
    IC::Io: AsyncRead + AsyncWrite + Unpin,
    IC::Connection: Connection + Unpin,
{
    type Output = Result<IC, (io::Error, IC::Io)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let mut stream =
            match mem::replace(this, MidHandshake::End) {
                MidHandshake::Handshaking(Ok(stream)) => stream,
                MidHandshake::Handshaking(Err((stream, err))) => return Poll::Ready(Err((
                    io::Error::new(io::ErrorKind::Other, err),
                    stream
                ))),
                _ => panic!("unexpected polling after handshake")
            };

        if !stream.skip_handshake() {
            let (state, io, connection) = stream.get_mut();
            let mut tls_stream = Stream::new(io, connection).set_eof(!state.readable());

            while tls_stream.connection.is_handshaking() {
                match tls_stream.handshake(cx) {
                    Poll::Ready(Ok(_)) => (),
                    Poll::Ready(Err(err)) => {
                        // In case we have an alert to send describing this error,
                        // try a last-gasp write -- but don't predate the primary
                        // error.
                        //
                        // see https://github.com/quininer/tokio-rustls/issues/12
                        if err.kind() == io::ErrorKind::Other
                            && (&err as &dyn std::error::Error).is::<rustls::Error>()
                            && tls_stream.connection.wants_write()
                        {
                            let _ = tls_stream.write_io(cx);
                        }

                        return Poll::Ready(Err((err, stream.into_io())));
                    },
                    Poll::Pending => {
                        *this = MidHandshake::Handshaking(Ok(stream));
                        return Poll::Pending;
                    }
                }
            }

            while tls_stream.connection.wants_write() {
                match tls_stream.write_io(cx) {
                    Poll::Ready(Ok(_)) => (),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err((err, stream.into_io()))),
                    Poll::Pending => {
                        *this = MidHandshake::Handshaking(Ok(stream));
                        return Poll::Pending;
                    }
                }
            }
        }

        Poll::Ready(Ok(stream))
    }
}
