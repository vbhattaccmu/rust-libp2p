// Copyright 2019 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Noise protocol I/O.

mod framed;
#[cfg(feature = "pq")]
pub(crate) mod framed_pq;
pub(crate) mod handshake;
#[cfg(feature = "pq")]
pub(crate) mod handshake_pq;
use std::{
    cmp::min,
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};

use asynchronous_codec::Framed;
use bytes::Bytes;
use framed::{Codec, MAX_FRAME_LEN};
use futures::{prelude::*, ready};

/// A noise session to a remote.
///
/// `T` is the type of the underlying I/O resource.
pub struct Output<T> {
    io: OutputIo<T>,
    recv_buffer: Bytes,
    recv_offset: usize,
    send_buffer: Vec<u8>,
    send_offset: usize,
}

/// Internal dispatch over the active Noise codec. The classic XX codec drives
/// `snow`; the post-quantum `pqXX` codec drives `clatter`. Both produce a
/// `Framed<T, _>` exposing identical [`Stream`] / [`Sink`] interfaces, so the
/// outer [`Output`] just dispatches per arm without further generics.
///
/// Both variants are boxed: their inner buffers differ substantially in size
/// (the PQ codec needs more headroom for ML-KEM material), and we don't want
/// either path to pay an in-place stack penalty for the other. There is one
/// `Output<T>` per connection so the extra allocation is amortized away.
enum OutputIo<T> {
    Classic(Box<Framed<T, Codec<snow::TransportState>>>),
    #[cfg(feature = "pq")]
    Pq(Box<Framed<T, framed_pq::PqCodec<framed_pq::PqTransportSession>>>),
}

impl<T> fmt::Debug for Output<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseOutput").finish()
    }
}

impl<T> Output<T> {
    pub(crate) fn new(io: Framed<T, Codec<snow::TransportState>>) -> Self {
        Output {
            io: OutputIo::Classic(Box::new(io)),
            recv_buffer: Bytes::new(),
            recv_offset: 0,
            send_buffer: Vec::new(),
            send_offset: 0,
        }
    }

    #[cfg(feature = "pq")]
    pub(crate) fn new_pq(io: Framed<T, framed_pq::PqCodec<framed_pq::PqTransportSession>>) -> Self {
        Output {
            io: OutputIo::Pq(Box::new(io)),
            recv_buffer: Bytes::new(),
            recv_offset: 0,
            send_buffer: Vec::new(),
            send_offset: 0,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Output<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let len = self.recv_buffer.len();
            let off = self.recv_offset;
            if len > 0 {
                let n = min(len - off, buf.len());
                buf[..n].copy_from_slice(&self.recv_buffer[off..off + n]);
                tracing::trace!(copied_bytes=%(off + n), total_bytes=%len, "read: copied");
                self.recv_offset += n;
                if len == self.recv_offset {
                    tracing::trace!("read: frame consumed");
                    // Drop the existing view so `NoiseFramed` can reuse
                    // the buffer when polling for the next frame below.
                    self.recv_buffer = Bytes::new();
                }
                return Poll::Ready(Ok(n));
            }

            let next = match &mut self.io {
                OutputIo::Classic(io) => Pin::new(io).poll_next(cx),
                #[cfg(feature = "pq")]
                OutputIo::Pq(io) => Pin::new(io).poll_next(cx),
            };
            match next {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(0)),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(Some(Ok(frame))) => {
                    self.recv_buffer = frame;
                    self.recv_offset = 0;
                }
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Output<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = Pin::into_inner(self);

        // The MAX_FRAME_LEN is the maximum buffer size before a frame must be sent.
        if this.send_offset == MAX_FRAME_LEN {
            tracing::trace!(bytes=%MAX_FRAME_LEN, "write: sending");
            match &mut this.io {
                OutputIo::Classic(io) => {
                    let mut io = Pin::new(io);
                    ready!(io.as_mut().poll_ready(cx))?;
                    io.as_mut().start_send(&this.send_buffer[..])?;
                }
                #[cfg(feature = "pq")]
                OutputIo::Pq(io) => {
                    let mut io = Pin::new(io);
                    ready!(io.as_mut().poll_ready(cx))?;
                    io.as_mut().start_send(&this.send_buffer[..])?;
                }
            }
            this.send_offset = 0;
        }

        let off = this.send_offset;
        let n = min(MAX_FRAME_LEN, off.saturating_add(buf.len()));
        this.send_buffer.resize(n, 0u8);
        let n = min(MAX_FRAME_LEN - off, buf.len());
        this.send_buffer[off..off + n].copy_from_slice(&buf[..n]);
        this.send_offset += n;
        tracing::trace!(bytes=%this.send_offset, "write: buffered");

        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = Pin::into_inner(self);

        // Check if there is still one more frame to send.
        if this.send_offset > 0 {
            tracing::trace!(bytes= %this.send_offset, "flush: sending");
            match &mut this.io {
                OutputIo::Classic(io) => {
                    let mut io = Pin::new(io);
                    ready!(io.as_mut().poll_ready(cx))?;
                    io.as_mut().start_send(&this.send_buffer[..])?;
                }
                #[cfg(feature = "pq")]
                OutputIo::Pq(io) => {
                    let mut io = Pin::new(io);
                    ready!(io.as_mut().poll_ready(cx))?;
                    io.as_mut().start_send(&this.send_buffer[..])?;
                }
            }
            this.send_offset = 0;
        }

        match &mut this.io {
            OutputIo::Classic(io) => Pin::new(io).poll_flush(cx),
            #[cfg(feature = "pq")]
            OutputIo::Pq(io) => Pin::new(io).poll_flush(cx),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        match &mut self.io {
            OutputIo::Classic(io) => Pin::new(io).poll_close(cx),
            #[cfg(feature = "pq")]
            OutputIo::Pq(io) => Pin::new(io).poll_close(cx),
        }
    }
}
