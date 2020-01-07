use core::fmt;
use core::task::{Context, Poll};
use std::sync::Mutex;

use core::pin::Pin;
use futures::{
    future::{Either, FusedFuture},
    prelude::*,
    stream::{Fuse, FusedStream, Stream, StreamExt},
};
use pin_utils::{unsafe_pinned, unsafe_unpinned};

/// A `Stream` that implements a `peek` method.
///
/// The `peek` method can be used to retrieve a reference
/// to the next `Stream::Item` if available. A subsequent
/// call to `poll` will return the owned item.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Peekable<St: Stream> {
    stream: Fuse<St>,
    peeked: Option<St::Item>,
}

impl<St: Stream + Unpin> Unpin for Peekable<St> {}

impl<St: Stream> Peekable<St> {
    unsafe_pinned!(stream: Fuse<St>);
    unsafe_unpinned!(peeked: Option<St::Item>);

    pub fn new(stream: St) -> Peekable<St> {
        Peekable {
            stream: stream.fuse(),
            peeked: None,
        }
    }

    /// Acquires a reference to the underlying stream that this combinator is
    /// pulling from.
    pub fn get_ref(&self) -> &St {
        self.stream.get_ref()
    }

    /// Acquires a mutable reference to the underlying stream that this
    /// combinator is pulling from.
    ///
    /// Note that care must be taken to avoid tampering with the state of the
    /// stream which may otherwise confuse this combinator.
    pub fn get_mut(&mut self) -> &mut St {
        self.stream.get_mut()
    }

    /// Acquires a pinned mutable reference to the underlying stream that this
    /// combinator is pulling from.
    ///
    /// Note that care must be taken to avoid tampering with the state of the
    /// stream which may otherwise confuse this combinator.
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut St> {
        self.stream().get_pin_mut()
    }

    /// Consumes this combinator, returning the underlying stream.
    ///
    /// Note that this may discard intermediate state of this combinator, so
    /// care should be taken to avoid losing resources when this is called.
    pub fn into_inner(self) -> St {
        self.stream.into_inner()
    }

    /// Peek retrieves a reference to the next item in the stream.
    ///
    /// This method polls the underlying stream and return either a reference
    /// to the next item if the stream is ready or passes through any errors.
    pub fn peek(self: Pin<&mut Self>) -> Peek<'_, St> {
        Peek { inner: Some(self) }
    }

    fn poll_peek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Either<Pin<&mut Self>, Poll<Option<&St::Item>>> {
        if self.peeked.is_some() {
            let this: &Self = self.into_ref().get_ref();
            return Either::Right(Poll::Ready(this.peeked.as_ref()));
        }
        match self.as_mut().stream().poll_next(cx) {
            Poll::Ready(None) => Either::Right(Poll::Ready(None)),
            Poll::Ready(Some(item)) => {
                *self.as_mut().peeked() = Some(item);
                let this: &Self = self.into_ref().get_ref();
                Either::Right(Poll::Ready(this.peeked.as_ref()))
            }
            _ => Either::Left(self),
        }
    }
}

impl<St: Stream> FusedStream for Peekable<St> {
    fn is_terminated(&self) -> bool {
        self.peeked.is_none() && self.stream.is_terminated()
    }
}

impl<S: Stream> Stream for Peekable<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(item) = self.as_mut().peeked().take() {
            return Poll::Ready(Some(item));
        }
        self.as_mut().stream().poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let peek_len = if self.peeked.is_some() { 1 } else { 0 };
        let (lower, upper) = self.stream.size_hint();
        let lower = lower.saturating_add(peek_len);
        let upper = match upper {
            Some(x) => x.checked_add(peek_len),
            None => None,
        };
        (lower, upper)
    }
}

// Forwarding impl of Sink from the underlying stream
#[cfg(feature = "sink")]
impl<S, Item> Sink<Item> for Peekable<S>
where
    S: Sink<Item> + Stream,
{
    type Error = S::Error;

    delegate_sink!(stream, Item);
}

/// Future for the [`peek()`] function from [`Peekable`]
#[must_use = "futures do nothing unless polled"]
pub struct Peek<'a, St: Stream> {
    inner: Option<Pin<&'a mut Peekable<St>>>,
}

impl<St: Stream> Unpin for Peek<'_, St> {}

impl<St: Stream> fmt::Debug for Peek<'_, St> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peek").finish()
    }
}

impl<St: Stream> FusedFuture for Peek<'_, St> {
    fn is_terminated(&self) -> bool {
        self.inner.is_none()
    }
}

impl<'a, St> Future for Peek<'a, St>
where
    St: Stream,
{
    type Output = Option<&'a St::Item>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(peekable) = self.inner.take() {
            match peekable.poll_peek(cx) {
                Either::Left(peekable) => {
                    self.inner = Some(peekable);
                    Poll::Pending
                }
                Either::Right(poll) => poll,
            }
        } else {
            Poll::Pending
        }
    }
}

pub struct TryFutureStream<T, E> {
    pub complete: Option<Box<dyn Send + Sync + Unpin + Future<Output = Result<(), E>>>>,
    pub stream: Option<Box<dyn Send + Sync + Unpin + Stream<Item = Result<T, E>>>>,
}

impl<T, E> TryFutureStream<T, E> {
    unsafe_pinned!(complete: Option<Box<dyn Send + Sync + Unpin + Future<Output = Result<(), E>>>>);
    unsafe_pinned!(stream: Option<Box<dyn Send + Sync + Unpin + Stream<Item = Result<T, E>>>>);
}

impl<T, E> Stream for TryFutureStream<T, E> {
    type Item = Result<T, E>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        use Poll::*;

        let stream = self
            .as_mut()
            .stream()
            .as_pin_mut()
            .map(|stream| stream.poll_next(cx));
        let complete = self
            .as_mut()
            .complete()
            .as_pin_mut()
            .map(|complete| complete.poll(cx));
        match (stream, complete) {
            (Some(Pending), Some(Pending)) => Pending,
            (_, Some(Ready(Ok(_)))) => {
                *self.as_mut().stream() = None;
                *self.as_mut().complete() = None;
                Ready(None)
            }
            (_, Some(Ready(Err(e)))) => {
                *self.as_mut().stream() = None;
                *self.as_mut().complete() = None;
                Ready(Some(Err(e)))
            }
            (_, None) => Ready(None),
            (Some(Ready(Some(item))), Some(_)) => Ready(Some(item)),
            (Some(Ready(None)), Some(_)) => {
                *self.as_mut().stream() = None;
                Pending
            }
            _ => Ready(None),
        }
    }
}

impl<T, E> Unpin for TryFutureStream<T, E> {}

pub struct SyncFuture<F>(Mutex<F>);

impl<F> SyncFuture<F> {
    pub fn new(f: F) -> Self {
        Self(Mutex::new(f))
    }
}

impl<F> Future for SyncFuture<F>
where
    F: Future + Unpin,
{
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut f = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Pin::new(&mut *f).poll(cx)
    }
}
