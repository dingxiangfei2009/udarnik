use core::fmt;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::{collections::VecDeque, error::Error, sync::Mutex};

use dyn_clone::{clone_box, DynClone};
use futures::{
    future::{Either, FusedFuture},
    prelude::*,
    stream::{Fuse, FusedStream, Stream, StreamExt},
};
use pin_utils::{unsafe_pinned, unsafe_unpinned};
use slab::Slab;

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
        Self {
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
    complete: Option<Box<dyn Send + Sync + Unpin + Future<Output = Result<(), E>>>>,
    stream: Option<Box<dyn Send + Sync + Unpin + Stream<Item = Result<T, E>>>>,
    flush: bool,
    stream_peek: Option<Result<T, E>>,
    complete_peek: Option<Result<(), E>>,
}

impl<T, E> TryFutureStream<T, E> {
    pub fn new(
        complete: Box<dyn Send + Sync + Unpin + Future<Output = Result<(), E>>>,
        stream: Box<dyn Send + Sync + Unpin + Stream<Item = Result<T, E>>>,
        flush: bool,
    ) -> Self {
        Self {
            complete: Some(complete),
            complete_peek: None,
            flush,
            stream: Some(stream),
            stream_peek: None,
        }
    }
}

impl<T, E> TryFutureStream<T, E> {
    unsafe_pinned!(complete: Option<Box<dyn Send + Sync + Unpin + Future<Output = Result<(), E>>>>);
    unsafe_pinned!(stream: Option<Box<dyn Send + Sync + Unpin + Stream<Item = Result<T, E>>>>);
}

impl<T, E> Stream for TryFutureStream<T, E> {
    type Item = Result<T, E>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        use Poll::*;

        let stream_item = match self
            .as_mut()
            .stream()
            .as_pin_mut()
            .map(|stream| stream.poll_next(cx))
        {
            None | Some(Pending) => None,
            Some(Ready(None)) => {
                self.stream = None;
                None
            }
            Some(Ready(Some(item))) => Some(item),
        };
        let complete_result = match self
            .as_mut()
            .complete()
            .as_pin_mut()
            .map(|complete| complete.poll(cx))
        {
            Some(Pending) | None => None,
            Some(Ready(result)) => {
                self.complete = None;
                Some(result)
            }
        };
        match (stream_item, complete_result) {
            (None, None) => {
                if self.flush {
                    if let Some(item) = self.stream_peek.take() {
                        Ready(Some(item))
                    } else if self.stream.is_some() || self.complete.is_some() {
                        Pending
                    } else if let Some(Err(e)) = self.complete_peek.take() {
                        Ready(Some(Err(e)))
                    } else {
                        Ready(None)
                    }
                } else if let Some(Err(e)) = self.complete_peek.take() {
                    self.stream = None;
                    Ready(Some(Err(e)))
                } else if self.stream.is_some() || self.complete.is_some() {
                    Pending
                } else {
                    Ready(None)
                }
            }
            (Some(item), Some(result)) => {
                if self.flush {
                    let item = if let Some(item_) = self.stream_peek.take() {
                        self.stream_peek = Some(item);
                        item_
                    } else {
                        item
                    };
                    self.complete_peek = Some(result);
                    Ready(Some(item))
                } else {
                    self.stream = None;
                    self.stream_peek = None;
                    if let Err(e) = result {
                        Ready(Some(Err(e)))
                    } else {
                        Ready(None)
                    }
                }
            }
            (None, Some(result)) => {
                if self.flush {
                    if let Some(item) = self.stream_peek.take() {
                        self.complete_peek = Some(result);
                        Ready(Some(item))
                    } else if self.stream.is_some() {
                        self.complete_peek = Some(result);
                        Pending
                    } else if let Err(e) = result {
                        Ready(Some(Err(e)))
                    } else {
                        Ready(None)
                    }
                } else {
                    self.stream = None;
                    self.stream_peek = None;
                    if let Err(e) = result {
                        Ready(Some(Err(e)))
                    } else {
                        Ready(None)
                    }
                }
            }
            (Some(item), None) => {
                if self.flush {
                    let item = if let Some(item_) = self.stream_peek.take() {
                        self.stream_peek = Some(item);
                        item_
                    } else {
                        item
                    };
                    Ready(Some(item))
                } else if let Some(Err(e)) = self.complete_peek.take() {
                    self.stream = None;
                    Ready(Some(Err(e)))
                } else if self.complete.is_some() {
                    Pending
                } else {
                    Ready(None)
                }
            }
        }
    }
}

impl<T, E> Unpin for TryFutureStream<T, E> {}

pub trait Spawn {
    type Error: Error + Send + Sync;

    /// Spawn task concurrently
    fn spawn<F, T>(
        &self,
        f: F,
    ) -> Box<dyn Future<Output = Result<T, Self::Error>> + Send + Sync + Unpin + 'static>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static;
}

#[derive(Clone)]
pub struct TokioSpawn(pub tokio::runtime::Handle);

impl Spawn for TokioSpawn {
    type Error = tokio::task::JoinError;
    fn spawn<F, T>(
        &self,
        f: F,
    ) -> Box<dyn Future<Output = Result<T, Self::Error>> + Send + Sync + Unpin + 'static>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        Box::new(Box::pin(self.0.spawn(f)))
    }
}

pub trait ClonableFuture<O>: DynClone + Future<Output = O> {
    fn clone_box(&self) -> Box<dyn ClonableFuture<O>>;
    fn clone_pin_box(&self) -> Pin<Box<dyn ClonableFuture<O>>> {
        ClonableFuture::clone_box(self).into()
    }
}

impl<T, O> ClonableFuture<O> for T
where
    T: 'static + Clone + Future<Output = O>,
{
    fn clone_box(&self) -> Box<dyn ClonableFuture<O>> {
        clone_box(self)
    }
}

pub trait ClonableSendableFuture<O>: Send + ClonableFuture<O> {
    fn clone_box(&self) -> Box<dyn Send + ClonableSendableFuture<O>>;
    fn clone_pin_box(&self) -> Pin<Box<dyn Send + ClonableSendableFuture<O>>> {
        ClonableSendableFuture::clone_box(self).into()
    }
}

impl<T, O> ClonableSendableFuture<O> for T
where
    T: 'static + Send + Clone + Future<Output = O>,
{
    fn clone_box(&self) -> Box<dyn Send + ClonableSendableFuture<O>> {
        clone_box(self)
    }
}

pub trait ClonableSink<T, E>: DynClone + Sink<T, Error = E> {
    fn clone_box(&self) -> Box<dyn Send + Sync + ClonableSink<T, E>>;
    fn clone_pin_box(&self) -> Pin<Box<dyn Send + Sync + ClonableSink<T, E>>> {
        ClonableSink::clone_box(self).into()
    }
}

impl<X, T, E> ClonableSink<T, E> for X
where
    X: 'static + Send + Sync + Clone + Sink<T, Error = E>,
{
    fn clone_box(&self) -> Box<dyn Send + Sync + ClonableSink<T, E>> {
        clone_box(self)
    }
}

#[derive(Default)]
pub struct WakerQueue {
    wait_queue: Mutex<(VecDeque<usize>, Slab<Option<Waker>>)>,
}

impl WakerQueue {
    pub fn register_poll_waker(&self, key: Option<usize>, w: Waker) -> Option<usize> {
        let (queue, wakers) = &mut *self.wait_queue.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(key) = key {
            if let Some(entry) = wakers.get_mut(key) {
                *entry = Some(w);
                return Some(key);
            }
        }
        let entry = wakers.vacant_entry();
        let key = entry.key();
        entry.insert(Some(w));
        queue.push_back(key);
        Some(key)
    }

    pub fn deregister_poll_waker(&self, key: Option<usize>) {
        if let Some(key) = key {
            let (_, wakers) = &mut *self.wait_queue.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = wakers.get_mut(key) {
                *entry = None;
            }
        }
    }

    pub fn try_notify_next(&self) {
        let (queue, wakers) = &mut *self.wait_queue.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(head) = queue.pop_front() {
            if let Some(Some(waker)) = wakers.get(head) {
                waker.wake_by_ref();
                queue.push_back(head);
                return;
            }
        }
        wakers.clear();
    }

    pub fn try_notify_all(&self) {
        let (queue, wakers) = &mut *self.wait_queue.lock().unwrap_or_else(|e| e.into_inner());
        let all_keys: Vec<_> = queue.drain(..).collect();
        for key in all_keys {
            if let Some(Some(waker)) = wakers.get(key) {
                waker.wake_by_ref();
                queue.push_back(key);
                return;
            }
        }
    }
}
