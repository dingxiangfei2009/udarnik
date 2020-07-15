use core::{
    mem::forget,
    pin::Pin,
    task::{Context, Poll},
};
use std::{error::Error, sync::Arc};

use dyn_clone::{clone_box, DynClone};
use futures::prelude::*;
use pin_utils::unsafe_pinned;

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

pub fn make_arc_clone<T>(p: *mut T) -> Option<Arc<T>> {
    if p.is_null() {
        None
    } else {
        let p = unsafe { Arc::from_raw(p) };
        let q = Arc::clone(&p);
        forget(p);
        Some(q)
    }
}
