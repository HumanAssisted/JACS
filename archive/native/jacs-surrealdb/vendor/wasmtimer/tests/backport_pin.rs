//! Preserve structural pinning and timeout behavior when replacing pin-utils.
#![cfg(target_arch = "wasm32")]

use std::cell::Cell;
use std::future::Future;
use std::marker::PhantomPinned;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Once;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::task::noop_waker_ref;
use wasm_bindgen_test::wasm_bindgen_test;
use wasmtimer::tokio::{advance, pause, timeout};

struct AddressCheckedFuture {
    address: Cell<Option<*const Self>>,
    ready: Rc<Cell<bool>>,
    dropped: Rc<Cell<bool>>,
    _pinned: PhantomPinned,
}

impl Future for AddressCheckedFuture {
    type Output = u32;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<u32> {
        let this = self.as_ref().get_ref();
        let address = this as *const Self;
        match this.address.get() {
            Some(previous) => assert_eq!(previous, address, "pinned future moved"),
            None => this.address.set(Some(address)),
        }
        if this.ready.get() {
            Poll::Ready(42)
        } else {
            Poll::Pending
        }
    }
}

impl Drop for AddressCheckedFuture {
    fn drop(&mut self) {
        if let Some(address) = self.address.get() {
            assert_eq!(
                address, self as *const Self,
                "pinned future moved before drop"
            );
        }
        assert!(!self.dropped.replace(true), "future dropped twice");
    }
}

fn future() -> (AddressCheckedFuture, Rc<Cell<bool>>, Rc<Cell<bool>>) {
    static INIT: Once = Once::new();
    INIT.call_once(pause);
    let ready = Rc::new(Cell::new(false));
    let dropped = Rc::new(Cell::new(false));
    (
        AddressCheckedFuture {
            address: Cell::new(None),
            ready: ready.clone(),
            dropped: dropped.clone(),
            _pinned: PhantomPinned,
        },
        ready,
        dropped,
    )
}

#[wasm_bindgen_test]
fn non_unpin_future_stays_in_place_until_completion_and_drop() {
    let (future, ready, dropped) = future();
    let mut timed = Box::pin(timeout(Duration::from_millis(100), future));
    let mut cx = Context::from_waker(noop_waker_ref());
    assert_eq!(timed.as_mut().poll(&mut cx), Poll::Pending);
    ready.set(true);
    assert_eq!(timed.as_mut().poll(&mut cx), Poll::Ready(Ok(42)));
    assert!(!dropped.get());
    drop(timed);
    assert!(dropped.get());
}

#[wasm_bindgen_test]
async fn expiry_keeps_future_pinned_until_timeout_is_dropped() {
    let (future, _, dropped) = future();
    let mut timed = Box::pin(timeout(Duration::from_millis(10), future));
    let mut cx = Context::from_waker(noop_waker_ref());
    assert_eq!(timed.as_mut().poll(&mut cx), Poll::Pending);
    advance(Duration::from_millis(11)).await;
    assert!(matches!(timed.as_mut().poll(&mut cx), Poll::Ready(Err(_))));
    assert!(!dropped.get());
    drop(timed);
    assert!(dropped.get());
}

#[wasm_bindgen_test]
async fn cancellation_drops_a_pending_pinned_future_once() {
    let (future, _, dropped) = future();
    let mut timed = Box::pin(timeout(Duration::from_millis(10), future));
    let mut cx = Context::from_waker(noop_waker_ref());
    assert_eq!(timed.as_mut().poll(&mut cx), Poll::Pending);
    drop(timed);
    assert!(dropped.get());
    advance(Duration::from_millis(11)).await;
}

#[wasm_bindgen_test]
async fn ready_future_wins_when_deadline_is_also_ready() {
    let (future, ready, _) = future();
    let mut timed = Box::pin(timeout(Duration::from_millis(10), future));
    let mut cx = Context::from_waker(noop_waker_ref());
    assert_eq!(timed.as_mut().poll(&mut cx), Poll::Pending);
    advance(Duration::from_millis(11)).await;
    ready.set(true);
    assert_eq!(timed.as_mut().poll(&mut cx), Poll::Ready(Ok(42)));
}

#[wasm_bindgen_test]
fn getters_and_into_inner_preserve_an_unpolled_non_unpin_future() {
    let (future, _, dropped) = future();
    let mut timed = timeout(Duration::from_millis(100), future);
    assert!(!timed.get_ref().ready.get());
    timed.get_mut().ready.set(true);
    let future = timed.into_inner();
    assert!(future.ready.get());
    assert!(!dropped.get());
    drop(future);
    assert!(dropped.get());
}
