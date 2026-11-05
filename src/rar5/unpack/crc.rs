//! The CRC32 of a file's output, worked out as the output leaves the window. Long stretches of it go to a helper
//! thread, which hashes them straight out of the window while decoding carries on; the decoder holds off writing
//! over a stretch until it is hashed ([`FileCrc::clear_before`]).

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;

/// Window bytes go to the helper in pieces of at most this many, so that the decoder, when it needs a stretch
/// hashed, mostly finds it either done or not yet begun, and hashes it itself.
const PIECE: usize = 1 << 20;

/// A stretch's bytes.
enum Bytes {
    /// bytes in the decoder's window
    Window(*const u8, usize),
    /// a filter's output
    Owned(Vec<u8>),
}

// SAFETY: window bytes are only read, and only while the decoder leaves them alone: it doesn't write over a stretch
// or let its window go until the stretch is hashed (see `FileCrc::window`)
unsafe impl Send for Bytes {}

impl Bytes {
    fn hash(&self, h: &mut crc32fast::Hasher) {
        match self {
            // SAFETY: the bytes are in the window and stay as they are until the stretch is hashed
            Bytes::Window(p, n) => h.update(unsafe { std::slice::from_raw_parts(*p, *n) }),
            Bytes::Owned(v) => h.update(v),
        }
    }
}

struct Stretch {
    /// where it starts in the stream
    start: u64,
    bytes: Bytes,
}

#[derive(Default)]
struct Chain {
    /// the file's hasher, unless a thread is hashing a stretch into it
    hasher: Option<crc32fast::Hasher>,
    /// stretches not yet hashed, oldest first
    waiting: VecDeque<Stretch>,
    /// where the stretch being hashed starts, while one is
    busy: Option<u64>,
    /// the helper waits for stretches
    idle: bool,
    /// the decoder waits for the stretch the helper is hashing
    waited: bool,
    /// filter output buffers hashed and done with, to reuse
    spare: Vec<Vec<u8>>,
    /// the decoder is gone: the helper stops
    closed: bool,
}

impl Chain {
    /// Hashes the oldest waiting stretch on this thread, the lock let go meanwhile; whoever calls holds the hasher
    /// for that time, so stretches are hashed one at a time and in order.
    fn hash_next<'a>(mut chain: MutexGuard<'a, Chain>, shared: &'a Shared) -> MutexGuard<'a, Chain> {
        let (Some(s), Some(mut h)) = (chain.waiting.pop_front(), chain.hasher.take()) else {
            unreachable!("a stretch is hashed only when one waits and the hasher is free")
        };
        chain.busy = Some(s.start);
        drop(chain);
        s.bytes.hash(&mut h);
        let mut chain = shared.lock();
        chain.hasher = Some(h);
        chain.busy = None;
        if let Bytes::Owned(v) = s.bytes {
            chain.spare.push(v);
        }
        chain
    }
}

#[derive(Default)]
struct Shared {
    chain: Mutex<Chain>,
    /// the helper waits here for stretches
    work: Condvar,
    /// the decoder waits here for the stretch the helper is hashing
    hashed: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Chain> {
        // nothing panics while holding the lock
        self.chain.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn helper(shared: &Shared) {
    let mut chain = shared.lock();
    loop {
        if chain.closed {
            return;
        }
        if chain.hasher.is_some() && !chain.waiting.is_empty() {
            chain = Chain::hash_next(chain, shared);
            if chain.waited {
                shared.hashed.notify_one();
            }
            continue;
        }
        chain.idle = true;
        chain = shared.work.wait(chain).unwrap_or_else(PoisonError::into_inner);
        chain.idle = false;
    }
}

/// The current file's CRC32, from its output as it leaves the window.
pub(super) struct FileCrc {
    /// the file's hasher, while none of its stretches are with the helper
    here: Option<crc32fast::Hasher>,
    /// what this shares with the helper, once there is one
    shared: Option<Arc<Shared>>,
    /// whether a helper thread hashes the stretches handed over; without one they are hashed here, when needed
    pub threaded: bool,
    /// stretches handed over, over the decoder's life
    pub handed_over: u64,
}

impl FileCrc {
    pub fn new() -> Self {
        FileCrc { here: Some(crc32fast::Hasher::new()), shared: None, threaded: true, handed_over: 0 }
    }

    /// Whether stretches of the file are with the helper.
    pub fn out(&self) -> bool {
        self.here.is_none()
    }

    /// The next of the file's bytes, `bytes` in the window, from stream position `start` on. With `hand_over`
    /// they go to the helper; so do they when earlier ones are with it, to keep them in order.
    ///
    /// # Safety
    ///
    /// Unless [`Self::out`] is false after the call, the bytes must stay in place, unchanged, until the stretch is
    /// hashed: until [`Self::clear_before`] is called with a limit past `start`, or [`Self::finish`] or
    /// [`Self::reset`] is called.
    pub unsafe fn window(&mut self, start: u64, bytes: &[u8], hand_over: bool) {
        if self.here.is_some() && !(hand_over && self.start()) {
            if let Some(h) = self.here.as_mut() {
                h.update(bytes);
            }
            return;
        }
        let shared = Arc::clone(self.shared.as_ref().expect("a helper's state when stretches go to it"));
        let mut chain = shared.lock();
        if let Some(h) = self.here.take() {
            chain.hasher = Some(h);
        }
        let mut at = start;
        for piece in bytes.chunks(PIECE) {
            chain.waiting.push_back(Stretch { start: at, bytes: Bytes::Window(piece.as_ptr(), piece.len()) });
            at += piece.len() as u64;
            self.handed_over += 1;
        }
        if hand_over && chain.idle {
            shared.work.notify_one();
        }
    }

    /// The next of the file's bytes, a filter's output, from stream position `start` on. Returns a buffer for the
    /// next filter's output: `data` itself unless it went to the helper.
    pub fn owned(&mut self, start: u64, data: Vec<u8>) -> Vec<u8> {
        if let Some(h) = self.here.as_mut() {
            h.update(&data);
            return data;
        }
        let shared = self.shared.as_ref().expect("a helper's state when stretches are with it");
        let mut chain = shared.lock();
        chain.waiting.push_back(Stretch { start, bytes: Bytes::Owned(data) });
        self.handed_over += 1;
        if chain.idle {
            shared.work.notify_one();
        }
        chain.spare.pop().unwrap_or_default()
    }

    /// Returns once every stretch handed over that starts before `limit` is hashed, hashing here those the helper
    /// hasn't begun. `overwritten` is where the window may already have been written over: no stretch still with
    /// the helper may start before it.
    pub fn clear_before(&mut self, limit: u64, overwritten: u64) {
        let Some(shared) = self.shared.clone().filter(|_| self.here.is_none()) else { return };
        let mut chain = shared.lock();
        let oldest = chain.busy.or(chain.waiting.front().map(|s| s.start));
        assert!(oldest.is_none_or(|s| s >= overwritten), "the window was written over output not yet hashed");
        loop {
            if chain.busy.is_some_and(|s| s < limit) {
                chain.waited = true;
                chain = shared.hashed.wait(chain).unwrap_or_else(PoisonError::into_inner);
                chain.waited = false;
            } else if chain.busy.is_none() && chain.waiting.front().is_some_and(|s| s.start < limit) {
                chain = Chain::hash_next(chain, &shared);
            } else {
                break;
            }
        }
        if chain.busy.is_none() && chain.waiting.is_empty() {
            self.here = chain.hasher.take();
        } else if chain.idle && chain.busy.is_none() {
            // what this thread didn't need hashed yet is the helper's again
            shared.work.notify_one();
        }
    }

    /// The CRC32 of all the file's bytes given since it began; the next file starts afresh.
    pub fn finish(&mut self) -> u32 {
        self.clear_before(u64::MAX, 0);
        self.here.replace(crc32fast::Hasher::new()).expect("everything hashed").finalize()
    }

    /// Forgets the file's bytes once the helper is done with any of them: the window may then be written anywhere.
    pub fn reset(&mut self) {
        if let Some(shared) = self.shared.as_ref().filter(|_| self.here.is_none()) {
            let mut chain = shared.lock();
            while let Some(s) = chain.waiting.pop_front() {
                if let Bytes::Owned(v) = s.bytes {
                    chain.spare.push(v);
                }
            }
            while chain.busy.is_some() {
                chain.waited = true;
                chain = shared.hashed.wait(chain).unwrap_or_else(PoisonError::into_inner);
                chain.waited = false;
            }
            chain.hasher = None;
        }
        self.here = Some(crc32fast::Hasher::new());
    }

    /// Starts the helper, unless there is one or it can't be started. Without a thread (`threaded` false) stretches
    /// handed over wait to be hashed here.
    fn start(&mut self) -> bool {
        if self.shared.is_some() {
            return true;
        }
        let shared = Arc::new(Shared::default());
        if self.threaded {
            let theirs = Arc::clone(&shared);
            if thread::Builder::new().name("zipfast-crc".into()).spawn(move || helper(&theirs)).is_err() {
                return false;
            }
        }
        self.shared = Some(shared);
        true
    }
}

impl Drop for FileCrc {
    fn drop(&mut self) {
        self.reset();
        if let Some(shared) = self.shared.as_ref() {
            shared.lock().closed = true;
            shared.work.notify_one();
        }
    }
}
