use super::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Open(u32),
    Write(u32, usize),
    Flush(u32),
    Drop(u32),
}

#[derive(Clone, Default)]
struct Fixture(Rc<FixtureState>);

#[derive(Default)]
struct FixtureState {
    volumes: RefCell<Vec<Vec<u8>>>,
    calls: RefCell<Vec<Call>>,
    live: Cell<bool>,
    write_cap: Cell<Option<usize>>,
    stop_write_at: Cell<Option<u64>>,
    interrupt_write: Cell<bool>,
    interrupt_flush: Cell<bool>,
    fail_open: Cell<Option<u32>>,
    fail_flush: Cell<Option<u32>>,
    cancel_flush: RefCell<Option<Cancellation>>,
}

struct Sink(Fixture, u32);

impl VolumeProvider for Fixture {
    type Sink = Sink;

    fn open(&mut self, disk: u32) -> io::Result<Sink> {
        let state = &self.0;
        state.calls.borrow_mut().push(Call::Open(disk));
        assert!(!state.live.get(), "previous volume still live");
        if state.fail_open.get() == Some(disk) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut volumes = state.volumes.borrow_mut();
        assert_eq!(volumes.len(), disk as usize);
        volumes.push(Vec::new());
        state.live.set(true);
        Ok(Sink(self.clone(), disk))
    }
}

impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let state = &self.0.0;
        state.calls.borrow_mut().push(Call::Write(self.1, bytes.len()));
        if state.interrupt_write.replace(false) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let mut volumes = state.volumes.borrow_mut();
        if state.stop_write_at.get() == Some(volumes.iter().map(|volume| volume.len() as u64).sum()) {
            return Ok(0);
        }
        let count = bytes.len().min(state.write_cap.get().unwrap_or(usize::MAX));
        volumes[self.1 as usize].extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        let state = &self.0.0;
        state.calls.borrow_mut().push(Call::Flush(self.1));
        if state.interrupt_flush.replace(false) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if state.fail_flush.get() == Some(self.1) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if let Some(cancel) = state.cancel_flush.borrow().as_ref() {
            cancel.cancel();
        }
        Ok(())
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        self.0.0.calls.borrow_mut().push(Call::Drop(self.1));
        assert!(self.0.0.live.replace(false));
    }
}

fn limits(capacity: u64) -> Limits {
    Limits { disk_bytes: capacity, disks: 32, output_bytes: 1024, attempts: 128 }
}

fn location(disk: u32, offset: u64) -> Location {
    Location { disk, offset }
}

#[test]
fn marker_and_exact_fit_do_not_open_a_trailing_disk() {
    let fixture = Fixture::default();
    let mut transport = Transport::new(fixture.clone(), limits(8), None).unwrap();
    assert_eq!(transport.position(), location(0, 4));
    let mut record = transport.reserve_record(4).unwrap();
    assert_eq!(record.location(), location(0, 4));
    record.write(b"ab").unwrap();
    assert_eq!(record.location(), location(0, 4));
    record.write(b"cd").unwrap();
    transport.write_payload(b"").unwrap();
    assert_eq!(transport.position(), location(0, 8));
    let (_, usage) = transport.finish().unwrap();
    assert_eq!(usage, Usage { disks: 1, bytes: 8, attempts: 5 });
    assert_eq!(*fixture.0.volumes.borrow(), [b"PK\x07\x08abcd"]);
    assert_eq!(
        *fixture.0.calls.borrow(),
        [Call::Open(0), Call::Write(0, 4), Call::Write(0, 2), Call::Write(0, 2), Call::Flush(0), Call::Drop(0)]
    );
}

#[test]
fn reserve_rolls_intact_and_payload_crosses_multiple_disks() {
    let fixture = Fixture::default();
    fixture.0.write_cap.set(Some(2));
    let mut transport = Transport::new(fixture.clone(), limits(8), None).unwrap();
    transport.write_payload(b"hi").unwrap();
    fixture.0.interrupt_flush.set(true);
    fixture.0.interrupt_write.set(true);
    let mut record = transport.reserve_record(5).unwrap();
    assert_eq!(record.location(), location(1, 0));
    record.write(b"ABC").unwrap();
    record.write(b"DE").unwrap();
    transport.write_payload(b"01234567890123456789").unwrap();
    assert_eq!(transport.position(), location(4, 1));
    let (_, usage) = transport.finish().unwrap();
    assert_eq!(usage.disks, 5);
    assert_eq!(usage.bytes, 31);
    assert_eq!(*fixture.0.volumes.borrow(), [b"PK\x07\x08hi".as_slice(), b"ABCDE012", b"34567890", b"12345678", b"9"]);
    let calls = fixture.0.calls.borrow();
    assert_eq!(usage.attempts as usize, calls.iter().filter(|call| !matches!(call, Call::Drop(_))).count());
    assert_eq!(calls.iter().filter(|call| **call == Call::Flush(0)).count(), 2);
    let first_write = calls.iter().position(|call| *call == Call::Write(1, 3)).unwrap();
    assert_eq!(calls[first_write..first_write + 3], [Call::Write(1, 3), Call::Write(1, 3), Call::Write(1, 1)]);
}

#[test]
fn impossible_record_fails_without_an_open_loop_or_padding() {
    let fixture = Fixture::default();
    let mut transport = Transport::new(fixture.clone(), limits(8), None).unwrap();
    let error = transport.reserve_record(9).err().unwrap();
    assert!(matches!(error.kind, ErrorKind::RecordTooLarge { requested: 9, capacity: 8 }));
    assert_eq!(error.at, location(0, 4));
    assert_eq!(error.usage, Usage { disks: 1, bytes: 4, attempts: 2 });
    assert!(transport.finish().is_err());
    assert_eq!(*fixture.0.volumes.borrow(), [b"PK\x07\x08"]);
    assert_eq!(*fixture.0.calls.borrow(), [Call::Open(0), Call::Write(0, 4), Call::Drop(0)]);
}

#[test]
fn failed_open_or_flush_poison_the_transport_and_preserve_usage() {
    for open in [false, true] {
        let fixture = Fixture::default();
        if open {
            fixture.0.fail_open.set(Some(1));
        } else {
            fixture.0.fail_flush.set(Some(0));
        }
        let mut transport = Transport::new(fixture.clone(), limits(6), None).unwrap();
        let error = transport.write_payload(b"abcd").unwrap_err();
        let (at, expected_stage, attempts) =
            if open { (location(1, 0), Stage::Open, 5) } else { (location(0, 6), Stage::Flush, 4) };
        assert_eq!(error.at, at);
        assert_eq!(error.stage, expected_stage);
        assert!(matches!(&error.kind, ErrorKind::Io(cause) if cause.kind() == io::ErrorKind::PermissionDenied));
        assert_eq!(error.usage, Usage { disks: 1, bytes: 6, attempts });
        assert!(std::sync::Arc::ptr_eq(&error, &transport.finish().err().unwrap()));
        assert_eq!(*fixture.0.volumes.borrow(), [b"PK\x07\x08ab"]);
    }
}

#[test]
fn cancel_after_flushing_never_opens_the_next_disk() {
    let fixture = Fixture::default();
    let cancel = Cancellation::default();
    fixture.0.cancel_flush.replace(Some(cancel.clone()));
    let mut transport = Transport::new(fixture.clone(), limits(4), Some(cancel)).unwrap();
    let error = transport.write_payload(b"a").unwrap_err();
    assert_eq!((error.at, error.stage), (location(1, 0), Stage::Open));
    assert!(matches!(error.kind, ErrorKind::Canceled));
    assert_eq!(error.usage, Usage { disks: 1, bytes: 4, attempts: 3 });
    assert!(transport.finish().is_err());
    assert_eq!(*fixture.0.calls.borrow(), [Call::Open(0), Call::Write(0, 4), Call::Flush(0), Call::Drop(0)]);
}

#[test]
fn volume_byte_and_attempt_limits_are_independent() {
    for (bounded, stage, bytes, attempts) in [
        (Limits { disks: 1, ..limits(6) }, Stage::Open, 6, 3),
        (Limits { output_bytes: 7, ..limits(6) }, Stage::Write, 4, 2),
        (Limits { attempts: 4, ..limits(6) }, Stage::Open, 6, 4),
    ] {
        let fixture = Fixture::default();
        let mut transport = Transport::new(fixture.clone(), bounded, None).unwrap();
        let error = transport.write_payload(b"abcd").unwrap_err();
        assert_eq!(error.stage, stage);
        assert!(
            matches!(error.kind, ErrorKind::Limit(Limit::Disks)) && bounded.disks == 1
                || matches!(error.kind, ErrorKind::Limit(Limit::OutputBytes)) && bounded.output_bytes == 7
                || matches!(error.kind, ErrorKind::Limit(Limit::Attempts)) && bounded.attempts == 4
        );
        assert_eq!(error.usage, Usage { disks: 1, bytes, attempts });
        assert!(transport.finish().is_err());
        assert_eq!(fixture.0.volumes.borrow().len(), 1);
    }
}

#[test]
fn interrupted_flush_stops_at_attempt_limit_and_final_flush_error_is_reported() {
    for interrupted in [false, true] {
        let fixture = Fixture::default();
        fixture.0.interrupt_flush.set(interrupted);
        fixture.0.fail_flush.set(Some(0));
        let transport = Transport::new(fixture.clone(), Limits { attempts: 3, ..limits(8) }, None).unwrap();
        let error = transport.finish().err().unwrap();
        assert_eq!((error.at, error.stage), (location(0, 4), Stage::Flush));
        assert_eq!(error.usage, Usage { disks: 1, bytes: 4, attempts: 3 });
        assert!(if interrupted {
            matches!(error.kind, ErrorKind::Limit(Limit::Attempts))
        } else {
            matches!(error.kind, ErrorKind::Io(_))
        });
        assert_eq!(*fixture.0.calls.borrow(), [Call::Open(0), Call::Write(0, 4), Call::Flush(0), Call::Drop(0)]);
    }
}

#[test]
fn zero_write_and_abandoned_record_never_finish_successfully() {
    let fixture = Fixture::default();
    fixture.0.write_cap.set(Some(1));
    fixture.0.stop_write_at.set(Some(6));
    let mut transport = Transport::new(fixture.clone(), limits(8), None).unwrap();
    let error = transport.write_payload(b"abcd").unwrap_err();
    assert!(matches!(&error.kind, ErrorKind::Io(cause) if cause.kind() == io::ErrorKind::WriteZero));
    assert_eq!(error.at, location(0, 6));
    assert_eq!(error.usage, Usage { disks: 1, bytes: 6, attempts: 8 });
    assert!(transport.finish().is_err());

    let fixture = Fixture::default();
    let mut transport = Transport::new(fixture, limits(8), None).unwrap();
    let mut record = transport.reserve_record(3).unwrap();
    record.write(b"a").unwrap();
    let error = transport.finish().err().unwrap();
    assert!(matches!(error.kind, ErrorKind::IncompleteRecord { remaining: 2 }));
    assert_eq!(error.at, location(0, 5));
}

#[test]
fn incomplete_reservation_cannot_be_followed_by_payload_or_finish() {
    let fixture = Fixture::default();
    let mut transport = Transport::new(fixture.clone(), limits(8), None).unwrap();
    let mut record = transport.reserve_record(3).unwrap();
    record.write(b"a").unwrap();
    let error = transport.write_payload(b"other").unwrap_err();
    assert!(matches!(error.kind, ErrorKind::IncompleteRecord { remaining: 2 }));
    assert_eq!(error.at, location(0, 5));
    assert!(std::sync::Arc::ptr_eq(&error, &transport.finish().err().unwrap()));
    assert_eq!(*fixture.0.volumes.borrow(), [b"PK\x07\x08a"]);
}

#[test]
fn marker_requires_capacity_and_byte_budget_before_opening_a_sink() {
    for (bounded, expected_stage) in [
        (limits(3), Stage::Reserve),
        (Limits { output_bytes: 3, ..limits(8) }, Stage::Write),
        (Limits { disks: 0, ..limits(8) }, Stage::Open),
    ] {
        let fixture = Fixture::default();
        let error = Transport::new(fixture.clone(), bounded, None).err().unwrap();
        assert_eq!((error.at, error.stage), (location(0, 0), expected_stage));
        assert_eq!(error.usage, Usage::default());
        assert!(fixture.0.calls.borrow().is_empty());
    }
}

#[test]
fn reserve_cannot_write_past_its_size_even_with_space_on_disk() {
    let fixture = Fixture::default();
    let mut transport = Transport::new(fixture.clone(), limits(8), None).unwrap();
    let mut record = transport.reserve_record(2).unwrap();
    record.write(b"a").unwrap();
    let error = record.write(b"bc").unwrap_err();
    assert!(matches!(error.kind, ErrorKind::RecordTooLarge { requested: 2, capacity: 1 }));
    assert_eq!(error.at, location(0, 5));
    assert!(std::sync::Arc::ptr_eq(&error, &transport.finish().err().unwrap()));
    assert_eq!(*fixture.0.volumes.borrow(), [b"PK\x07\x08a"]);
}
