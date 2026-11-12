// Copyright (C) 2026 xbmc4lyfe
// SPDX-License-Identifier: RPL-1.5
//
// Unless explicitly acquired and licensed from Licensor under another license,
// the contents of this file are subject to the Reciprocal Public License
// ("RPL") Version 1.5, or subsequent versions as allowed by the RPL, and You
// may not copy or use this file in either source code or executable form,
// except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS"
// basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR
// HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, QUIET
// ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing
// rights and limitations under the RPL.

use std::{
    cmp::Ordering,
    hash::{BuildHasher, RandomState},
};

use super::*;

pub(super) struct Exact {
    /// Old raw names sorted via borrowed canonical ordinals.
    old_order: Vec<usize>,
    old_group: Vec<usize>,
    live: Vec<usize>,
    append_slots: Vec<Option<usize>>,
    append_count: usize,
    hasher: RandomState,
}

impl Exact {
    pub(super) fn new(
        metadata: &Metadata,
        options: &RewriteOptions,
        usage: &mut RewriteUsage,
        other: u64,
    ) -> Result<Self> {
        let len = metadata.len();
        let need = bytes_for::<[usize; 3]>(len)?;
        work(options, usage, (len as u64).checked_mul(3).ok_or(CreateError::Overflow)?)?;
        limit(add(other, need)?, options.limits.common.plan_capacity, CreateLimit::PlanCapacity)?;
        let mut old_order = Vec::new();
        let mut old_group = Vec::new();
        let mut live = Vec::new();
        old_order.try_reserve_exact(len)?;
        old_group.try_reserve_exact(len)?;
        live.try_reserve_exact(len)?;
        old_order.extend(0..len);
        old_group.resize(len, 0);
        live.resize(len, 0);
        let name = |ordinal| metadata.view(ordinal).raw_name();
        sort_indices(&mut old_order, |a, b| compare(name(a), name(b), options, usage))?;
        let mut group = 0;
        for (i, &ordinal) in old_order.iter().enumerate() {
            if i != 0 && compare(name(old_order[i - 1]), name(ordinal), options, usage)? != Ordering::Equal {
                group = i;
            }
            old_group[ordinal] = group;
            live[group] += 1;
        }
        let exact =
            Self { old_order, old_group, live, append_slots: Vec::new(), append_count: 0, hasher: RandomState::new() };
        let capacity = add(other, exact.capacity()?)?;
        limit(capacity, options.limits.common.plan_capacity, CreateLimit::PlanCapacity)?;
        usage.common.plan.capacity = capacity;
        Ok(exact)
    }

    pub(super) fn capacity(&self) -> create::Result<u64> {
        let old = self.old_order.capacity() + self.old_group.capacity() + self.live.capacity();
        add(bytes_for::<usize>(old)?, bytes_for::<Option<usize>>(self.append_slots.capacity())?)
    }

    pub(super) fn remove(&mut self, ordinal: usize) {
        self.live[self.old_group[ordinal]] -= 1;
    }

    pub(super) fn check_append(
        &self,
        raw: &[u8],
        metadata: &Metadata,
        inputs: &[PlannedEntry],
        options: &RewriteOptions,
        usage: &mut RewriteUsage,
    ) -> Result<()> {
        let mut range = 0..self.old_order.len();
        while range.start < range.end {
            let mid = range.start + (range.end - range.start) / 2;
            let ordinal = self.old_order[mid];
            match compare(raw, metadata.view(ordinal).raw_name(), options, usage)? {
                Ordering::Less => range.end = mid,
                Ordering::Greater => range.start = mid + 1,
                Ordering::Equal => {
                    if self.live[self.old_group[ordinal]] != 0 {
                        return Err(RewriteError::NameConflict);
                    }
                    break;
                }
            }
        }
        if !self.append_slots.is_empty() {
            let slot = self.slot(&self.append_slots, raw, inputs, options, usage)?;
            if self.append_slots[slot].is_some() {
                return Err(RewriteError::NameConflict);
            }
        }
        Ok(())
    }

    pub(super) fn insert_append(
        &mut self,
        raw: &[u8],
        index: usize,
        inputs: &[PlannedEntry],
        options: &RewriteOptions,
        usage: &mut RewriteUsage,
        allocated: u64,
    ) -> Result<()> {
        if self.append_count >= self.append_slots.len() / 2 {
            let len = self.append_slots.len().max(2).checked_mul(2).ok_or(CreateError::Overflow)?;
            let required = add(allocated, bytes_for::<Option<usize>>(len)?)?;
            limit(required, options.limits.common.plan_capacity, CreateLimit::PlanCapacity)?;
            let mut grown = Vec::new();
            grown.try_reserve_exact(len)?;
            grown.resize(len, None);
            let actual = add(allocated, bytes_for::<Option<usize>>(grown.capacity())?)?;
            limit(actual, options.limits.common.plan_capacity, CreateLimit::PlanCapacity)?;
            usage.common.plan.capacity = usage.common.plan.capacity.max(actual);
            for &index in self.append_slots.iter().flatten() {
                let slot = self.slot(&grown, &inputs[index].name, inputs, options, usage)?;
                grown[slot] = Some(index);
            }
            let slot = self.slot(&grown, raw, inputs, options, usage)?;
            grown[slot] = Some(index);
            self.append_slots = grown;
        } else {
            let slot = self.slot(&self.append_slots, raw, inputs, options, usage)?;
            self.append_slots[slot] = Some(index);
        }
        self.append_count += 1;
        Ok(())
    }

    fn slot(
        &self,
        slots: &[Option<usize>],
        raw: &[u8],
        inputs: &[PlannedEntry],
        options: &RewriteOptions,
        usage: &mut RewriteUsage,
    ) -> create::Result<usize> {
        work(options, usage, raw.len() as u64)?;
        let mask = slots.len() - 1;
        let mut i = (self.hasher.hash_one(raw) as usize) & mask;
        loop {
            work(options, usage, 1)?;
            let Some(index) = slots[i] else { return Ok(i) };
            if compare(raw, &inputs[index].name, options, usage)? == Ordering::Equal {
                return Ok(i);
            }
            i = (i + 1) & mask;
        }
    }
}

fn compare(a: &[u8], b: &[u8], options: &RewriteOptions, usage: &mut RewriteUsage) -> create::Result<Ordering> {
    work(options, usage, a.len().min(b.len()) as u64 + 1)?;
    Ok(a.cmp(b))
}

#[derive(Clone, Copy)]
struct Name<'a> {
    raw: &'a [u8],
    key: &'a [u8],
    directory: bool,
    introduced: bool,
}

fn components(
    a: Name<'_>,
    b: Name<'_>,
    options: &RewriteOptions,
    usage: &mut RewriteUsage,
) -> create::Result<Ordering> {
    work(options, usage, (a.key.len() + b.key.len()) as u64 + 1)?;
    Ok(a.key.split(|&byte| byte == b'/').cmp(b.key.split(|&byte| byte == b'/')))
}

pub(super) fn validate(plan: &RewritePlan, usage: &mut RewriteUsage, order: &mut Vec<usize>) -> Result<()> {
    let options = &plan.options;
    let old = plan.metadata.len();
    let input_name = |index: usize, keyed: bool| {
        let input = &plan.inputs[index];
        let raw = input.name.strip_suffix(b"/").unwrap_or(&input.name);
        let key = if keyed { input.keys.as_deref().expect("admitted keys") } else { raw };
        Name { raw, key, directory: input.source.is_none(), introduced: true }
    };
    let name = |index| {
        if index >= old {
            input_name(plan.appends[index - old], false)
        } else if let Action::Replace(input) = plan.actions[index] {
            input_name(input, false)
        } else {
            let entry = plan.metadata.view(index);
            let bytes = entry.raw_name();
            let raw = bytes.strip_suffix(b"/").unwrap_or(bytes);
            Name { raw, key: raw, directory: layout::raw_directory(entry), introduced: false }
        }
    };
    order.clear();
    for (index, action) in plan.actions.iter().enumerate() {
        if !matches!(action, Action::Remove) {
            order.push(index)
        }
    }
    order.extend(old..old + plan.appends.len());
    check_hierarchy(order, name, options, usage)?;
    if options.collisions == CollisionPolicy::CallerKeys {
        order.clear();
        order.extend(0..plan.inputs.len());
        check_hierarchy(order, |index| input_name(index, true), options, usage)?;
        for pair in order.windows(2) {
            let (a, b) = (input_name(pair[0], true), input_name(pair[1], true));
            work(options, usage, (a.raw.len() + b.raw.len() + a.key.len() + b.key.len()) as u64 + 1)?;
            fn split(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
                bytes.split(|&byte| byte == b'/')
            }
            let common_keys = split(a.key).zip(split(b.key)).take_while(|(left, right)| left == right);
            if common_keys.zip(split(a.raw).zip(split(b.raw))).any(|(_, (left, right))| left != right) {
                return Err(RewriteError::NameConflict);
            }
        }
    }
    Ok(())
}

fn check_hierarchy<'a>(
    order: &mut [usize],
    name: impl Fn(usize) -> Name<'a>,
    options: &RewriteOptions,
    usage: &mut RewriteUsage,
) -> Result<()> {
    sort_indices(order, |a, b| components(name(a), name(b), options, usage))?;
    let mut file_ancestor: Option<Name<'a>> = None;
    let mut i = 0;
    while i < order.len() {
        let first = name(order[i]);
        let mut file = None;
        let mut directory = None;
        let mut introduced = false;
        loop {
            let item = name(order[i]);
            let kind: &mut Option<Name<'a>> = if item.directory { &mut directory } else { &mut file };
            if kind.is_none_or(|previous| !previous.introduced) {
                *kind = Some(item)
            }
            introduced |= item.introduced;
            i += 1;
            if i == order.len() || compare(first.key, name(order[i]).key, options, usage)? != Ordering::Equal {
                break;
            }
        }
        if file.is_some() && directory.is_some() && introduced {
            return Err(RewriteError::NameConflict);
        }
        if let Some(parent) = file_ancestor {
            work(options, usage, parent.key.len() as u64 + 1)?;
            if first.key.strip_prefix(parent.key).is_some_and(|suffix| suffix.starts_with(b"/")) {
                if parent.introduced || introduced {
                    return Err(RewriteError::NameConflict);
                }
                continue;
            }
        }
        file_ancestor = file;
    }
    Ok(())
}
