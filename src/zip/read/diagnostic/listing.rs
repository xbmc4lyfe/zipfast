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

//! One held observation: constant metadata independent of the row count.
use super::*;
#[derive(Debug)]
pub(crate) struct ListingError {
    pub(crate) error: ZipReadError,
    pub(crate) prewrite: bool,
    pub(crate) usage: ZipDiagnosticUsage,
}
impl ProjectedReadSession {
    #[cfg(test)]
    #[allow(clippy::result_large_err)]
    pub(crate) fn render_listing<W: Write + AsFd, T>(
        &mut self,
        out: &mut W,
        cancel: &Cancellation,
        render: impl FnOnce(&[ZipEntry], &mut ZipDiagnosticWriter<'_, W>) -> ZipDiagnosticResult<T>,
    ) -> Result<(T, ZipDiagnosticUsage, RunUsage), ListingError> {
        self.render_listing_inner(out, cancel, &mut None, render)
    }
    #[allow(clippy::result_large_err)]
    pub(crate) fn render_listing_owned<W: Write + AsFd, T>(
        mut self,
        out: &mut W,
        cancel: &Cancellation,
        render: impl FnOnce(&[ZipEntry], &mut ZipDiagnosticWriter<'_, W>) -> ZipDiagnosticResult<T>,
    ) -> Result<(T, ZipDiagnosticUsage, RunUsage), ListingError> {
        let mut storage = None;
        let result = self.render_listing_inner(out, cancel, &mut storage, render);
        let Some(context) = storage.as_ref().filter(|c| c.ledger.with_state(|s| s.source_registered())) else {
            return match result {
                Err(error) => Err(ListingError {
                    error: self.owner.reject(error.error),
                    prewrite: error.prewrite,
                    usage: error.usage,
                }),
                Ok(_) => unreachable!("listing context initialized before rendering"),
            };
        };
        let close = super::super::run::retire_owned_source(self.owner.file, context, result.is_ok());
        match (result, close) {
            (Ok((value, usage, _)), None) => Ok((value, usage, context.run_usage())),
            (Ok((_, usage, _)), Some(error)) => Err(ListingError {
                error: error.with_usage(context.usage(), context.run_usage()),
                prewrite: false,
                usage,
            }),
            (Err(mut failure), close) => {
                if let Some(close) = close {
                    failure.error = failure.error.merge_cleanup_only(close);
                }
                failure.error = failure.error.with_usage(context.usage(), context.run_usage());
                Err(failure)
            }
        }
    }
    #[allow(clippy::result_large_err)]
    fn render_listing_inner<W: Write + AsFd, T>(
        &mut self,
        out: &mut W,
        cancel: &Cancellation,
        storage: &mut Option<EncryptedReadContext>,
        render: impl FnOnce(&[ZipEntry], &mut ZipDiagnosticWriter<'_, W>) -> ZipDiagnosticResult<T>,
    ) -> Result<(T, ZipDiagnosticUsage, RunUsage), ListingError> {
        let mut usage = ZipDiagnosticUsage::default();
        let mut attempted = false;
        let result = (|| -> ZipReadResult<(T, RunUsage)> {
            *storage = Some(EncryptedReadContext::new(Default::default())?);
            let context = storage.as_mut().unwrap();
            let stamp = self.owner.source.as_ref().map_err(|_| ReadFault::InvalidPlan)?.stamp;
            let plan = budget::ActionPlan::derive(
                budget::PlanGeometry { records: self.owner.entries.len() as u128, ..Default::default() },
                16,
                16,
            )?
            .with_binding(budget::PlanBinding {
                source: stamp,
                scope: ProjectedReadScope::AllRegular,
                output: budget::PlannedOutput::Discard,
                configuration_id: self.owner.identity,
            })?;
            context.ledger.with_state(|s| s.bind(plan))?;
            context.ledger.with_state(|s| s.bind_listing_diagnostics())?;
            context.ledger.with_state(|s| s.register_controlled_source())?;
            let before = self.list_source(context, &mut usage);
            let descriptor = self.list_descriptor(out, context, &mut usage);
            let original_result = match (before, descriptor) {
                (Ok(()), Ok(d)) if d.safe || !(d.dev == stamp.dev && d.ino == stamp.ino) => Ok(d),
                (Err(e), _) => Err(e),
                (_, Err(f)) => Err(ZipReadError::from(ReadFault::InvalidPlan).merge_diagnostic_boundary(f)),
                _ => Err(ZipReadError::from(ReadFault::InvalidPlan).merge_diagnostic_boundary(
                    DiagnosticBoundaryFault::Refused { reason: "listing aliases ZIP source" },
                )),
            };
            let original = match original_result {
                Ok(d) => d,
                Err(mut error) => {
                    if error.source_change().is_none()
                        && let Err(source) = self.list_source(context, &mut usage)
                    {
                        error = error.merge_source_boundary(source);
                    }
                    if let Err(boundary) = self.list_descriptor(out, context, &mut usage) {
                        error = error.merge_diagnostic_boundary(boundary);
                    }
                    return Err(error.with_usage(context.usage(), context.run_usage()));
                }
            };
            let mut fault = None;
            let token = Token { action: Some(context.ledger.identity()), serial: 1 };
            let rendered = {
                let mut writer = ZipDiagnosticWriter {
                    out,
                    usage: &mut usage,
                    fault: &mut fault,
                    cancel,
                    retries: 16,
                    token,
                    remaining: self.owner.entries.len() as u128 + 1,
                    attempted: &mut attempted,
                };
                render(&self.owner.entries, &mut writer)
            };
            let source = self.list_source(context, &mut usage);
            let after = self.list_descriptor(out, context, &mut usage);
            let mut error = fault.map(|f| ZipReadError::from(ReadFault::InvalidPlan).merge_diagnostic(f));
            if let Err(stop) = &rendered
                && (stop.token != token || error.is_none())
            {
                error = Some(ReadFault::InvalidPlan.into());
            }
            match after {
                Ok(d) if d == original => {}
                Ok(_) => {
                    error = Some(
                        error
                            .unwrap_or_else(|| ReadFault::InvalidPlan.into())
                            .merge_diagnostic_boundary(DiagnosticBoundaryFault::DescriptorChanged),
                    );
                }
                Err(f) => {
                    error = Some(error.unwrap_or_else(|| ReadFault::InvalidPlan.into()).merge_diagnostic_boundary(f));
                }
            }
            if let Err(boundary) = source {
                error = Some(match error {
                    Some(e) => e.merge_source_boundary(boundary),
                    None => boundary,
                });
            }
            if let Some(error) = error {
                return Err(error.with_usage(context.usage(), context.run_usage()));
            }
            Ok((rendered.map_err(|_| ReadFault::InvalidPlan)?, context.run_usage()))
        })();
        result.map(|(value, run)| (value, usage, run)).map_err(|error| ListingError {
            error,
            prewrite: !attempted,
            usage,
        })
    }
    #[allow(clippy::result_large_err)] // Fixed source/cleanup evidence cannot allocate on failure.
    fn list_source(&mut self, context: &mut EncryptedReadContext, usage: &mut ZipDiagnosticUsage) -> ZipReadResult<()> {
        context.ledger.with_state(|s| s.charge_category(RunCategory::DiagnosticSourceGroups, 1))?;
        self.owner
            .source
            .as_mut()
            .map_err(|_| ReadFault::InvalidPlan)?
            .verify_with(&self.owner.file, |stage, call| {
                context.source_stat(stage, || {
                    usage.metadata(0)?;
                    call()
                })
            })
            .map_err(ZipReadError::from)
    }
    fn list_descriptor<W: AsFd>(
        &self,
        out: &W,
        context: &EncryptedReadContext,
        usage: &mut ZipDiagnosticUsage,
    ) -> Result<Descriptor, DiagnosticBoundaryFault> {
        classify(out.as_fd().as_raw_fd(), |operation, call| {
            io::operation(
                &context.ledger,
                false,
                RunCategory::DiagnosticAdmissionOperations,
                IoStage::ExternalOutput,
                operation,
                None,
                || {
                    usage.metadata(1)?;
                    call()
                },
            )
        })
    }
}
