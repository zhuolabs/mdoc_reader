use crate::{
    build_service_select_message, ndef_transact_with_params, parse_service_parameters,
    parse_status, read_cc, read_ndef_message, select_by_name, Cc, Error, Result,
    ServiceParameterRecord, TnepService, NDEF_TAG_APP_AID,
};

use log::debug;
use ndef_rs::NdefMessage;
use nfc_reader::NfcTag;

/// TNEP Client
///
/// Entry point of TNEP communication.
///
/// Owns the tag.
pub struct TnepClient<'a, T> {
    pub initial_ndef_message: NdefMessage,
    pub(crate) tag: &'a mut T,
    pub(crate) cc: Cc,
}

fn dump_discovered_services(services: &[ServiceParameterRecord]) {
    debug!("discover.discovered_services: count={}", services.len());
    for (idx, service) in services.iter().enumerate() {
        debug!("discover.discovered_services[{}]: {:?}", idx, service);
    }
}

impl<'a, T> TnepClient<'a, T>
where
    T: NfcTag,
{
    /// Create new TNEP client.
    pub async fn new(tag: &'a mut T) -> Result<Self> {
        select_by_name(tag, &NDEF_TAG_APP_AID).await?;
        let cc = read_cc(tag).await?;
        let initial_ndef_message = read_ndef_message(tag, &cc).await?;
        Ok(Self {
            tag,
            cc,
            initial_ndef_message,
        })
    }

    /// Select a TNEP service by Service Name.
    ///
    /// Example:
    ///
    /// "urn:nfc:sn:handover"
    pub async fn select(&'a mut self, service_name: &str) -> Result<TnepService<'a, T>> {
        let services = parse_service_parameters(&self.initial_ndef_message);
        dump_discovered_services(&services);

        let service = services
            .into_iter()
            .find(|sp| sp.service_name == service_name)
            .ok_or_else(|| Error::service_not_found(service_name))?;

        let service_select = build_service_select_message(&service.service_name)?;
        let response = ndef_transact_with_params(
            self.tag,
            &self.cc,
            &service_select,
            service.n_wait,
            service.wt_int,
        )
        .await?;

        if parse_status(&response) != Some(0x00) {
            return Err(Error::protocol_error());
        }

        Ok(TnepService {
            client: self,
            service,
        })
    }
}
