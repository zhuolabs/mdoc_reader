use crate::{
    Result, ServiceParameterRecord, receive_ndef_message_selected, write_ndef_message_selected,
};

use ndef_rs::NdefMessage;
use nfc_reader::NfcTag;

/// Active TNEP service session.
///
/// Created by TnepClient::select().
///
/// Borrowing the client prevents selecting another service
/// while this session is active.
pub struct TnepService<'a, T> {
    pub(crate) client: &'a mut crate::TnepClient<'a, T>,
    pub(crate) service: ServiceParameterRecord,
}

impl<'a, T> TnepService<'a, T>
where
    T: NfcTag,
{
    /// Send NDEF Message to the service.
    pub async fn send(&mut self, msg: &NdefMessage) -> Result<()> {
        write_ndef_message_selected(self.client.tag, &self.client.cc, msg).await
    }

    /// Receive next message.
    ///
    /// Some services support multiple messages.
    pub async fn receive(&mut self) -> Result<NdefMessage> {
        receive_ndef_message_selected(
            &mut *self.client.tag,
            &self.client.cc,
            self.service.n_wait,
            self.service.wt_int,
        )
        .await
    }

    /// Send and receive in one call.
    ///
    /// Convenience method.
    pub async fn exchange(&mut self, msg: &NdefMessage) -> Result<NdefMessage> {
        self.send(msg).await?;
        self.receive().await
    }

    /// Get service name.
    pub fn service_name(&self) -> &str {
        &self.service.service_name
    }
}
