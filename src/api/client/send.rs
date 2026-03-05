use std::collections::BTreeMap;

use axum::extract::State;
use ruma::{
	api::client::message::send_message_event,
	events::{
		MessageLikeEventType, reaction::ReactionEventContent,
		room::redaction::RoomRedactionEventContent,
	},
};
use serde_json::from_str;
use tuwunel_core::{
	Err, Event, Result, err,
	matrix::pdu::PduBuilder,
	utils::{self, ReadyExt},
	warn,
};

use crate::Ruma;

/// # `PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}`
///
/// Send a message event into the room.
///
/// - Is a NOOP if the txn id was already used before and returns the same event
///   id again
/// - The only requirement for the content is that it has to be valid json
/// - Tries to send the event into the room, auth rules will determine if it is
///   allowed
pub(crate) async fn send_message_event_route(
	State(services): State<crate::State>,
	body: Ruma<send_message_event::v3::Request>,
) -> Result<send_message_event::v3::Response> {
	let sender_user = body.sender_user();
	let sender_device = body.sender_device.as_deref();
	let appservice_info = body.appservice_info.as_ref();

	if body.event_type == MessageLikeEventType::RoomRedaction
		&& services.config.disable_local_redactions
		&& !services.admin.user_is_admin(sender_user).await
	{
		if let Some(event_id) = body
			.body
			.body
			.deserialize_as_unchecked::<RoomRedactionEventContent>()
			.ok()
			.and_then(|content| content.redacts)
		{
			warn!(
				%sender_user,
				%event_id,
				"Local redactions are disabled, non-admin user attempted to redact an event"
			);
		} else {
			warn!(
				%sender_user,
				event = %body.body.body.json(),
				"Local redactions are disabled, non-admin user attempted to redact an event \
				 with an invalid redaction event"
			);
		}

		return Err!(Request(Forbidden("Redactions are disabled on this server.")));
	}

	// Forbid duplicate reactions
	if body.event_type == MessageLikeEventType::Reaction
		&& let Ok(content) = body
			.body
			.body
			.deserialize_as_unchecked::<ReactionEventContent>()
		&& let Ok(reacted_to_pdu_id) = services
			.timeline
			.get_pdu_id(&content.relates_to.event_id)
			.await
	{
		let shortroomid = u64::from_be_bytes(reacted_to_pdu_id.shortroomid());
		let is_duplicate = services
			.pdu_metadata
			.get_relations(shortroomid, reacted_to_pdu_id.pdu_count(), None, ruma::api::Direction::Forward, Some(sender_user))
			// Potentially wasteful to deserialuze whole PDU content
			.ready_filter_map(|(_, pdu)| pdu.get_content::<ReactionEventContent>().ok())
			.ready_filter(|other_reaction| other_reaction.relates_to.key == content.relates_to.key)
			// Will return `false` if there are no elements
			.ready_any(|_| true)
			.await;

		if is_duplicate {
			return Err!(Request(DuplicateAnnotation("Duplicate reactions are not allowed.")));
		}
	}

	// Forbid m.room.encrypted if encryption is disabled
	if MessageLikeEventType::RoomEncrypted == body.event_type && !services.config.allow_encryption
	{
		return Err!(Request(Forbidden("Encryption has been disabled")));
	}

	let state_lock = services.state.mutex.lock(&body.room_id).await;

	if body.event_type == MessageLikeEventType::CallInvite
		&& services
			.directory
			.is_public_room(&body.room_id)
			.await
	{
		return Err!(Request(Forbidden("Room call invites are not allowed in public rooms")));
	}

	// Check if this is a new transaction id
	if let Ok(response) = services
		.transaction_ids
		.existing_txnid(sender_user, sender_device, &body.txn_id)
		.await
	{
		// The client might have sent a txnid of the /sendToDevice endpoint
		// This txnid has no response associated with it
		if response.is_empty() {
			return Err!(Request(InvalidParam(
				"Tried to use txn id already used for an incompatible endpoint."
			)));
		}

		return Ok(send_message_event::v3::Response {
			event_id: utils::string_from_bytes(&response)
				.map(TryInto::try_into)
				.map_err(|e| err!(Database("Invalid event_id in txnid data: {e:?}")))??,
		});
	}

	let mut unsigned = BTreeMap::new();
	unsigned.insert("transaction_id".to_owned(), body.txn_id.to_string().into());

	let content = from_str(body.body.body.json().get())
		.map_err(|e| err!(Request(BadJson("Invalid JSON body: {e}"))))?;

	let event_id = services
		.timeline
		.build_and_append_pdu(
			PduBuilder {
				event_type: body.event_type.clone().into(),
				content,
				unsigned: Some(unsigned),
				timestamp: appservice_info.and(body.timestamp),
				..Default::default()
			},
			sender_user,
			&body.room_id,
			&state_lock,
		)
		.await?;

	services.transaction_ids.add_txnid(
		sender_user,
		sender_device,
		&body.txn_id,
		event_id.as_bytes(),
	);

	drop(state_lock);

	Ok(send_message_event::v3::Response { event_id })
}
