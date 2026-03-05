use std::collections::BTreeMap;

use axum::extract::State;
use ruma::{
	api::client::message::send_message_event,
	events::{
		MessageLikeEventType, reaction::ReactionEventContent,
		room::redaction::RoomRedactionEventContent,
	},
};
use futures::StreamExt;
use serde_json::from_str;
use tuwunel_core::{
	Err, Event, Result, debug, err,
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

	// Forbid m.room.encrypted if encryption is disabled
	if MessageLikeEventType::RoomEncrypted == body.event_type && !services.config.allow_encryption
	{
		return Err!(Request(Forbidden("Encryption has been disabled")));
	}

	let state_lock = services.state.mutex.lock(&body.room_id).await;

	// Forbid duplicate reactions (must be inside state lock to prevent races)
	if body.event_type == MessageLikeEventType::Reaction {
		if let Ok(reaction_content) = body
			.body
			.body
			.deserialize_as_unchecked::<ReactionEventContent>()
		{
			debug!(
				%sender_user,
				target_event = %reaction_content.relates_to.event_id,
				key = %reaction_content.relates_to.key,
				"Checking for duplicate reaction"
			);

			if let Ok(reacted_to_pdu_id) = services
				.timeline
				.get_pdu_id(&reaction_content.relates_to.event_id)
				.await
			{
				let shortroomid = u64::from_be_bytes(reacted_to_pdu_id.shortroomid());
				let target_count = reacted_to_pdu_id.pdu_count();

				debug!(
					?shortroomid,
					?target_count,
					"Found target event, scanning relations"
				);

				let relations: Vec<_> = services
					.pdu_metadata
					.get_relations(shortroomid, target_count, None, ruma::api::Direction::Forward, None)
					.collect()
					.await;

				debug!(
					relation_count = relations.len(),
					"Relations found for target event"
				);

				let is_duplicate = relations.iter().any(|(_, pdu)| {
					let sender_matches = pdu.sender() == sender_user;
					let content_result = pdu.get_content::<ReactionEventContent>();
					let key_matches = content_result
						.as_ref()
						.map(|c| c.relates_to.key == reaction_content.relates_to.key)
						.unwrap_or(false);

					debug!(
						relation_sender = %pdu.sender(),
						?sender_matches,
						content_ok = content_result.is_ok(),
						?key_matches,
						"Checking relation"
					);

					sender_matches && key_matches
				});

				if is_duplicate {
					return Err!(Request(DuplicateAnnotation("Duplicate reactions are not allowed.")));
				}
			} else {
				debug!(
					target_event = %reaction_content.relates_to.event_id,
					"Target event not found, skipping duplicate check"
				);
			}
		}
	}

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
