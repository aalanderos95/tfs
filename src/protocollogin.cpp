// Copyright 2022 The Forgotten Server Authors. All rights reserved.
// Use of this source code is governed by the GPL-2.0 License that can be found in the LICENSE file.

#include "otpch.h"

#include "protocollogin.h"

#include "outputmessage.h"
#include "tasks.h"

#include "configmanager.h"
#include "iologindata.h"
#include "ban.h"
#include "game.h"

#include <fmt/format.h>

extern ConfigManager g_config;
extern Game g_game;

void ProtocolLogin::disconnectClient(const std::string& message, uint16_t version)
{
	auto output = OutputMessagePool::getOutputMessage();

	output->addByte(version >= 1076 ? 0x0B : 0x0A);
	output->addString(message);
	send(output);

	disconnect();
}

void ProtocolLogin::getCharacterList(const std::string& accountName, const std::string& password, const std::string& token, uint16_t version)
{
	Account account;
	if (!IOLoginData::loginserverAuthentication(accountName, password, account)) {
		disconnectClient("Account name or password is not correct.", version);
		return;
	}

	auto output = OutputMessagePool::getOutputMessage();
	if (!account.key.empty()) {
		int32_t ticks = static_cast<int32_t>(time(nullptr) / AUTHENTICATOR_PERIOD);
		if (token.empty() || !(token == generateToken(account.key, ticks) || token == generateToken(account.key, ticks - 1) || token == generateToken(account.key, ticks + 1))) {
			output->addByte(0x0D);
			output->addByte(0);
			send(output);
			disconnect();
			return;
		}
		output->addByte(0x0C);
		output->addByte(0);
	}

	//Update premium days
	addWorldInfo(output, accountName, password, version);
}

void ProtocolLogin::addWorldInfo(OutputMessage_ptr& output, const std::string& accountName, const std::string& password, uint16_t version, bool isLiveCastLogin /*=false*/)
{
	const std::string& motd = g_config.getString(ConfigManager::MOTD);
	if (!motd.empty()) {
		//Add MOTD
		output->addByte(0x14);

		std::ostringstream ss;
		ss << g_game.getMotdNum() << "\n" << motd;
		output->addString(ss.str());
	}

	//Add session key
	output->addByte(0x28);
	output->addString(accountName + "\n" + password);

	//Add char list
	output->addByte(0x64);

	output->addByte(1); // number of worlds

	output->addByte(0); // world id
	output->addString(g_config.getString(ConfigManager::SERVER_NAME));
	output->addString(g_config.getString(ConfigManager::IP));

	if (isLiveCastLogin) {
		output->add<uint16_t>(g_config.getNumber(ConfigManager::LIVE_CAST_PORT));
	} else {
		output->add<uint16_t>(g_config.getNumber(ConfigManager::GAME_PORT));
	}
	output->addByte(0);
}

void ProtocolLogin::getCastingStreamsList(const std::string& password, uint16_t version)
{
	//dispatcher thread
	auto output = OutputMessagePool::getOutputMessage();
	addWorldInfo(output, "", password, version, true);

	const auto& casts = ProtocolGame::getLiveCasts();
	output->addByte(casts.size());
	for (const auto& cast : casts) {
		output->addByte(0);
		output->addString(cast.first->getName());
	}
	output->add<uint16_t>(0x0); //The client expects the number of premium days left.
	send(std::move(output));

	disconnect();
}
void ProtocolLogin::onRecvFirstMessage(NetworkMessage& msg)
{
	if (g_game.getGameState() == GAME_STATE_SHUTDOWN) {
		disconnect();
		return;
	}

	msg.skipBytes(2); // client OS

	uint16_t version = msg.get<uint16_t>();
	if (version >= 971) {
		msg.skipBytes(17);
	} else {
		msg.skipBytes(12);
	}
	/*
	 * Skipped bytes:
	 * 4 bytes: protocolVersion
	 * 12 bytes: dat, spr, pic signatures (4 bytes each)
	 * 1 byte: 0
	 */

	if (version <= 760) {
		disconnectClient(fmt::format("Only clients with protocol {:s} allowed!", CLIENT_VERSION_STR), version);
		return;
	}

	if (!Protocol::RSA_decrypt(msg)) {
		disconnect();
		return;
	}

	xtea::key key;
	key[0] = msg.get<uint32_t>();
	key[1] = msg.get<uint32_t>();
	key[2] = msg.get<uint32_t>();
	key[3] = msg.get<uint32_t>();
	enableXTEAEncryption();
	setXTEAKey(std::move(key));

	if (version < CLIENT_VERSION_MIN || version > CLIENT_VERSION_MAX) {
		disconnectClient(fmt::format("Only clients with protocol {:s} allowed!", CLIENT_VERSION_STR), version);
		return;
	}

	if (g_game.getGameState() == GAME_STATE_STARTUP) {
		disconnectClient("Gameworld is starting up. Please wait.", version);
		return;
	}

	if (g_game.getGameState() == GAME_STATE_MAINTAIN) {
		disconnectClient("Gameworld is under maintenance.\nPlease re-connect in a while.", version);
		return;
	}

	BanInfo banInfo;
	auto connection = getConnection();
	if (!connection) {
		return;
	}

	if (IOBan::isIpBanned(connection->getIP(), banInfo)) {
		if (banInfo.reason.empty()) {
			banInfo.reason = "(none)";
		}

		disconnectClient(fmt::format("Your IP has been banned until {:s} by {:s}.\n\nReason specified:\n{:s}", formatDateShort(banInfo.expiresAt), banInfo.bannedBy, banInfo.reason), version);
		return;
	}

	std::string accountName = msg.getString();
	std::string password = msg.getString();
	auto thisPtr = std::static_pointer_cast<ProtocolLogin>(shared_from_this());
	if (accountName.empty()) {
		disconnectClient("Invalid account name.", version);
		if (g_config.getBoolean(ConfigManager::ENABLE_LIVE_CASTING)) {
			g_dispatcher.addTask(createTask(std::bind(&ProtocolLogin::getCastingStreamsList, thisPtr, password, version)));
		} else {
			disconnectClient("Invalid account name.", version);
		}
		return;
	}

	if (password.empty()) {
		disconnectClient("Invalid password.", version);
		return;
	}

	// read authenticator token and stay logged in flag from last 128 bytes
	msg.skipBytes((msg.getLength() - 128) - msg.getBufferPosition());
	if (!Protocol::RSA_decrypt(msg)) {
		disconnectClient("Invalid authentication token.", version);
		return;
	}

	std::string authToken = msg.getString();
	
	g_dispatcher.addTask(createTask(std::bind(&ProtocolLogin::getCharacterList, thisPtr, accountName, password, authToken, version)));
}
