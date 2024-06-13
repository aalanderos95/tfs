// Copyright 2022 The Forgotten Server Authors. All rights reserved.
// Use of this source code is governed by the GPL-2.0 License that can be found in the LICENSE file.

#include "otpch.h"

#include <boost/range/adaptor/reversed.hpp>

#include "protocolgame.h"

#include "outputmessage.h"

#include "player.h"

#include "configmanager.h"
#include "actions.h"
#include "game.h"
#include "iologindata.h"
#include "iomarket.h"
#include "ban.h"
#include "scheduler.h"
#include "databasetasks.h"



#include <fmt/format.h>

extern ConfigManager g_config;
extern Actions actions;
extern CreatureEvents* g_creatureEvents;
extern Chat* g_chat;
extern Game g_game;


namespace {

using WaitList = std::deque<std::pair<int64_t, uint32_t>>; // (timeout, player guid)

WaitList priorityWaitList, waitList;

std::tuple<WaitList&, WaitList::iterator, WaitList::size_type> findClient(const Player& player) {
	const auto fn = [&](const WaitList::value_type& it) { return it.second == player.getGUID(); };

	auto it = std::find_if(priorityWaitList.begin(), priorityWaitList.end(), fn);
	if (it != priorityWaitList.end()) {
		return std::make_tuple(std::ref(priorityWaitList), it, std::distance(it, priorityWaitList.end()) + 1);
	}

	it = std::find_if(waitList.begin(), waitList.end(), fn);
	if (it != waitList.end()) {
		return std::make_tuple(std::ref(waitList), it, priorityWaitList.size() + std::distance(it, waitList.end()) + 1);
	}

	return std::make_tuple(std::ref(waitList), waitList.end(), priorityWaitList.size() + waitList.size());
}

uint8_t getWaitTime(std::size_t slot)
{
	if (slot < 5) {
		return 5;
	} else if (slot < 10) {
		return 10;
	} else if (slot < 20) {
		return 20;
	} else if (slot < 50) {
		return 60;
	} else {
		return 120;
	}
}

int64_t getTimeout(std::size_t slot)
{
	// timeout is set to 15 seconds longer than expected retry attempt
	return getWaitTime(slot) + 15;
}

void cleanupList(WaitList& list)
{
	int64_t time = OTSYS_TIME();

	auto it = list.begin();
	while (it != list.end()) {
		if (it->first <= time) {
			it = list.erase(it);
		} else {
			++it;
		}
	}
}

std::size_t clientLogin(const Player& player)
{
	// Currentslot = position in wait list, 0 for direct access
	if (player.hasFlag(PlayerFlag_CanAlwaysLogin) || player.getAccountType() >= ACCOUNT_TYPE_GAMEMASTER) {
		return 0;
	}

	cleanupList(priorityWaitList);
	cleanupList(waitList);

	uint32_t maxPlayers = static_cast<uint32_t>(g_config.getNumber(ConfigManager::MAX_PLAYERS));
	if (maxPlayers == 0 || (priorityWaitList.empty() && waitList.empty() && g_game.getPlayersOnline() < maxPlayers)) {
		return 0;
	}

	auto result = findClient(player);
	if (std::get<1>(result) != std::get<0>(result).end()) {
		auto currentSlot = std::get<2>(result);
		// If server has capacity for this client, let him in even though his current slot might be higher than 0.
		if ((g_game.getPlayersOnline() + currentSlot) <= maxPlayers) {
			std::get<0>(result).erase(std::get<1>(result));
			return 0;
		}

		//let them wait a bit longer
		std::get<1>(result)->second = OTSYS_TIME() + (getTimeout(currentSlot) * 1000);
		return currentSlot;
	}

	auto currentSlot = priorityWaitList.size();
	if (player.isPremium()) {
		priorityWaitList.emplace_back(OTSYS_TIME() + (getTimeout(++currentSlot) * 1000), player.getGUID());
	} else {
		currentSlot += waitList.size();
		waitList.emplace_back(OTSYS_TIME() + (getTimeout(++currentSlot) * 1000), player.getGUID());
	}
	return currentSlot;
}

}

ProtocolGame::LiveCastsMap ProtocolGame::liveCasts;

void ProtocolGame::release()
{
	//dispatcher thread
	stopLiveCast();
	if (player && player->client == shared_from_this()) {
		player->client.reset();
		player->decrementReferenceCounter();
		player = nullptr;
	}

	OutputMessagePool::getInstance().removeProtocolFromAutosend(shared_from_this());
	Protocol::release();
}

void ProtocolGame::login(const std::string& name, uint32_t accountId, OperatingSystem_t operatingSystem)
{
	//dispatcher thread
	Player* foundPlayer = g_game.getPlayerByName(name);
	if (!foundPlayer || g_config.getBoolean(ConfigManager::ALLOW_CLONES)) {
		player = new Player(getThis());
		player->setName(name);

		player->incrementReferenceCounter();
		player->setID();

		if (!IOLoginData::preloadPlayer(player, name)) {
			disconnectClient("Your character could not be loaded.");
			return;
		}

		if (IOBan::isPlayerNamelocked(player->getGUID())) {
			disconnectClient("Your character has been namelocked.");
			return;
		}

		if (g_game.getGameState() == GAME_STATE_CLOSING && !player->hasFlag(PlayerFlag_CanAlwaysLogin)) {
			disconnectClient("The game is just going down.\nPlease try again later.");
			return;
		}

		if (g_game.getGameState() == GAME_STATE_CLOSED && !player->hasFlag(PlayerFlag_CanAlwaysLogin)) {
			disconnectClient("Server is currently closed.\nPlease try again later.");
			return;
		}

		if (g_config.getBoolean(ConfigManager::ONE_PLAYER_ON_ACCOUNT) && player->getAccountType() < ACCOUNT_TYPE_GAMEMASTER && g_game.getPlayerByAccount(player->getAccount())) {
			disconnectClient("You may only login with one character\nof your account at the same time.");
			return;
		}

		if (!player->hasFlag(PlayerFlag_CannotBeBanned)) {
			BanInfo banInfo;
			if (IOBan::isAccountBanned(accountId, banInfo)) {
				if (banInfo.reason.empty()) {
					banInfo.reason = "(none)";
				}

				if (banInfo.expiresAt > 0) {
					disconnectClient(fmt::format("Your account has been banned until {:s} by {:s}.\n\nReason specified:\n{:s}", formatDateShort(banInfo.expiresAt), banInfo.bannedBy, banInfo.reason));
				} else {
					disconnectClient(fmt::format("Your account has been permanently banned by {:s}.\n\nReason specified:\n{:s}", banInfo.bannedBy, banInfo.reason));
				}
				return;
			}
		}

		if (std::size_t currentSlot = clientLogin(*player)) {
			uint8_t retryTime = getWaitTime(currentSlot);
			auto output = OutputMessagePool::getOutputMessage();
			output->addByte(0x16);
			output->addString(fmt::format("Too many players online.\nYou are at place {:d} on the waiting list.", currentSlot));
			output->addByte(retryTime);
			send(output);
			disconnect();
			return;
		}

		if (!IOLoginData::loadPlayerById(player, player->getGUID())) {
			disconnectClient("Your character could not be loaded.");
			return;
		}

		player->setOperatingSystem(operatingSystem);

		if (!g_game.placeCreature(player, player->getLoginPosition())) {
			if (!g_game.placeCreature(player, player->getTemplePosition(), false, true)) {
				disconnectClient("Temple position is wrong. Contact the administrator.");
				return;
			}
		}

		if (operatingSystem >= CLIENTOS_OTCLIENT_LINUX) {
			player->registerCreatureEvent("ExtendedOpcode");
		}

		player->lastIP = player->getIP();
		player->lastLoginSaved = std::max<time_t>(time(nullptr), player->lastLoginSaved + 1);
		acceptPackets = true;
	} else {
		if (eventConnect != 0 || !g_config.getBoolean(ConfigManager::REPLACE_KICK_ON_LOGIN)) {
			//Already trying to connect
			disconnectClient("You are already logged in.");
			return;
		}

		if (foundPlayer->client) {
			foundPlayer->disconnect();
			foundPlayer->isConnecting = true;

			eventConnect = g_scheduler.addEvent(createSchedulerTask(1000, std::bind(&ProtocolGame::connect, getThis(), foundPlayer->getID(), operatingSystem)));
		} else {
			connect(foundPlayer->getID(), operatingSystem);
		}
	}
	OutputMessagePool::getInstance().addProtocolToAutosend(shared_from_this());
}

void ProtocolGame::connect(uint32_t playerId, OperatingSystem_t operatingSystem)
{
	eventConnect = 0;

	Player* foundPlayer = g_game.getPlayerByID(playerId);
	if (!foundPlayer || foundPlayer->client) {
		disconnectClient("You are already logged in.");
		return;
	}

	if (isConnectionExpired()) {
		//ProtocolGame::release() has been called at this point and the Connection object
		//no longer exists, so we return to prevent leakage of the Player.
		return;
	}

	player = foundPlayer;
	player->incrementReferenceCounter();

	g_chat->removeUserFromAllChannels(*player);
	player->clearModalWindows();
	player->setOperatingSystem(operatingSystem);
	player->isConnecting = false;

	player->client = getThis();
	sendAddCreature(player, player->getPosition(), 0, false);
	player->lastIP = player->getIP();
	player->lastLoginSaved = std::max<time_t>(time(nullptr), player->lastLoginSaved + 1);
	player->resetIdleTime();
	acceptPackets = true;
}

void ProtocolGame::logout(bool displayEffect, bool forced)
{
	//dispatcher thread
	if (!player) {
		return;
	}

	if (!player->isRemoved()) {
		if (!forced) {
			if (!player->isAccessPlayer()) {
				if (player->getTile()->hasFlag(TILESTATE_NOLOGOUT)) {
					player->sendCancelMessage(RETURNVALUE_YOUCANNOTLOGOUTHERE);
					return;
				}

				if (!player->getTile()->hasFlag(TILESTATE_PROTECTIONZONE) && player->hasCondition(CONDITION_INFIGHT)) {
					player->sendCancelMessage(RETURNVALUE_YOUMAYNOTLOGOUTDURINGAFIGHT);
					return;
				}
			}

			//scripting event - onLogout
			if (!g_creatureEvents->playerLogout(player)) {
				//Let the script handle the error message
				return;
			}
		}

		if (displayEffect && player->getHealth() > 0 && !player->isInGhostMode()) {
			g_game.addMagicEffect(player->getPosition(), CONST_ME_POFF);
		}
	}
	
	stopLiveCast();
	disconnect();

	g_game.removeCreature(player);
}

bool ProtocolGame::startLiveCast(const std::string& password /*= ""*/)
{
	auto connection = getConnection();
	if (!g_config.getBoolean(ConfigManager::ENABLE_LIVE_CASTING) || isLiveCaster() || !player || player->isRemoved() || !connection || liveCasts.size() >= getMaxLiveCastCount()) {
		return false;
	}

	{
		std::lock_guard<decltype(liveCastLock)> lock {liveCastLock};
		//DO NOT do any send operations here
		liveCastName = player->getName();
		liveCastPassword = password;
		isCaster.store(true, std::memory_order_relaxed);
	}

	liveCasts.insert(std::make_pair(player, getThis()));

	registerLiveCast();
	//Send a "dummy" channel
	sendChannel(CHANNEL_CAST, LIVE_CAST_CHAT_NAME, nullptr, nullptr);
	return true;
}

bool ProtocolGame::stopLiveCast()
{
	//dispatcher
	if (!isLiveCaster()) {
		return false;
	}

	CastSpectatorVec spectators;

	{
		std::lock_guard<decltype(liveCastLock)> lock {liveCastLock};
		//DO NOT do any send operations here
		std::swap(this->spectators, spectators);
		isCaster.store(false, std::memory_order_relaxed);
	}

	liveCasts.erase(player);
	for (auto& spectator : spectators) {
		spectator->onLiveCastStop();
	}
	unregisterLiveCast();

	return true;
}

void ProtocolGame::clearLiveCastInfo()
{
	static std::once_flag flag;
	std::call_once(flag, []() {
			assert(g_game.getGameState() == GAME_STATE_INIT);
			std::ostringstream query;
			query << "TRUNCATE TABLE `live_casts`;";
			g_databaseTasks.addTask(query.str());
		});
}

void ProtocolGame::registerLiveCast()
{
	std::ostringstream query;
	query << "INSERT into `live_casts` (`player_id`, `cast_name`, `password`) VALUES (" << player->getGUID() << ", '"
		<< getLiveCastName() << "', " << isPasswordProtected() << ");";
	g_databaseTasks.addTask(query.str());
}

void ProtocolGame::unregisterLiveCast()
{
	std::ostringstream query;
	query << "DELETE FROM `live_casts` WHERE `player_id`=" << player->getGUID() << ";";
	g_databaseTasks.addTask(query.str());
}

void ProtocolGame::updateLiveCastInfo()
{
	std::ostringstream query;
	query << "UPDATE `live_casts` SET `cast_name`='" << getLiveCastName() << "', `password`="
		<< isPasswordProtected() << ", `spectators`=" << getSpectatorCount()
		<< " WHERE `player_id`=" << player->getGUID() << ";";
	g_databaseTasks.addTask(query.str());
}

void ProtocolGame::addSpectator(ProtocolSpectator_ptr spectatorClient)
{
	std::lock_guard<decltype(liveCastLock)> lock(liveCastLock);
	//DO NOT do any send operations here
	spectators.emplace_back(spectatorClient);
	updateLiveCastInfo();
}

void ProtocolGame::removeSpectator(ProtocolSpectator_ptr spectatorClient)
{
	std::lock_guard<decltype(liveCastLock)> lock(liveCastLock);
	//DO NOT do any send operations here
	auto it = std::find(spectators.begin(), spectators.end(), spectatorClient);
	if (it != spectators.end()) {
		spectators.erase(it);
		updateLiveCastInfo();
	}
}


void ProtocolGame::onRecvFirstMessage(NetworkMessage& msg)
{
	if (g_game.getGameState() == GAME_STATE_SHUTDOWN) {
		disconnect();
		return;
	}

	OperatingSystem_t operatingSystem = static_cast<OperatingSystem_t>(msg.get<uint16_t>());
	version = msg.get<uint16_t>();

	msg.skipBytes(7); // U32 client version, U8 client type, U16 dat revision

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

	if (operatingSystem >= CLIENTOS_OTCLIENT_LINUX) {
		NetworkMessage opcodeMessage;
		opcodeMessage.addByte(0x32);
		opcodeMessage.addByte(0x00);
		opcodeMessage.add<uint16_t>(0x00);
		writeToOutputBuffer(opcodeMessage);
	}

	msg.skipBytes(1); // gamemaster flag

	std::string sessionKey = msg.getString();

	auto sessionArgs = explodeString(sessionKey, "\n", 4);
	if (sessionArgs.size() != 4) {
		disconnect();
		return;
	}

	std::string& accountName = sessionArgs[0];
	std::string& password = sessionArgs[1];
	std::string& token = sessionArgs[2];
	uint32_t tokenTime = 0;
	try {
		tokenTime = std::stoul(sessionArgs[3]);
	} catch (const std::invalid_argument&) {
		disconnectClient("Malformed token packet.");
		return;
	} catch (const std::out_of_range&) {
		disconnectClient("Token time is too long.");
		return;
	}

	if (accountName.empty()) {
		disconnectClient("You must enter your account name.");
		return;
	}

	std::string characterName = msg.getString();

	uint32_t timeStamp = msg.get<uint32_t>();
	uint8_t randNumber = msg.getByte();
	if (challengeTimestamp != timeStamp || challengeRandom != randNumber) {
		disconnect();
		return;
	}

	if (version < CLIENT_VERSION_MIN || version > CLIENT_VERSION_MAX) {
		disconnectClient(fmt::format("Only clients with protocol {:s} allowed!", CLIENT_VERSION_STR));
		return;
	}

	if (g_game.getGameState() == GAME_STATE_STARTUP) {
		disconnectClient("Gameworld is starting up. Please wait.");
		return;
	}

	if (g_game.getGameState() == GAME_STATE_MAINTAIN) {
		disconnectClient("Gameworld is under maintenance. Please re-connect in a while.");
		return;
	}

	BanInfo banInfo;
	if (IOBan::isIpBanned(getIP(), banInfo)) {
		if (banInfo.reason.empty()) {
			banInfo.reason = "(none)";
		}

		disconnectClient(fmt::format("Your IP has been banned until {:s} by {:s}.\n\nReason specified:\n{:s}", formatDateShort(banInfo.expiresAt), banInfo.bannedBy, banInfo.reason));
		return;
	}

	uint32_t accountId = IOLoginData::gameworldAuthentication(accountName, password, characterName, token, tokenTime);
	if (accountId == 0) {
		disconnectClient("Account name or password is not correct.");
		return;
	}

	g_dispatcher.addTask(createTask(std::bind(&ProtocolGame::login, getThis(), characterName, accountId, operatingSystem)));
}

void ProtocolGame::disconnectClient(const std::string& message) const
{
	auto output = OutputMessagePool::getOutputMessage();
	output->addByte(0x14);
	output->addString(message);
	send(output);
	disconnect();
}

void ProtocolGame::writeToOutputBuffer(const NetworkMessage& msg, bool broadcast /*= true*/)
{
	auto out = getOutputBuffer(msg.getLength());
	out->append(msg);
	if (!broadcast && isLiveCaster()) {
		//We're casting and we need to send a packet that's not supposed to be broadcast so we need a new messasge.
		//This shouldn't impact performance by a huge amount as most packets can be broadcast.
		auto out = OutputMessagePool::getOutputMessage();
		out->append(msg);
		send(std::move(out));
	} else {
		auto out = getOutputBuffer(msg.getLength());
		if (isLiveCaster()) {
			out->setBroadcastMsg(true);
		}
		out->append(msg);
	}
}

void ProtocolGame::parsePacket(NetworkMessage& msg)
{
	if (!acceptPackets || g_game.getGameState() == GAME_STATE_SHUTDOWN || msg.getLength() == 0) {
		return;
	}

	uint8_t recvbyte = msg.getByte();

	if (!player) {
		if (recvbyte == 0x0F) {
			disconnect();
		}

		return;
	}

	//a dead player can not performs actions
	if (!player || player->isRemoved() || player->getHealth() <= 0) {
		auto this_ptr = getThis();
		g_dispatcher.addTask(createTask([this_ptr]() {
			this_ptr->stopLiveCast();
		}));
		if (recvbyte == 0x0F) {
			disconnect();
			return;
		}

		if (recvbyte != 0x14) {
			return;
		}
	}

	switch (recvbyte) {
		case 0x14: g_dispatcher.addTask(createTask(std::bind(&ProtocolGame::logout, getThis(), true, false))); break;
		case 0x1D: addGameTask(&Game::playerReceivePingBack, player->getID()); break;
		case 0x1E: addGameTask(&Game::playerReceivePing, player->getID()); break;
		case 0x32: parseExtendedOpcode(msg); break; //otclient extended opcode
		case 0x64: parseAutoWalk(msg); break;
		case 0x65: addGameTask(&Game::playerMove, player->getID(), DIRECTION_NORTH); break;
		case 0x66: addGameTask(&Game::playerMove, player->getID(), DIRECTION_EAST); break;
		case 0x67: addGameTask(&Game::playerMove, player->getID(), DIRECTION_SOUTH); break;
		case 0x68: addGameTask(&Game::playerMove, player->getID(), DIRECTION_WEST); break;
		case 0x69: addGameTask(&Game::playerStopAutoWalk, player->getID()); break;
		case 0x6A: addGameTask(&Game::playerMove, player->getID(), DIRECTION_NORTHEAST); break;
		case 0x6B: addGameTask(&Game::playerMove, player->getID(), DIRECTION_SOUTHEAST); break;
		case 0x6C: addGameTask(&Game::playerMove, player->getID(), DIRECTION_SOUTHWEST); break;
		case 0x6D: addGameTask(&Game::playerMove, player->getID(), DIRECTION_NORTHWEST); break;
		case 0x6F: addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerTurn, player->getID(), DIRECTION_NORTH); break;
		case 0x70: addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerTurn, player->getID(), DIRECTION_EAST); break;
		case 0x71: addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerTurn, player->getID(), DIRECTION_SOUTH); break;
		case 0x72: addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerTurn, player->getID(), DIRECTION_WEST); break;
		case 0x77: parseEquipObject(msg); break;
		case 0x78: parseThrow(msg); break;
		case 0x79: parseLookInShop(msg); break;
		case 0x7A: parsePlayerPurchase(msg); break;
		case 0x7B: parsePlayerSale(msg); break;
		case 0x7C: addGameTask(&Game::playerCloseShop, player->getID()); break;
		case 0x7D: parseRequestTrade(msg); break;
		case 0x7E: parseLookInTrade(msg); break;
		case 0x7F: addGameTask(&Game::playerAcceptTrade, player->getID()); break;
		case 0x80: addGameTask(&Game::playerCloseTrade, player->getID()); break;
		case 0x82: parseUseItem(msg); break;
		case 0x83: parseUseItemEx(msg); break;
		case 0x84: parseUseWithCreature(msg); break;
		case 0x85: parseRotateItem(msg); break;
		case 0x87: parseCloseContainer(msg); break;
		case 0x88: parseUpArrowContainer(msg); break;
		case 0x89: parseTextWindow(msg); break;
		case 0x8A: parseHouseWindow(msg); break;
		case 0x8B: parseWrapItem(msg); break;
		case 0x8C: parseLookAt(msg); break;
		case 0x8D: parseLookInBattleList(msg); break;
		case 0x8E: /* join aggression */ break;
		case 0x96: parseSay(msg); break;
		case 0x97: addGameTask(&Game::playerRequestChannels, player->getID()); break;
		case 0x98: parseOpenChannel(msg); break;
		case 0x99: parseCloseChannel(msg); break;
		case 0x9A: parseOpenPrivateChannel(msg); break;
		case 0x9E: addGameTask(&Game::playerCloseNpcChannel, player->getID()); break;
		case 0xA0: parseFightModes(msg); break;
		case 0xA1: parseAttack(msg); break;
		case 0xA2: parseFollow(msg); break;
		case 0xA3: parseInviteToParty(msg); break;
		case 0xA4: parseJoinParty(msg); break;
		case 0xA5: parseRevokePartyInvite(msg); break;
		case 0xA6: parsePassPartyLeadership(msg); break;
		case 0xA7: addGameTask(&Game::playerLeaveParty, player->getID()); break;
		case 0xA8: parseEnableSharedPartyExperience(msg); break;
		case 0xAA: addGameTask(&Game::playerCreatePrivateChannel, player->getID()); break;
		case 0xAB: parseChannelInvite(msg); break;
		case 0xAC: parseChannelExclude(msg); break;
		case 0xBE: addGameTask(&Game::playerCancelAttackAndFollow, player->getID()); break;
		case 0xC9: /* update tile */ break;
		case 0xCA: parseUpdateContainer(msg); break;
		case 0xCB: parseBrowseField(msg); break;
		case 0xCC: parseSeekInContainer(msg); break;
		case 0xD2: addGameTask(&Game::playerRequestOutfit, player->getID()); break;
		case 0xD3: parseSetOutfit(msg); break;
		case 0xD4: parseToggleMount(msg); break;
		case 0xDC: parseAddVip(msg); break;
		case 0xDD: parseRemoveVip(msg); break;
		case 0xDE: parseEditVip(msg); break;
		case 0xE6: parseBugReport(msg); break;
		case 0xE7: /* thank you */ break;
		case 0xE8: parseDebugAssert(msg); break;
		case 0xF0: addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerShowQuestLog, player->getID()); break;
		case 0xF1: parseQuestLine(msg); break;
		case 0xF2: parseRuleViolationReport(msg); break;
		case 0xF3: /* get object info */ break;
		case 0xF4: parseMarketLeave(); break;
		case 0xF5: parseMarketBrowse(msg); break;
		case 0xF6: parseMarketCreateOffer(msg); break;
		case 0xF7: parseMarketCancelOffer(msg); break;
		case 0xF8: parseMarketAcceptOffer(msg); break;
		case 0xF9: parseModalWindowAnswer(msg); break;

		default:
			// std::cout << "Player: " << player->getName() << " sent an unknown packet header: 0x" << std::hex << static_cast<uint16_t>(recvbyte) << std::dec << "!" << std::endl;
			break;
	}

	if (msg.isOverrun()) {
		disconnect();
	}
}

// Parse methods
void ProtocolGame::parseChannelInvite(NetworkMessage& msg)
{
	const std::string name = msg.getString();
	addGameTask(&Game::playerChannelInvite, player->getID(), name);
}

void ProtocolGame::parseChannelExclude(NetworkMessage& msg)
{
	const std::string name = msg.getString();
	addGameTask(&Game::playerChannelExclude, player->getID(), name);
}

void ProtocolGame::parseOpenChannel(NetworkMessage& msg)
{
	uint16_t channelId = msg.get<uint16_t>();
	addGameTask(&Game::playerOpenChannel, player->getID(), channelId);
}

void ProtocolGame::parseCloseChannel(NetworkMessage& msg)
{
	uint16_t channelId = msg.get<uint16_t>();
	addGameTask(&Game::playerCloseChannel, player->getID(), channelId);
}

void ProtocolGame::parseOpenPrivateChannel(NetworkMessage& msg)
{
	const std::string receiver = msg.getString();
	addGameTask(&Game::playerOpenPrivateChannel, player->getID(), receiver);
}

void ProtocolGame::parseAutoWalk(NetworkMessage& msg)
{
	uint8_t numdirs = msg.getByte();
	if (numdirs == 0 || (msg.getBufferPosition() + numdirs) != (msg.getLength() + 8)) {
		return;
	}

	msg.skipBytes(numdirs);

	std::vector<Direction> path;
	path.reserve(numdirs);

	for (uint8_t i = 0; i < numdirs; ++i) {
		uint8_t rawdir = msg.getPreviousByte();
		switch (rawdir) {
			case 1: path.push_back(DIRECTION_EAST); break;
			case 2: path.push_back(DIRECTION_NORTHEAST); break;
			case 3: path.push_back(DIRECTION_NORTH); break;
			case 4: path.push_back(DIRECTION_NORTHWEST); break;
			case 5: path.push_back(DIRECTION_WEST); break;
			case 6: path.push_back(DIRECTION_SOUTHWEST); break;
			case 7: path.push_back(DIRECTION_SOUTH); break;
			case 8: path.push_back(DIRECTION_SOUTHEAST); break;
			default: break;
		}
	}

	if (path.empty()) {
		return;
	}

	addGameTask(&Game::playerAutoWalk, player->getID(), std::move(path));
}

void ProtocolGame::parseSetOutfit(NetworkMessage& msg)
{
	Outfit_t newOutfit;
	newOutfit.lookType = msg.get<uint16_t>();
	newOutfit.lookHead = msg.getByte();
	newOutfit.lookBody = msg.getByte();
	newOutfit.lookLegs = msg.getByte();
	newOutfit.lookFeet = msg.getByte();
	newOutfit.lookAddons = msg.getByte();
	newOutfit.lookMount = msg.get<uint16_t>();
	addGameTask(&Game::playerChangeOutfit, player->getID(), newOutfit);
}

void ProtocolGame::parseToggleMount(NetworkMessage& msg)
{
	bool mount = msg.getByte() != 0;
	addGameTask(&Game::playerToggleMount, player->getID(), mount);
}

void ProtocolGame::parseUseItem(NetworkMessage& msg)
{
	Position pos = msg.getPosition();
	uint16_t spriteId = msg.get<uint16_t>();
	uint8_t stackpos = msg.getByte();
	uint8_t index = msg.getByte();
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerUseItem, player->getID(), pos, stackpos, index, spriteId);
}

void ProtocolGame::parseUseItemEx(NetworkMessage& msg)
{
	Position fromPos = msg.getPosition();
	uint16_t fromSpriteId = msg.get<uint16_t>();
	uint8_t fromStackPos = msg.getByte();
	Position toPos = msg.getPosition();
	uint16_t toSpriteId = msg.get<uint16_t>();
	uint8_t toStackPos = msg.getByte();
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerUseItemEx, player->getID(), fromPos, fromStackPos, fromSpriteId, toPos, toStackPos, toSpriteId);
}

void ProtocolGame::parseUseWithCreature(NetworkMessage& msg)
{
	Position fromPos = msg.getPosition();
	uint16_t spriteId = msg.get<uint16_t>();
	uint8_t fromStackPos = msg.getByte();
	uint32_t creatureId = msg.get<uint32_t>();
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerUseWithCreature, player->getID(), fromPos, fromStackPos, creatureId, spriteId);
}

void ProtocolGame::parseCloseContainer(NetworkMessage& msg)
{
	uint8_t cid = msg.getByte();
	addGameTask(&Game::playerCloseContainer, player->getID(), cid);
}

void ProtocolGame::parseUpArrowContainer(NetworkMessage& msg)
{
	uint8_t cid = msg.getByte();
	addGameTask(&Game::playerMoveUpContainer, player->getID(), cid);
}

void ProtocolGame::parseUpdateContainer(NetworkMessage& msg)
{
	uint8_t cid = msg.getByte();
	addGameTask(&Game::playerUpdateContainer, player->getID(), cid);
}

void ProtocolGame::parseThrow(NetworkMessage& msg)
{
	Position fromPos = msg.getPosition();
	uint16_t spriteId = msg.get<uint16_t>();
	uint8_t fromStackpos = msg.getByte();
	Position toPos = msg.getPosition();
	uint8_t count = msg.getByte();

	if (toPos != fromPos) {
		addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerMoveThing, player->getID(), fromPos, spriteId, fromStackpos, toPos, count);
	}
}

void ProtocolGame::parseLookAt(NetworkMessage& msg)
{
	Position pos = msg.getPosition();
	msg.skipBytes(2); // spriteId
	uint8_t stackpos = msg.getByte();
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerLookAt, player->getID(), pos, stackpos);
}

void ProtocolGame::parseLookInBattleList(NetworkMessage& msg)
{
	uint32_t creatureId = msg.get<uint32_t>();
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerLookInBattleList, player->getID(), creatureId);
}

void ProtocolGame::parseSay(NetworkMessage& msg)
{
	std::string receiver;
	uint16_t channelId;

	SpeakClasses type = static_cast<SpeakClasses>(msg.getByte());
	switch (type) {
		case TALKTYPE_PRIVATE_TO:
		case TALKTYPE_PRIVATE_RED_TO:
			receiver = msg.getString();
			channelId = 0;
			break;

		case TALKTYPE_CHANNEL_Y:
		case TALKTYPE_CHANNEL_R1:
			channelId = msg.get<uint16_t>();
			break;

		default:
			channelId = 0;
			break;
	}

	const std::string text = msg.getString();
	if (text.length() > 255) {
		return;
	}

	addGameTask(&Game::playerSay, player->getID(), channelId, type, receiver, text);
}

void ProtocolGame::parseFightModes(NetworkMessage& msg)
{
	uint8_t rawFightMode = msg.getByte(); // 1 - offensive, 2 - balanced, 3 - defensive
	uint8_t rawChaseMode = msg.getByte(); // 0 - stand while fighting, 1 - chase opponent
	uint8_t rawSecureMode = msg.getByte(); // 0 - can't attack unmarked, 1 - can attack unmarked
	// uint8_t rawPvpMode = msg.getByte(); // pvp mode introduced in 10.0

	fightMode_t fightMode;
	if (rawFightMode == 1) {
		fightMode = FIGHTMODE_ATTACK;
	} else if (rawFightMode == 2) {
		fightMode = FIGHTMODE_BALANCED;
	} else {
		fightMode = FIGHTMODE_DEFENSE;
	}

	addGameTask(&Game::playerSetFightModes, player->getID(), fightMode, rawChaseMode != 0, rawSecureMode != 0);
}

void ProtocolGame::parseAttack(NetworkMessage& msg)
{
	uint32_t creatureId = msg.get<uint32_t>();
	// msg.get<uint32_t>(); creatureId (same as above)
	addGameTask(&Game::playerSetAttackedCreature, player->getID(), creatureId);
}

void ProtocolGame::parseFollow(NetworkMessage& msg)
{
	uint32_t creatureId = msg.get<uint32_t>();
	// msg.get<uint32_t>(); creatureId (same as above)
	addGameTask(&Game::playerFollowCreature, player->getID(), creatureId);
}

void ProtocolGame::parseEquipObject(NetworkMessage& msg)
{
	uint16_t spriteId = msg.get<uint16_t>();
	// msg.get<uint8_t>();

	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerEquipItem, player->getID(), spriteId);
}

void ProtocolGame::parseTextWindow(NetworkMessage& msg)
{
	uint32_t windowTextId = msg.get<uint32_t>();
	const std::string newText = msg.getString();
	addGameTask(&Game::playerWriteItem, player->getID(), windowTextId, newText);
}

void ProtocolGame::parseHouseWindow(NetworkMessage& msg)
{
	uint8_t doorId = msg.getByte();
	uint32_t id = msg.get<uint32_t>();
	const std::string text = msg.getString();
	addGameTask(&Game::playerUpdateHouseWindow, player->getID(), doorId, id, text);
}

void ProtocolGame::parseWrapItem(NetworkMessage& msg)
{
	Position pos = msg.getPosition();
	uint16_t spriteId = msg.get<uint16_t>();
	uint8_t stackpos = msg.getByte();
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerWrapItem, player->getID(), pos, stackpos, spriteId);
}

void ProtocolGame::parseLookInShop(NetworkMessage& msg)
{
	uint16_t id = msg.get<uint16_t>();
	uint8_t count = msg.getByte();
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerLookInShop, player->getID(), id, count);
}

void ProtocolGame::parsePlayerPurchase(NetworkMessage& msg)
{
	uint16_t id = msg.get<uint16_t>();
	uint8_t count = msg.getByte();
	uint8_t amount = msg.getByte();
	bool ignoreCap = msg.getByte() != 0;
	bool inBackpacks = msg.getByte() != 0;
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerPurchaseItem, player->getID(), id, count, amount, ignoreCap, inBackpacks);
}

void ProtocolGame::parsePlayerSale(NetworkMessage& msg)
{
	uint16_t id = msg.get<uint16_t>();
	uint8_t count = msg.getByte();
	uint8_t amount = msg.getByte();
	bool ignoreEquipped = msg.getByte() != 0;
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerSellItem, player->getID(), id, count, amount, ignoreEquipped);
}

void ProtocolGame::parseRequestTrade(NetworkMessage& msg)
{
	Position pos = msg.getPosition();
	uint16_t spriteId = msg.get<uint16_t>();
	uint8_t stackpos = msg.getByte();
	uint32_t playerId = msg.get<uint32_t>();
	addGameTask(&Game::playerRequestTrade, player->getID(), pos, stackpos, playerId, spriteId);
}

void ProtocolGame::parseLookInTrade(NetworkMessage& msg)
{
	bool counterOffer = (msg.getByte() == 0x01);
	uint8_t index = msg.getByte();
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerLookInTrade, player->getID(), counterOffer, index);
}

void ProtocolGame::parseAddVip(NetworkMessage& msg)
{
	const std::string name = msg.getString();
	addGameTask(&Game::playerRequestAddVip, player->getID(), name);
}

void ProtocolGame::parseRemoveVip(NetworkMessage& msg)
{
	uint32_t guid = msg.get<uint32_t>();
	addGameTask(&Game::playerRequestRemoveVip, player->getID(), guid);
}

void ProtocolGame::parseEditVip(NetworkMessage& msg)
{
	uint32_t guid = msg.get<uint32_t>();
	const std::string description = msg.getString();
	uint32_t icon = std::min<uint32_t>(10, msg.get<uint32_t>()); // 10 is max icon in 9.63
	bool notify = msg.getByte() != 0;
	addGameTask(&Game::playerRequestEditVip, player->getID(), guid, description, icon, notify);
}

void ProtocolGame::parseRotateItem(NetworkMessage& msg)
{
	Position pos = msg.getPosition();
	uint16_t spriteId = msg.get<uint16_t>();
	uint8_t stackpos = msg.getByte();
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerRotateItem, player->getID(), pos, stackpos, spriteId);
}

void ProtocolGame::parseRuleViolationReport(NetworkMessage& msg)
{
	uint8_t reportType = msg.getByte();
	uint8_t reportReason = msg.getByte();
	const std::string& targetName = msg.getString();
	const std::string& comment = msg.getString();
	std::string translation;
	if (reportType == REPORT_TYPE_NAME) {
		translation = msg.getString();
	} else if (reportType == REPORT_TYPE_STATEMENT) {
		translation = msg.getString();
		msg.get<uint32_t>(); // statement id, used to get whatever player have said, we don't log that.
	}

	addGameTask(&Game::playerReportRuleViolation, player->getID(), targetName, reportType, reportReason, comment, translation);
}

void ProtocolGame::parseBugReport(NetworkMessage& msg)
{
	uint8_t category = msg.getByte();
	std::string message = msg.getString();

	Position position;
	if (category == BUG_CATEGORY_MAP) {
		position = msg.getPosition();
	}

	addGameTask(&Game::playerReportBug, player->getID(), message, position, category);
}

void ProtocolGame::parseDebugAssert(NetworkMessage& msg)
{
	if (debugAssertSent) {
		return;
	}

	debugAssertSent = true;

	std::string assertLine = msg.getString();
	std::string date = msg.getString();
	std::string description = msg.getString();
	std::string comment = msg.getString();
	addGameTask(&Game::playerDebugAssert, player->getID(), assertLine, date, description, comment);
}

void ProtocolGame::parseInviteToParty(NetworkMessage& msg)
{
	uint32_t targetId = msg.get<uint32_t>();
	addGameTask(&Game::playerInviteToParty, player->getID(), targetId);
}

void ProtocolGame::parseJoinParty(NetworkMessage& msg)
{
	uint32_t targetId = msg.get<uint32_t>();
	addGameTask(&Game::playerJoinParty, player->getID(), targetId);
}

void ProtocolGame::parseRevokePartyInvite(NetworkMessage& msg)
{
	uint32_t targetId = msg.get<uint32_t>();
	addGameTask(&Game::playerRevokePartyInvitation, player->getID(), targetId);
}

void ProtocolGame::parsePassPartyLeadership(NetworkMessage& msg)
{
	uint32_t targetId = msg.get<uint32_t>();
	addGameTask(&Game::playerPassPartyLeadership, player->getID(), targetId);
}

void ProtocolGame::parseEnableSharedPartyExperience(NetworkMessage& msg)
{
	bool sharedExpActive = msg.getByte() == 1;
	addGameTask(&Game::playerEnableSharedPartyExperience, player->getID(), sharedExpActive);
}

void ProtocolGame::parseQuestLine(NetworkMessage& msg)
{
	uint16_t questId = msg.get<uint16_t>();
	addGameTask(&Game::playerShowQuestLine, player->getID(), questId);
}

void ProtocolGame::parseMarketLeave()
{
	addGameTask(&Game::playerLeaveMarket, player->getID());
}

void ProtocolGame::parseMarketBrowse(NetworkMessage& msg)
{
	uint16_t browseId = msg.get<uint16_t>();

	if (browseId == MARKETREQUEST_OWN_OFFERS) {
		addGameTask(&Game::playerBrowseMarketOwnOffers, player->getID());
	} else if (browseId == MARKETREQUEST_OWN_HISTORY) {
		addGameTask(&Game::playerBrowseMarketOwnHistory, player->getID());
	} else {
		addGameTask(&Game::playerBrowseMarket, player->getID(), browseId);
	}
}

void ProtocolGame::parseMarketCreateOffer(NetworkMessage& msg)
{
	uint8_t type = msg.getByte();
	uint16_t spriteId = msg.get<uint16_t>();
	uint16_t amount = msg.get<uint16_t>();
	uint32_t price = msg.get<uint32_t>();
	bool anonymous = (msg.getByte() != 0);
	addGameTask(&Game::playerCreateMarketOffer, player->getID(), type, spriteId, amount, price, anonymous);
}

void ProtocolGame::parseMarketCancelOffer(NetworkMessage& msg)
{
	uint32_t timestamp = msg.get<uint32_t>();
	uint16_t counter = msg.get<uint16_t>();
	addGameTask(&Game::playerCancelMarketOffer, player->getID(), timestamp, counter);
}

void ProtocolGame::parseMarketAcceptOffer(NetworkMessage& msg)
{
	uint32_t timestamp = msg.get<uint32_t>();
	uint16_t counter = msg.get<uint16_t>();
	uint16_t amount = msg.get<uint16_t>();
	addGameTask(&Game::playerAcceptMarketOffer, player->getID(), timestamp, counter, amount);
}

void ProtocolGame::parseModalWindowAnswer(NetworkMessage& msg)
{
	uint32_t id = msg.get<uint32_t>();
	uint8_t button = msg.getByte();
	uint8_t choice = msg.getByte();
	addGameTask(&Game::playerAnswerModalWindow, player->getID(), id, button, choice);
}

void ProtocolGame::parseBrowseField(NetworkMessage& msg)
{
	const Position& pos = msg.getPosition();
	addGameTask(&Game::playerBrowseField, player->getID(), pos);
}

void ProtocolGame::parseSeekInContainer(NetworkMessage& msg)
{
	uint8_t containerId = msg.getByte();
	uint16_t index = msg.get<uint16_t>();
	addGameTask(&Game::playerSeekInContainer, player->getID(), containerId, index);
}

// Send methods
void ProtocolGame::sendOpenPrivateChannel(const std::string& receiver)
{
	NetworkMessage msg;
	msg.addByte(0xAD);
	msg.addString(receiver);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendChannelEvent(uint16_t channelId, const std::string& playerName, ChannelEvent_t channelEvent)
{
	NetworkMessage msg;
	msg.addByte(0xF3);
	msg.add<uint16_t>(channelId);
	msg.addString(playerName);
	msg.addByte(channelEvent);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendCreatureOutfit(const Creature* creature, const Outfit_t& outfit)
{
	if (!canSee(creature)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x8E);
	msg.add<uint32_t>(creature->getID());
	AddOutfit(msg, outfit);
	writeToOutputBuffer(msg);
}


void ProtocolGame::sendCreatureWalkthrough(const Creature* creature, bool walkthrough)
{
	if (!canSee(creature)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x92);
	msg.add<uint32_t>(creature->getID());
	msg.addByte(walkthrough ? 0x00 : 0x01);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendCreatureShield(const Creature* creature)
{
	if (!canSee(creature)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x91);
	msg.add<uint32_t>(creature->getID());
	msg.addByte(player->getPartyShield(creature->getPlayer()));
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendCreatureSkull(const Creature* creature)
{
	if (g_game.getWorldType() != WORLD_TYPE_PVP) {
		return;
	}

	if (!canSee(creature)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x90);
	msg.add<uint32_t>(creature->getID());
	msg.addByte(player->getSkullClient(creature));
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendCreatureType(uint32_t creatureId, uint8_t creatureType)
{
	NetworkMessage msg;
	msg.addByte(0x95);
	msg.add<uint32_t>(creatureId);
	msg.addByte(creatureType);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendCreatureHelpers(uint32_t creatureId, uint16_t helpers)
{
	NetworkMessage msg;
	msg.addByte(0x94);
	msg.add<uint32_t>(creatureId);
	msg.add<uint16_t>(helpers);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendCreatureSquare(const Creature* creature, SquareColor_t color)
{
	if (!canSee(creature)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x93);
	msg.add<uint32_t>(creature->getID());
	msg.addByte(0x01);
	msg.addByte(color);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendTutorial(uint8_t tutorialId)
{
	NetworkMessage msg;
	msg.addByte(0xDC);
	msg.addByte(tutorialId);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendAddMarker(const Position& pos, uint8_t markType, const std::string& desc)
{
	NetworkMessage msg;
	msg.addByte(0xDD);
	msg.addPosition(pos);
	msg.addByte(markType);
	msg.addString(desc);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendReLoginWindow(uint8_t unfairFightReduction)
{
	NetworkMessage msg;
	msg.addByte(0x28);
	msg.addByte(0x00);
	msg.addByte(unfairFightReduction);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendTextMessage(const TextMessage& message)
{
	NetworkMessage msg;
	msg.addByte(0xB4);
	msg.addByte(message.type);
	switch (message.type) {
		case MESSAGE_DAMAGE_DEALT:
		case MESSAGE_DAMAGE_RECEIVED:
		case MESSAGE_DAMAGE_OTHERS: {
			msg.addPosition(message.position);
			msg.add<uint32_t>(message.primary.value);
			msg.addByte(message.primary.color);
			msg.add<uint32_t>(message.secondary.value);
			msg.addByte(message.secondary.color);
			break;
		}
		case MESSAGE_HEALED:
		case MESSAGE_HEALED_OTHERS:
		case MESSAGE_EXPERIENCE:
		case MESSAGE_EXPERIENCE_OTHERS: {
			msg.addPosition(message.position);
			msg.add<uint32_t>(message.primary.value);
			msg.addByte(message.primary.color);
			break;
		}
		case MESSAGE_GUILD:
		case MESSAGE_PARTY_MANAGEMENT:
		case MESSAGE_PARTY:
			msg.add<uint16_t>(message.channelId);
			break;
		default: {
			break;
		}
	}
	msg.addString(message.text);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendClosePrivate(uint16_t channelId)
{
	NetworkMessage msg;
	msg.addByte(0xB3);
	msg.add<uint16_t>(channelId);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendCreatePrivateChannel(uint16_t channelId, const std::string& channelName)
{
	NetworkMessage msg;
	msg.addByte(0xB2);
	msg.add<uint16_t>(channelId);
	msg.addString(channelName);
	msg.add<uint16_t>(0x01);
	msg.addString(player->getName());
	msg.add<uint16_t>(0x00);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendChannelsDialog()
{
	NetworkMessage msg;
	msg.addByte(0xAB);

	const ChannelList& list = g_chat->getChannelList(*player);
	msg.addByte(list.size());
	for (ChatChannel* channel : list) {
		msg.add<uint16_t>(channel->getId());
		msg.addString(channel->getName());
	}

	writeToOutputBuffer(msg);
}

void ProtocolGame::sendChannelMessage(const std::string& author, const std::string& text, SpeakClasses type, uint16_t channel)
{
	NetworkMessage msg;
	msg.addByte(0xAA);
	msg.add<uint32_t>(0x00);
	msg.addString(author);
	msg.add<uint16_t>(0x00);
	msg.addByte(type);
	msg.add<uint16_t>(channel);
	msg.addString(text);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendIcons(uint16_t icons)
{
	NetworkMessage msg;
	msg.addByte(0xA2);
	msg.add<uint16_t>(icons);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendShop(Npc* npc, const ShopInfoList& itemList)
{
	NetworkMessage msg;
	msg.addByte(0x7A);
	msg.addString(npc->getName());

	uint16_t itemsToSend = std::min<size_t>(itemList.size(), std::numeric_limits<uint16_t>::max());
	msg.add<uint16_t>(itemsToSend);

	uint16_t i = 0;
	for (auto it = itemList.begin(); i < itemsToSend; ++it, ++i) {
		AddShopItem(msg, *it);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGame::sendCloseShop()
{
	NetworkMessage msg;
	msg.addByte(0x7C);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendSaleItemList(const std::list<ShopInfo>& shop)
{
	NetworkMessage msg;
	msg.addByte(0x7B);
	msg.add<uint64_t>(player->getMoney() + player->getBankBalance());

	std::map<uint16_t, uint32_t> saleMap;

	if (shop.size() <= 5) {
		// For very small shops it's not worth it to create the complete map
		for (const ShopInfo& shopInfo : shop) {
			if (shopInfo.sellPrice == 0) {
				continue;
			}

			int8_t subtype = -1;

			const ItemType& itemType = Item::items[shopInfo.itemId];
			if (itemType.hasSubType() && !itemType.stackable) {
				subtype = (shopInfo.subType == 0 ? -1 : shopInfo.subType);
			}

			uint32_t count = player->getItemTypeCount(shopInfo.itemId, subtype);
			if (count > 0) {
				saleMap[shopInfo.itemId] = count;
			}
		}
	} else {
		// Large shop, it's better to get a cached map of all item counts and use it
		// We need a temporary map since the finished map should only contain items
		// available in the shop
		std::map<uint32_t, uint32_t> tempSaleMap;
		player->getAllItemTypeCount(tempSaleMap);

		// We must still check manually for the special items that require subtype matches
		// (That is, fluids such as potions etc., actually these items are very few since
		// health potions now use their own ID)
		for (const ShopInfo& shopInfo : shop) {
			if (shopInfo.sellPrice == 0) {
				continue;
			}

			int8_t subtype = -1;

			const ItemType& itemType = Item::items[shopInfo.itemId];
			if (itemType.hasSubType() && !itemType.stackable) {
				subtype = (shopInfo.subType == 0 ? -1 : shopInfo.subType);
			}

			if (subtype != -1) {
				uint32_t count;
				if (itemType.isFluidContainer() || itemType.isSplash()) {
					count = player->getItemTypeCount(shopInfo.itemId, subtype); // This shop item requires extra checks
				} else {
					count = subtype;
				}

				if (count > 0) {
					saleMap[shopInfo.itemId] = count;
				}
			} else {
				std::map<uint32_t, uint32_t>::const_iterator findIt = tempSaleMap.find(shopInfo.itemId);
				if (findIt != tempSaleMap.end() && findIt->second > 0) {
					saleMap[shopInfo.itemId] = findIt->second;
				}
			}
		}
	}

	uint8_t itemsToSend = std::min<size_t>(saleMap.size(), std::numeric_limits<uint8_t>::max());
	msg.addByte(itemsToSend);

	uint8_t i = 0;
	for (std::map<uint16_t, uint32_t>::const_iterator it = saleMap.begin(); i < itemsToSend; ++it, ++i) {
		msg.addItemId(it->first);
		msg.addByte(std::min<uint32_t>(it->second, std::numeric_limits<uint8_t>::max()));
	}

	writeToOutputBuffer(msg);
}

void ProtocolGame::sendMarketEnter(uint32_t depotId)
{
	NetworkMessage msg;
	msg.addByte(0xF6);

	msg.add<uint64_t>(player->getBankBalance());
	msg.addByte(std::min<uint32_t>(IOMarket::getPlayerOfferCount(player->getGUID()), std::numeric_limits<uint8_t>::max()));

	DepotChest* depotChest = player->getDepotChest(depotId, false);
	if (!depotChest) {
		msg.add<uint16_t>(0x00);
		writeToOutputBuffer(msg);
		return;
	}

	player->setInMarket(true);

	std::map<uint16_t, uint32_t> depotItems;
	std::forward_list<Container*> containerList { depotChest, player->getInbox() };

	do {
		Container* container = containerList.front();
		containerList.pop_front();

		for (Item* item : container->getItemList()) {
			Container* c = item->getContainer();
			if (c && !c->empty()) {
				containerList.push_front(c);
				continue;
			}

			const ItemType& itemType = Item::items[item->getID()];
			if (itemType.wareId == 0) {
				continue;
			}

			if (c && (!itemType.isContainer() || c->capacity() != itemType.maxItems)) {
				continue;
			}

			if (!item->hasMarketAttributes()) {
				continue;
			}

			depotItems[itemType.wareId] += Item::countByType(item, -1);
		}
	} while (!containerList.empty());

	uint16_t itemsToSend = std::min<size_t>(depotItems.size(), std::numeric_limits<uint16_t>::max());
	msg.add<uint16_t>(itemsToSend);

	uint16_t i = 0;
	for (std::map<uint16_t, uint32_t>::const_iterator it = depotItems.begin(); i < itemsToSend; ++it, ++i) {
		msg.add<uint16_t>(it->first);
		msg.add<uint16_t>(std::min<uint32_t>(0xFFFF, it->second));
	}

	writeToOutputBuffer(msg);
}

void ProtocolGame::sendMarketLeave()
{
	NetworkMessage msg;
	msg.addByte(0xF7);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendMarketBrowseItem(uint16_t itemId, const MarketOfferList& buyOffers, const MarketOfferList& sellOffers)
{
	NetworkMessage msg;

	msg.addByte(0xF9);
	msg.addItemId(itemId);

	msg.add<uint32_t>(buyOffers.size());
	for (const MarketOffer& offer : buyOffers) {
		msg.add<uint32_t>(offer.timestamp);
		msg.add<uint16_t>(offer.counter);
		msg.add<uint16_t>(offer.amount);
		msg.add<uint32_t>(offer.price);
		msg.addString(offer.playerName);
	}

	msg.add<uint32_t>(sellOffers.size());
	for (const MarketOffer& offer : sellOffers) {
		msg.add<uint32_t>(offer.timestamp);
		msg.add<uint16_t>(offer.counter);
		msg.add<uint16_t>(offer.amount);
		msg.add<uint32_t>(offer.price);
		msg.addString(offer.playerName);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGame::sendMarketAcceptOffer(const MarketOfferEx& offer)
{
	NetworkMessage msg;
	msg.addByte(0xF9);
	msg.addItemId(offer.itemId);

	if (offer.type == MARKETACTION_BUY) {
		msg.add<uint32_t>(0x01);
		msg.add<uint32_t>(offer.timestamp);
		msg.add<uint16_t>(offer.counter);
		msg.add<uint16_t>(offer.amount);
		msg.add<uint32_t>(offer.price);
		msg.addString(offer.playerName);
		msg.add<uint32_t>(0x00);
	} else {
		msg.add<uint32_t>(0x00);
		msg.add<uint32_t>(0x01);
		msg.add<uint32_t>(offer.timestamp);
		msg.add<uint16_t>(offer.counter);
		msg.add<uint16_t>(offer.amount);
		msg.add<uint32_t>(offer.price);
		msg.addString(offer.playerName);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGame::sendMarketBrowseOwnOffers(const MarketOfferList& buyOffers, const MarketOfferList& sellOffers)
{
	NetworkMessage msg;
	msg.addByte(0xF9);
	msg.add<uint16_t>(MARKETREQUEST_OWN_OFFERS);

	msg.add<uint32_t>(buyOffers.size());
	for (const MarketOffer& offer : buyOffers) {
		msg.add<uint32_t>(offer.timestamp);
		msg.add<uint16_t>(offer.counter);
		msg.addItemId(offer.itemId);
		msg.add<uint16_t>(offer.amount);
		msg.add<uint32_t>(offer.price);
	}

	msg.add<uint32_t>(sellOffers.size());
	for (const MarketOffer& offer : sellOffers) {
		msg.add<uint32_t>(offer.timestamp);
		msg.add<uint16_t>(offer.counter);
		msg.addItemId(offer.itemId);
		msg.add<uint16_t>(offer.amount);
		msg.add<uint32_t>(offer.price);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGame::sendMarketCancelOffer(const MarketOfferEx& offer)
{
	NetworkMessage msg;
	msg.addByte(0xF9);
	msg.add<uint16_t>(MARKETREQUEST_OWN_OFFERS);

	if (offer.type == MARKETACTION_BUY) {
		msg.add<uint32_t>(0x01);
		msg.add<uint32_t>(offer.timestamp);
		msg.add<uint16_t>(offer.counter);
		msg.addItemId(offer.itemId);
		msg.add<uint16_t>(offer.amount);
		msg.add<uint32_t>(offer.price);
		msg.add<uint32_t>(0x00);
	} else {
		msg.add<uint32_t>(0x00);
		msg.add<uint32_t>(0x01);
		msg.add<uint32_t>(offer.timestamp);
		msg.add<uint16_t>(offer.counter);
		msg.addItemId(offer.itemId);
		msg.add<uint16_t>(offer.amount);
		msg.add<uint32_t>(offer.price);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGame::sendMarketBrowseOwnHistory(const HistoryMarketOfferList& buyOffers, const HistoryMarketOfferList& sellOffers)
{
	uint32_t i = 0;
	std::map<uint32_t, uint16_t> counterMap;
	uint32_t buyOffersToSend = std::min<uint32_t>(buyOffers.size(), 810 + std::max<int32_t>(0, 810 - sellOffers.size()));
	uint32_t sellOffersToSend = std::min<uint32_t>(sellOffers.size(), 810 + std::max<int32_t>(0, 810 - buyOffers.size()));

	NetworkMessage msg;
	msg.addByte(0xF9);
	msg.add<uint16_t>(MARKETREQUEST_OWN_HISTORY);

	msg.add<uint32_t>(buyOffersToSend);
	for (auto it = buyOffers.begin(); i < buyOffersToSend; ++it, ++i) {
		msg.add<uint32_t>(it->timestamp);
		msg.add<uint16_t>(counterMap[it->timestamp]++);
		msg.addItemId(it->itemId);
		msg.add<uint16_t>(it->amount);
		msg.add<uint32_t>(it->price);
		msg.addByte(it->state);
	}

	counterMap.clear();
	i = 0;

	msg.add<uint32_t>(sellOffersToSend);
	for (auto it = sellOffers.begin(); i < sellOffersToSend; ++it, ++i) {
		msg.add<uint32_t>(it->timestamp);
		msg.add<uint16_t>(counterMap[it->timestamp]++);
		msg.addItemId(it->itemId);
		msg.add<uint16_t>(it->amount);
		msg.add<uint32_t>(it->price);
		msg.addByte(it->state);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGame::sendMarketDetail(uint16_t itemId)
{
	NetworkMessage msg;
	msg.addByte(0xF8);
	msg.addItemId(itemId);

	const ItemType& it = Item::items[itemId];
	if (it.armor != 0) {
		msg.addString(std::to_string(it.armor));
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (it.attack != 0) {
		// TODO: chance to hit, range
		// example:
		// "attack +x, chance to hit +y%, z fields"
		if (it.abilities && it.abilities->elementType != COMBAT_NONE && it.abilities->elementDamage != 0) {
			msg.addString(fmt::format("{:d} physical +{:d} {:s}", it.attack, it.abilities->elementDamage, getCombatName(it.abilities->elementType)));
		} else {
			msg.addString(std::to_string(it.attack));
		}
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (it.isContainer()) {
		msg.addString(std::to_string(it.maxItems));
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (it.defense != 0) {
		if (it.extraDefense != 0) {
			msg.addString(fmt::format("{:d} {:+d}", it.defense, it.extraDefense));
		} else {
			msg.addString(std::to_string(it.defense));
		}
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (!it.description.empty()) {
		const std::string& descr = it.description;
		if (descr.back() == '.') {
			msg.addString(std::string(descr, 0, descr.length() - 1));
		} else {
			msg.addString(descr);
		}
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (it.decayTime != 0) {
		msg.addString(fmt::format("{:d} seconds", it.decayTime));
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (it.abilities) {
		std::ostringstream ss;
		bool separator = false;

		for (size_t i = 0; i < COMBAT_COUNT; ++i) {
			if (it.abilities->absorbPercent[i] == 0) {
				continue;
			}

			if (separator) {
				ss << ", ";
			} else {
				separator = true;
			}

			ss << getCombatName(indexToCombatType(i)) << ' ' << std::showpos << it.abilities->absorbPercent[i] << std::noshowpos << '%';
		}

		msg.addString(ss.str());
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (it.minReqLevel != 0) {
		msg.addString(std::to_string(it.minReqLevel));
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (it.minReqMagicLevel != 0) {
		msg.addString(std::to_string(it.minReqMagicLevel));
	} else {
		msg.add<uint16_t>(0x00);
	}

	msg.addString(it.vocationString);

	msg.addString(it.runeSpellName);

	if (it.abilities) {
		std::ostringstream ss;
		bool separator = false;

		for (uint8_t i = SKILL_FIRST; i <= SKILL_LAST; i++) {
			if (!it.abilities->skills[i]) {
				continue;
			}

			if (separator) {
				ss << ", ";
			} else {
				separator = true;
			}

			ss << getSkillName(i) << ' ' << std::showpos << it.abilities->skills[i] << std::noshowpos;
		}

		if (it.abilities->stats[STAT_MAGICPOINTS] != 0) {
			if (separator) {
				ss << ", ";
			} else {
				separator = true;
			}

			ss << "magic level " << std::showpos << it.abilities->stats[STAT_MAGICPOINTS] << std::noshowpos;
		}

		if (it.abilities->speed != 0) {
			if (separator) {
				ss << ", ";
			}

			ss << "speed " << std::showpos << (it.abilities->speed >> 1) << std::noshowpos;
		}

		msg.addString(ss.str());
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (it.charges != 0) {
		msg.addString(std::to_string(it.charges));
	} else {
		msg.add<uint16_t>(0x00);
	}

	std::string weaponName = getWeaponName(it.weaponType);

	if (it.slotPosition & SLOTP_TWO_HAND) {
		if (!weaponName.empty()) {
			weaponName += ", two-handed";
		} else {
			weaponName = "two-handed";
		}
	}

	msg.addString(weaponName);

	if (it.weight != 0) {
		std::ostringstream ss;
		if (it.weight < 10) {
			ss << "0.0" << it.weight;
		} else if (it.weight < 100) {
			ss << "0." << it.weight;
		} else {
			std::string weightString = std::to_string(it.weight);
			weightString.insert(weightString.end() - 2, '.');
			ss << weightString;
		}
		ss << " oz";
		msg.addString(ss.str());
	} else {
		msg.add<uint16_t>(0x00);
	}

	MarketStatistics* statistics = IOMarket::getInstance().getPurchaseStatistics(itemId);
	if (statistics) {
		msg.addByte(0x01);
		msg.add<uint32_t>(statistics->numTransactions);
		msg.add<uint32_t>(std::min<uint64_t>(std::numeric_limits<uint32_t>::max(), statistics->totalPrice));
		msg.add<uint32_t>(statistics->highestPrice);
		msg.add<uint32_t>(statistics->lowestPrice);
	} else {
		msg.addByte(0x00);
	}

	statistics = IOMarket::getInstance().getSaleStatistics(itemId);
	if (statistics) {
		msg.addByte(0x01);
		msg.add<uint32_t>(statistics->numTransactions);
		msg.add<uint32_t>(std::min<uint64_t>(std::numeric_limits<uint32_t>::max(), statistics->totalPrice));
		msg.add<uint32_t>(statistics->highestPrice);
		msg.add<uint32_t>(statistics->lowestPrice);
	} else {
		msg.addByte(0x00);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGame::sendQuestLog()
{
	NetworkMessage msg;
	msg.addByte(0xF0);
	msg.add<uint16_t>(g_game.quests.getQuestsCount(player));

	for (const Quest& quest : g_game.quests.getQuests()) {
		if (quest.isStarted(player)) {
			msg.add<uint16_t>(quest.getID());
			msg.addString(quest.getName());
			msg.addByte(quest.isCompleted(player));
		}
	}

	writeToOutputBuffer(msg);
}

void ProtocolGame::sendQuestLine(const Quest* quest)
{
	NetworkMessage msg;
	msg.addByte(0xF1);
	msg.add<uint16_t>(quest->getID());
	msg.addByte(quest->getMissionsCount(player));

	for (const Mission& mission : quest->getMissions()) {
		if (mission.isStarted(player)) {
			msg.addString(mission.getName(player));
			msg.addString(mission.getDescription(player));
		}
	}

	writeToOutputBuffer(msg);
}

void ProtocolGame::sendTradeItemRequest(const std::string& traderName, const Item* item, bool ack)
{
	NetworkMessage msg;

	if (ack) {
		msg.addByte(0x7D);
	} else {
		msg.addByte(0x7E);
	}

	msg.addString(traderName);

	if (const Container* tradeContainer = item->getContainer()) {
		std::list<const Container*> listContainer {tradeContainer};
		std::list<const Item*> itemList {tradeContainer};
		while (!listContainer.empty()) {
			const Container* container = listContainer.front();
			listContainer.pop_front();

			for (Item* containerItem : container->getItemList()) {
				Container* tmpContainer = containerItem->getContainer();
				if (tmpContainer) {
					listContainer.push_back(tmpContainer);
				}
				itemList.push_back(containerItem);
			}
		}

		msg.addByte(itemList.size());
		for (const Item* listItem : itemList) {
			msg.addItem(listItem);
		}
	} else {
		msg.addByte(0x01);
		msg.addItem(item);
	}
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendCloseTrade()
{
	NetworkMessage msg;
	msg.addByte(0x7F);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendCloseContainer(uint8_t cid)
{
	NetworkMessage msg;
	msg.addByte(0x6F);
	msg.addByte(cid);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendCreatureTurn(const Creature* creature, uint32_t stackPos)
{
	if (!canSee(creature)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x6B);
	if (stackPos >= 10) {
		msg.add<uint16_t>(0xFFFF);
		msg.add<uint32_t>(creature->getID());
	} else {
		msg.addPosition(creature->getPosition());
		msg.addByte(stackPos);
	}

	msg.add<uint16_t>(0x63);
	msg.add<uint32_t>(creature->getID());
	msg.addByte(creature->getDirection());
	msg.addByte(player->canWalkthroughEx(creature) ? 0x00 : 0x01);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendCreatureSay(const Creature* creature, SpeakClasses type, const std::string& text, const Position* pos/* = nullptr*/)
{
	NetworkMessage msg;
	msg.addByte(0xAA);

	static uint32_t statementId = 0;
	msg.add<uint32_t>(++statementId);

	msg.addString(creature->getName());

	//Add level only for players
	if (const Player* speaker = creature->getPlayer()) {
		msg.add<uint16_t>(speaker->getLevel());
	} else {
		msg.add<uint16_t>(0x00);
	}

	msg.addByte(type);
	if (pos) {
		msg.addPosition(*pos);
	} else {
		msg.addPosition(creature->getPosition());
	}

	msg.addString(text);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendToChannel(const Creature* creature, SpeakClasses type, const std::string& text, uint16_t channelId)
{
	NetworkMessage msg;
	msg.addByte(0xAA);

	static uint32_t statementId = 0;
	msg.add<uint32_t>(++statementId);
	if (!creature) {
		msg.add<uint32_t>(0x00);
	} else {
		msg.addString(creature->getName());
		//Add level only for players
		if (const Player* speaker = creature->getPlayer()) {
			msg.add<uint16_t>(speaker->getLevel());
		} else {
			msg.add<uint16_t>(0x00);
		}
	}

	msg.addByte(type);
	msg.add<uint16_t>(channelId);
	msg.addString(text);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendPrivateMessage(const Player* speaker, SpeakClasses type, const std::string& text)
{
	NetworkMessage msg;
	msg.addByte(0xAA);
	static uint32_t statementId = 0;
	msg.add<uint32_t>(++statementId);
	if (speaker) {
		msg.addString(speaker->getName());
		msg.add<uint16_t>(speaker->getLevel());
	} else {
		msg.add<uint32_t>(0x00);
	}
	msg.addByte(type);
	msg.addString(text);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendCancelTarget()
{
	NetworkMessage msg;
	msg.addByte(0xA3);
	msg.add<uint32_t>(0x00);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendChangeSpeed(const Creature* creature, uint32_t speed)
{
	NetworkMessage msg;
	msg.addByte(0x8F);
	msg.add<uint32_t>(creature->getID());
	msg.add<uint16_t>(creature->getBaseSpeed() / 2);
	msg.add<uint16_t>(speed / 2);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendDistanceShoot(const Position& from, const Position& to, uint8_t type)
{
	NetworkMessage msg;
	msg.addByte(0x85);
	msg.addPosition(from);
	msg.addPosition(to);
	msg.addByte(type);
	writeToOutputBuffer(msg);
}



void ProtocolGame::sendCreatureHealth(const Creature* creature)
{
	NetworkMessage msg;
	msg.addByte(0x8C);
	msg.add<uint32_t>(creature->getID());

	if (creature->isHealthHidden()) {
		msg.addByte(0x00);
	} else {
		msg.addByte(std::ceil((static_cast<double>(creature->getHealth()) / std::max<int32_t>(creature->getMaxHealth(), 1)) * 100));
	}
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendFYIBox(const std::string& message)
{
	NetworkMessage msg;
	msg.addByte(0x15);
	msg.addString(message);
	writeToOutputBuffer(msg);
}

//tile


void ProtocolGame::sendAddTileItem(const Position& pos, uint32_t stackpos, const Item* item)
{
	if (!canSee(pos)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x6A);
	msg.addPosition(pos);
	msg.addByte(stackpos);
	msg.addItem(item);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendUpdateTileItem(const Position& pos, uint32_t stackpos, const Item* item)
{
	if (!canSee(pos)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x6B);
	msg.addPosition(pos);
	msg.addByte(stackpos);
	msg.addItem(item);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendRemoveTileThing(const Position& pos, uint32_t stackpos)
{
	if (!canSee(pos)) {
		return;
	}

	NetworkMessage msg;
	RemoveTileThing(msg, pos, stackpos);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendUpdateTileCreature(const Position& pos, uint32_t stackpos, const Creature* creature)
{
	if (!canSee(pos)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x6B);
	msg.addPosition(pos);
	msg.addByte(stackpos);

	bool known;
	uint32_t removedKnown;
	ProtocolGameBase::checkCreatureAsKnown(creature->getID(), known, removedKnown);
	AddCreature(msg, creature, false, removedKnown);

	writeToOutputBuffer(msg);
}

void ProtocolGame::sendRemoveTileCreature(const Creature* creature, const Position& pos, uint32_t stackpos)
{
	if (stackpos < 10) {
		if (!canSee(pos)) {
			return;
		}

		NetworkMessage msg;
		RemoveTileThing(msg, pos, stackpos);
		writeToOutputBuffer(msg);
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x6C);
	msg.add<uint16_t>(0xFFFF);
	msg.add<uint32_t>(creature->getID());
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendFightModes()
{
	NetworkMessage msg;
	msg.addByte(0xA7);
	msg.addByte(player->fightMode);
	msg.addByte(player->chaseMode);
	msg.addByte(player->secureMode);
	msg.addByte(PVP_MODE_DOVE);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendMoveCreature(const Creature* creature, const Position& newPos, int32_t newStackPos, const Position& oldPos, int32_t oldStackPos, bool teleport)
{
	if (creature == player) {
		if (teleport) {
			sendRemoveTileCreature(creature, oldPos, oldStackPos);
			sendMapDescription(newPos);
		} else {
			NetworkMessage msg;
			if (oldPos.z == 7 && newPos.z >= 8) {
				RemoveTileCreature(msg, creature, oldPos, oldStackPos);
			} else {
				msg.addByte(0x6D);
				if (oldStackPos < 10) {
					msg.addPosition(oldPos);
					msg.addByte(oldStackPos);
				} else {
					msg.add<uint16_t>(0xFFFF);
					msg.add<uint32_t>(creature->getID());
				}
				msg.addPosition(newPos);
			}

			if (newPos.z > oldPos.z) {
				MoveDownCreature(msg, creature, newPos, oldPos);
			} else if (newPos.z < oldPos.z) {
				MoveUpCreature(msg, creature, newPos, oldPos);
			}

			if (oldPos.y > newPos.y) { // north, for old x
				msg.addByte(0x65);
				GetMapDescription(oldPos.x - Map::maxClientViewportX, newPos.y - Map::maxClientViewportY, newPos.z, (Map::maxClientViewportX * 2) + 2, 1, msg);
			} else if (oldPos.y < newPos.y) { // south, for old x
				msg.addByte(0x67);
				GetMapDescription(oldPos.x - Map::maxClientViewportX, newPos.y + (Map::maxClientViewportY + 1), newPos.z, (Map::maxClientViewportX * 2) + 2, 1, msg);
			}

			if (oldPos.x < newPos.x) { // east, [with new y]
				msg.addByte(0x66);
				GetMapDescription(newPos.x + (Map::maxClientViewportX + 1), newPos.y - Map::maxClientViewportY, newPos.z, 1, (Map::maxClientViewportY * 2) + 2, msg);
			} else if (oldPos.x > newPos.x) { // west, [with new y]
				msg.addByte(0x68);
				GetMapDescription(newPos.x - Map::maxClientViewportX, newPos.y - Map::maxClientViewportY, newPos.z, 1, (Map::maxClientViewportY * 2) + 2, msg);
			}
			writeToOutputBuffer(msg);
		}
	} else if (canSee(oldPos) && canSee(creature->getPosition())) {
		if (teleport || (oldPos.z == 7 && newPos.z >= 8)) {
			sendRemoveTileCreature(creature, oldPos, oldStackPos);
			sendAddCreature(creature, newPos, newStackPos, false);
		} else {
			NetworkMessage msg;
			msg.addByte(0x6D);
			if (oldStackPos < 10) {
				msg.addPosition(oldPos);
				msg.addByte(oldStackPos);
			} else {
				msg.add<uint16_t>(0xFFFF);
				msg.add<uint32_t>(creature->getID());
			}
			msg.addPosition(creature->getPosition());
			writeToOutputBuffer(msg);
		}
	} else if (canSee(oldPos)) {
		sendRemoveTileCreature(creature, oldPos, oldStackPos);
	} else if (canSee(creature->getPosition())) {
		sendAddCreature(creature, newPos, newStackPos, false);
	}
}

void ProtocolGame::sendItems()
{
	NetworkMessage msg;
	msg.addByte(0xF5);

	const std::vector<uint16_t>& inventory = Item::items.getInventory();
	msg.add<uint16_t>(inventory.size() + 11);
	for (uint16_t i = 1; i <= 11; i++) {
		msg.add<uint16_t>(i);
		msg.addByte(0); //always 0
		msg.add<uint16_t>(1); // always 1
	}

	for (auto clientId : inventory) {
		msg.add<uint16_t>(clientId);
		msg.addByte(0); //always 0
		msg.add<uint16_t>(1);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGame::sendAddContainerItem(uint8_t cid, uint16_t slot, const Item* item)
{
	NetworkMessage msg;
	msg.addByte(0x70);
	msg.addByte(cid);
	msg.add<uint16_t>(slot);
	msg.addItem(item);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendUpdateContainerItem(uint8_t cid, uint16_t slot, const Item* item)
{
	NetworkMessage msg;
	msg.addByte(0x71);
	msg.addByte(cid);
	msg.add<uint16_t>(slot);
	msg.addItem(item);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendRemoveContainerItem(uint8_t cid, uint16_t slot, const Item* lastItem)
{
	NetworkMessage msg;
	msg.addByte(0x72);
	msg.addByte(cid);
	msg.add<uint16_t>(slot);
	if (lastItem) {
		msg.addItem(lastItem);
	} else {
		msg.add<uint16_t>(0x00);
	}
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendTextWindow(uint32_t windowTextId, Item* item, uint16_t maxlen, bool canWrite)
{
	NetworkMessage msg;
	msg.addByte(0x96);
	msg.add<uint32_t>(windowTextId);
	msg.addItem(item);

	if (canWrite) {
		msg.add<uint16_t>(maxlen);
		msg.addString(item->getText());
	} else {
		const std::string& text = item->getText();
		msg.add<uint16_t>(text.size());
		msg.addString(text);
	}

	const std::string& writer = item->getWriter();
	if (!writer.empty()) {
		msg.addString(writer);
	} else {
		msg.add<uint16_t>(0x00);
	}

	time_t writtenDate = item->getDate();
	if (writtenDate != 0) {
		msg.addString(formatDateShort(writtenDate));
	} else {
		msg.add<uint16_t>(0x00);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGame::sendTextWindow(uint32_t windowTextId, uint32_t itemId, const std::string& text)
{
	NetworkMessage msg;
	msg.addByte(0x96);
	msg.add<uint32_t>(windowTextId);
	msg.addItem(itemId, 1);
	msg.add<uint16_t>(text.size());
	msg.addString(text);
	msg.add<uint16_t>(0x00);
	msg.add<uint16_t>(0x00);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendHouseWindow(uint32_t windowTextId, const std::string& text)
{
	NetworkMessage msg;
	msg.addByte(0x97);
	msg.addByte(0x00);
	msg.add<uint32_t>(windowTextId);
	msg.addString(text);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendOutfitWindow()
{
	const auto& outfits = Outfits::getInstance().getOutfits(player->getSex());
	if (outfits.size() == 0) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0xC8);

	Outfit_t currentOutfit = player->getDefaultOutfit();
	if (currentOutfit.lookType == 0) {
		Outfit_t newOutfit;
		newOutfit.lookType = outfits.front().lookType;
		currentOutfit = newOutfit;
	}

	Mount* currentMount = g_game.mounts.getMountByID(player->getCurrentMount());
	if (currentMount) {
		currentOutfit.lookMount = currentMount->clientId;
	}

	AddOutfit(msg, currentOutfit);

	std::vector<ProtocolOutfit> protocolOutfits;
	if (player->isAccessPlayer()) {
		static const std::string gamemasterOutfitName = "Gamemaster";
		protocolOutfits.emplace_back(gamemasterOutfitName, 75, 0);
	}

	protocolOutfits.reserve(outfits.size());
	for (const Outfit& outfit : outfits) {
		uint8_t addons;
		if (!player->getOutfitAddons(outfit, addons)) {
			continue;
		}

		protocolOutfits.emplace_back(outfit.name, outfit.lookType, addons);
		if (protocolOutfits.size() == std::numeric_limits<uint8_t>::max()) { // Game client currently doesn't allow more than 255 outfits
			break;
		}
	}

	msg.addByte(protocolOutfits.size());
	for (const ProtocolOutfit& outfit : protocolOutfits) {
		msg.add<uint16_t>(outfit.lookType);
		msg.addString(outfit.name);
		msg.addByte(outfit.addons);
	}

	std::vector<const Mount*> mounts;
	for (const Mount& mount : g_game.mounts.getMounts()) {
		if (player->hasMount(&mount)) {
			mounts.push_back(&mount);
		}
	}

	msg.addByte(mounts.size());
	for (const Mount* mount : mounts) {
		msg.add<uint16_t>(mount->clientId);
		msg.addString(mount->name);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGame::sendUpdatedVIPStatus(uint32_t guid, VipStatus_t newStatus)
{
	NetworkMessage msg;
	msg.addByte(0xD3);
	msg.add<uint32_t>(guid);
	msg.addByte(newStatus);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendVIPEntries()
{
	const std::forward_list<VIPEntry>& vipEntries = IOLoginData::getVIPEntries(player->getAccount());

	for (const VIPEntry& entry : vipEntries) {
		VipStatus_t vipStatus = VIPSTATUS_ONLINE;

		Player* vipPlayer = g_game.getPlayerByGUID(entry.guid);

		if (!vipPlayer || !player->canSeeCreature(vipPlayer)) {
			vipStatus = VIPSTATUS_OFFLINE;
		}

		sendVIP(entry.guid, entry.name, entry.description, entry.icon, entry.notify, vipStatus);
	}
}

void ProtocolGame::sendSpellCooldown(uint8_t spellId, uint32_t time)
{
	NetworkMessage msg;
	msg.addByte(0xA4);
	msg.addByte(spellId);
	msg.add<uint32_t>(time);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendSpellGroupCooldown(SpellGroup_t groupId, uint32_t time)
{
	NetworkMessage msg;
	msg.addByte(0xA5);
	msg.addByte(groupId);
	msg.add<uint32_t>(time);
	writeToOutputBuffer(msg);
}

void ProtocolGame::sendModalWindow(const ModalWindow& modalWindow)
{
	NetworkMessage msg;
	msg.addByte(0xFA);

	msg.add<uint32_t>(modalWindow.id);
	msg.addString(modalWindow.title);
	msg.addString(modalWindow.message);

	msg.addByte(modalWindow.buttons.size());
	for (const auto& it : modalWindow.buttons) {
		msg.addString(it.first);
		msg.addByte(it.second);
	}

	msg.addByte(modalWindow.choices.size());
	for (const auto& it : modalWindow.choices) {
		msg.addString(it.first);
		msg.addByte(it.second);
	}

	msg.addByte(modalWindow.defaultEscapeButton);
	msg.addByte(modalWindow.defaultEnterButton);
	msg.addByte(modalWindow.priority ? 0x01 : 0x00);

	writeToOutputBuffer(msg);
}

////////////// Add common messages

//tile
void ProtocolGame::RemoveTileCreature(NetworkMessage& msg, const Creature* creature, const Position& pos, uint32_t stackpos)
{
	if (stackpos < 10) {
		RemoveTileThing(msg, pos, stackpos);
		return;
	}

	msg.addByte(0x6C);
	msg.add<uint16_t>(0xFFFF);
	msg.add<uint32_t>(creature->getID());
}

void ProtocolGame::MoveUpCreature(NetworkMessage& msg, const Creature* creature, const Position& newPos, const Position& oldPos)
{
	if (creature != player) {
		return;
	}

	//floor change up
	msg.addByte(0xBE);

	//going to surface
	if (newPos.z == 7) {
		int32_t skip = -1;

		// floor 7 and 6 already set
		for (int i = 5; i >= 0; --i) {
			GetFloorDescription(msg, oldPos.x - Map::maxClientViewportX, oldPos.y - Map::maxClientViewportY, i, (Map::maxClientViewportX * 2) + 2, (Map::maxClientViewportY * 2) + 2, 8 - i, skip);
		}
		if (skip >= 0) {
			msg.addByte(skip);
			msg.addByte(0xFF);
		}
	}
	//underground, going one floor up (still underground)
	else if (newPos.z > 7) {
		int32_t skip = -1;
		GetFloorDescription(msg, oldPos.x - Map::maxClientViewportX, oldPos.y - Map::maxClientViewportY, oldPos.getZ() - 3, (Map::maxClientViewportX * 2) + 2, (Map::maxClientViewportY * 2) + 2, 3, skip);

		if (skip >= 0) {
			msg.addByte(skip);
			msg.addByte(0xFF);
		}
	}

	//moving up a floor up makes us out of sync
	//west
	msg.addByte(0x68);
	GetMapDescription(oldPos.x - Map::maxClientViewportX, oldPos.y - (Map::maxClientViewportY - 1), newPos.z, 1, (Map::maxClientViewportY * 2) + 2, msg);

	//north
	msg.addByte(0x65);
	GetMapDescription(oldPos.x - Map::maxClientViewportX, oldPos.y - Map::maxClientViewportY, newPos.z, (Map::maxClientViewportX * 2) + 2, 1, msg);
}

void ProtocolGame::MoveDownCreature(NetworkMessage& msg, const Creature* creature, const Position& newPos, const Position& oldPos)
{
	if (creature != player) {
		return;
	}

	//floor change down
	msg.addByte(0xBF);

	//going from surface to underground
	if (newPos.z == 8) {
		int32_t skip = -1;

		for (int i = 0; i < 3; ++i) {
			GetFloorDescription(msg, oldPos.x - Map::maxClientViewportX, oldPos.y - Map::maxClientViewportY, newPos.z + i, (Map::maxClientViewportX * 2) + 2, (Map::maxClientViewportY * 2) + 2, -i - 1, skip);
		}
		if (skip >= 0) {
			msg.addByte(skip);
			msg.addByte(0xFF);
		}
	}
	//going further down
	else if (newPos.z > oldPos.z && newPos.z > 8 && newPos.z < 14) {
		int32_t skip = -1;
		GetFloorDescription(msg, oldPos.x - Map::maxClientViewportX, oldPos.y - Map::maxClientViewportY, newPos.z + 2, (Map::maxClientViewportX * 2) + 2, (Map::maxClientViewportY * 2) + 2, -3, skip);

		if (skip >= 0) {
			msg.addByte(skip);
			msg.addByte(0xFF);
		}
	}

	//moving down a floor makes us out of sync
	//east
	msg.addByte(0x66);
	GetMapDescription(oldPos.x + (Map::maxClientViewportX + 1), oldPos.y - (Map::maxClientViewportY + 1), newPos.z, 1, (Map::maxClientViewportY * 2) + 2, msg);

	//south
	msg.addByte(0x67);
	GetMapDescription(oldPos.x - Map::maxClientViewportX, oldPos.y + (Map::maxClientViewportY + 1), newPos.z, (Map::maxClientViewportX * 2) + 2, 1, msg);
}

void ProtocolGame::AddShopItem(NetworkMessage& msg, const ShopInfo& item)
{
	const ItemType& it = Item::items[item.itemId];
	msg.add<uint16_t>(it.clientId);

	if (it.isSplash() || it.isFluidContainer()) {
		msg.addByte(serverFluidToClient(item.subType));
	} else {
		msg.addByte(0x00);
	}

	msg.addString(item.realName);
	msg.add<uint32_t>(it.weight);
	msg.add<uint32_t>(item.buyPrice);
	msg.add<uint32_t>(item.sellPrice);
}

void ProtocolGame::parseExtendedOpcode(NetworkMessage& msg)
{
	uint8_t opcode = msg.getByte();
	const std::string& buffer = msg.getString();

	// process additional opcodes via lua script event
	addGameTask(&Game::parsePlayerExtendedOpcode, player->getID(), opcode, buffer);
}
