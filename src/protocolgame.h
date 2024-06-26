// Copyright 2022 The Forgotten Server Authors. All rights reserved.
// Use of this source code is governed by the GPL-2.0 License that can be found in the LICENSE file.

#ifndef FS_PROTOCOLGAME_H_FACA2A2D1A9348B78E8FD7E8003EBB87
#define FS_PROTOCOLGAME_H_FACA2A2D1A9348B78E8FD7E8003EBB87

#include "protocol.h"
#include "chat.h"
#include "creature.h"
#include "tasks.h"
#include "protocolgamebase.h"
#include "protocolspectator.h"

class NetworkMessage;
class Player;
class Game;
class House;
class Container;
class Tile;
class Connection;
class Quest;
class ProtocolGame;
using ProtocolGame_ptr = std::shared_ptr<ProtocolGame>;

extern Game g_game;

struct TextMessage
{
    MessageClasses type = MESSAGE_STATUS_DEFAULT;
    std::string text;
    Position position;
    uint16_t channelId;
    struct {
        int32_t value = 0;
        TextColor_t color;
    } primary, secondary;

    TextMessage() = default;
    TextMessage(MessageClasses type, std::string text) : type(type), text(std::move(text)) {}
};

class ProtocolGame final : public ProtocolGameBase
{
    public:
        explicit ProtocolGame(Connection_ptr connection):
            ProtocolGameBase(connection) {}

        // Agrega esta función estática
        static const char* protocol_name() { return "ProtocolGame"; }

        void login(const std::string& name, uint32_t accountId, OperatingSystem_t operatingSystem);
        void logout(bool displayEffect, bool forced);

        uint16_t getVersion() const {
            return version;
        }

        const std::unordered_set<uint32_t>& getKnownCreatures() const {
            return knownCreatureSet;
        }

        typedef std::unordered_map<Player*, ProtocolGame_ptr> LiveCastsMap;
        typedef std::vector<ProtocolSpectator_ptr> CastSpectatorVec;

        void addSpectator(ProtocolSpectator_ptr spectatorClient);
        void removeSpectator(ProtocolSpectator_ptr spectatorClient);
        bool startLiveCast(const std::string& password = "");
        bool stopLiveCast();
        const CastSpectatorVec& getLiveCastSpectators() const {
            return spectators;
        }
        size_t getSpectatorCount() const {
            return spectators.size();
        }
        bool isLiveCaster() const {
            return isCaster.load(std::memory_order_relaxed);
        }

        std::mutex liveCastLock;

        void registerLiveCast();
        void unregisterLiveCast();
        void updateLiveCastInfo();
        static void clearLiveCastInfo();
        static ProtocolGame_ptr getLiveCast(Player* player) {
            const auto it = liveCasts.find(player);
            return it != liveCasts.end() ? it->second : nullptr;
        }
        const std::string& getLiveCastName() const {
            return liveCastName;
        }
        const std::string& getLiveCastPassword() const {
            return liveCastPassword;
        }
        bool isPasswordProtected() const {
            return !liveCastPassword.empty();
        }
        static const LiveCastsMap& getLiveCasts() {
            return liveCasts;
        }
        void broadcastSpectatorMessage(const std::string& text) {
            if (player) {
                sendChannelMessage("Spectator", text, TALKTYPE_CHANNEL_Y, CHANNEL_CAST);
            }
        }
        static uint8_t getMaxLiveCastCount() {
            return std::numeric_limits<int8_t>::max();
        }

    private:
        ProtocolGame_ptr getThis() {
            return std::static_pointer_cast<ProtocolGame>(shared_from_this());
        }
        void connect(uint32_t playerId, OperatingSystem_t operatingSystem);
        void disconnectClient(const std::string& message) const;
        void writeToOutputBuffer(const NetworkMessage& msg, bool broadcast = true) final;

        void release() override;

        void checkCreatureAsKnown(uint32_t id, bool& known, uint32_t& removedKnown);

        void parsePacket(NetworkMessage& msg) override;
        void onRecvFirstMessage(NetworkMessage& msg) override;

        void parseAutoWalk(NetworkMessage& msg);
        void parseSetOutfit(NetworkMessage& msg);
        void parseSay(NetworkMessage& msg);
        void parseLookAt(NetworkMessage& msg);
        void parseLookInBattleList(NetworkMessage& msg);
        void parseFightModes(NetworkMessage& msg);
        void parseAttack(NetworkMessage& msg);
        void parseFollow(NetworkMessage& msg);
        void parseEquipObject(NetworkMessage& msg);

        void parseBugReport(NetworkMessage& msg);
        void parseDebugAssert(NetworkMessage& msg);
        void parseRuleViolationReport(NetworkMessage& msg);

        void parseThrow(NetworkMessage& msg);
        void parseUseItemEx(NetworkMessage& msg);
        void parseUseWithCreature(NetworkMessage& msg);
        void parseUseItem(NetworkMessage& msg);
        void parseCloseContainer(NetworkMessage& msg);
        void parseUpArrowContainer(NetworkMessage& msg);
        void parseUpdateContainer(NetworkMessage& msg);
        void parseTextWindow(NetworkMessage& msg);
        void parseHouseWindow(NetworkMessage& msg);
        void parseWrapItem(NetworkMessage& msg);

        void parseLookInShop(NetworkMessage& msg);
        void parsePlayerPurchase(NetworkMessage& msg);
        void parsePlayerSale(NetworkMessage& msg);

        void parseQuestLine(NetworkMessage& msg);

        void parseInviteToParty(NetworkMessage& msg);
        void parseJoinParty(NetworkMessage& msg);
        void parseRevokePartyInvite(NetworkMessage& msg);
        void parsePassPartyLeadership(NetworkMessage& msg);
        void parseEnableSharedPartyExperience(NetworkMessage& msg);

        void parseToggleMount(NetworkMessage& msg);

        void parseModalWindowAnswer(NetworkMessage& msg);

        void parseBrowseField(NetworkMessage& msg);
        void parseSeekInContainer(NetworkMessage& msg);

        void parseRequestTrade(NetworkMessage& msg);
        void parseLookInTrade(NetworkMessage& msg);

        void parseMarketLeave();
        void parseMarketBrowse(NetworkMessage& msg);
        void parseMarketCreateOffer(NetworkMessage& msg);
        void parseMarketCancelOffer(NetworkMessage& msg);
        void parseMarketAcceptOffer(NetworkMessage& msg);

        void parseAddVip(NetworkMessage& msg);
        void parseRemoveVip(NetworkMessage& msg);
        void parseEditVip(NetworkMessage& msg);

        void parseRotateItem(NetworkMessage& msg);

        void parseChannelInvite(NetworkMessage& msg);
        void parseChannelExclude(NetworkMessage& msg);
        void parseOpenChannel(NetworkMessage& msg);
        void parseOpenPrivateChannel(NetworkMessage& msg);
        void parseCloseChannel(NetworkMessage& msg);

        void sendChannelMessage(const std::string& author, const std::string& text, SpeakClasses type, uint16_t channel);
        void sendChannelEvent(uint16_t channelId, const std::string& playerName, ChannelEvent_t channelEvent);
        void sendClosePrivate(uint16_t channelId);
        void sendCreatePrivateChannel(uint16_t channelId, const std::string& channelName);
        void sendChannelsDialog();
        void sendOpenPrivateChannel(const std::string& receiver);
        void sendToChannel(const Creature* creature, SpeakClasses type, const std::string& text, uint16_t channelId);
        void sendPrivateMessage(const Player* speaker, SpeakClasses type, const std::string& text);
        void sendIcons(uint16_t icons);
        void sendFYIBox(const std::string& message);
        void sendDistanceShoot(const Position& from, const Position& to, uint8_t type);
        void sendCreatureHealth(const Creature* creature);
        void sendCreatureTurn(const Creature* creature, uint32_t stackPos);
        void sendCreatureSay(const Creature* creature, SpeakClasses type, const std::string& text, const Position* pos = nullptr);
        void sendQuestLog();
        void sendQuestLine(const Quest* quest);
        void sendChangeSpeed(const Creature* creature, uint32_t speed);
        void sendCancelTarget();
        void sendCreatureOutfit(const Creature* creature, const Outfit_t& outfit);
        void sendTextMessage(const TextMessage& message);
        void sendReLoginWindow(uint8_t unfairFightReduction);
        void sendTutorial(uint8_t tutorialId);
        void sendAddMarker(const Position& pos, uint8_t markType, const std::string& desc);
        void sendCreatureWalkthrough(const Creature* creature, bool walkthrough);
        void sendCreatureShield(const Creature* creature);
        void sendCreatureSkull(const Creature* creature);
        void sendCreatureType(uint32_t creatureId, uint8_t creatureType);
        void sendCreatureHelpers(uint32_t creatureId, uint16_t helpers);
        void sendShop(Npc* npc, const ShopInfoList& itemList);
        void sendCloseShop();
        void sendSaleItemList(const std::list<ShopInfo>& shop);
        void sendMarketEnter(uint32_t depotId);
        void sendMarketLeave();
        void sendMarketBrowseItem(uint16_t itemId, const MarketOfferList& buyOffers, const MarketOfferList& sellOffers);
        void sendMarketAcceptOffer(const MarketOfferEx& offer);
        void sendMarketBrowseOwnOffers(const MarketOfferList& buyOffers, const MarketOfferList& sellOffers);
        void sendMarketCancelOffer(const MarketOfferEx& offer);
        void sendMarketBrowseOwnHistory(const HistoryMarketOfferList& buyOffers, const HistoryMarketOfferList& sellOffers);
        void sendMarketDetail(uint16_t itemId);
        void sendTradeItemRequest(const std::string& traderName, const Item* item, bool ack);
        void sendCloseTrade();
        void sendTextWindow(uint32_t windowTextId, Item* item, uint16_t maxlen, bool canWrite);
        void sendTextWindow(uint32_t windowTextId, uint32_t itemId, const std::string& text);
        void sendHouseWindow(uint32_t windowTextId, const std::string& text);
        void sendOutfitWindow();
        void sendUpdatedVIPStatus(uint32_t guid, VipStatus_t newStatus);
        void sendVIPEntries();
        void sendFightModes();
        void sendCreatureSquare(const Creature* creature, SquareColor_t color);
        void sendSpellCooldown(uint8_t spellId, uint32_t time);
        void sendSpellGroupCooldown(SpellGroup_t groupId, uint32_t time);
        void sendAddTileItem(const Position& pos, uint32_t stackpos, const Item* item);
        void sendUpdateTileItem(const Position& pos, uint32_t stackpos, const Item* item);
        void sendRemoveTileThing(const Position& pos, uint32_t stackpos);
        void sendUpdateTileCreature(const Position& pos, uint32_t stackpos, const Creature* creature);
        void sendRemoveTileCreature(const Creature* creature, const Position& pos, uint32_t stackpos);
        void sendMoveCreature(const Creature* creature, const Position& newPos, int32_t newStackPos, const Position& oldPos, int32_t oldStackPos, bool teleport);
        void sendAddContainerItem(uint8_t cid, uint16_t slot, const Item* item);
        void sendUpdateContainerItem(uint8_t cid, uint16_t slot, const Item* item);
        void sendRemoveContainerItem(uint8_t cid, uint16_t slot, const Item* lastItem);
        void sendCloseContainer(uint8_t cid);
        void sendItems();
        void sendModalWindow(const ModalWindow& modalWindow);
        static void RemoveTileCreature(NetworkMessage& msg, const Creature* creature, const Position& pos, uint32_t stackpos);
        void MoveUpCreature(NetworkMessage& msg, const Creature* creature, const Position& newPos, const Position& oldPos);
        void MoveDownCreature(NetworkMessage& msg, const Creature* creature, const Position& newPos, const Position& oldPos);
        void AddShopItem(NetworkMessage& msg, const ShopInfo& item);
        void parseExtendedOpcode(NetworkMessage& msg);
        friend class Player;
        template <typename Callable, typename... Args>
        void addGameTask(Callable&& function, Args&&... args) {
            g_dispatcher.addTask(createTask(std::bind(std::forward<Callable>(function), &g_game, std::forward<Args>(args)...)));
        }
        template <typename Callable, typename... Args>
        void addGameTaskTimed(uint32_t delay, Callable&& function, Args&&... args) {
            g_dispatcher.addTask(createTask(delay, std::bind(std::forward<Callable>(function), &g_game, std::forward<Args>(args)...)));
        }
        static LiveCastsMap liveCasts; ///< Stores all available casts.
        std::atomic<bool> isCaster {false}; ///< Determines if this \ref ProtocolGame object is casting
        uint32_t eventConnect = 0;
        uint32_t challengeTimestamp = 0;
        uint16_t version = CLIENT_VERSION_MIN;
        CastSpectatorVec spectators;
        uint8_t challengeRandom = 0;
        std::string liveCastName;
        std::string liveCastPassword;
};

#endif // FS_PROTOCOLGAME_H_FACA2A2D1A9348B78E8FD7E8003EBB87