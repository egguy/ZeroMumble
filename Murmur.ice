#include <Ice/SliceChecksumDict.ice>
module Murmur
{
["python:seq:tuple"] sequence<byte> NetAddress;
struct User {
int session;
int userid;
bool mute;
bool deaf;
bool suppress;
bool prioritySpeaker;
bool selfMute;
bool selfDeaf;
bool recording;
int channel;
string name;
int onlinesecs;
int bytespersec;
int version;
string release;
string os;
string osversion;
string identity;
string context;
string comment;
NetAddress address;
bool tcponly;
int idlesecs;
};
sequence<int> IntList;
struct Channel {
int id;
string name;
int parent;
IntList links;
string description;
bool temporary;
int position;
};
struct Group {
string name;
bool inherited;
bool inherit;
bool inheritable;
IntList add;
IntList remove;
IntList members;
};
const int PermissionWrite = 0x01;
const int PermissionTraverse = 0x02;
const int PermissionEnter = 0x04;
const int PermissionSpeak = 0x08;
const int PermissionWhisper = 0x100;
const int PermissionMuteDeafen = 0x10;
const int PermissionMove = 0x20;
const int PermissionMakeChannel = 0x40;
const int PermissionMakeTempChannel = 0x400;
const int PermissionLinkChannel = 0x80;
const int PermissionTextMessage = 0x200;
const int PermissionKick = 0x10000;
const int PermissionBan = 0x20000;
const int PermissionRegister = 0x40000;
const int PermissionRegisterSelf = 0x80000;
struct ACL {
bool applyHere;
bool applySubs;
bool inherited;
int userid;
string group;
int allow;
int deny;
};
struct Ban {
NetAddress address;
int bits;
string name;
string hash;
string reason;
int start;
int duration;
};
struct LogEntry {
int timestamp;
string txt;
};
class Tree;
sequence<Tree> TreeList;
enum ChannelInfo { ChannelDescription, ChannelPosition };
enum UserInfo { UserName, UserEmail, UserComment, UserHash, UserPassword, UserLastActive };
dictionary<int, User> UserMap;
dictionary<int, Channel> ChannelMap;
sequence<Channel> ChannelList;
sequence<User> UserList;
sequence<Group> GroupList;
sequence<ACL> ACLList;
sequence<LogEntry> LogList;
sequence<Ban> BanList;
sequence<int> IdList;
sequence<string> NameList;
dictionary<int, string> NameMap;
dictionary<string, int> IdMap;
sequence<byte> Texture;
dictionary<string, string> ConfigMap;
sequence<string> GroupNameList;
sequence<byte> CertificateDer;
sequence<CertificateDer> CertificateList;
dictionary<UserInfo, string> UserInfoMap;
class Tree {
Channel c;
TreeList children;
UserList users;
};
exception MurmurException {};
exception InvalidSessionException extends MurmurException {};
exception InvalidChannelException extends MurmurException {};
exception InvalidServerException extends MurmurException {};
exception ServerBootedException extends MurmurException {};
exception ServerFailureException extends MurmurException {};
exception InvalidUserException extends MurmurException {};
exception InvalidTextureException extends MurmurException {};
exception InvalidCallbackException extends MurmurException {};
exception InvalidSecretException extends MurmurException {};
interface ServerCallback {
idempotent void userConnected(User state);
idempotent void userDisconnected(User state);
idempotent void userStateChanged(User state);
idempotent void channelCreated(Channel state);
idempotent void channelRemoved(Channel state);
idempotent void channelStateChanged(Channel state);
};
const int ContextServer = 0x01;
const int ContextChannel = 0x02;
const int ContextUser = 0x04;
interface ServerContextCallback {
idempotent void contextAction(string action, User usr, int session, int channelid);
};
interface ServerAuthenticator {
idempotent int authenticate(string name, string pw, CertificateList certificates, string certhash, bool certstrong, out string newname, out GroupNameList groups);
idempotent bool getInfo(int id, out UserInfoMap info);
idempotent int nameToId(string name);
idempotent string idToName(int id);
idempotent Texture idToTexture(int id);
};
interface ServerUpdatingAuthenticator extends ServerAuthenticator {
int registerUser(UserInfoMap info);
int unregisterUser(int id);
idempotent NameMap getRegisteredUsers(string filter);
idempotent int setInfo(int id, UserInfoMap info);
idempotent int setTexture(int id, Texture tex);
};
["amd"] interface Server {
idempotent bool isRunning() throws InvalidSecretException;
void start() throws ServerBootedException, ServerFailureException, InvalidSecretException;
void stop() throws ServerBootedException, InvalidSecretException;
void delete() throws ServerBootedException, InvalidSecretException;
idempotent int id() throws InvalidSecretException;
void addCallback(ServerCallback *cb) throws ServerBootedException, InvalidCallbackException, InvalidSecretException;
void removeCallback(ServerCallback *cb) throws ServerBootedException, InvalidCallbackException, InvalidSecretException;
void setAuthenticator(ServerAuthenticator *auth) throws ServerBootedException, InvalidCallbackException, InvalidSecretException;
idempotent string getConf(string key) throws InvalidSecretException;
idempotent ConfigMap getAllConf() throws InvalidSecretException;
idempotent void setConf(string key, string value) throws InvalidSecretException;
idempotent void setSuperuserPassword(string pw) throws InvalidSecretException;
idempotent LogList getLog(int first, int last) throws InvalidSecretException;
idempotent int getLogLen() throws InvalidSecretException;
idempotent UserMap getUsers() throws ServerBootedException, InvalidSecretException;
idempotent ChannelMap getChannels() throws ServerBootedException, InvalidSecretException;
idempotent CertificateList getCertificateList(int session) throws ServerBootedException, InvalidSessionException, InvalidSecretException;
idempotent Tree getTree() throws ServerBootedException, InvalidSecretException;
idempotent BanList getBans() throws ServerBootedException, InvalidSecretException;
idempotent void setBans(BanList bans) throws ServerBootedException, InvalidSecretException;
void kickUser(int session, string reason) throws ServerBootedException, InvalidSessionException, InvalidSecretException;
idempotent User getState(int session) throws ServerBootedException, InvalidSessionException, InvalidSecretException;
idempotent void setState(User state) throws ServerBootedException, InvalidSessionException, InvalidChannelException, InvalidSecretException;
void sendMessage(int session, string text) throws ServerBootedException, InvalidSessionException, InvalidSecretException;
bool hasPermission(int session, int channelid, int perm) throws ServerBootedException, InvalidSessionException, InvalidChannelException, InvalidSecretException;
void addContextCallback(int session, string action, string text, ServerContextCallback *cb, int ctx) throws ServerBootedException, InvalidCallbackException, InvalidSecretException;
void removeContextCallback(ServerContextCallback *cb) throws ServerBootedException, InvalidCallbackException, InvalidSecretException;
idempotent Channel getChannelState(int channelid) throws ServerBootedException, InvalidChannelException, InvalidSecretException;
idempotent void setChannelState(Channel state) throws ServerBootedException, InvalidChannelException, InvalidSecretException;
void removeChannel(int channelid) throws ServerBootedException, InvalidChannelException, InvalidSecretException;
int addChannel(string name, int parent) throws ServerBootedException, InvalidChannelException, InvalidSecretException;
void sendMessageChannel(int channelid, bool tree, string text) throws ServerBootedException, InvalidChannelException, InvalidSecretException;
idempotent void getACL(int channelid, out ACLList acls, out GroupList groups, out bool inherit) throws ServerBootedException, InvalidChannelException, InvalidSecretException;
idempotent void setACL(int channelid, ACLList acls, GroupList groups, bool inherit) throws ServerBootedException, InvalidChannelException, InvalidSecretException;
idempotent void addUserToGroup(int channelid, int session, string group) throws ServerBootedException, InvalidChannelException, InvalidSessionException, InvalidSecretException;
idempotent void removeUserFromGroup(int channelid, int session, string group) throws ServerBootedException, InvalidChannelException, InvalidSessionException, InvalidSecretException;
idempotent void redirectWhisperGroup(int session, string source, string target) throws ServerBootedException, InvalidSessionException, InvalidSecretException;
idempotent NameMap getUserNames(IdList ids) throws ServerBootedException, InvalidSecretException;
idempotent IdMap getUserIds(NameList names) throws ServerBootedException, InvalidSecretException;
int registerUser(UserInfoMap info) throws ServerBootedException, InvalidUserException, InvalidSecretException;
void unregisterUser(int userid) throws ServerBootedException, InvalidUserException, InvalidSecretException;
idempotent void updateRegistration(int userid, UserInfoMap info) throws ServerBootedException, InvalidUserException, InvalidSecretException;
idempotent UserInfoMap getRegistration(int userid) throws ServerBootedException, InvalidUserException, InvalidSecretException;
idempotent NameMap getRegisteredUsers(string filter) throws ServerBootedException, InvalidSecretException;
idempotent int verifyPassword(string name, string pw) throws ServerBootedException, InvalidSecretException;
idempotent Texture getTexture(int userid) throws ServerBootedException, InvalidUserException, InvalidSecretException;
idempotent void setTexture(int userid, Texture tex) throws ServerBootedException, InvalidUserException, InvalidTextureException, InvalidSecretException;
idempotent int getUptime() throws ServerBootedException, InvalidSecretException;
};
interface MetaCallback {
void started(Server *srv);
void stopped(Server *srv);
};
sequence<Server *> ServerList;
["amd"] interface Meta {
idempotent Server *getServer(int id) throws InvalidSecretException;
Server *newServer() throws InvalidSecretException;
idempotent ServerList getBootedServers() throws InvalidSecretException;
idempotent ServerList getAllServers() throws InvalidSecretException;
idempotent ConfigMap getDefaultConf() throws InvalidSecretException;
idempotent void getVersion(out int major, out int minor, out int patch, out string text);
void addCallback(MetaCallback *cb) throws InvalidCallbackException, InvalidSecretException;
void removeCallback(MetaCallback *cb) throws InvalidCallbackException, InvalidSecretException;
idempotent int getUptime();
idempotent string getSlice();
idempotent Ice::SliceChecksumDict getSliceChecksums();
};
};
