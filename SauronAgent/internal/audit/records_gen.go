// Code generated from <linux/audit.h>. DO NOT EDIT BY HAND.
//
// Regenerate with: go generate ./internal/audit/...

package audit

// RecordType is a Linux audit record type, matching the netlink message type
// of the record as delivered by the kernel.
//
// The numeric values are generated from <linux/audit.h>. The canonical text
// names (SYSCALL, EXECVE, USER_AUTH, ...) are the same strings auditd writes
// as "type=" in /var/log/audit/audit.log.
type RecordType uint16

const (
	// AUDIT_GET = 1000
	TypeGet RecordType = 1000
	// AUDIT_SET = 1001
	TypeSet RecordType = 1001
	// AUDIT_LIST = 1002
	TypeList RecordType = 1002
	// AUDIT_ADD = 1003
	TypeAdd RecordType = 1003
	// AUDIT_DEL = 1004
	TypeDel RecordType = 1004
	// AUDIT_USER = 1005
	TypeUser RecordType = 1005
	// AUDIT_LOGIN = 1006
	TypeLogin RecordType = 1006
	// AUDIT_WATCH_INS = 1007
	TypeWatchIns RecordType = 1007
	// AUDIT_WATCH_REM = 1008
	TypeWatchRem RecordType = 1008
	// AUDIT_WATCH_LIST = 1009
	TypeWatchList RecordType = 1009
	// AUDIT_SIGNAL_INFO = 1010
	TypeSignalInfo RecordType = 1010
	// AUDIT_ADD_RULE = 1011
	TypeAddRule RecordType = 1011
	// AUDIT_DEL_RULE = 1012
	TypeDelRule RecordType = 1012
	// AUDIT_LIST_RULES = 1013
	TypeListRules RecordType = 1013
	// AUDIT_TRIM = 1014
	TypeTrim RecordType = 1014
	// AUDIT_MAKE_EQUIV = 1015
	TypeMakeEquiv RecordType = 1015
	// AUDIT_TTY_GET = 1016
	TypeTtyGet RecordType = 1016
	// AUDIT_TTY_SET = 1017
	TypeTtySet RecordType = 1017
	// AUDIT_SET_FEATURE = 1018
	TypeSetFeature RecordType = 1018
	// AUDIT_GET_FEATURE = 1019
	TypeGetFeature RecordType = 1019
	// AUDIT_FIRST_USER_MSG = 1100
	TypeFirstUserMsg RecordType = 1100
	// AUDIT_USER_AVC = 1107
	TypeUserAvc RecordType = 1107
	// AUDIT_USER_TTY = 1124
	TypeUserTty RecordType = 1124
	// AUDIT_LAST_USER_MSG = 1199
	TypeLastUserMsg RecordType = 1199
	// AUDIT_FIRST_USER_MSG2 = 2100
	TypeFirstUserMsg2 RecordType = 2100
	// AUDIT_LAST_USER_MSG2 = 2999
	TypeLastUserMsg2 RecordType = 2999
	// AUDIT_DAEMON_START = 1200
	TypeDaemonStart RecordType = 1200
	// AUDIT_DAEMON_END = 1201
	TypeDaemonEnd RecordType = 1201
	// AUDIT_DAEMON_ABORT = 1202
	TypeDaemonAbort RecordType = 1202
	// AUDIT_DAEMON_CONFIG = 1203
	TypeDaemonConfig RecordType = 1203
	// AUDIT_SYSCALL = 1300
	TypeSyscall RecordType = 1300
	// AUDIT_PATH = 1302
	TypePath RecordType = 1302
	// AUDIT_IPC = 1303
	TypeIpc RecordType = 1303
	// AUDIT_SOCKETCALL = 1304
	TypeSocketcall RecordType = 1304
	// AUDIT_CONFIG_CHANGE = 1305
	TypeConfigChange RecordType = 1305
	// AUDIT_SOCKADDR = 1306
	TypeSockaddr RecordType = 1306
	// AUDIT_CWD = 1307
	TypeCwd RecordType = 1307
	// AUDIT_EXECVE = 1309
	TypeExecve RecordType = 1309
	// AUDIT_IPC_SET_PERM = 1311
	TypeIpcSetPerm RecordType = 1311
	// AUDIT_MQ_OPEN = 1312
	TypeMqOpen RecordType = 1312
	// AUDIT_MQ_SENDRECV = 1313
	TypeMqSendrecv RecordType = 1313
	// AUDIT_MQ_NOTIFY = 1314
	TypeMqNotify RecordType = 1314
	// AUDIT_MQ_GETSETATTR = 1315
	TypeMqGetsetattr RecordType = 1315
	// AUDIT_KERNEL_OTHER = 1316
	TypeKernelOther RecordType = 1316
	// AUDIT_FD_PAIR = 1317
	TypeFdPair RecordType = 1317
	// AUDIT_OBJ_PID = 1318
	TypeObjPid RecordType = 1318
	// AUDIT_TTY = 1319
	TypeTty RecordType = 1319
	// AUDIT_EOE = 1320
	TypeEoe RecordType = 1320
	// AUDIT_BPRM_FCAPS = 1321
	TypeBprmFcaps RecordType = 1321
	// AUDIT_CAPSET = 1322
	TypeCapset RecordType = 1322
	// AUDIT_MMAP = 1323
	TypeMmap RecordType = 1323
	// AUDIT_NETFILTER_PKT = 1324
	TypeNetfilterPkt RecordType = 1324
	// AUDIT_NETFILTER_CFG = 1325
	TypeNetfilterCfg RecordType = 1325
	// AUDIT_SECCOMP = 1326
	TypeSeccomp RecordType = 1326
	// AUDIT_PROCTITLE = 1327
	TypeProctitle RecordType = 1327
	// AUDIT_FEATURE_CHANGE = 1328
	TypeFeatureChange RecordType = 1328
	// AUDIT_REPLACE = 1329
	TypeReplace RecordType = 1329
	// AUDIT_KERN_MODULE = 1330
	TypeKernModule RecordType = 1330
	// AUDIT_FANOTIFY = 1331
	TypeFanotify RecordType = 1331
	// AUDIT_TIME_INJOFFSET = 1332
	TypeTimeInjoffset RecordType = 1332
	// AUDIT_TIME_ADJNTPVAL = 1333
	TypeTimeAdjntpval RecordType = 1333
	// AUDIT_BPF = 1334
	TypeBpf RecordType = 1334
	// AUDIT_EVENT_LISTENER = 1335
	TypeEventListener RecordType = 1335
	// AUDIT_URINGOP = 1336
	TypeUringop RecordType = 1336
	// AUDIT_OPENAT2 = 1337
	TypeOpenat2 RecordType = 1337
	// AUDIT_DM_CTRL = 1338
	TypeDmCtrl RecordType = 1338
	// AUDIT_DM_EVENT = 1339
	TypeDmEvent RecordType = 1339
	// AUDIT_AVC = 1400
	TypeAvc RecordType = 1400
	// AUDIT_SELINUX_ERR = 1401
	TypeSelinuxErr RecordType = 1401
	// AUDIT_AVC_PATH = 1402
	TypeAvcPath RecordType = 1402
	// AUDIT_MAC_POLICY_LOAD = 1403
	TypeMacPolicyLoad RecordType = 1403
	// AUDIT_MAC_STATUS = 1404
	TypeMacStatus RecordType = 1404
	// AUDIT_MAC_CONFIG_CHANGE = 1405
	TypeMacConfigChange RecordType = 1405
	// AUDIT_MAC_UNLBL_ALLOW = 1406
	TypeMacUnlblAllow RecordType = 1406
	// AUDIT_MAC_CIPSOV4_ADD = 1407
	TypeMacCipsov4Add RecordType = 1407
	// AUDIT_MAC_CIPSOV4_DEL = 1408
	TypeMacCipsov4Del RecordType = 1408
	// AUDIT_MAC_MAP_ADD = 1409
	TypeMacMapAdd RecordType = 1409
	// AUDIT_MAC_MAP_DEL = 1410
	TypeMacMapDel RecordType = 1410
	// AUDIT_MAC_IPSEC_ADDSA = 1411
	TypeMacIpsecAddsa RecordType = 1411
	// AUDIT_MAC_IPSEC_DELSA = 1412
	TypeMacIpsecDelsa RecordType = 1412
	// AUDIT_MAC_IPSEC_ADDSPD = 1413
	TypeMacIpsecAddspd RecordType = 1413
	// AUDIT_MAC_IPSEC_DELSPD = 1414
	TypeMacIpsecDelspd RecordType = 1414
	// AUDIT_MAC_IPSEC_EVENT = 1415
	TypeMacIpsecEvent RecordType = 1415
	// AUDIT_MAC_UNLBL_STCADD = 1416
	TypeMacUnlblStcadd RecordType = 1416
	// AUDIT_MAC_UNLBL_STCDEL = 1417
	TypeMacUnlblStcdel RecordType = 1417
	// AUDIT_MAC_CALIPSO_ADD = 1418
	TypeMacCalipsoAdd RecordType = 1418
	// AUDIT_MAC_CALIPSO_DEL = 1419
	TypeMacCalipsoDel RecordType = 1419
	// AUDIT_MAC_TASK_CONTEXTS = 1420
	TypeMacTaskContexts RecordType = 1420
	// AUDIT_MAC_OBJ_CONTEXTS = 1421
	TypeMacObjContexts RecordType = 1421
	// AUDIT_FIRST_KERN_ANOM_MSG = 1700
	TypeFirstKernAnomMsg RecordType = 1700
	// AUDIT_LAST_KERN_ANOM_MSG = 1799
	TypeLastKernAnomMsg RecordType = 1799
	// AUDIT_ANOM_PROMISCUOUS = 1700
	TypeAnomPromiscuous RecordType = 1700
	// AUDIT_ANOM_ABEND = 1701
	TypeAnomAbend RecordType = 1701
	// AUDIT_ANOM_LINK = 1702
	TypeAnomLink RecordType = 1702
	// AUDIT_ANOM_CREAT = 1703
	TypeAnomCreat RecordType = 1703
	// AUDIT_INTEGRITY_DATA = 1800
	TypeIntegrityData RecordType = 1800
	// AUDIT_INTEGRITY_METADATA = 1801
	TypeIntegrityMetadata RecordType = 1801
	// AUDIT_INTEGRITY_STATUS = 1802
	TypeIntegrityStatus RecordType = 1802
	// AUDIT_INTEGRITY_HASH = 1803
	TypeIntegrityHash RecordType = 1803
	// AUDIT_INTEGRITY_PCR = 1804
	TypeIntegrityPcr RecordType = 1804
	// AUDIT_INTEGRITY_RULE = 1805
	TypeIntegrityRule RecordType = 1805
	// AUDIT_INTEGRITY_EVM_XATTR = 1806
	TypeIntegrityEvmXattr RecordType = 1806
	// AUDIT_INTEGRITY_POLICY_RULE = 1807
	TypeIntegrityPolicyRule RecordType = 1807
	// AUDIT_KERNEL = 2000
	TypeKernel RecordType = 2000
)

// User-space message types in the AUDIT_FIRST_USER_MSG..AUDIT_LAST_USER_MSG
// range. <linux/audit.h> only defines the range boundaries, so these names
// come from the audit user-space definitions (msg_typetab.h). Types in this
// range that are not listed here still parse correctly; they are reported as
// UNKNOWN[nnnn] and keep their numeric type.
const (
	TypeUserAuth       RecordType = 1100
	TypeUserAcct       RecordType = 1101
	TypeUserMgmt       RecordType = 1102
	TypeCredAcq        RecordType = 1103
	TypeCredDisp       RecordType = 1104
	TypeUserStart      RecordType = 1105
	TypeUserEnd        RecordType = 1106
	TypeUserChauthtok  RecordType = 1108
	TypeUserErr        RecordType = 1109
	TypeCredRefr       RecordType = 1110
	TypeUsysConfig     RecordType = 1111
	TypeUserLogin      RecordType = 1112
	TypeUserLogout     RecordType = 1113
	TypeAddUser        RecordType = 1114
	TypeDelUser        RecordType = 1115
	TypeAddGroup       RecordType = 1116
	TypeDelGroup       RecordType = 1117
	TypeDacCheck       RecordType = 1118
	TypeChgrpID        RecordType = 1119
	TypeTest           RecordType = 1120
	TypeTrustedApp     RecordType = 1121
	TypeUserSelinuxErr RecordType = 1122
	TypeUserCmd        RecordType = 1123
	TypeChuserID       RecordType = 1125
	TypeRoleAssign     RecordType = 1126
	TypeRoleRemove     RecordType = 1127
)

// Anomaly, crypto and virtualisation message types from the second user-space
// range (AUDIT_FIRST_USER_MSG2..AUDIT_LAST_USER_MSG2).
const (
	TypeAnomLoginFailures     RecordType = 2100
	TypeAnomLoginTime         RecordType = 2101
	TypeAnomLoginSessions     RecordType = 2102
	TypeAnomLoginAcct         RecordType = 2103
	TypeAnomLoginLocation     RecordType = 2104
	TypeAnomMaxDac            RecordType = 2105
	TypeAnomMaxMac            RecordType = 2106
	TypeAnomAmtuFail          RecordType = 2107
	TypeAnomRbacFail          RecordType = 2108
	TypeAnomRbacIntegrityFail RecordType = 2109
	TypeAnomCryptoFail        RecordType = 2110
	TypeAnomAccessFs          RecordType = 2111
	TypeAnomExec              RecordType = 2112
	TypeAnomMkExec            RecordType = 2113
	TypeAnomAddAcct           RecordType = 2114
	TypeAnomDelAcct           RecordType = 2115
	TypeAnomModAcct           RecordType = 2116
	TypeAnomRootTrans         RecordType = 2117
	TypeAnomLoginService      RecordType = 2118
	TypeAnomLoginRoot         RecordType = 2119
	TypeAnomOriginFailures    RecordType = 2120
	TypeAnomSession           RecordType = 2121

	TypeCryptoTestUser        RecordType = 2400
	TypeCryptoParamChangeUser RecordType = 2401
	TypeCryptoLogin           RecordType = 2402
	TypeCryptoLogout          RecordType = 2403
	TypeCryptoKeyUser         RecordType = 2404
	TypeCryptoFailureUser     RecordType = 2405
	TypeCryptoReplayUser      RecordType = 2406
	TypeCryptoSession         RecordType = 2407
	TypeCryptoIkeSa           RecordType = 2408
	TypeCryptoIpsecSa         RecordType = 2409

	TypeVirtControl        RecordType = 2500
	TypeVirtResource       RecordType = 2501
	TypeVirtMachineID      RecordType = 2502
	TypeVirtIntegrityCheck RecordType = 2503
	TypeVirtCreate         RecordType = 2504
	TypeVirtDestroy        RecordType = 2505
	TypeVirtMigrateIn      RecordType = 2506
	TypeVirtMigrateOut     RecordType = 2507
)

// AUDIT_NLGRP_READLOG is the netlink multicast group carrying the read-only
// audit log stream. Joining it requires CAP_AUDIT_READ and, unlike becoming
// the audit daemon, does not take ownership of the audit subsystem.
const AUDIT_NLGRP_READLOG = 1

// recordTypeNames maps a record type to the canonical auditd "type=" string.
var recordTypeNames = map[RecordType]string{
	1000: "GET",
	1001: "SET",
	1002: "LIST",
	1003: "ADD",
	1004: "DEL",
	1005: "USER",
	1006: "LOGIN",
	1007: "WATCH_INS",
	1008: "WATCH_REM",
	1009: "WATCH_LIST",
	1010: "SIGNAL_INFO",
	1011: "ADD_RULE",
	1012: "DEL_RULE",
	1013: "LIST_RULES",
	1014: "TRIM",
	1015: "MAKE_EQUIV",
	1016: "TTY_GET",
	1017: "TTY_SET",
	1018: "SET_FEATURE",
	1019: "GET_FEATURE",
	1107: "USER_AVC",
	1124: "USER_TTY",
	1200: "DAEMON_START",
	1201: "DAEMON_END",
	1202: "DAEMON_ABORT",
	1203: "DAEMON_CONFIG",
	1300: "SYSCALL",
	1302: "PATH",
	1303: "IPC",
	1304: "SOCKETCALL",
	1305: "CONFIG_CHANGE",
	1306: "SOCKADDR",
	1307: "CWD",
	1309: "EXECVE",
	1311: "IPC_SET_PERM",
	1312: "MQ_OPEN",
	1313: "MQ_SENDRECV",
	1314: "MQ_NOTIFY",
	1315: "MQ_GETSETATTR",
	1316: "KERNEL_OTHER",
	1317: "FD_PAIR",
	1318: "OBJ_PID",
	1319: "TTY",
	1320: "EOE",
	1321: "BPRM_FCAPS",
	1322: "CAPSET",
	1323: "MMAP",
	1324: "NETFILTER_PKT",
	1325: "NETFILTER_CFG",
	1326: "SECCOMP",
	1327: "PROCTITLE",
	1328: "FEATURE_CHANGE",
	1329: "REPLACE",
	1330: "KERN_MODULE",
	1331: "FANOTIFY",
	1332: "TIME_INJOFFSET",
	1333: "TIME_ADJNTPVAL",
	1334: "BPF",
	1335: "EVENT_LISTENER",
	1336: "URINGOP",
	1337: "OPENAT2",
	1338: "DM_CTRL",
	1339: "DM_EVENT",
	1400: "AVC",
	1401: "SELINUX_ERR",
	1402: "AVC_PATH",
	1403: "MAC_POLICY_LOAD",
	1404: "MAC_STATUS",
	1405: "MAC_CONFIG_CHANGE",
	1406: "MAC_UNLBL_ALLOW",
	1407: "MAC_CIPSOV4_ADD",
	1408: "MAC_CIPSOV4_DEL",
	1409: "MAC_MAP_ADD",
	1410: "MAC_MAP_DEL",
	1411: "MAC_IPSEC_ADDSA",
	1412: "MAC_IPSEC_DELSA",
	1413: "MAC_IPSEC_ADDSPD",
	1414: "MAC_IPSEC_DELSPD",
	1415: "MAC_IPSEC_EVENT",
	1416: "MAC_UNLBL_STCADD",
	1417: "MAC_UNLBL_STCDEL",
	1418: "MAC_CALIPSO_ADD",
	1419: "MAC_CALIPSO_DEL",
	1420: "MAC_TASK_CONTEXTS",
	1421: "MAC_OBJ_CONTEXTS",
	1700: "ANOM_PROMISCUOUS",
	1701: "ANOM_ABEND",
	1702: "ANOM_LINK",
	1703: "ANOM_CREAT",
	1800: "INTEGRITY_DATA",
	1801: "INTEGRITY_METADATA",
	1802: "INTEGRITY_STATUS",
	1803: "INTEGRITY_HASH",
	1804: "INTEGRITY_PCR",
	1805: "INTEGRITY_RULE",
	1806: "INTEGRITY_EVM_XATTR",
	1807: "INTEGRITY_POLICY_RULE",
	2000: "KERNEL",
	1100: "USER_AUTH",
	1101: "USER_ACCT",
	1102: "USER_MGMT",
	1103: "CRED_ACQ",
	1104: "CRED_DISP",
	1105: "USER_START",
	1106: "USER_END",
	1108: "USER_CHAUTHTOK",
	1109: "USER_ERR",
	1110: "CRED_REFR",
	1111: "USYS_CONFIG",
	1112: "USER_LOGIN",
	1113: "USER_LOGOUT",
	1114: "ADD_USER",
	1115: "DEL_USER",
	1116: "ADD_GROUP",
	1117: "DEL_GROUP",
	1118: "DAC_CHECK",
	1119: "CHGRP_ID",
	1120: "TEST",
	1121: "TRUSTED_APP",
	1122: "USER_SELINUX_ERR",
	1123: "USER_CMD",
	1125: "CHUSER_ID",
	1126: "ROLE_ASSIGN",
	1127: "ROLE_REMOVE",
	2100: "ANOM_LOGIN_FAILURES",
	2101: "ANOM_LOGIN_TIME",
	2102: "ANOM_LOGIN_SESSIONS",
	2103: "ANOM_LOGIN_ACCT",
	2104: "ANOM_LOGIN_LOCATION",
	2105: "ANOM_MAX_DAC",
	2106: "ANOM_MAX_MAC",
	2107: "ANOM_AMTU_FAIL",
	2108: "ANOM_RBAC_FAIL",
	2109: "ANOM_RBAC_INTEGRITY_FAIL",
	2110: "ANOM_CRYPTO_FAIL",
	2111: "ANOM_ACCESS_FS",
	2112: "ANOM_EXEC",
	2113: "ANOM_MK_EXEC",
	2114: "ANOM_ADD_ACCT",
	2115: "ANOM_DEL_ACCT",
	2116: "ANOM_MOD_ACCT",
	2117: "ANOM_ROOT_TRANS",
	2118: "ANOM_LOGIN_SERVICE",
	2119: "ANOM_LOGIN_ROOT",
	2120: "ANOM_ORIGIN_FAILURES",
	2121: "ANOM_SESSION",
	2400: "CRYPTO_TEST_USER",
	2401: "CRYPTO_PARAM_CHANGE_USER",
	2402: "CRYPTO_LOGIN",
	2403: "CRYPTO_LOGOUT",
	2404: "CRYPTO_KEY_USER",
	2405: "CRYPTO_FAILURE_USER",
	2406: "CRYPTO_REPLAY_USER",
	2407: "CRYPTO_SESSION",
	2408: "CRYPTO_IKE_SA",
	2409: "CRYPTO_IPSEC_SA",
	2500: "VIRT_CONTROL",
	2501: "VIRT_RESOURCE",
	2502: "VIRT_MACHINE_ID",
	2503: "VIRT_INTEGRITY_CHECK",
	2504: "VIRT_CREATE",
	2505: "VIRT_DESTROY",
	2506: "VIRT_MIGRATE_IN",
	2507: "VIRT_MIGRATE_OUT",
}
