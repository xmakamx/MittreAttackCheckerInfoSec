##########################################################################################
# 
# SOC on a Budget - Small Business Companies
# 
# MittreAttackCheckerInfoSecPSSecuritySysMon.ps1
# 
# - Event log threat hunting based on Mittre Attack Framework List
# 
# - Network output folder
# 
# - IP Detection if user is at work
# 
# - Internal and external HTML mail reports (depending if at work or not: ip filters)
# 
# - Local HTML Report
# 
# - Automated install of Sysmon
# 
# - Automated scheduled task creation
# 
# - History on Task Scheduler enabled
# 
# - Active user detection
# 
# - Severity classes (possibly needs adjustments)
# 
# - Event logs: Powershell, Security and Sysmon
# 
# - Summary of results
# 
# - Console version available
# 
# - Php/MySql - WebPage with Autorefresh and search / order functionality
# 
# - Bash script: Automated import of CSV Files put on the network
# 
# Note: not for big companies - the log amount could not be monitored unless you build your custom design.
# 
# MittreAttackCheckerInfoSecPSSecuritySysMon.ps1
# 
# version 2.1
# 
# Written on: 02/02/2020 - Finished on 01/07/2020
# 
# In honor to Black Hills Information Security Attack Tactics
# 
# Techniques from: 'https://attack.mitre.org/'
# 
# Disclaimer: You will be notified if configured ok, but the thread will not be stopped!
# 
# Test-Environment HTML Report (Local Storage C:\Logs) DURATION: 00:00:11.4832781
# 
# Test-Environment Network Share CSV Storing DURATION: 00:00:31.5361025
# 
# Mittre Attack Framework List: (list is not completely processed due to implementation issues - missing approx: 3)
# 
# T1156,T1134,T1134,T1015,T1015,T1087,T1098,T1098,T1182,T1182,T1103,T1103,T1155,T1155,T1017,T1138,T1138,T1010,T1123,T1131,T1119,T1020,T1197,T1197,T1139,T1009,T1067,T1217,T1176,T1110,T1088,T1088,T1191,T1191,T1042,T1146,T1115,T1116,T1059,T1043,T1092,T1500,T1223,T1223,T1109,T1109,T1122,T1122,T1090,T1196,T1196,T1136,T1003,T1081,T1214,T1094,T1024,T1207,T1038,T1038,T1038,T1073,T1002,T1485,T1132,T1022,T1486,T1001,T1074,T1030,T1213,T1005,T1039,T1025,T1491,T1140,T1089,T1488,T1487,T1175,T1172,T1483,T1482,T1189,T1157,T1157,T1173,T1114,T1499,T1480,T1106,T1129,T1048,T1041,T1011,T1052,T1190,T1203,T1212,T1211,T1068,T1210,T1133,T1133,T1181,T1181,T1008,T1107,T1222,T1006,T1044,T1044,T1083,T1495,T1187,T1144,T1061,T1484,T1148,T1200,T1158,T1158,T1147,T1143,T1179,T1179,T1179,T1062,T1183,T1183,T1183,T1054,T1066,T1070,T1202,T1490,T1056,T1056,T1141,T1130,T1118,T1118,T1208,T1215,T1142,T1161,T1149,T1171,T1177,T1177,T1159,T1160,T1160,T1152,T1152,T1152,T1168,T1168,T1162,T1037,T1037,T1185,T1036,T1031,T1112,T1170,T1170,T1104,T1188,T1026,T1079,T1096,T1128,T1498,T1046,T1126,T1135,T1040,T1040,T1050,T1050,T1027,T1137,T1075,T1097,T1174,T1201,T1034,T1034,T1120,T1069,T1150,T1150,T1150,T1205,T1205,T1205,T1013,T1013,T1086,T1145,T1057,T1186,T1093,T1055,T1055,T1012,T1163,T1164,T1108,T1108,T1060,T1121,T1121,T1117,T1117,T1219,T1076,T1105,T1105,T1021,T1018,T1091,T1091,T1496,T1014,T1085,T1085,T1494,T1178,T1198,T1198,T1184,T1053,T1053,T1053,T1029,T1113,T1180,T1064,T1064,T1063,T1101,T1167,T1035,T1058,T1058,T1489,T1166,T1166,T1051,T1023,T1218,T1218,T1216,T1216,T1045,T1153,T1151,T1151,T1193,T1192,T1194,T1071,T1032,T1095,T1165,T1165,T1492,T1169,T1206,T1195,T1019,T1082,T1016,T1049,T1033,T1007,T1124,T1501,T1080,T1221,T1072,T1072,T1209,T1099,T1493,T1154,T1154,T1127,T1127,T1199,T1111,T1065,T1204,T1078,T1078,T1078,T1078,T1125,T1497,T1497,T1102,T1102,T1100,T1100,T1077,T1047,T1084,T1028,T1028,T1004,T1220,T1220
# 
# Weblink: https://www.isee2it.nl/index.php/do-you-see-it-2/27-powershell/89-soc-on-a-budget-smb-mittreattackcheckerinfosecpssecuritysysmon-ps1
#
# Youtube: https://www.youtube.com/watch?v=wuFXgEdB2UE