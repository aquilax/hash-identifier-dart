/// Supported hashing algorithms
enum Hash {
  CRC_16,
  CRC_16_CCITT,
  FCS_16,
  Adler_32,
  CRC_32B,
  FCS_32,
  GHash_32_3,
  GHash_32_5,
  FNV_132,
  Fletcher_32,
  Joaat,
  ELF_32,
  XOR_32,
  CRC_24,
  CRC_32,
  Eggdrop_IRC_Bot,
  DES_Unix,
  Traditional_DES,
  DEScrypt,
  MySQL323,
  DES_Oracle,
  Half_MD5,
  Oracle_7_10g,
  FNV_164,
  CRC_64,
  Cisco_PIX_MD5,
  Lotus_Notes_Domino_6,
  BSDi_Crypt,
  CRC_96_ZIP,
  Crypt16,
  MD2,
  MD5,
  MD4,
  Double_MD5,
  LM,
  RIPEMD_128,
  Haval_128,
  Tiger_128,
  Skein_256_128,
  Skein_512_128,
  Lotus_Notes_Domino_5,
  Skype,
  ZipMonster,
  PrestaShop,
  Md5_md5_md5_pass,
  Md5_strtoupper_md5_pass,
  Md5_sha1_pass,
  Md5_pass_salt,
  Md5_salt_pass,
  Md5_unicode_pass_salt,
  Md5_salt_unicode_pass,
  HMAC_MD5_key_pass,
  HMAC_MD5_key_salt,
  Md5_md5_salt_pass,
  Md5_salt_md5_pass,
  Md5_pass_md5_salt,
  Md5_salt_pass_salt,
  Md5_md5_pass_md5_salt,
  Md5_salt_md5_salt_pass,
  Md5_salt_md5_pass_salt,
  Md5_username_0_pass,
  Snefru_128,
  NTLM,
  Domain_Cached_Credentials,
  Domain_Cached_Credentials_2,
  SHA_1_Base64,
  Netscape_LDAP_SHA,
  MD5_Crypt,
  Cisco_IOS_MD5,
  FreeBSD_MD5,
  Lineage_II_C4,
  PhpBB_v3_x,
  Wordpress_v2_6_0_2_6_1,
  PHPass_Portable_Hash,
  Wordpress_v2_6_2,
  OsCommerce,
  Xt_Commerce,
  MD5_APR,
  Apache_MD5,
  Md5apr1,
  AIX_smd5,
  WebEdition_CMS,
  IP_Board_v2,
  MyBB_v1_2,
  CryptoCurrency_Adress,
  SHA_1,
  Double_SHA_1,
  RIPEMD_160,
  Haval_160,
  Tiger_160,
  HAS_160,
  LinkedIn,
  Skein_256_160,
  Skein_512_160,
  MangosWeb_Enhanced_CMS,
  Sha1_sha1_sha1_pass,
  Sha1_md5_pass,
  Sha1_pass_salt,
  Sha1_salt_pass,
  Sha1_unicode_pass_salt,
  Sha1_salt_unicode_pass,
  HMAC_SHA1_key_pass,
  HMAC_SHA1_key_salt,
  Sha1_salt_pass_salt,
  MySQL5_x,
  MySQL4_1,
  Cisco_IOS_SHA_256,
  SSHA_1_Base64,
  Netscape_LDAP_SSHA,
  Nsldaps,
  Fortigate_FortiOS,
  Haval_192,
  Tiger_192,
  SHA_1_Oracle,
  OSX_v10_4,
  OSX_v10_5,
  OSX_v10_6,
  Palshop_CMS,
  CryptoCurrency_PrivateKey,
  AIX_ssha1,
  MSSQL_2005,
  MSSQL_2008,
  Sun_MD5_Crypt,
  SHA_224,
  Haval_224,
  SHA3_224,
  Skein_256_224,
  Skein_512_224,
  Blowfish_OpenBSD,
  Woltlab_Burning_Board_4_x,
  Bcrypt,
  Android_PIN,
  Oracle_11g_12c,
  Bcrypt_SHA_256,
  VBulletin_v3_8_5,
  Snefru_256,
  SHA_256,
  RIPEMD_256,
  Haval_256,
  GOST_R_34_11_94,
  GOST_CryptoPro_S_Box,
  SHA3_256,
  Skein_256,
  Skein_512_256,
  Ventrilo,
  Sha256_pass_salt,
  Sha256_salt_pass,
  Sha256_unicode_pass_salt,
  Sha256_salt_unicode_pass,
  HMAC_SHA256_key_pass,
  HMAC_SHA256_key_salt,
  Joomla_v2_5_18,
  SAM_LM_Hash_NT_Hash,
  MD5_Chap,
  ISCSI_CHAP_Authentication,
  EPiServer_6_x_v4,
  AIX_ssha256,
  RIPEMD_320,
  MSSQL_2000,
  SHA_384,
  SHA3_384,
  Skein_512_384,
  Skein_1024_384,
  SSHA_512_Base64,
  LDAP_SSHA_512,
  AIX_ssha512,
  SHA_512,
  Whirlpool,
  Salsa10,
  Salsa20,
  SHA3_512,
  Skein_512,
  Skein_1024_512,
  Sha512_pass_salt,
  Sha512_salt_pass,
  Sha512_unicode_pass_salt,
  Sha512_salt_unicode_pass,
  HMAC_SHA512_key_pass,
  HMAC_SHA512_key_salt,
  OSX_v10_7,
  MSSQL_2012,
  MSSQL_2014,
  OSX_v10_8,
  OSX_v10_9,
  Skein_1024,
  GRUB_2,
  Django_SHA_1,
  Citrix_Netscaler,
  Drupal_v7_x,
  SHA_256_Crypt,
  Sybase_ASE,
  SHA_512_Crypt,
  Minecraft_AuthMe_Reloaded,
  Django_SHA_256,
  Django_SHA_384,
  Clavister_Secure_Gateway,
  Cisco_VPN_Client_PCF_File,
  Microsoft_MSTSC_RDP_File,
  NetNTLMv1_VANILLA_NetNTLMv1_ESS,
  NetNTLMv2,
  Kerberos_5_AS_REQ_Pre_Auth,
  SCRAM_Hash,
  Redmine_Project_Management_Web_App,
  SAP_CODVN_B_BCODE,
  SAP_CODVN_F_G_PASSCODE,
  Juniper_Netscreen_SSG_ScreenOS,
  EPi,
  SMF_v1_1,
  Woltlab_Burning_Board_3_x,
  IPMI2_RAKP_HMAC_SHA1,
  Lastpass,
  Cisco_ASA_MD5,
  VNC,
  DNSSEC_NSEC3,
  RACF,
  NTHash_FreeBSD_Variant,
  SHA_1_Crypt,
  HMailServer,
  MediaWiki,
  Minecraft_xAuth,
  PBKDF2_SHA1_Generic,
  PBKDF2_SHA256_Generic,
  PBKDF2_SHA512_Generic,
  PBKDF2_Cryptacular,
  PBKDF2_Dwayne_Litzenberger,
  Fairly_Secure_Hashed_Password,
  PHPS,
  OnePassword_Agile_Keychain,
  OnePassword_Cloud_Keychain,
  IKE_PSK_MD5,
  IKE_PSK_SHA1,
  PeopleSoft,
  Django_DES_Crypt_Wrapper,
  Django_PBKDF2_HMAC_SHA256,
  Django_PBKDF2_HMAC_SHA1,
  Django_bcrypt,
  Django_MD5,
  PBKDF2_Atlassian,
  PostgreSQL_MD5,
  Lotus_Notes_Domino_8,
  Scrypt,
  Cisco_Type_8,
  Cisco_Type_9,
  Microsoft_Office_2007,
  Microsoft_Office_2010,
  Microsoft_Office_2013,
  Android_FDE_4_3,
  Microsoft_Office_2003_MD5_RC4,
  Microsoft_Office_2003_MD5_RC4_collider_mode_1,
  Microsoft_Office_2003_MD5_RC4_collider_mode_2,
  Microsoft_Office_2003_SHA1_RC4,
  Microsoft_Office_2003_SHA1_RC4_collider_mode_1,
  Microsoft_Office_2003_SHA1_RC4_collider_mode_2,
  RAdmin_v2_x,
  SAP_CODVN_H_PWDSALTEDHASH_iSSHA_1,
  CRAM_MD5,
  SipHash,
  Cisco_Type_7,
  BigCrypt,
  Cisco_Type_4,
  Django_bcrypt_SHA256,
  PostgreSQL_Challenge_Response_Authentication_MD5,
  Siemens_S7,
  Microsoft_Outlook_PST,
  PBKDF2_HMAC_SHA256_PHP,
  Dahua,
  MySQL_Challenge_Response_Authentication_SHA1,
  PDF_1_4_1_6_Acrobat_5_8,
}

/// Names of the supported hashing algorithms
Map<Hash, String> names = {
  Hash.CRC_16: r'CRC-16',
  Hash.CRC_16_CCITT: r'CRC-16-CCITT',
  Hash.FCS_16: r'FCS-16',
  Hash.Adler_32: r'Adler-32',
  Hash.CRC_32B: r'CRC-32B',
  Hash.FCS_32: r'FCS-32',
  Hash.GHash_32_3: r'GHash-32-3',
  Hash.GHash_32_5: r'GHash-32-5',
  Hash.FNV_132: r'FNV-132',
  Hash.Fletcher_32: r'Fletcher-32',
  Hash.Joaat: r'Joaat',
  Hash.ELF_32: r'ELF-32',
  Hash.XOR_32: r'XOR-32',
  Hash.CRC_24: r'CRC-24',
  Hash.CRC_32: r'CRC-32',
  Hash.Eggdrop_IRC_Bot: r'Eggdrop IRC Bot',
  Hash.DES_Unix: r'DES(Unix)',
  Hash.Traditional_DES: r'Traditional DES',
  Hash.DEScrypt: r'DEScrypt',
  Hash.MySQL323: r'MySQL323',
  Hash.DES_Oracle: r'DES(Oracle)',
  Hash.Half_MD5: r'Half MD5',
  Hash.Oracle_7_10g: r'Oracle 7-10g',
  Hash.FNV_164: r'FNV-164',
  Hash.CRC_64: r'CRC-64',
  Hash.Cisco_PIX_MD5: r'Cisco-PIX(MD5)',
  Hash.Lotus_Notes_Domino_6: r'Lotus Notes/Domino 6',
  Hash.BSDi_Crypt: r'BSDi Crypt',
  Hash.CRC_96_ZIP: r'CRC-96(ZIP)',
  Hash.Crypt16: r'Crypt16',
  Hash.MD2: r'MD2',
  Hash.MD5: r'MD5',
  Hash.MD4: r'MD4',
  Hash.Double_MD5: r'Double MD5',
  Hash.LM: r'LM',
  Hash.RIPEMD_128: r'RIPEMD-128',
  Hash.Haval_128: r'Haval-128',
  Hash.Tiger_128: r'Tiger-128',
  Hash.Skein_256_128: r'Skein-256(128)',
  Hash.Skein_512_128: r'Skein-512(128)',
  Hash.Lotus_Notes_Domino_5: r'Lotus Notes/Domino 5',
  Hash.Skype: r'Skype',
  Hash.ZipMonster: r'ZipMonster',
  Hash.PrestaShop: r'PrestaShop',
  Hash.Md5_md5_md5_pass: r'md5(md5(md5($pass)))',
  Hash.Md5_strtoupper_md5_pass: r'md5(strtoupper(md5($pass)))',
  Hash.Md5_sha1_pass: r'md5(sha1($pass))',
  Hash.Md5_pass_salt: r'md5($pass.$salt)',
  Hash.Md5_salt_pass: r'md5($salt.$pass)',
  Hash.Md5_unicode_pass_salt: r'md5(unicode($pass).$salt)',
  Hash.Md5_salt_unicode_pass: r'md5($salt.unicode($pass))',
  Hash.HMAC_MD5_key_pass: r'HMAC-MD5 (key = $pass)',
  Hash.HMAC_MD5_key_salt: r'HMAC-MD5 (key = $salt)',
  Hash.Md5_md5_salt_pass: r'md5(md5($salt).$pass)',
  Hash.Md5_salt_md5_pass: r'md5($salt.md5($pass))',
  Hash.Md5_pass_md5_salt: r'md5($pass.md5($salt))',
  Hash.Md5_salt_pass_salt: r'md5($salt.$pass.$salt)',
  Hash.Md5_md5_pass_md5_salt: r'md5(md5($pass).md5($salt))',
  Hash.Md5_salt_md5_salt_pass: r'md5($salt.md5($salt.$pass))',
  Hash.Md5_salt_md5_pass_salt: r'md5($salt.md5($pass.$salt))',
  Hash.Md5_username_0_pass: r'md5($username.0.$pass)',
  Hash.Snefru_128: r'Snefru-128',
  Hash.NTLM: r'NTLM',
  Hash.Domain_Cached_Credentials: r'Domain Cached Credentials',
  Hash.Domain_Cached_Credentials_2: r'Domain Cached Credentials 2',
  Hash.SHA_1_Base64: r'SHA-1(Base64)',
  Hash.Netscape_LDAP_SHA: r'Netscape LDAP SHA',
  Hash.MD5_Crypt: r'MD5 Crypt',
  Hash.Cisco_IOS_MD5: r'Cisco-IOS(MD5)',
  Hash.FreeBSD_MD5: r'FreeBSD MD5',
  Hash.Lineage_II_C4: r'Lineage II C4',
  Hash.PhpBB_v3_x: r'phpBB v3.x',
  Hash.Wordpress_v2_6_0_2_6_1: r'Wordpress v2.6.0/2.6.1',
  Hash.PHPass_Portable_Hash: r"PHPass' Portable Hash",
  Hash.Wordpress_v2_6_2: r'Wordpress ≥ v2.6.2',
  Hash.Joomla_v2_5_18: r'Joomla < v2.5.18',
  Hash.OsCommerce: r'osCommerce',
  Hash.Xt_Commerce: r'xt:Commerce',
  Hash.MD5_APR: r'MD5(APR)',
  Hash.Apache_MD5: r'Apache MD5',
  Hash.Md5apr1: r'md5apr1',
  Hash.AIX_smd5: r'AIX(smd5)',
  Hash.WebEdition_CMS: r'WebEdition CMS',
  Hash.IP_Board_v2: r'IP.Board ≥ v2+',
  Hash.MyBB_v1_2: r'MyBB ≥ v1.2+',
  Hash.CryptoCurrency_Adress: r'CryptoCurrency(Adress)',
  Hash.SHA_1: r'SHA-1',
  Hash.Double_SHA_1: r'Double SHA-1',
  Hash.RIPEMD_160: r'RIPEMD-160',
  Hash.Haval_160: r'Haval-160',
  Hash.Tiger_160: r'Tiger-160',
  Hash.HAS_160: r'HAS-160',
  Hash.LinkedIn: r'LinkedIn',
  Hash.Skein_256_160: r'Skein-256(160)',
  Hash.Skein_512_160: r'Skein-512(160)',
  Hash.MangosWeb_Enhanced_CMS: r'MangosWeb Enhanced CMS',
  Hash.Sha1_sha1_sha1_pass: r'sha1(sha1(sha1($pass)))',
  Hash.Sha1_md5_pass: r'sha1(md5($pass))',
  Hash.Sha1_pass_salt: r'sha1($pass.$salt)',
  Hash.Sha1_salt_pass: r'sha1($salt.$pass)',
  Hash.Sha1_unicode_pass_salt: r'sha1(unicode($pass).$salt)',
  Hash.Sha1_salt_unicode_pass: r'sha1($salt.unicode($pass))',
  Hash.HMAC_SHA1_key_pass: r'HMAC-SHA1 (key = $pass)',
  Hash.HMAC_SHA1_key_salt: r'HMAC-SHA1 (key = $salt)',
  Hash.Sha1_salt_pass_salt: r'sha1($salt.$pass.$salt)',
  Hash.MySQL5_x: r'MySQL5.x',
  Hash.MySQL4_1: r'MySQL4.1',
  Hash.Cisco_IOS_SHA_256: r'Cisco-IOS(SHA-256)',
  Hash.SSHA_1_Base64: r'SSHA-1(Base64)',
  Hash.Netscape_LDAP_SSHA: r'Netscape LDAP SSHA',
  Hash.Nsldaps: r'nsldaps',
  Hash.Fortigate_FortiOS: r'Fortigate(FortiOS)',
  Hash.Haval_192: r'Haval-192',
  Hash.Tiger_192: r'Tiger-192',
  Hash.SHA_1_Oracle: r'SHA-1(Oracle)',
  Hash.OSX_v10_4: r'OSX v10.4',
  Hash.OSX_v10_5: r'OSX v10.5',
  Hash.OSX_v10_6: r'OSX v10.6',
  Hash.Palshop_CMS: r'Palshop CMS',
  Hash.CryptoCurrency_PrivateKey: r'CryptoCurrency(PrivateKey)',
  Hash.AIX_ssha1: r'AIX(ssha1)',
  Hash.MSSQL_2005: r'MSSQL(2005)',
  Hash.MSSQL_2008: r'MSSQL(2008)',
  Hash.Sun_MD5_Crypt: r'Sun MD5 Crypt',
  Hash.SHA_224: r'SHA-224',
  Hash.Haval_224: r'Haval-224',
  Hash.SHA3_224: r'SHA3-224',
  Hash.Skein_256_224: r'Skein-256(224)',
  Hash.Skein_512_224: r'Skein-512(224)',
  Hash.Blowfish_OpenBSD: r'Blowfish(OpenBSD)',
  Hash.Woltlab_Burning_Board_4_x: r'Woltlab Burning Board 4.x',
  Hash.Bcrypt: r'bcrypt',
  Hash.Android_PIN: r'Android PIN',
  Hash.Oracle_11g_12c: r'Oracle 11g/12c',
  Hash.Bcrypt_SHA_256: r'bcrypt(SHA-256)',
  Hash.VBulletin_v3_8_5: r'vBulletin ≥ v3.8.5',
  Hash.Snefru_256: r'Snefru-256',
  Hash.SHA_256: r'SHA-256',
  Hash.RIPEMD_256: r'RIPEMD-256',
  Hash.Haval_256: r'Haval-256',
  Hash.GOST_R_34_11_94: r'GOST R 34.11-94',
  Hash.GOST_CryptoPro_S_Box: r'GOST CryptoPro S-Box',
  Hash.SHA3_256: r'SHA3-256',
  Hash.Skein_256: r'Skein-256',
  Hash.Skein_512_256: r'Skein-512(256)',
  Hash.Ventrilo: r'Ventrilo',
  Hash.Sha256_pass_salt: r'sha256($pass.$salt)',
  Hash.Sha256_salt_pass: r'sha256($salt.$pass)',
  Hash.Sha256_unicode_pass_salt: r'sha256(unicode($pass).$salt)',
  Hash.Sha256_salt_unicode_pass: r'sha256($salt.unicode($pass))',
  Hash.HMAC_SHA256_key_pass: r'HMAC-SHA256 (key = $pass)',
  Hash.HMAC_SHA256_key_salt: r'HMAC-SHA256 (key = $salt)',
  Hash.SAM_LM_Hash_NT_Hash: r'SAM(LM_Hash:NT_Hash)',
  Hash.MD5_Chap: r'MD5(Chap)',
  Hash.ISCSI_CHAP_Authentication: r'iSCSI CHAP Authentication',
  Hash.EPiServer_6_x_v4: r'EPiServer 6.x ≥ v4',
  Hash.AIX_ssha256: r'AIX(ssha256)',
  Hash.RIPEMD_320: r'RIPEMD-320',
  Hash.MSSQL_2000: r'MSSQL(2000)',
  Hash.SHA_384: r'SHA-384',
  Hash.SHA3_384: r'SHA3-384',
  Hash.Skein_512_384: r'Skein-512(384)',
  Hash.Skein_1024_384: r'Skein-1024(384)',
  Hash.SSHA_512_Base64: r'SSHA-512(Base64)',
  Hash.LDAP_SSHA_512: r'LDAP(SSHA-512)',
  Hash.AIX_ssha512: r'AIX(ssha512)',
  Hash.SHA_512: r'SHA-512',
  Hash.Whirlpool: r'Whirlpool',
  Hash.Salsa10: r'Salsa10',
  Hash.Salsa20: r'Salsa20',
  Hash.SHA3_512: r'SHA3-512',
  Hash.Skein_512: r'Skein-512',
  Hash.Skein_1024_512: r'Skein-1024(512)',
  Hash.Sha512_pass_salt: r'sha512($pass.$salt)',
  Hash.Sha512_salt_pass: r'sha512($salt.$pass)',
  Hash.Sha512_unicode_pass_salt: r'sha512(unicode($pass).$salt)',
  Hash.Sha512_salt_unicode_pass: r'sha512($salt.unicode($pass))',
  Hash.HMAC_SHA512_key_pass: r'HMAC-SHA512 (key = $pass)',
  Hash.HMAC_SHA512_key_salt: r'HMAC-SHA512 (key = $salt)',
  Hash.OSX_v10_7: r'OSX v10.7',
  Hash.MSSQL_2012: r'MSSQL(2012)',
  Hash.MSSQL_2014: r'MSSQL(2014)',
  Hash.OSX_v10_8: r'OSX v10.8',
  Hash.OSX_v10_9: r'OSX v10.9',
  Hash.Skein_1024: r'Skein-1024',
  Hash.GRUB_2: r'GRUB 2',
  Hash.Django_SHA_1: r'Django(SHA-1)',
  Hash.Citrix_Netscaler: r'Citrix Netscaler',
  Hash.Drupal_v7_x: r'Drupal > v7.x',
  Hash.SHA_256_Crypt: r'SHA-256 Crypt',
  Hash.Sybase_ASE: r'Sybase ASE',
  Hash.SHA_512_Crypt: r'SHA-512 Crypt',
  Hash.Minecraft_AuthMe_Reloaded: r'Minecraft(AuthMe Reloaded)',
  Hash.Django_SHA_256: r'Django(SHA-256)',
  Hash.Django_SHA_384: r'Django(SHA-384)',
  Hash.Clavister_Secure_Gateway: r'Clavister Secure Gateway',
  Hash.Cisco_VPN_Client_PCF_File: r'Cisco VPN Client(PCF-File)',
  Hash.Microsoft_MSTSC_RDP_File: r'Microsoft MSTSC(RDP-File)',
  Hash.NetNTLMv1_VANILLA_NetNTLMv1_ESS: r'NetNTLMv1-VANILLA / NetNTLMv1+ESS',
  Hash.NetNTLMv2: r'NetNTLMv2',
  Hash.Kerberos_5_AS_REQ_Pre_Auth: r'Kerberos 5 AS-REQ Pre-Auth',
  Hash.SCRAM_Hash: r'SCRAM Hash',
  Hash.Redmine_Project_Management_Web_App:
      r'Redmine Project Management Web App',
  Hash.SAP_CODVN_B_BCODE: r'SAP CODVN B (BCODE)',
  Hash.SAP_CODVN_F_G_PASSCODE: r'SAP CODVN F/G (PASSCODE)',
  Hash.Juniper_Netscreen_SSG_ScreenOS: r'Juniper Netscreen/SSG(ScreenOS)',
  Hash.EPi: r'EPi',
  Hash.SMF_v1_1: r'SMF ≥ v1.1',
  Hash.Woltlab_Burning_Board_3_x: r'Woltlab Burning Board 3.x',
  Hash.IPMI2_RAKP_HMAC_SHA1: r'IPMI2 RAKP HMAC-SHA1',
  Hash.Lastpass: r'Lastpass',
  Hash.Cisco_ASA_MD5: r'Cisco-ASA(MD5)',
  Hash.VNC: r'VNC',
  Hash.DNSSEC_NSEC3: r'DNSSEC(NSEC3)',
  Hash.RACF: r'RACF',
  Hash.NTHash_FreeBSD_Variant: r'NTHash(FreeBSD Variant)',
  Hash.SHA_1_Crypt: r'SHA-1 Crypt',
  Hash.HMailServer: r'hMailServer',
  Hash.MediaWiki: r'MediaWiki',
  Hash.Minecraft_xAuth: r'Minecraft(xAuth)',
  Hash.PBKDF2_SHA1_Generic: r'PBKDF2-SHA1(Generic)',
  Hash.PBKDF2_SHA256_Generic: r'PBKDF2-SHA256(Generic)',
  Hash.PBKDF2_SHA512_Generic: r'PBKDF2-SHA512(Generic)',
  Hash.PBKDF2_Cryptacular: r'PBKDF2(Cryptacular)',
  Hash.PBKDF2_Dwayne_Litzenberger: r'PBKDF2(Dwayne Litzenberger)',
  Hash.Fairly_Secure_Hashed_Password: r'Fairly Secure Hashed Password',
  Hash.PHPS: r'PHPS',
  Hash.OnePassword_Agile_Keychain: r'1Password(Agile Keychain)',
  Hash.OnePassword_Cloud_Keychain: r'1Password(Cloud Keychain)',
  Hash.IKE_PSK_MD5: r'IKE-PSK MD5',
  Hash.IKE_PSK_SHA1: r'IKE-PSK SHA1',
  Hash.PeopleSoft: r'PeopleSoft',
  Hash.Django_DES_Crypt_Wrapper: r'Django(DES Crypt Wrapper)',
  Hash.Django_PBKDF2_HMAC_SHA256: r'Django(PBKDF2-HMAC-SHA256)',
  Hash.Django_PBKDF2_HMAC_SHA1: r'Django(PBKDF2-HMAC-SHA1)',
  Hash.Django_bcrypt: r'Django(bcrypt)',
  Hash.Django_MD5: r'Django(MD5)',
  Hash.PBKDF2_Atlassian: r'PBKDF2(Atlassian)',
  Hash.PostgreSQL_MD5: r'PostgreSQL MD5',
  Hash.Lotus_Notes_Domino_8: r'Lotus Notes/Domino 8',
  Hash.Scrypt: r'scrypt',
  Hash.Cisco_Type_8: r'Cisco Type 8',
  Hash.Cisco_Type_9: r'Cisco Type 9',
  Hash.Microsoft_Office_2007: r'Microsoft Office 2007',
  Hash.Microsoft_Office_2010: r'Microsoft Office 2010',
  Hash.Microsoft_Office_2013: r'Microsoft Office 2013',
  Hash.Android_FDE_4_3: r'Android FDE ≤ 4.3',
  Hash.Microsoft_Office_2003_MD5_RC4: r'Microsoft Office ≤ 2003 (MD5+RC4)',
  Hash.Microsoft_Office_2003_MD5_RC4_collider_mode_1:
      r'Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #1',
  Hash.Microsoft_Office_2003_MD5_RC4_collider_mode_2:
      r'Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #2',
  Hash.Microsoft_Office_2003_SHA1_RC4: r'Microsoft Office ≤ 2003 (SHA1+RC4)',
  Hash.Microsoft_Office_2003_SHA1_RC4_collider_mode_1:
      r'Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #1',
  Hash.Microsoft_Office_2003_SHA1_RC4_collider_mode_2:
      r'Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #2',
  Hash.RAdmin_v2_x: r'RAdmin v2.x',
  Hash.SAP_CODVN_H_PWDSALTEDHASH_iSSHA_1:
      r'SAP CODVN H (PWDSALTEDHASH) iSSHA-1',
  Hash.CRAM_MD5: r'CRAM-MD5',
  Hash.SipHash: r'SipHash',
  Hash.Cisco_Type_7: r'Cisco Type 7',
  Hash.BigCrypt: r'BigCrypt',
  Hash.Cisco_Type_4: r'Cisco Type 4',
  Hash.Django_bcrypt_SHA256: r'Django(bcrypt-SHA256)',
  Hash.PostgreSQL_Challenge_Response_Authentication_MD5:
      r'PostgreSQL Challenge-Response Authentication (MD5)',
  Hash.Siemens_S7: r'Siemens-S7',
  Hash.Microsoft_Outlook_PST: r'Microsoft Outlook PST',
  Hash.PBKDF2_HMAC_SHA256_PHP: r'PBKDF2-HMAC-SHA256(PHP)',
  Hash.Dahua: r'Dahua',
  Hash.MySQL_Challenge_Response_Authentication_SHA1:
      r'MySQL Challenge-Response Authentication (SHA1)',
  Hash.PDF_1_4_1_6_Acrobat_5_8: r'PDF 1.4 - 1.6 (Acrobat 5 - 8)',
};

/// Hashing algorithm details
class HashInfo {
  final Hash id;
  final String? hashcat;
  final String? john;
  final bool extended;

  const HashInfo(
      {required this.id, this.hashcat, this.john, required this.extended});

  @override
  String toString() {
    return getName(id);
  }
}

/// Hashing matcher set
class Prototype {
  final RegExp exp;
  final List<HashInfo> modes;

  const Prototype(this.exp, this.modes);
}

/// Returns the default set of hashing algorithms
List<Prototype> getDefaultPrototypes() {
  return [
    Prototype(RegExp(r'^[a-f0-9]{4}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.CRC_16, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.CRC_16_CCITT, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.FCS_16, hashcat: null, john: null, extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{8}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Adler_32, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.CRC_32B, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.FCS_32, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.GHash_32_3, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.GHash_32_5, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.FNV_132, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.Fletcher_32, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.Joaat, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.ELF_32, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.XOR_32, hashcat: null, john: null, extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{6}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.CRC_24, hashcat: null, john: null, extended: false),
    ]),
    Prototype(
        RegExp(r'^(\$crc32\$[a-f0-9]{8}.)?[a-f0-9]{8}$', caseSensitive: false),
        [
          const HashInfo(
              id: Hash.CRC_32, hashcat: null, john: 'crc32', extended: false),
        ]),
    Prototype(RegExp(r'^\+[a-z0-9\/.]{12}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Eggdrop_IRC_Bot,
          hashcat: null,
          john: 'bfegg',
          extended: false),
    ]),
    Prototype(RegExp(r'^[a-z0-9\/.]{13}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.DES_Unix,
          hashcat: '1500',
          john: 'descrypt',
          extended: false),
      const HashInfo(
          id: Hash.Traditional_DES,
          hashcat: '1500',
          john: 'descrypt',
          extended: false),
      const HashInfo(
          id: Hash.DEScrypt,
          hashcat: '1500',
          john: 'descrypt',
          extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{16}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.MySQL323, hashcat: '200', john: 'mysql', extended: false),
      const HashInfo(
          id: Hash.DES_Oracle, hashcat: '3100', john: null, extended: false),
      const HashInfo(
          id: Hash.Half_MD5, hashcat: '5100', john: null, extended: false),
      const HashInfo(
          id: Hash.Oracle_7_10g, hashcat: '3100', john: null, extended: false),
      const HashInfo(
          id: Hash.FNV_164, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.CRC_64, hashcat: null, john: null, extended: false),
    ]),
    Prototype(RegExp(r'^[a-z0-9\/.]{16}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Cisco_PIX_MD5,
          hashcat: '2400',
          john: 'pix-md5',
          extended: false),
    ]),
    Prototype(RegExp(r'^\([a-z0-9\/+]{20}\)$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Lotus_Notes_Domino_6,
          hashcat: '8700',
          john: 'dominosec',
          extended: false),
    ]),
    Prototype(RegExp(r'^_[a-z0-9\/.]{19}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.BSDi_Crypt,
          hashcat: null,
          john: 'bsdicrypt',
          extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{24}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.CRC_96_ZIP, hashcat: null, john: null, extended: false),
    ]),
    Prototype(RegExp(r'^[a-z0-9\/.]{24}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Crypt16, hashcat: null, john: null, extended: false),
    ]),
    Prototype(RegExp(r'^(\$md2\$)?[a-f0-9]{32}$', caseSensitive: false), [
      const HashInfo(id: Hash.MD2, hashcat: null, john: 'md2', extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{32}(:.+)?$', caseSensitive: false), [
      const HashInfo(
          id: Hash.MD5, hashcat: '0', john: 'raw-md5', extended: false),
      const HashInfo(
          id: Hash.MD4, hashcat: '900', john: 'raw-md4', extended: false),
      const HashInfo(
          id: Hash.Double_MD5, hashcat: '2600', john: null, extended: false),
      const HashInfo(id: Hash.LM, hashcat: '3000', john: 'lm', extended: false),
      const HashInfo(
          id: Hash.RIPEMD_128,
          hashcat: null,
          john: 'ripemd-128',
          extended: false),
      const HashInfo(
          id: Hash.Haval_128,
          hashcat: null,
          john: 'haval-128-4',
          extended: false),
      const HashInfo(
          id: Hash.Tiger_128, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.Skein_256_128, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.Skein_512_128, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.Lotus_Notes_Domino_5,
          hashcat: '8600',
          john: 'lotus5',
          extended: false),
      const HashInfo(
          id: Hash.Skype, hashcat: '23', john: null, extended: false),
      const HashInfo(
          id: Hash.ZipMonster, hashcat: null, john: null, extended: true),
      const HashInfo(
          id: Hash.PrestaShop, hashcat: '11000', john: null, extended: true),
      const HashInfo(
          id: Hash.Md5_md5_md5_pass,
          hashcat: '3500',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Md5_strtoupper_md5_pass,
          hashcat: '4300',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Md5_sha1_pass, hashcat: '4400', john: null, extended: true),
      const HashInfo(
          id: Hash.Md5_pass_salt, hashcat: '10', john: null, extended: true),
      const HashInfo(
          id: Hash.Md5_salt_pass, hashcat: '20', john: null, extended: true),
      const HashInfo(
          id: Hash.Md5_unicode_pass_salt,
          hashcat: '30',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Md5_salt_unicode_pass,
          hashcat: '40',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.HMAC_MD5_key_pass,
          hashcat: '50',
          john: 'hmac-md5',
          extended: true),
      const HashInfo(
          id: Hash.HMAC_MD5_key_salt,
          hashcat: '60',
          john: 'hmac-md5',
          extended: true),
      const HashInfo(
          id: Hash.Md5_md5_salt_pass,
          hashcat: '3610',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Md5_salt_md5_pass,
          hashcat: '3710',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Md5_pass_md5_salt,
          hashcat: '3720',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Md5_salt_pass_salt,
          hashcat: '3810',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Md5_md5_pass_md5_salt,
          hashcat: '3910',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Md5_salt_md5_salt_pass,
          hashcat: '4010',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Md5_salt_md5_pass_salt,
          hashcat: '4110',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Md5_username_0_pass,
          hashcat: '4210',
          john: null,
          extended: true),
    ]),
    Prototype(RegExp(r'^(\$snefru\$)?[a-f0-9]{32}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Snefru_128,
          hashcat: null,
          john: 'snefru-128',
          extended: false),
    ]),
    Prototype(RegExp(r'^(\$NT\$)?[a-f0-9]{32}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.NTLM, hashcat: '1000', john: 'nt', extended: false),
    ]),
    Prototype(
        RegExp(
            r'^([^\\\/:*?"<>|]{1,20}:)?[a-f0-9]{32}(:[^\\\/:*?"<>|]{1,20})?$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Domain_Cached_Credentials,
              hashcat: '1100',
              john: 'mscach',
              extended: false),
        ]),
    Prototype(
        RegExp(
            r'^([^\\\/:*?"<>|]{1,20}:)?(\$DCC2\$10240#[^\\\/:*?"<>|]{1,20}#)?[a-f0-9]{32}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Domain_Cached_Credentials_2,
              hashcat: '2100',
              john: 'mscach2',
              extended: false),
        ]),
    Prototype(RegExp(r'^{SHA}[a-z0-9\/+]{27}=$', caseSensitive: false), [
      const HashInfo(
          id: Hash.SHA_1_Base64,
          hashcat: '101',
          john: 'nsldap',
          extended: false),
      const HashInfo(
          id: Hash.Netscape_LDAP_SHA,
          hashcat: '101',
          john: 'nsldap',
          extended: false),
    ]),
    Prototype(
        RegExp(r'^\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.MD5_Crypt,
              hashcat: '500',
              john: 'md5crypt',
              extended: false),
          const HashInfo(
              id: Hash.Cisco_IOS_MD5,
              hashcat: '500',
              john: 'md5crypt',
              extended: false),
          const HashInfo(
              id: Hash.FreeBSD_MD5,
              hashcat: '500',
              john: 'md5crypt',
              extended: false),
        ]),
    Prototype(RegExp(r'^0x[a-f0-9]{32}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Lineage_II_C4, hashcat: null, john: null, extended: false),
    ]),
    Prototype(RegExp(r'^\$H\$[a-z0-9\/.]{31}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.PhpBB_v3_x, hashcat: '400', john: 'phpass', extended: false),
      const HashInfo(
          id: Hash.Wordpress_v2_6_0_2_6_1,
          hashcat: '400',
          john: 'phpass',
          extended: false),
      const HashInfo(
          id: Hash.PHPass_Portable_Hash,
          hashcat: '400',
          john: 'phpass',
          extended: false),
    ]),
    Prototype(RegExp(r'^\$P\$[a-z0-9\/.]{31}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Wordpress_v2_6_2,
          hashcat: '400',
          john: 'phpass',
          extended: false),
      const HashInfo(
          id: Hash.Joomla_v2_5_18,
          hashcat: '400',
          john: 'phpass',
          extended: false),
      const HashInfo(
          id: Hash.PHPass_Portable_Hash,
          hashcat: '400',
          john: 'phpass',
          extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{32}:[a-z0-9]{2}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.OsCommerce, hashcat: '21', john: null, extended: false),
      const HashInfo(
          id: Hash.Xt_Commerce, hashcat: '21', john: null, extended: false),
    ]),
    Prototype(
        RegExp(r'^\$apr1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.MD5_APR, hashcat: '1600', john: null, extended: false),
          const HashInfo(
              id: Hash.Apache_MD5,
              hashcat: '1600',
              john: null,
              extended: false),
          const HashInfo(
              id: Hash.Md5apr1, hashcat: '1600', john: null, extended: true),
        ]),
    Prototype(RegExp(r'^{smd5}[a-z0-9$\/.]{31}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.AIX_smd5,
          hashcat: '6300',
          john: 'aix-smd5',
          extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{32}:[a-f0-9]{32}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.WebEdition_CMS,
          hashcat: '3721',
          john: null,
          extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{32}:.{5}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.IP_Board_v2, hashcat: '2811', john: null, extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{32}:.{8}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.MyBB_v1_2, hashcat: '2811', john: null, extended: false),
    ]),
    Prototype(RegExp(r'^[a-z0-9]{34}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.CryptoCurrency_Adress,
          hashcat: null,
          john: null,
          extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{40}(:.+)?$', caseSensitive: false), [
      const HashInfo(
          id: Hash.SHA_1, hashcat: '100', john: 'raw-sha1', extended: false),
      const HashInfo(
          id: Hash.Double_SHA_1, hashcat: '4500', john: null, extended: false),
      const HashInfo(
          id: Hash.RIPEMD_160,
          hashcat: '6000',
          john: 'ripemd-160',
          extended: false),
      const HashInfo(
          id: Hash.Haval_160, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.Tiger_160, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.HAS_160, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.LinkedIn,
          hashcat: '190',
          john: 'raw-sha1-linkedin',
          extended: false),
      const HashInfo(
          id: Hash.Skein_256_160, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.Skein_512_160, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.MangosWeb_Enhanced_CMS,
          hashcat: null,
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Sha1_sha1_sha1_pass,
          hashcat: '4600',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Sha1_md5_pass, hashcat: '4700', john: null, extended: true),
      const HashInfo(
          id: Hash.Sha1_pass_salt, hashcat: '110', john: null, extended: true),
      const HashInfo(
          id: Hash.Sha1_salt_pass, hashcat: '120', john: null, extended: true),
      const HashInfo(
          id: Hash.Sha1_unicode_pass_salt,
          hashcat: '130',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Sha1_salt_unicode_pass,
          hashcat: '140',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.HMAC_SHA1_key_pass,
          hashcat: '150',
          john: 'hmac-sha1',
          extended: true),
      const HashInfo(
          id: Hash.HMAC_SHA1_key_salt,
          hashcat: '160',
          john: 'hmac-sha1',
          extended: true),
      const HashInfo(
          id: Hash.Sha1_salt_pass_salt,
          hashcat: '4710',
          john: null,
          extended: true),
    ]),
    Prototype(RegExp(r'^\*[a-f0-9]{40}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.MySQL5_x,
          hashcat: '300',
          john: 'mysql-sha1',
          extended: false),
      const HashInfo(
          id: Hash.MySQL4_1,
          hashcat: '300',
          john: 'mysql-sha1',
          extended: false),
    ]),
    Prototype(RegExp(r'^[a-z0-9]{43}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Cisco_IOS_SHA_256,
          hashcat: '5700',
          john: null,
          extended: false),
    ]),
    Prototype(RegExp(r'^{SSHA}[a-z0-9\/+]{38}==$', caseSensitive: false), [
      const HashInfo(
          id: Hash.SSHA_1_Base64,
          hashcat: '111',
          john: 'nsldaps',
          extended: false),
      const HashInfo(
          id: Hash.Netscape_LDAP_SSHA,
          hashcat: '111',
          john: 'nsldaps',
          extended: false),
      const HashInfo(
          id: Hash.Nsldaps, hashcat: '111', john: 'nsldaps', extended: true),
    ]),
    Prototype(RegExp(r'^[a-z0-9=]{47}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Fortigate_FortiOS,
          hashcat: '7000',
          john: 'fortigate',
          extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{48}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Haval_192, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.Tiger_192, hashcat: null, john: 'tiger', extended: false),
      const HashInfo(
          id: Hash.SHA_1_Oracle, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.OSX_v10_4, hashcat: '122', john: 'xsha', extended: false),
      const HashInfo(
          id: Hash.OSX_v10_5, hashcat: '122', john: 'xsha', extended: false),
      const HashInfo(
          id: Hash.OSX_v10_6, hashcat: '122', john: 'xsha', extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{51}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Palshop_CMS, hashcat: null, john: null, extended: false),
    ]),
    Prototype(RegExp(r'^[a-z0-9]{51}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.CryptoCurrency_PrivateKey,
          hashcat: null,
          john: null,
          extended: false),
    ]),
    Prototype(
        RegExp(r'^{ssha1}[0-9]{2}\$[a-z0-9$\/.]{44}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.AIX_ssha1,
          hashcat: '6700',
          john: 'aix-ssha1',
          extended: false),
    ]),
    Prototype(RegExp(r'^0x0100[a-f0-9]{48}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.MSSQL_2005,
          hashcat: '132',
          john: 'mssql05',
          extended: false),
      const HashInfo(
          id: Hash.MSSQL_2008,
          hashcat: '132',
          john: 'mssql05',
          extended: false),
    ]),
    Prototype(
        RegExp(
            r'^(\$md5,rounds=[0-9]+\$|\$md5\$rounds=[0-9]+\$|\$md5\$)[a-z0-9\/.]{0,16}(\$|\$\$)[a-z0-9\/.]{22}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Sun_MD5_Crypt,
              hashcat: '3300',
              john: 'sunmd5',
              extended: false),
        ]),
    Prototype(RegExp(r'^[a-f0-9]{56}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.SHA_224, hashcat: null, john: 'raw-sha224', extended: false),
      const HashInfo(
          id: Hash.Haval_224, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.SHA3_224, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.Skein_256_224, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.Skein_512_224, hashcat: null, john: null, extended: false),
    ]),
    Prototype(
        RegExp(r'^(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Blowfish_OpenBSD,
              hashcat: '3200',
              john: 'bcrypt',
              extended: false),
          const HashInfo(
              id: Hash.Woltlab_Burning_Board_4_x,
              hashcat: null,
              john: null,
              extended: false),
          const HashInfo(
              id: Hash.Bcrypt,
              hashcat: '3200',
              john: 'bcrypt',
              extended: false),
        ]),
    Prototype(RegExp(r'^[a-f0-9]{40}:[a-f0-9]{16}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Android_PIN, hashcat: '5800', john: null, extended: false),
    ]),
    Prototype(
        RegExp(r'^(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Oracle_11g_12c,
          hashcat: '112',
          john: 'oracle11',
          extended: false),
    ]),
    Prototype(
        RegExp(
            r'^\$bcrypt-sha256\$(2[axy]|2)\,[0-9]+\$[a-z0-9\/.]{22}\$[a-z0-9\/.]{31}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Bcrypt_SHA_256,
              hashcat: null,
              john: null,
              extended: false),
        ]),
    Prototype(RegExp(r'^[a-f0-9]{32}:.{3}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.VBulletin_v3_8_5,
          hashcat: '2611',
          john: null,
          extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{32}:.{30}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.VBulletin_v3_8_5,
          hashcat: '2711',
          john: null,
          extended: false),
    ]),
    Prototype(RegExp(r'^(\$snefru\$)?[a-f0-9]{64}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Snefru_256,
          hashcat: null,
          john: 'snefru-256',
          extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{64}(:.+)?$', caseSensitive: false), [
      const HashInfo(
          id: Hash.SHA_256,
          hashcat: '1400',
          john: 'raw-sha256',
          extended: false),
      const HashInfo(
          id: Hash.RIPEMD_256, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.Haval_256,
          hashcat: null,
          john: 'haval-256-3',
          extended: false),
      const HashInfo(
          id: Hash.GOST_R_34_11_94,
          hashcat: '6900',
          john: 'gost',
          extended: false),
      const HashInfo(
          id: Hash.GOST_CryptoPro_S_Box,
          hashcat: null,
          john: null,
          extended: false),
      const HashInfo(
          id: Hash.SHA3_256,
          hashcat: '5000',
          john: 'raw-keccak-256',
          extended: false),
      const HashInfo(
          id: Hash.Skein_256,
          hashcat: null,
          john: 'skein-256',
          extended: false),
      const HashInfo(
          id: Hash.Skein_512_256, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.Ventrilo, hashcat: null, john: null, extended: true),
      const HashInfo(
          id: Hash.Sha256_pass_salt,
          hashcat: '1410',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Sha256_salt_pass,
          hashcat: '1420',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Sha256_unicode_pass_salt,
          hashcat: '1430',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Sha256_salt_unicode_pass,
          hashcat: '1440',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.HMAC_SHA256_key_pass,
          hashcat: '1450',
          john: 'hmac-sha256',
          extended: true),
      const HashInfo(
          id: Hash.HMAC_SHA256_key_salt,
          hashcat: '1460',
          john: 'hmac-sha256',
          extended: true),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{32}:[a-z0-9]{32}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Joomla_v2_5_18, hashcat: '11', john: null, extended: false),
    ]),
    Prototype(RegExp(r'^[a-f-0-9]{32}:[a-f-0-9]{32}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.SAM_LM_Hash_NT_Hash,
          hashcat: null,
          john: null,
          extended: false),
    ]),
    Prototype(
        RegExp(r'^(\$chap\$0\*)?[a-f0-9]{32}[\*:][a-f0-9]{32}(:[0-9]{2})?$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.MD5_Chap,
              hashcat: '4800',
              john: 'chap',
              extended: false),
          const HashInfo(
              id: Hash.ISCSI_CHAP_Authentication,
              hashcat: '4800',
              john: 'chap',
              extended: false),
        ]),
    Prototype(
        RegExp(r'^\$episerver\$\*0\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{27,28}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.EPiServer_6_x_v4,
              hashcat: '141',
              john: 'episerver',
              extended: false),
        ]),
    Prototype(
        RegExp(r'^{ssha256}[0-9]{2}\$[a-z0-9$\/.]{60}$', caseSensitive: false),
        [
          const HashInfo(
              id: Hash.AIX_ssha256,
              hashcat: '6400',
              john: 'aix-ssha256',
              extended: false),
        ]),
    Prototype(RegExp(r'^[a-f0-9]{80}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.RIPEMD_320, hashcat: null, john: null, extended: false),
    ]),
    Prototype(
        RegExp(r'^\$episerver\$\*1\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{42,43}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.EPiServer_6_x_v4,
              hashcat: '1441',
              john: 'episerver',
              extended: false),
        ]),
    Prototype(RegExp(r'^0x0100[a-f0-9]{88}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.MSSQL_2000, hashcat: '131', john: 'mssql', extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{96}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.SHA_384,
          hashcat: '10800',
          john: 'raw-sha384',
          extended: false),
      const HashInfo(
          id: Hash.SHA3_384, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.Skein_512_384, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.Skein_1024_384, hashcat: null, john: null, extended: false),
    ]),
    Prototype(RegExp(r'^{SSHA512}[a-z0-9\/+]{96}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.SSHA_512_Base64,
          hashcat: '1711',
          john: 'ssha512',
          extended: false),
      const HashInfo(
          id: Hash.LDAP_SSHA_512,
          hashcat: '1711',
          john: 'ssha512',
          extended: false),
    ]),
    Prototype(
        RegExp(r'^{ssha512}[0-9]{2}\$[a-z0-9\/.]{16,48}\$[a-z0-9\/.]{86}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.AIX_ssha512,
              hashcat: '6500',
              john: 'aix-ssha512',
              extended: false),
        ]),
    Prototype(RegExp(r'^[a-f0-9]{128}(:.+)?$', caseSensitive: false), [
      const HashInfo(
          id: Hash.SHA_512,
          hashcat: '1700',
          john: 'raw-sha512',
          extended: false),
      const HashInfo(
          id: Hash.Whirlpool,
          hashcat: '6100',
          john: 'whirlpool',
          extended: false),
      const HashInfo(
          id: Hash.Salsa10, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.Salsa20, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.SHA3_512,
          hashcat: null,
          john: 'raw-keccak',
          extended: false),
      const HashInfo(
          id: Hash.Skein_512,
          hashcat: null,
          john: 'skein-512',
          extended: false),
      const HashInfo(
          id: Hash.Skein_1024_512, hashcat: null, john: null, extended: false),
      const HashInfo(
          id: Hash.Sha512_pass_salt,
          hashcat: '1710',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Sha512_salt_pass,
          hashcat: '1720',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Sha512_unicode_pass_salt,
          hashcat: '1730',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.Sha512_salt_unicode_pass,
          hashcat: '1740',
          john: null,
          extended: true),
      const HashInfo(
          id: Hash.HMAC_SHA512_key_pass,
          hashcat: '1750',
          john: 'hmac-sha512',
          extended: true),
      const HashInfo(
          id: Hash.HMAC_SHA512_key_salt,
          hashcat: '1760',
          john: 'hmac-sha512',
          extended: true),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{136}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.OSX_v10_7,
          hashcat: '1722',
          john: 'xsha512',
          extended: false),
    ]),
    Prototype(RegExp(r'^0x0200[a-f0-9]{136}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.MSSQL_2012,
          hashcat: '1731',
          john: 'msql12',
          extended: false),
      const HashInfo(
          id: Hash.MSSQL_2014,
          hashcat: '1731',
          john: 'msql12',
          extended: false),
    ]),
    Prototype(
        RegExp(r'^\$ml\$[0-9]+\$[a-f0-9]{64}\$[a-f0-9]{128}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.OSX_v10_8,
              hashcat: '7100',
              john: 'pbkdf2-hmac-sha512',
              extended: false),
          const HashInfo(
              id: Hash.OSX_v10_9,
              hashcat: '7100',
              john: 'pbkdf2-hmac-sha512',
              extended: false),
        ]),
    Prototype(RegExp(r'^[a-f0-9]{256}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Skein_1024, hashcat: null, john: null, extended: false),
    ]),
    Prototype(
        RegExp(
            r'^grub\.pbkdf2\.sha512\.[0-9]+\.([a-f0-9]{128,2048}\.|[0-9]+\.)?[a-f0-9]{128}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.GRUB_2, hashcat: '7200', john: null, extended: false),
        ]),
    Prototype(
        RegExp(r'^sha1\$[a-z0-9]+\$[a-f0-9]{40}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Django_SHA_1, hashcat: '124', john: null, extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{49}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Citrix_Netscaler,
          hashcat: '8100',
          john: 'citrix_ns10',
          extended: false),
    ]),
    Prototype(RegExp(r'^\$S\$[a-z0-9\/.]{52}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Drupal_v7_x,
          hashcat: '7900',
          john: 'drupal7',
          extended: false),
    ]),
    Prototype(
        RegExp(r'^\$5\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{43}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.SHA_256_Crypt,
              hashcat: '7400',
              john: 'sha256crypt',
              extended: false),
        ]),
    Prototype(
        RegExp(r'^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Sybase_ASE,
              hashcat: '8000',
              john: 'sybasease',
              extended: false),
        ]),
    Prototype(
        RegExp(r'^\$6\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{86}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.SHA_512_Crypt,
              hashcat: '1800',
              john: 'sha512crypt',
              extended: false),
        ]),
    Prototype(
        RegExp(
            r'^\$sha\$[a-z0-9]{1,16}\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Minecraft_AuthMe_Reloaded,
              hashcat: null,
              john: null,
              extended: false),
        ]),
    Prototype(
        RegExp(r'^sha256\$[a-z0-9]+\$[a-f0-9]{64}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Django_SHA_256, hashcat: null, john: null, extended: false),
    ]),
    Prototype(
        RegExp(r'^sha384\$[a-z0-9]+\$[a-f0-9]{96}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Django_SHA_384, hashcat: null, john: null, extended: false),
    ]),
    Prototype(
        RegExp(r'^crypt1:[a-z0-9+=]{12}:[a-z0-9+=]{12}$', caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Clavister_Secure_Gateway,
              hashcat: null,
              john: null,
              extended: false),
        ]),
    Prototype(RegExp(r'^[a-f0-9]{112}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Cisco_VPN_Client_PCF_File,
          hashcat: null,
          john: null,
          extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{1329}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Microsoft_MSTSC_RDP_File,
          hashcat: null,
          john: null,
          extended: false),
    ]),
    Prototype(
        RegExp(
            r'^[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20})?:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.NetNTLMv1_VANILLA_NetNTLMv1_ESS,
              hashcat: '5500',
              john: 'netntlm',
              extended: false),
        ]),
    Prototype(
        RegExp(
            r'^([^\\\/:*?"<>|]{1,20}\\)?[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20}:)?[^\\\/:*?"<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.NetNTLMv2,
              hashcat: '5600',
              john: 'netntlmv2',
              extended: false),
        ]),
    Prototype(
        RegExp(r'^\$(krb5pa|mskrb5)\$([0-9]{2})?\$.+\$[a-f0-9]{1,}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Kerberos_5_AS_REQ_Pre_Auth,
              hashcat: '7500',
              john: 'krb5pa-md5',
              extended: false),
        ]),
    Prototype(
        RegExp(
            r'^\$scram\$[0-9]+\$[a-z0-9\/.]{16}\$sha-1=[a-z0-9\/.]{27},sha-256=[a-z0-9\/.]{43},sha-512=[a-z0-9\/.]{86}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.SCRAM_Hash, hashcat: null, john: null, extended: false),
        ]),
    Prototype(RegExp(r'^[a-f0-9]{40}:[a-f0-9]{0,32}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Redmine_Project_Management_Web_App,
          hashcat: '7600',
          john: null,
          extended: false),
    ]),
    Prototype(RegExp(r'^(.+)?\$[a-f0-9]{16}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.SAP_CODVN_B_BCODE,
          hashcat: '7700',
          john: 'sapb',
          extended: false),
    ]),
    Prototype(RegExp(r'^(.+)?\$[a-f0-9]{40}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.SAP_CODVN_F_G_PASSCODE,
          hashcat: '7800',
          john: 'sapg',
          extended: false),
    ]),
    Prototype(
        RegExp(r'^(.+\$)?[a-z0-9\/.+]{30}(:.+)?$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Juniper_Netscreen_SSG_ScreenOS,
          hashcat: '22',
          john: 'md5ns',
          extended: false),
    ]),
    Prototype(
        RegExp(r'^0x[a-f0-9]{60}\s0x[a-f0-9]{40}$', caseSensitive: false), [
      const HashInfo(id: Hash.EPi, hashcat: '123', john: null, extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{40}:[^*]{1,25}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.SMF_v1_1, hashcat: '121', john: null, extended: false),
    ]),
    Prototype(
        RegExp(r'^(\$wbb3\$\*1\*)?[a-f0-9]{40}[:*][a-f0-9]{40}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Woltlab_Burning_Board_3_x,
              hashcat: '8400',
              john: 'wbb3',
              extended: false),
        ]),
    Prototype(
        RegExp(r'^[a-f0-9]{130}(:[a-f0-9]{40})?$', caseSensitive: false), [
      const HashInfo(
          id: Hash.IPMI2_RAKP_HMAC_SHA1,
          hashcat: '7300',
          john: null,
          extended: false),
    ]),
    Prototype(
        RegExp(r'^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Lastpass, hashcat: '6800', john: null, extended: false),
        ]),
    Prototype(RegExp(r'^[a-z0-9\/.]{16}([:$].{1,})?$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Cisco_ASA_MD5,
          hashcat: '2410',
          john: 'asa-md5',
          extended: false),
    ]),
    Prototype(
        RegExp(r'^\$vnc\$\*[a-f0-9]{32}\*[a-f0-9]{32}$', caseSensitive: false),
        [
          const HashInfo(
              id: Hash.VNC, hashcat: null, john: 'vnc', extended: false),
        ]),
    Prototype(
        RegExp(
            r'^[a-z0-9]{32}(:([a-z0-9-]+\.)?[a-z0-9-.]+\.[a-z]{2,7}:.+:[0-9]+)?$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.DNSSEC_NSEC3,
              hashcat: '8300',
              john: null,
              extended: false),
        ]),
    Prototype(
        RegExp(r'^(user-.+:)?\$racf\$\*.+\*[a-f0-9]{16}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.RACF, hashcat: '8500', john: 'racf', extended: false),
        ]),
    Prototype(RegExp(r'^\$3\$\$[a-f0-9]{32}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.NTHash_FreeBSD_Variant,
          hashcat: null,
          john: null,
          extended: false),
    ]),
    Prototype(
        RegExp(r'^\$sha1\$[0-9]+\$[a-z0-9\/.]{0,64}\$[a-z0-9\/.]{28}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.SHA_1_Crypt,
              hashcat: null,
              john: 'sha1crypt',
              extended: false),
        ]),
    Prototype(RegExp(r'^[a-f0-9]{70}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.HMailServer,
          hashcat: '1421',
          john: 'hmailserver',
          extended: false),
    ]),
    Prototype(
        RegExp(r'^[:\$][AB][:\$]([a-f0-9]{1,8}[:\$])?[a-f0-9]{32}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.MediaWiki,
              hashcat: '3711',
              john: 'mediawiki',
              extended: false),
        ]),
    Prototype(RegExp(r'^[a-f0-9]{140}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Minecraft_xAuth, hashcat: null, john: null, extended: false),
    ]),
    Prototype(
        RegExp(r'^\$pbkdf2(-sha1)?\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{27}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.PBKDF2_SHA1_Generic,
              hashcat: null,
              john: null,
              extended: false),
        ]),
    Prototype(
        RegExp(r'^\$pbkdf2-sha256\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{43}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.PBKDF2_SHA256_Generic,
              hashcat: null,
              john: 'pbkdf2-hmac-sha256',
              extended: false),
        ]),
    Prototype(
        RegExp(r'^\$pbkdf2-sha512\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{86}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.PBKDF2_SHA512_Generic,
              hashcat: null,
              john: null,
              extended: false),
        ]),
    Prototype(
        RegExp(r'^\$p5k2\$[0-9]+\$[a-z0-9\/+=-]+\$[a-z0-9\/+-]{27}=$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.PBKDF2_Cryptacular,
              hashcat: null,
              john: null,
              extended: false),
        ]),
    Prototype(
        RegExp(r'^\$p5k2\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{32}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.PBKDF2_Dwayne_Litzenberger,
              hashcat: null,
              john: null,
              extended: false),
        ]),
    Prototype(
        RegExp(r'^{FSHP[0123]\|[0-9]+\|[0-9]+}[a-z0-9\/+=]+$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Fairly_Secure_Hashed_Password,
              hashcat: null,
              john: null,
              extended: false),
        ]),
    Prototype(RegExp(r'^\$PHPS\$.+\$[a-f0-9]{32}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.PHPS, hashcat: '2612', john: 'phps', extended: false),
    ]),
    Prototype(
        RegExp(r'^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{2080}$', caseSensitive: false),
        [
          const HashInfo(
              id: Hash.OnePassword_Agile_Keychain,
              hashcat: '6600',
              john: null,
              extended: false),
        ]),
    Prototype(
        RegExp(r'^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.OnePassword_Cloud_Keychain,
              hashcat: '8200',
              john: null,
              extended: false),
        ]),
    Prototype(
        RegExp(
            r'^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.IKE_PSK_MD5,
              hashcat: '5300',
              john: null,
              extended: false),
        ]),
    Prototype(
        RegExp(
            r'^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.IKE_PSK_SHA1,
              hashcat: '5400',
              john: null,
              extended: false),
        ]),
    Prototype(RegExp(r'^[a-z0-9\/+]{27}=$', caseSensitive: false), [
      const HashInfo(
          id: Hash.PeopleSoft, hashcat: '133', john: null, extended: false),
    ]),
    Prototype(
        RegExp(r'^crypt\$[a-f0-9]{5}\$[a-z0-9\/.]{13}$', caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Django_DES_Crypt_Wrapper,
              hashcat: null,
              john: null,
              extended: false),
        ]),
    Prototype(
        RegExp(
            r'^(\$django\$\*1\*)?pbkdf2_sha256\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{44}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Django_PBKDF2_HMAC_SHA256,
              hashcat: '10000',
              john: 'django',
              extended: false),
        ]),
    Prototype(
        RegExp(r'^pbkdf2_sha1\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{28}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Django_PBKDF2_HMAC_SHA1,
              hashcat: null,
              john: null,
              extended: false),
        ]),
    Prototype(
        RegExp(r'^bcrypt(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Django_bcrypt,
              hashcat: null,
              john: null,
              extended: false),
        ]),
    Prototype(RegExp(r'^md5\$[a-f0-9]+\$[a-f0-9]{32}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Django_MD5, hashcat: null, john: null, extended: false),
    ]),
    Prototype(RegExp(r'^\{PKCS5S2\}[a-z0-9\/+]{64}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.PBKDF2_Atlassian,
          hashcat: null,
          john: null,
          extended: false),
    ]),
    Prototype(RegExp(r'^md5[a-f0-9]{32}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.PostgreSQL_MD5, hashcat: null, john: null, extended: false),
    ]),
    Prototype(RegExp(r'^\([a-z0-9\/+]{49}\)$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Lotus_Notes_Domino_8,
          hashcat: '9100',
          john: null,
          extended: false),
    ]),
    Prototype(
        RegExp(r'^SCRYPT:[0-9]{1,}:[0-9]{1}:[0-9]{1}:[a-z0-9:\/+=]{1,}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Scrypt, hashcat: '8900', john: null, extended: false),
        ]),
    Prototype(
        RegExp(r'^\$8\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Cisco_Type_8,
              hashcat: '9200',
              john: 'cisco8',
              extended: false),
        ]),
    Prototype(
        RegExp(r'^\$9\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Cisco_Type_9,
              hashcat: '9300',
              john: 'cisco9',
              extended: false),
        ]),
    Prototype(
        RegExp(
            r'^\$office\$\*2007\*[0-9]{2}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{40}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Microsoft_Office_2007,
              hashcat: '9400',
              john: 'office',
              extended: false),
        ]),
    Prototype(
        RegExp(
            r'^\$office\$\*2010\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Microsoft_Office_2010,
              hashcat: '9500',
              john: null,
              extended: false),
        ]),
    Prototype(
        RegExp(
            r'^\$office\$\*2013\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Microsoft_Office_2013,
              hashcat: '9600',
              john: null,
              extended: false),
        ]),
    Prototype(
        RegExp(
            r'^\$fde\$[0-9]{2}\$[a-f0-9]{32}\$[0-9]{2}\$[a-f0-9]{32}\$[a-f0-9]{3072}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Android_FDE_4_3,
              hashcat: '8800',
              john: 'fde',
              extended: false),
        ]),
    Prototype(
        RegExp(r'^\$oldoffice\$[01]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{32}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Microsoft_Office_2003_MD5_RC4,
              hashcat: '9700',
              john: 'oldoffice',
              extended: false),
          const HashInfo(
              id: Hash.Microsoft_Office_2003_MD5_RC4_collider_mode_1,
              hashcat: '9710',
              john: 'oldoffice',
              extended: false),
          const HashInfo(
              id: Hash.Microsoft_Office_2003_MD5_RC4_collider_mode_2,
              hashcat: '9720',
              john: 'oldoffice',
              extended: false),
        ]),
    Prototype(
        RegExp(r'^\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Microsoft_Office_2003_SHA1_RC4,
              hashcat: '9800',
              john: null,
              extended: false),
          const HashInfo(
              id: Hash.Microsoft_Office_2003_SHA1_RC4_collider_mode_1,
              hashcat: '9810',
              john: null,
              extended: false),
          const HashInfo(
              id: Hash.Microsoft_Office_2003_SHA1_RC4_collider_mode_2,
              hashcat: '9820',
              john: null,
              extended: false),
        ]),
    Prototype(RegExp(r'^(\$radmin2\$)?[a-f0-9]{32}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.RAdmin_v2_x,
          hashcat: '9900',
          john: 'radmin',
          extended: false),
    ]),
    Prototype(
        RegExp(r'^{x-issha,\s[0-9]{4}}[a-z0-9\/+=]+$', caseSensitive: false), [
      const HashInfo(
          id: Hash.SAP_CODVN_H_PWDSALTEDHASH_iSSHA_1,
          hashcat: '10300',
          john: 'saph',
          extended: false),
    ]),
    Prototype(
        RegExp(r'^\$cram_md5\$[a-z0-9\/+=-]+\$[a-z0-9\/+=-]{52}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.CRAM_MD5, hashcat: '10200', john: null, extended: false),
        ]),
    Prototype(
        RegExp(r'^[a-f0-9]{16}:2:4:[a-f0-9]{32}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.SipHash, hashcat: '10100', john: null, extended: false),
    ]),
    Prototype(RegExp(r'^[a-f0-9]{4,}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Cisco_Type_7, hashcat: null, john: null, extended: true),
    ]),
    Prototype(RegExp(r'^[a-z0-9\/.]{13,}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.BigCrypt, hashcat: null, john: 'bigcrypt', extended: true),
    ]),
    Prototype(RegExp(r'^(\$cisco4\$)?[a-z0-9\/.]{43}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Cisco_Type_4,
          hashcat: null,
          john: 'cisco4',
          extended: false),
    ]),
    Prototype(
        RegExp(r'^bcrypt_sha256\$\$(2[axy]|2)\$[0-9]+\$[a-z0-9\/.]{53}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Django_bcrypt_SHA256,
              hashcat: null,
              john: null,
              extended: false),
        ]),
    Prototype(
        RegExp(r'^\$postgres\$.[^\*]+[*:][a-f0-9]{1,32}[*:][a-f0-9]{32}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.PostgreSQL_Challenge_Response_Authentication_MD5,
              hashcat: '11100',
              john: 'postgres',
              extended: false),
        ]),
    Prototype(
        RegExp(r'^\$siemens-s7\$\$[0-9]{1}\$[a-f0-9]{40}\$[a-f0-9]{40}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.Siemens_S7,
              hashcat: null,
              john: 'siemens-s7',
              extended: false),
        ]),
    Prototype(RegExp(r'^(\$pst\$)?[a-f0-9]{8}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Microsoft_Outlook_PST,
          hashcat: null,
          john: null,
          extended: false),
    ]),
    Prototype(
        RegExp(r'^sha256[:$][0-9]+[:$][a-z0-9\/+]+[:$][a-z0-9\/+]{32,128}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.PBKDF2_HMAC_SHA256_PHP,
              hashcat: '10900',
              john: null,
              extended: false),
        ]),
    Prototype(RegExp(r'^(\$dahua\$)?[a-z0-9]{8}$', caseSensitive: false), [
      const HashInfo(
          id: Hash.Dahua, hashcat: null, john: 'dahua', extended: false),
    ]),
    Prototype(
        RegExp(r'^\$mysqlna\$[a-f0-9]{40}[:*][a-f0-9]{40}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.MySQL_Challenge_Response_Authentication_SHA1,
              hashcat: '11200',
              john: null,
              extended: false),
        ]),
    Prototype(
        RegExp(
            r'^\$pdf\$[24]\*[34]\*128\*[0-9-]{1,5}\*1\*(16|32)\*[a-f0-9]{32,64}\*32\*[a-f0-9]{64}\*(8|16|32)\*[a-f0-9]{16,64}$',
            caseSensitive: false),
        [
          const HashInfo(
              id: Hash.PDF_1_4_1_6_Acrobat_5_8,
              hashcat: '10500',
              john: 'pdf',
              extended: false),
        ]),
  ];
}

/// Returns the algorythm name given Hash
String getName(Hash hash) {
  return names[hash] ?? 'UNKNOWN';
}

/// Returns list of hashing alorithms possibly used to create the hash
List<HashInfo> Identify(String text, List<Prototype> prototypes) {
  var result = <HashInfo>[];
  prototypes.forEach((Prototype p) => {
        if (p.exp.hasMatch(text)) {result..addAll(p.modes)}
      });
  return result;
}
