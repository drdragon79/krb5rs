#![allow(dead_code)]
#![allow(non_upper_case_globals)]

pub mod pa {
    pub const PA_TGS_REQ: i32 =                 1;
    pub const PA_ENC_TIMESTAMP: i32 =           2;
    pub const PA_PW_SALT: i32 =                 3;
    pub const PA_ENC_UNIX_TIME: i32 =           5;        // (deprecated)
    pub const PA_SANDIA_SECUREID: i32 =         6;
    pub const PA_SESAME: i32 =                  7;
    pub const PA_OSF_DCE: i32 =                 8;
    pub const PA_CYBERSAFE_SECUREID: i32 =      9;
    pub const PA_AFS3_SALT: i32 =               10;
    pub const PA_ETYPE_INFO: i32 =              11;
    pub const PA_SAM_CHALLENGE: i32 =           12;       // (sam/otp)
    pub const PA_SAM_RESPONSE: i32 =            13;       // (sam/otp)
    pub const PA_PK_AS_REQ_OLD: i32 =           14;       // (pkinit)
    pub const PA_PK_AS_REP_OLD: i32 =           15;       // (pkinit)
    pub const PA_PK_AS_REQ: i32 =               16;       // (pkinit)
    pub const PA_PK_AS_REP: i32 =               17;       // (pkinit)
    pub const PA_ETYPE_INFO2: i32 =             19;       // (replaces pa_etype_info)
    pub const PA_USE_SPECIFIED_KVNO: i32 =      20;
    pub const PA_SAM_REDIRECT: i32 =            21;       // (sam/otp)
    pub const PA_GET_FROM_TYPED_DATA: i32 =     22;       // (embedded in typed data)
    pub const TD_PADATA: i32 =                  22;       // (embeds padata)
    pub const PA_SAM_ETYPE_INFO: i32 =          23;       // (sam/otp)
    pub const PA_ALT_PRINC: i32 =               24;       // (crawdad@fnal.gov)
    pub const PA_SAM_CHALLENGE2: i32 =          30;       // (kenh@pobox.com)
    pub const PA_SAM_RESPONSE2: i32 =           31;       // (kenh@pobox.com)
    pub const PA_EXTRA_TGT: i32 =               41;       // Reserved extra TGT
    pub const TD_PKINIT_CMS_CERTIFICATES: i32 = 101;      // CertificateSet from CMS
    pub const TD_KRB_PRINCIPAL: i32 =           102;      // PrincipalName
    pub const TD_KRB_REALM: i32 =               103;      // Realm
    pub const TD_TRUSTED_CERTIFIERS: i32 =      104;      // from PKINIT
    pub const TD_CERTIFICATE_INDEX: i32 =       105;      // from PKINIT
    pub const TD_APP_DEFINED_ERROR: i32 =       106;      // application specific
    pub const TD_REQ_NONCE: i32 =               107;      // INTEGER
    pub const TD_REQ_SEQ: i32 =                 108;      // INTEGER
    pub const PA_PAC_REQUEST: i32 =             128;      // (jbrezak@exchange.microsoft.com)
}

mod address {
}

mod auth {
    pub const AD_IF_RELEVANT: i32 =                     1;
    pub const AD_INTENDED_FOR_SERVER: i32 =             2;
    pub const AD_INTENDED_FOR_APPLICATION_CLASS: i32 =  3;
    pub const AD_KDC_ISSUED: i32 =                      4;
    pub const AD_AND_OR: i32 =                          5;
    pub const AD_MANDATORY_TICKET_EXTENSIONS: i32 =     6;
    pub const AD_IN_TICKET_EXTENSIONS: i32 =            7;
    pub const AD_MANDATORY_FOR_KDC: i32 =               8;
    pub const OSF_DCE: i32 =                           64;
    pub const SESAME: i32 =                            65;
    pub const AD_OSF_DCE_PKI_CERTID: i32 =             66; // (hemsath@us.ibm.com)
    pub const AD_WIN2K_PAC: i32 =                     128; // (jbrezak@exchange.microsoft.com)
    pub const AD_ETYPE_NEGOTIATION: i32 =             129; // (lzhu@windows.microsoft.com)
}

pub mod transited {
    pub const DOMAIN_X500_COMPRESS: i32 = 1;
}

pub mod protocol {
    pub const pvno: i32 = 5; // Kerberos protocol version 5
}

pub mod message {
    pub const KRB_AS_REQ: i32 =       10;    // Request for initial authentication
    pub const KRB_AS_REP: i32 =       11;    // Response to KRB_AS_REQ request
    pub const KRB_TGS_REQ: i32 =      12;    // Request for authentication based on TGT
    pub const KRB_TGS_REP: i32 =      13;    // Response to KRB_TGS_REQ request
    pub const KRB_AP_REQ: i32 =       14;    // Application request to server
    pub const KRB_AP_REP: i32 =       15;    // Response to KRB_AP_REQ_MUTUAL
    pub const KRB_RESERVED16: i32 =   16;    // Reserved for user-to-user krb_tgt_request
    pub const KRB_RESERVED17: i32 =   17;    // Reserved for user-to-user krb_tgt_reply
    pub const KRB_SAFE: i32 =         20;    // Safe (checksummed) application message
    pub const KRB_PRIV: i32 =         21;    // Private (encrypted) application message
    pub const KRB_CRED: i32 =         22;    // Private (encrypted) message to forward crednetials
    pub const KRB_ERROR: i32 =        30;    // Error response
}

pub mod name {
    pub const KRB_NT_UNKNOWN: i32 =         0;    // Name type not known
    pub const KRB_NT_PRINCIPAL: i32 =       1;    // Just the name of the principal as in DCE, or for users
    pub const KRB_NT_SRV_INST: i32 =        2;    // Service and other unique instance (krbtgt)
    pub const KRB_NT_SRV_HST: i32 =         3;    // Service with host name as instance (telnet, rcommands)
    pub const KRB_NT_SRV_XHST: i32 =        4;    // Service with host as remaining components
    pub const KRB_NT_UID: i32 =             5;    // Unique ID
    pub const KRB_NT_X500_PRINCIPAL: i32 =  6;    // Encoded X.509 Distinguished name [RFC2253]
    pub const KRB_NT_SMTP_NAME: i32 =       7;    // Name in form of SMTP email name (e.g., user@example.com)
    pub const KRB_NT_ENTERPRISE: i32 =     10;    // Enterprise name; may be mapped to principal name
}

pub mod krberrors {
    pub const KDC_ERR_NONE: i32 =                            0;  // No error
    pub const KDC_ERR_NAME_EXP: i32 =                        1;  // Client's entry in database has expired
    pub const KDC_ERR_SERVICE_EXP: i32 =                     2;  // Server's entry in database has expired
    pub const KDC_ERR_BAD_PVNO: i32 =                        3;  // Requested protocol version number not supported
    pub const KDC_ERR_C_OLD_MAST_KVNO: i32 =                 4;  // Client's key encrypted in old master key
    pub const KDC_ERR_S_OLD_MAST_KVNO: i32 =                 5;  // Server's key encrypted in old master key
    pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: i32 =             6;  // Client not found in Kerberos database
    pub const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 =             7;  // Server not found in Kerberos database
    pub const KDC_ERR_PRINCIPAL_NOT_UNIQUE: i32 =            8;  // Multiple principal entries in database
    pub const KDC_ERR_NULL_KEY: i32 =                        9;  // The client or server has a null key
    pub const KDC_ERR_CANNOT_POSTDATE: i32 =                10;  // Ticket not eligible for postdating
    pub const KDC_ERR_NEVER_VALID: i32 =                    11;  // Requested starttime is later than end time
    pub const KDC_ERR_POLICY: i32 =                         12;  // KDC policy rejects request
    pub const KDC_ERR_BADOPTION: i32 =                      13;  // KDC cannot accommodate requested option
    pub const KDC_ERR_ETYPE_NOSUPP: i32 =                   14;  // KDC has no support for encryption type
    pub const KDC_ERR_SUMTYPE_NOSUPP: i32 =                 15;  // KDC has no support for checksum type
    pub const KDC_ERR_PADATA_TYPE_NOSUPP: i32 =             16;  // KDC has no support for padata type
    pub const KDC_ERR_TRTYPE_NOSUPP: i32 =                  17;  // KDC has no support for transited type
    pub const KDC_ERR_CLIENT_REVOKED: i32 =                 18;  // Clients credentials have been revoked
    pub const KDC_ERR_SERVICE_REVOKED: i32 =                19;  // Credentials for server have been revoked
    pub const KDC_ERR_TGT_REVOKED: i32 =                    20;  // TGT has been revoked
    pub const KDC_ERR_CLIENT_NOTYET: i32 =                  21;  // Client not yet valid; try again later
    pub const KDC_ERR_SERVICE_NOTYET: i32 =                 22;  // Server not yet valid; try again later
    pub const KDC_ERR_KEY_EXPIRED: i32 =                    23;  // Password has expired; change password to reset
    pub const KDC_ERR_PREAUTH_FAILED: i32 =                 24;  // Pre-authentication information was invalid
    pub const KDC_ERR_PREAUTH_REQUIRED: i32 =               25;  // Additional pre- authentication required
    pub const KDC_ERR_SERVER_NOMATCH: i32 =                 26;  // Requested server and ticket don't match
    pub const KDC_ERR_MUST_USE_USER2USER: i32 =             27;  // Server principal valid for user2user only
    pub const KDC_ERR_PATH_NOT_ACCEPTED: i32 =              28;  // KDC Policy rejects transited path
    pub const KDC_ERR_SVC_UNAVAILABLE: i32 =                29;  // A service is not available
    pub const KRB_AP_ERR_BAD_INTEGRITY: i32 =               31;  // Integrity check on decrypted field failed
    pub const KRB_AP_ERR_TKT_EXPIRED: i32 =                 32;  // Ticket expired
    pub const KRB_AP_ERR_TKT_NYV: i32 =                     33;  // Ticket not yet valid pub const KRB_AP_ERR_REPEAT                     34  Request is a replay
    pub const KRB_AP_ERR_REPEAT: i32 =                      34;  // Request is a replay pub const KRB_AP_ERR_NOT_US                     35  The ticket isn't for usr don't match
    pub const KRB_AP_ERR_NOT_US: i32 =                      35;  // The ticket isn't for us pub const KRB_AP_ERR_BADMATCH                   36  Ticket and authenticator don't match
    pub const KRB_AP_ERR_BADMATCH: i32 =                    36;  // Ticket and authenticator don't match pub const KRB_AP_ERR_SKEW                       37  Clock skew too great
    pub const KRB_AP_ERR_SKEW: i32 =                        37;  // Clock skew too great pub const KRB_AP_ERR_BADADDR                    38  Incorrect net address
    pub const KRB_AP_ERR_BADADDR: i32 =                     38;  // Incorrect net address pub const KRB_AP_ERR_BADVERSION                 39  Protocol version mismatch
    pub const KRB_AP_ERR_BADVERSION: i32 =                  39;  // Protocol version mismatch pub const KRB_AP_ERR_MSG_TYPE                   40  Invalid msg typee direction
    pub const KRB_AP_ERR_MSG_TYPE: i32 =                    40;  // Invalid msg type pub const KRB_AP_ERR_MODIFIED                   41  Message stream modifieder in message
    pub const KRB_AP_ERR_MODIFIED: i32 =                    41;  // Message stream modified pub const KRB_AP_ERR_BADORDER                   42  Message out of order
    pub const KRB_AP_ERR_BADORDER: i32 =                    42;  // Message out of order pub const KRB_AP_ERR_BADKEYVER                  44  Specified version of key is not available
    pub const KRB_AP_ERR_BADKEYVER: i32 =                   44;  // Specified version of key is not available pub const KRB_AP_ERR_NOKEY                      45  Service key not available
    pub const KRB_AP_ERR_NOKEY: i32 =                       45;  // Service key not available pub const KRB_AP_ERR_MUT_FAIL                   46  Mutual authentication failed
    pub const KRB_AP_ERR_MUT_FAIL: i32 =                    46;  // Mutual authentication failed pub const KRB_AP_ERR_BADDIRECTION               47  Incorrect message direction
    pub const KRB_AP_ERR_BADDIRECTION: i32 =                47;  // Incorrect message direction pub const KRB_AP_ERR_METHOD                     48  Alternative authentication method required
    pub const KRB_AP_ERR_METHOD: i32 =                      48;  // Alternative authentication method required pub const KRB_AP_ERR_BADSEQ                     49  Incorrect sequence number in message
    pub const KRB_AP_ERR_BADSEQ: i32 =                      49;  // Incorrect sequence number in message KRB_AP_ERR_INAPP_CKSUM                50  Inappropriate type of checksum in message
    pub const KRB_AP_ERR_INAPP_CKSUM: i32 =                 50;  // Inappropriate type of checksum in message
    pub const KRB_AP_PATH_NOT_ACCEPTED: i32 =               51;  // Policy rejects transited path
    pub const KRB_ERR_RESPONSE_TOO_BIG: i32 =               52;  // Response too big for UDP; retry with TCP
    pub const KRB_ERR_GENERIC: i32 =                        60;  // Generic error (description in e-text)
    pub const KRB_ERR_FIELD_TOOLONG: i32 =                  61;  // Field is too long for this implementation
    pub const KDC_ERROR_CLIENT_NOT_TRUSTED: i32 =           62;  // Reserved for PKINIT
    pub const KDC_ERROR_KDC_NOT_TRUSTED: i32 =              63;  // Reserved for PKINIT
    pub const KDC_ERROR_INVALID_SIG: i32 =                  64;  // Reserved for PKINIT
    pub const KDC_ERR_KEY_TOO_WEAK: i32 =                   65;  // Reserved for PKINIT
    pub const KDC_ERR_CERTIFICATE_MISMATCH: i32 =           66;  // Reserved for PKINIT
    pub const KRB_AP_ERR_NO_TGT: i32 =                      67;  // No TGT available to validate USER-TO-USER
    pub const KDC_ERR_WRONG_REALM: i32 =                    68;  // Reserved for future use
    pub const KRB_AP_ERR_USER_TO_USER_REQUIRED: i32 =       69;  // Ticket must be for USER-TO-USER
    pub const KDC_ERR_CANT_VERIFY_CERTIFICATE: i32 =        70;  // Reserved for PKINIT
    pub const KDC_ERR_INVALID_CERTIFICATE: i32 =            71;  // Reserved for PKINIT
    pub const KDC_ERR_REVOKED_CERTIFICATE: i32 =            72;  // Reserved for PKINIT
    pub const KDC_ERR_REVOCATION_STATUS_UNKNOWN: i32 =      73;  // Reserved for PKINIT
    pub const KDC_ERR_REVOCATION_STATUS_UNAVAILABLE: i32 =  74;  // Reserved for PKINIT
    pub const KDC_ERR_CLIENT_NAME_MISMATCH: i32 =           75;  // Reserved for PKINIT
    pub const KDC_ERR_KDC_NAME_MISMATCH: i32 =              76;  // Reserved for PKINIT

    pub fn get_error(code: i32) -> Option<String> {
        match code {
            0 => Some("KDC_ERR_NONE".to_string()),
            1 => Some("KDC_ERR_NAME_EXP".to_string()),
            2 => Some("KDC_ERR_SERVICE_EXP".to_string()),
            3 => Some("KDC_ERR_BAD_PVNO".to_string()),
            4 => Some("KDC_ERR_C_OLD_MAST_KVNO".to_string()),
            5 => Some("KDC_ERR_S_OLD_MAST_KVNO".to_string()),
            6 => Some("KDC_ERR_C_PRINCIPAL_UNKNOWN".to_string()),
            7 => Some("KDC_ERR_S_PRINCIPAL_UNKNOWN".to_string()),
            8 => Some("KDC_ERR_PRINCIPAL_NOT_UNIQUE".to_string()),
            9 => Some("KDC_ERR_NULL_KEY".to_string()),
            10 => Some("KDC_ERR_CANNOT_POSTDATE".to_string()),
            11 => Some("KDC_ERR_NEVER_VALID".to_string()),
            12 => Some("KDC_ERR_POLICY".to_string()),
            13 => Some("KDC_ERR_BADOPTION".to_string()),
            14 => Some("KDC_ERR_ETYPE_NOSUPP".to_string()),
            15 => Some("KDC_ERR_SUMTYPE_NOSUPP".to_string()),
            16 => Some("KDC_ERR_PADATA_TYPE_NOSUPP".to_string()),
            17 => Some("KDC_ERR_TRTYPE_NOSUPP".to_string()),
            18 => Some("KDC_ERR_CLIENT_REVOKED".to_string()),
            19 => Some("KDC_ERR_SERVICE_REVOKED".to_string()),
            20 => Some("KDC_ERR_TGT_REVOKED".to_string()),
            21 => Some("KDC_ERR_CLIENT_NOTYET".to_string()),
            22 => Some("KDC_ERR_SERVICE_NOTYET".to_string()),
            23 => Some("KDC_ERR_KEY_EXPIRED".to_string()),
            24 => Some("KDC_ERR_PREAUTH_FAILED".to_string()),
            25 => Some("KDC_ERR_PREAUTH_REQUIRED".to_string()),
            26 => Some("KDC_ERR_SERVER_NOMATCH".to_string()),
            27 => Some("KDC_ERR_MUST_USE_USER2USER".to_string()),
            28 => Some("KDC_ERR_PATH_NOT_ACCEPTED".to_string()),
            29 => Some("KDC_ERR_SVC_UNAVAILABLE".to_string()),
            31 => Some("KRB_AP_ERR_BAD_INTEGRITY".to_string()),
            32 => Some("KRB_AP_ERR_TKT_EXPIRED".to_string()),
            33 => Some("KRB_AP_ERR_TKT_NYV".to_string()),
            34 => Some("KRB_AP_ERR_REPEAT".to_string()),
            35 => Some("KRB_AP_ERR_NOT_US".to_string()),
            36 => Some("KRB_AP_ERR_BADMATCH".to_string()),
            37 => Some("KRB_AP_ERR_SKEW".to_string()),
            38 => Some("KRB_AP_ERR_BADADDR".to_string()),
            39 => Some("KRB_AP_ERR_BADVERSION".to_string()),
            40 => Some("KRB_AP_ERR_MSG_TYPE".to_string()),
            41 => Some("KRB_AP_ERR_MODIFIED".to_string()),
            42 => Some("KRB_AP_ERR_BADORDER".to_string()),
            44 => Some("KRB_AP_ERR_BADKEYVER".to_string()),
            45 => Some("KRB_AP_ERR_NOKEY".to_string()),
            46 => Some("KRB_AP_ERR_MUT_FAIL".to_string()),
            47 => Some("KRB_AP_ERR_BADDIRECTION".to_string()),
            48 => Some("KRB_AP_ERR_METHOD".to_string()),
            49 => Some("KRB_AP_ERR_BADSEQ".to_string()),
            50 => Some("KRB_AP_ERR_INAPP_CKSUM".to_string()),
            51 => Some("KRB_AP_PATH_NOT_ACCEPTED".to_string()),
            52 => Some("KRB_ERR_RESPONSE_TOO_BIG".to_string()),
            60 => Some("KRB_ERR_GENERIC".to_string()),
            61 => Some("KRB_ERR_FIELD_TOOLONG".to_string()),
            62 => Some("KDC_ERROR_CLIENT_NOT_TRUSTED".to_string()),
            63 => Some("KDC_ERROR_KDC_NOT_TRUSTED".to_string()),
            64 => Some("KDC_ERROR_INVALID_SIG".to_string()),
            65 => Some("KDC_ERR_KEY_TOO_WEAK".to_string()),
            66 => Some("KDC_ERR_CERTIFICATE_MISMATCH".to_string()),
            67 => Some("KRB_AP_ERR_NO_TGT".to_string()),
            68 => Some("KDC_ERR_WRONG_REALM".to_string()),
            69 => Some("KRB_AP_ERR_USER_TO_USER_REQUIRED".to_string()),
            70 => Some("KDC_ERR_CANT_VERIFY_CERTIFICATE".to_string()),
            71 => Some("KDC_ERR_INVALID_CERTIFICATE".to_string()),
            72 => Some("KDC_ERR_REVOKED_CERTIFICATE".to_string()),
            73 => Some("KDC_ERR_REVOCATION_STATUS_UNKNOWN".to_string()),
            74 => Some("KDC_ERR_REVOCATION_STATUS_UNAVAILABLE".to_string()),
            75 => Some("KDC_ERR_CLIENT_NAME_MISMATCH".to_string()),
            76 => Some("KDC_ERR_KDC_NAME_MISMATCH".to_string()),
            _ => None
        }
    }
}

pub mod kdcoptions {
    pub const reserved: usize = 0; 
    pub const forwardable: usize = 1; 
    pub const forwarded: usize = 2; 
    pub const proxiable: usize = 3; 
    pub const proxy: usize = 4; 
    pub const allow_postdate: usize = 5; 
    pub const postdated: usize = 6; 
    pub const unused7: usize = 7; 
    pub const renewable: usize = 8; 
    pub const unused9: usize = 9; 
    pub const unused10: usize = 10; 
    pub const opt_hardware_auth: usize = 11; 
    pub const unused12: usize = 12; 
    pub const unused13: usize = 13; 
}

pub mod encryption {
    pub const des_cbc_crc                     : usize =   1; //              6.2.3
    pub const des_cbc_md4                     : usize =   2; //              6.2.2
    pub const des_cbc_md5                     : usize =   3; //              6.2.1
    // pub const [reserved]                      : usize =   4; // 
    pub const des3_cbc_md5                    : usize =   5; // 
    // pub const [reserved]                      : usize =   6; // 
    pub const des3_cbc_sha1                   : usize =   7; // 
    pub const dsaWithSHA1_CmsOID              : usize =   9; //            (pkinit)
    pub const md5WithRSAEncryption_CmsOID     : usize =  10; //            (pkinit)
    pub const sha1WithRSAEncryption_CmsOID    : usize =  11; //            (pkinit)
    pub const rc2CBC_EnvOID                   : usize =  12; //            (pkinit)
    pub const rsaEncryption_EnvOID            : usize =  13; //    (pkinit from PKCS#1 v1.5)
    pub const rsaES_OAEP_ENV_OID              : usize =  14; //    (pkinit from PKCS#1 v2.0)
    pub const des_ede3_cbc_Env_OID            : usize =  15; //            (pkinit)
    pub const des3_cbc_sha1_kd                : usize =  16; //               6.3
    pub const aes128_cts_hmac_sha1_96         : usize =  17; //           [KRB5_AES]
    pub const aes256_cts_hmac_sha1_96         : usize =  18; //           [KRB5_AES]
    pub const rc4_hmac                        : usize =  23; //           (Microsoft)
    pub const rc4_hmac_exp                    : usize =  24; //           (Microsoft)
    pub const subkey_keymaterial              : usize =  65; //      (opaque; PacketCable)
}
