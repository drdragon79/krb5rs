#![allow(dead_code)]
use rasn::prelude::*;

/// ```asn.1
/// Int32           ::= INTEGER (-2147483648..2147483647)
/// ```
pub type Int32 = i32;

/// ```asn.1
/// UInt32          ::= INTEGER (0..4294967295)
/// ```
pub type UInt32 = u32;

/// ```asn.1
/// Microseconds    ::= INTEGER (0..999999)
/// ```
pub type Microseconds = u32;

/// ```asn.1
/// KerberosString  ::= GeneralString (IA5String)
/// ```
pub type KerberosString = GeneralString;

/// ```asn.1
/// Realm           ::= KerberosString
/// ```
pub type Realm = KerberosString;

/// ```asn.1
/// PrincipalName   ::= SEQUENCE {
///         name-type       [0] Int32,
///         name-string     [1] SEQUENCE OF KerberosString
/// }
/// ```
#[derive(AsnType, Decode, Encode, Clone, Debug)]
pub struct PrincipalName {
    #[rasn(tag(explicit(0)))]
    pub name_type: Int32,
    #[rasn(tag(explicit(1)))]
    pub name_string: SequenceOf<KerberosString>
}

/// ```asn.1
/// KerberosTime    ::= GeneralizedTime -- with no fractional seconds
/// ```
pub type KerberosTime = GeneralizedTime;

/// ```asn.1
/// HostAddress     ::= SEQUENCE  {
///         addr-type       [0] Int32,
///         address         [1] OCTET STRING
/// }
/// ```
#[derive(AsnType, Decode, Encode, Clone, Debug)]
pub struct HostAddress {
    #[rasn(tag(explicit(0)))]
    pub addr_type: Int32,
    #[rasn(tag(explicit(1)))]
    pub address: OctetString
}

/// ```asn.1
/// HostAddresses       ::= SEQUENCE OF HostAddress
/// ```
pub type HostAddresses = SequenceOf<HostAddress>;

#[derive(AsnType, Decode, Encode, Clone, Debug)]
pub struct AdEntry {
    #[rasn(tag(explicit(1)))]
    pub ad_type: Int32,
    #[rasn(tag(explicit(2)))]
    pub ad_data: OctetString
}

/// ```asn.1
/// AuthorizationData       ::= SEQUENCE OF SEQUENCE {
///         ad-type         [0] Int32,
///         ad-data         [1] OCTET STRING
/// }
/// ```
pub type AuthorizationData = SequenceOf<AdEntry>;

/// ```asn1
/// PA-DATA         ::= SEQUENCE {
///         -- NOTE: first tag is [1], not [0]
///         padata-type     [1] Int32,
///         padata-value    [2] OCTET STRING 
/// }
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
pub struct PaData {
    #[rasn(tag(explicit(1)))]
    pub padata_type: Int32,
    #[rasn(tag(explicit(2)))]
    pub padata_value: OctetString
}

/// ```asn.1
/// KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
/// ```
pub type KerberosFlags = BitString;

/// ```asn.1
/// EncryptedData   ::= SEQUENCE {
///         etype   [0] Int32 -- EncryptionType --,
///         kvno    [1] UInt32 OPTIONAL,
///         cipher  [2] OCTET STRING -- ciphertext
/// }
/// ```
#[derive(AsnType, Decode, Encode, Clone, Debug)]
pub struct EncryptedData {
    #[rasn(tag(explicit(0)))]
    pub etype: Int32,
    #[rasn(tag(explicit(1)))]
    pub kvno: Option<UInt32>,
    #[rasn(tag(explicit(2)))]
    pub cipher: OctetString
}

/// ```asn.1
/// EncryptionKey   ::= SEQUENCE {
///         keytype         [0] Int32 -- actually encryption type --,
///         keyvalue        [1] OCTET STRING
/// }
/// ```
#[derive(AsnType, Debug, Decode, Encode, Clone)]
pub struct EncryptionKey {
    #[rasn(tag(explicit(0)))]
    pub keytype: Int32,
    #[rasn(tag(explicit(1)))]
    pub keyvalue: OctetString
}

/// ```asn.1
/// Checksum        ::= SEQUENCE {
///         cksumtype       [0] Int32,
///         checksum        [1] OCTET STRING
/// }
/// ```
#[derive(AsnType, Decode, Encode, Clone, Debug)]
pub struct Checksum {
    #[rasn(tag(explicit(0)))]
    pub cksumtype: Int32,
    #[rasn(tag(explicit(1)))]
    pub checksum: OctetString
}

/// ```asn.1
/// Ticket          ::= [APPLICATION 1] SEQUENCE {
///         tkt-vno         [0] INTEGER (5),
///         realm           [1] Realm,
///         sname           [2] PrincipalName,
///         enc-part        [3] EncryptedData -- EncTicketPart
/// }
/// ```
#[derive(AsnType, Decode, Encode, Clone, Debug)]
#[rasn(tag(explicit(application, 1)))]
pub struct Ticket {
    #[rasn(tag(explicit(0)))]
    pub tkt_vno: Int32,
    #[rasn(tag(explicit(1)))]
    pub realm: Realm,
    #[rasn(tag(explicit(2)))]
    pub sname: PrincipalName,
    #[rasn(tag(explicit(3)))]
    pub enc_part: EncryptedData
}

/// ```asn.1
/// EncTicketPart   ::= [APPLICATION 3] SEQUENCE {
///         flags                   [0] TicketFlags,
///         key                     [1] EncryptionKey,
///         crealm                  [2] Realm,
///         cname                   [3] PrincipalName,
///         transited               [4] TransitedEncoding,
///         authtime                [5] KerberosTime,
///         starttime               [6] KerberosTime OPTIONAL,
///         endtime                 [7] KerberosTime,
///         renew-till              [8] KerberosTime OPTIONAL,
///         caddr                   [9] HostAddresses OPTIONAL,
///         authorization-data      [10] AuthorizationData OPTIONAL
/// }
/// ```
#[derive(AsnType, Decode, Encode, Clone, Debug)]
#[rasn(tag(explicit(application, 3)))]
pub struct EncTicketPart {
    #[rasn(tag(explicit(0)))]
    pub flags: TicketFlags,
    #[rasn(tag(explicit(1)))]
    pub key: EncryptionKey,
    #[rasn(tag(explicit(2)))]
    pub crealm: Realm,
    #[rasn(tag(explicit(3)))]
    pub cname: PrincipalName,
    #[rasn(tag(explicit(4)))]
    pub transited: TransitedEncoding,
    #[rasn(tag(explicit(5)))]
    pub authtime: KerberosTime,
    #[rasn(tag(explicit(6)))]
    pub starttime: Option<KerberosTime>,
    #[rasn(tag(explicit(7)))]
    pub endtime: KerberosTime,
    #[rasn(tag(explicit(8)))]
    pub renew_till: Option<KerberosTime>,
    #[rasn(tag(explicit(9)))]
    pub caddr: Option<HostAddresses>,
    #[rasn(tag(explicit(10)))]
    pub authorization_data: Option<AuthorizationData>
}

/// ```asn.1
/// TransitedEncoding       ::= SEQUENCE {
///     tr-type         [0] Int32 -- must be registered --,
///     contents        [1] OCTET STRING
/// }
/// ```
#[derive(AsnType, Decode, Encode, Clone, Debug)]
pub struct TransitedEncoding {
    #[rasn(tag(explicit(0)))]
    pub tr_type: Int32,
    #[rasn(tag(explicit(1)))]
    pub contents: OctetString
}

/// ```asn.1
/// TicketFlags     ::= KerberosFlags
///         -- reserved(0),
///         -- forwardable(1),
///         -- forwarded(2),
///         -- proxiable(3),
///         -- proxy(4),
///         -- may-postdate(5),
///         -- postdated(6),
///         -- invalid(7),
///         -- renewable(8),
///         -- initial(9),
///         -- pre-authent(10),
///         -- hw-authent(11),
/// -- the following are new since 1510
///         -- transited-policy-checked(12),
///         -- ok-as-delegate(13)
/// ```
pub type TicketFlags = KerberosFlags;

/// ```asn.1
/// AS-REQ          ::= [APPLICATION 10] KDC-REQ
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
#[rasn(delegate, tag(explicit(application, 10)))]
pub struct AsReq(pub KdcReq);

/// ```asn.1
/// TGS-REQ         ::= [APPLICATION 12] KDC-REQ
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
#[rasn(delegate, tag(explicit(application, 12)))]
pub struct TgsReq(pub KdcReq);

/// ```asn.1
/// KDC-REQ         ::= SEQUENCE {
///         -- NOTE: first tag is [1], not [0]
///         pvno            [1] INTEGER (5) ,
///         msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
///         padata          [3] SEQUENCE OF PA-DATA OPTIONAL
///                             -- NOTE: not empty --,
///         req-body        [4] KDC-REQ-BODY
/// }
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
pub struct KdcReq {
    #[rasn(tag(explicit(1)))]
    pub pvno: Int32,
    #[rasn(tag(explicit(2)))]
    pub msg_type: Int32,
    #[rasn(tag(explicit(3)))]
    pub padata: Option<SequenceOf<PaData>>,
    #[rasn(tag(explicit(4)))]
    pub req_body: KdcReqBody
}

/// ```asn.1
/// KDC-REQ-BODY    ::= SEQUENCE {
///         kdc-options             [0] KDCOptions,
///         cname                   [1] PrincipalName OPTIONAL
///                                     -- Used only in AS-REQ --,
///         realm                   [2] Realm
///                                     -- Server's realm
///                                     -- Also client's in AS-REQ --,
///         sname                   [3] PrincipalName OPTIONAL,
///         from                    [4] KerberosTime OPTIONAL,
///         till                    [5] KerberosTime,
///         rtime                   [6] KerberosTime OPTIONAL,
///         nonce                   [7] UInt32,
///         etype                   [8] SEQUENCE OF Int32 -- EncryptionType
///                                     -- in preference order --,
///         addresses               [9] HostAddresses OPTIONAL,
///         enc-authorization-data  [10] EncryptedData OPTIONAL
///                                     -- AuthorizationData --,
///         additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
///                                         -- NOTE: not empty
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
pub struct KdcReqBody {
    #[rasn(tag(explicit(0)))]
    pub kdc_options: KdcOptions,
    #[rasn(tag(explicit(1)))]
    pub cname: Option<PrincipalName>,
    #[rasn(tag(explicit(2)))]
    pub realm: Realm,
    #[rasn(tag(explicit(3)))]
    pub sname: Option<PrincipalName>,
    #[rasn(tag(explicit(4)))]
    pub from: Option<KerberosTime>,
    #[rasn(tag(explicit(5)))]
    pub till: KerberosTime,
    #[rasn(tag(explicit(6)))]
    pub rtime:Option<KerberosTime>,
    #[rasn(tag(explicit(7)))]
    pub nonce: UInt32,
    #[rasn(tag(explicit(8)))]
    pub etype: SequenceOf<Int32>,
    #[rasn(tag(explicit(9)))]
    pub addresses: Option<HostAddresses>,
    #[rasn(tag(explicit(10)))]
    pub enc_authorization_data: Option<EncryptedData>,
    #[rasn(tag(explicit(12)))]
    pub additional_tickets: Option<SequenceOf<Ticket>>
}

/// ```asn.1
/// KDCOptions      ::= KerberosFlags
///         -- reserved(0),
///         -- forwardable(1),
///         -- forwarded(2),
///         -- proxiable(3),
///         -- proxy(4),
///         -- allow-postdate(5),
///         -- postdated(6),
///         -- unused7(7),
///         -- renewable(8),
///         -- unused9(9),
///         -- unused10(10),
///         -- opt-hardware-auth(11),
///         -- unused12(12),
///         -- unused13(13),
/// -- 15 is reserved for canonicalize
///         -- unused15(15),
/// -- 26 was unused in 1510
///         -- disable-transited-check(26),
/// --
///         -- renewable-ok(27),
///         -- enc-tkt-in-skey(28),
///         -- renew(30),
///         -- validate(31)
pub type KdcOptions = KerberosFlags;

/// ```asn.1
/// AS-REP          ::= [APPLICATION 11] KDC-REP
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
#[rasn(delegate, tag(explicit(application, 11)))]
pub struct AsRep(pub KdcRep);

/// ```asn.1
/// TGS-REP         ::= [APPLICATION 13] KDC-REP
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
#[rasn(delegate, tag(explicit(application, 13)))]
pub struct TgsRep(pub KdcRep);

/// ```asn.1
/// KDC-REP         ::= SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
///         padata          [2] SEQUENCE OF PA-DATA OPTIONAL
///                                 -- NOTE: not empty --,
///         crealm          [3] Realm,
///         cname           [4] PrincipalName,
///         ticket          [5] Ticket,
///         enc-part        [6] EncryptedData
///                                 -- EncASRepPart or EncTGSRepPart,
///                                 -- as appropriate
/// }
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
pub struct KdcRep {
    #[rasn(tag(explicit(0)))]
    pub pvno: Int32,
    #[rasn(tag(explicit(1)))]
    pub mgs_type: Int32,
    #[rasn(tag(explicit(2)))]
    pub padata: Option<SequenceOf<PaData>>,
    #[rasn(tag(explicit(3)))]
    pub crealm: Realm,
    #[rasn(tag(explicit(4)))]
    pub cname: PrincipalName,
    #[rasn(tag(explicit(5)))]
    pub ticket: Ticket,
    #[rasn(tag(explicit(6)))]
    pub enc_part: EncryptedData
}

/// ```asn.1
/// EncASRepPart    ::= [APPLICATION 25] EncKDCRepPart
/// ```
#[derive(AsnType, Decode, Encode, Clone, Debug)]
#[rasn(delegate, tag(explicit(application, 25)))]
pub struct EncAsRepPart(pub EncKdcRepPart);

/// ```asn.1
/// EncTGSRepPart   ::= [APPLICATION 26] EncKDCRepPart
/// ```
#[derive(AsnType, Decode, Encode, Clone, Debug)]
#[rasn(delegate, tag(explicit(application, 25)))]
pub struct EncTgsRepPart(pub EncKdcRepPart);

/// ```asn.1
/// EncKDCRepPart   ::= SEQUENCE {
///         key             [0] EncryptionKey,
///         last-req        [1] LastReq,
///         nonce           [2] UInt32,
///         key-expiration  [3] KerberosTime OPTIONAL,
///         flags           [4] TicketFlags,
///         authtime        [5] KerberosTime,
///         starttime       [6] KerberosTime OPTIONAL,
///         endtime         [7] KerberosTime,
///         renew-till      [8] KerberosTime OPTIONAL,
///         srealm          [9] Realm,
///         sname           [10] PrincipalName,
///         caddr           [11] HostAddresses OPTIONAL
/// }
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
pub struct EncKdcRepPart {
    #[rasn(tag(explicit(0)))]
    pub key: EncryptionKey,
    #[rasn(tag(explicit(1)))]
    pub last_req: LastReq,
    #[rasn(tag(explicit(2)))]
    pub none: UInt32,
    #[rasn(tag(explicit(3)))]
    pub key_expiration: Option<KerberosTime>,
    #[rasn(tag(explicit(4)))]
    pub flags: TicketFlags,
    #[rasn(tag(explicit(5)))]
    pub authtime: KerberosTime,
    #[rasn(tag(explicit(6)))]
    pub starttime: Option<KerberosTime>,
    #[rasn(tag(explicit(7)))]
    pub endtime: KerberosTime,
    #[rasn(tag(explicit(8)))]
    pub renew_till: Option<KerberosTime>,
    #[rasn(tag(explicit(9)))]
    pub srealm: Realm,
    #[rasn(tag(explicit(10)))]
    pub sname: PrincipalName,
    #[rasn(tag(explicit(11)))]
    pub caddr: Option<HostAddresses>
}

/// ```asn.1
/// LastReq         ::=     SEQUENCE OF SEQUENCE {
///         lr-type         [0] Int32,
///         lr-value        [1] KerberosTime
/// } 
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
pub struct LastReq {
    #[rasn(tag(explicit(0)))]
    lr_type: Int32,
    #[rasn(tag(explicit(1)))]
    lr_value: KerberosTime
}

/// ```asn.1
/// AP-REQ          ::= [APPLICATION 14] SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (14),
///         ap-options      [2] APOptions,
///         ticket          [3] Ticket,
///         authenticator   [4] EncryptedData -- Authenticator
/// }
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
#[rasn(tag(explicit(application, 14)))]
pub struct ApReq {
    #[rasn(tag(explicit(0)))]
    pub pvno: Int32,
    #[rasn(tag(explicit(1)))]
    pub msg_type: Int32,
    #[rasn(tag(explicit(2)))]
    pub ap_options: ApOptions,
    #[rasn(tag(explicit(3)))]
    pub ticket: Ticket,
    #[rasn(tag(explicit(4)))]
    pub authenticator: EncryptedData
}

/// ```asn.1
/// APOptions       ::= KerberosFlags
///         -- reserved(0),
///         -- use-session-key(1),
///         -- mutual-required(2)
/// ```
pub type ApOptions = KerberosFlags;

/// ```asn.1
/// Authenticator   ::= [APPLICATION 2] SEQUENCE  {
///         authenticator-vno       [0] INTEGER (5),
///         crealm                  [1] Realm,
///         cname                   [2] PrincipalName,
///         cksum                   [3] Checksum OPTIONAL,
///         cusec                   [4] Microseconds,
///         ctime                   [5] KerberosTime,
///         subkey                  [6] EncryptionKey OPTIONAL,
///         seq-number              [7] UInt32 OPTIONAL,
///         authorization-data      [8] AuthorizationData OPTIONAL
/// }
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
#[rasn(tag(explicit(application, 2)))]
pub struct Authenticator {
    #[rasn(tag(explicit(0)))]
    pub authenticator_vno: Int32,
    #[rasn(tag(explicit(1)))]
    pub creaml: Realm,
    #[rasn(tag(explicit(2)))]
    pub cname: PrincipalName,
    #[rasn(tag(explicit(3)))]
    pub cksum: Option<Checksum>,
    #[rasn(tag(explicit(4)))]
    pub cusec: Microseconds,
    #[rasn(tag(explicit(5)))]
    pub ctime: KerberosTime,
    #[rasn(tag(explicit(6)))]
    pub subkey: Option<EncryptionKey>,
    #[rasn(tag(explicit(7)))]
    pub seq_number: Option<UInt32>,
    #[rasn(tag(explicit(8)))]
    pub authorization_data: Option<AuthorizationData>
}

/// ```asn.1
/// AP-REP          ::= [APPLICATION 15] SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (15),
///         enc-part        [2] EncryptedData -- EncAPRepPart
/// }
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
#[rasn(tag(explicit(application, 15)))]
pub struct ApRep {
    #[rasn(tag(explicit(0)))]
    pub pnvo: Int32,
    #[rasn(tag(explicit(1)))]
    pub msg_type: Int32,
    #[rasn(tag(explicit(2)))]
    pub enc_part: EncryptedData
}

/// ```asn.1
/// EncAPRepPart    ::= [APPLICATION 27] SEQUENCE {
///         ctime           [0] KerberosTime,
///         cusec           [1] Microseconds,
///         subkey          [2] EncryptionKey OPTIONAL,
///         seq-number      [3] UInt32 OPTIONAL
/// }
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
#[rasn(tag(explicit(application, 27)))]
pub struct EncApRepPart {
    #[rasn(tag(explicit(0)))]
    pub ctime: KerberosTime,
    #[rasn(tag(explicit(1)))]
    pub cusec: Microseconds,
    #[rasn(tag(explicit(2)))]
    pub subkey: Option<EncryptionKey>,
    #[rasn(tag(explicit(3)))]
    pub seq_number: Option<UInt32>
}

/// ```asn.1
/// KRB-SAFE        ::= [APPLICATION 20] SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (20),
///         safe-body       [2] KRB-SAFE-BODY,
///         cksum           [3] Checksum
/// }
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
#[rasn(tag(explicit(application, 20)))]
pub struct KrbSafe {
    #[rasn(tag(explicit(0)))]
    pub pvno: Int32,
    #[rasn(tag(explicit(1)))]
    pub msg_type: Int32,
    #[rasn(tag(explicit(2)))]
    pub safe_body: KrbSafeBody,
    #[rasn(tag(explicit(3)))]
    pub cksum: Checksum
}

/// ```asn.1
/// KRB-SAFE-BODY   ::= SEQUENCE {
///         user-data       [0] OCTET STRING,
///         timestamp       [1] KerberosTime OPTIONAL,
///         usec            [2] Microseconds OPTIONAL,
///         seq-number      [3] UInt32 OPTIONAL,
///         s-address       [4] HostAddress,
///         r-address       [5] HostAddress OPTIONAL
/// }
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
pub struct KrbSafeBody {
    #[rasn(tag(explicit(0)))]
    pub user_data: OctetString,
    #[rasn(tag(explicit(1)))]
    pub timestamp: Option<KerberosTime>,
    #[rasn(tag(explicit(2)))]
    pub usec: Option<Microseconds>,
    #[rasn(tag(explicit(3)))]
    pub seq_number: Option<UInt32>,
    #[rasn(tag(explicit(4)))]
    pub s_address: HostAddress,
    #[rasn(tag(explicit(5)))]
    pub r_address: Option<HostAddresses>
}

/// ```asn.1
/// KRB-PRIV        ::= [APPLICATION 21] SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (21),
///                         -- NOTE: there is no [2] tag
///         enc-part        [3] EncryptedData -- EncKrbPrivPart
/// }
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
#[rasn(tag(explicit(application, 21)))]
pub struct KrbPriv {
    #[rasn(tag(explicit(0)))]
    pub pvno: Int32,
    #[rasn(tag(explicit(1)))]
    pub msg_type: Int32,
    #[rasn(tag(explicit(2)))]
    pub enc_part: EncryptedData
}

/// ```asn.1
/// EncKrbPrivPart  ::= [APPLICATION 28] SEQUENCE {
///         user-data       [0] OCTET STRING,
///         timestamp       [1] KerberosTime OPTIONAL,
///         usec            [2] Microseconds OPTIONAL,
///         seq-number      [3] UInt32 OPTIONAL,
///         s-address       [4] HostAddress -- sender's addr --,
///         r-address       [5] HostAddress OPTIONAL -- recip's addr
/// }
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
#[rasn(tag(explicit(application, 28)))]
pub struct EncKrbPrivPart {
    #[rasn(tag(explicit(0)))]
    pub user_data: OctetString,
    #[rasn(tag(explicit(1)))]
    pub timestamp: Option<KerberosTime>,
    #[rasn(tag(explicit(2)))]
    pub usec: Option<Microseconds>,
    #[rasn(tag(explicit(3)))]
    pub seq_number: Option<UInt32>,
    #[rasn(tag(explicit(4)))]
    pub s_address: HostAddress,
    #[rasn(tag(explicit(5)))]
    pub r_address: Option<HostAddress>
}

/// ```asn.1
/// KRB-CRED        ::= [APPLICATION 22] SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (22),
///         tickets         [2] SEQUENCE OF Ticket,
///         enc-part        [3] EncryptedData -- EncKrbCredPart
/// }
/// ```
#[derive(AsnType, Decode, Encode, Clone, Debug)]
#[rasn(tag(explicit(application, 22)))]
pub struct KrbCred {
    #[rasn(tag(explicit(0)))]
    pub pnvo: Int32,
    #[rasn(tag(explicit(0)))]
    pub msg_type: Int32,
    #[rasn(tag(explicit(0)))]
    pub tickets: SequenceOf<Ticket>,
    #[rasn(tag(explicit(0)))]
    pub enc_part: EncryptedData
}

/// ```asn.1
/// EncKrbCredPart  ::= [APPLICATION 29] SEQUENCE {
///         ticket-info     [0] SEQUENCE OF KrbCredInfo,
///         nonce           [1] UInt32 OPTIONAL,
///         timestamp       [2] KerberosTime OPTIONAL,
///         usec            [3] Microseconds OPTIONAL,
///         s-address       [4] HostAddress OPTIONAL,
///         r-address       [5] HostAddress OPTIONAL
/// }
/// ```
#[derive(AsnType, Decode, Encode, Clone, Debug)]
pub struct EncKrbCredPart {
    #[rasn(tag(explicit(0)))]
    pub ticket_info: SequenceOf<KrbCredInfo>,
    #[rasn(tag(explicit(1)))]
    pub nonce: Option<UInt32>,
    #[rasn(tag(explicit(2)))]
    pub timestamp: Option<KerberosTime>,
    #[rasn(tag(explicit(3)))]
    pub usec: Option<Microseconds>,
    #[rasn(tag(explicit(4)))]
    pub s_adrress: Option<HostAddress>,
    #[rasn(tag(explicit(5)))]
    pub r_address: Option<HostAddress>
}

/// ```asn.1
/// KrbCredInfo     ::= SEQUENCE {
///         key             [0] EncryptionKey,
///         prealm          [1] Realm OPTIONAL,
///         pname           [2] PrincipalName OPTIONAL,
///         flags           [3] TicketFlags OPTIONAL,
///         authtime        [4] KerberosTime OPTIONAL,
///         starttime       [5] KerberosTime OPTIONAL,
///         endtime         [6] KerberosTime OPTIONAL,
///         renew-till      [7] KerberosTime OPTIONAL,
///         srealm          [8] Realm OPTIONAL,
///         sname           [9] PrincipalName OPTIONAL,
///         caddr           [10] HostAddresses OPTIONAL
/// }
/// ```
#[derive(AsnType, Decode, Encode, Clone, Debug)]
pub struct KrbCredInfo {
    #[rasn(tag(explicit(0)))]
    pub key: EncryptionKey,
    #[rasn(tag(explicit(1)))]
    pub prealm: Option<Realm>,
    #[rasn(tag(explicit(2)))]
    pub pname: Option<PrincipalName>,
    #[rasn(tag(explicit(3)))]
    pub flags: Option<TicketFlags>,
    #[rasn(tag(explicit(4)))]
    pub authtime: Option<KerberosTime>,
    #[rasn(tag(explicit(5)))]
    pub starttime: Option<KerberosTime>,
    #[rasn(tag(explicit(6)))]
    pub endtime: Option<KerberosTime>,
    #[rasn(tag(explicit(7)))]
    pub renew_till: Option<KerberosTime>,
    #[rasn(tag(explicit(8)))]
    pub srealm: Option<Realm>,
    #[rasn(tag(explicit(9)))]
    pub sname: Option<PrincipalName>,
    #[rasn(tag(explicit(10)))]
    pub caddr: Option<HostAddresses>
}

/// ```asn.1
/// KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (30),
///         ctime           [2] KerberosTime OPTIONAL,
///         cusec           [3] Microseconds OPTIONAL,
///         stime           [4] KerberosTime,
///         susec           [5] Microseconds,
///         error-code      [6] Int32,
///         crealm          [7] Realm OPTIONAL,
///         cname           [8] PrincipalName OPTIONAL,
///         realm           [9] Realm -- service realm --,
///         sname           [10] PrincipalName -- service name --,
///         e-text          [11] KerberosString OPTIONAL,
///         e-data          [12] OCTET STRING OPTIONAL
/// }
/// ```
#[derive(AsnType, Decode, Encode, Clone, Debug)]
#[rasn(tag(explicit(application, 30)))]
pub struct KrbError {
    #[rasn(tag(explicit(0)))]
    pub pvno: Int32,
    #[rasn(tag(explicit(1)))]
    pub msg_type: Int32,
    #[rasn(tag(explicit(2)))]
    pub ctime: Option<KerberosTime>,
    #[rasn(tag(explicit(3)))]
    pub usec: Option<Microseconds>,
    #[rasn(tag(explicit(4)))]
    pub stime: KerberosTime,
    #[rasn(tag(explicit(5)))]
    pub susec: Microseconds,
    #[rasn(tag(explicit(6)))]
    pub error_code: Int32,
    #[rasn(tag(explicit(7)))]
    pub crealm: Option<Realm>,
    #[rasn(tag(explicit(8)))]
    pub cname: Option<PrincipalName>,
    #[rasn(tag(explicit(9)))]
    pub realm: Realm,
    #[rasn(tag(explicit(10)))]
    pub sname: PrincipalName,
    #[rasn(tag(explicit(11)))]
    pub e_text: Option<KerberosString>,
    #[rasn(tag(explicit(12)))]
    pub e_data: Option<OctetString>
}

/// ```asn.1
/// METHOD-DATA     ::= SEQUENCE OF PA-DATA
/// ```
pub type MethodData = SequenceOf<PaData>;

/// ```asn.1
/// ```
#[derive(AsnType, Decode, Encode, Clone, Debug)]
pub struct TypedDataEntry {
    #[rasn(tag(explicit(0)))]
    pub data_type: Int32,
    #[rasn(tag(explicit(1)))]
    pub data_value: Option<OctetString>
}

/// ```asn.1
/// TYPED-DATA      ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
///         data-type       [0] Int32,
///         data-value      [1] OCTET STRING OPTIONAL
/// }
/// ```
pub type TypedData = SequenceOf<TypedDataEntry>;

/// --Preauth stuff follows

/// ```asn.1
/// PA-ENC-TIMESTAMP        ::= EncryptedData -- PA-ENC-TS-ENC
/// ```
pub type PaEncTimestamp = EncryptedData;

/// ```asn.1
/// PA-ENC-TS-ENC           ::= SEQUENCE {
///         patimestamp     [0] KerberosTime -- client's time --,
///         pausec          [1] Microseconds OPTIONAL
/// }
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
pub struct PaEncTsEnc {
    #[rasn(tag(explicit(0)))]
    pub patimestamp: KerberosTime,
    #[rasn(tag(explicit(1)))]
    pub pausec: Option<Microseconds>
}

/// ```asn.1
/// ETYPE-INFO-ENTRY        ::= SEQUENCE {
///         etype           [0] Int32,
///         salt            [1] OCTET STRING OPTIONAL
/// }
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
pub struct EtypeInfoEntry {
    #[rasn(tag(explicit(0)))]
    pub etype: Int32,
    #[rasn(tag(explicit(1)))]
    pub salt: Option<OctetString>
}

/// ```asn.1
/// ETYPE-INFO              ::= SEQUENCE OF ETYPE-INFO-ENTRY
/// ```
pub type EtypeInfo = SequenceOf<EtypeInfoEntry>;

/// ```asn.1
/// ETYPE-INFO2-ENTRY       ::= SEQUENCE {
///         etype           [0] Int32,
///         salt            [1] KerberosString OPTIONAL,
///         s2kparams       [2] OCTET STRING OPTIONAL
/// }
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
pub struct EtypeInfo2Entry {
    #[rasn(tag(explicit(0)))]
    pub etype: Int32,
    #[rasn(tag(explicit(1)))]
    pub salt: Option<KerberosString>,
    #[rasn(tag(explicit(2)))]
    pub s2kparams: Option<OctetString>
}

/// ```asn.1
/// ETYPE-INFO2             ::= SEQUENCE SIZE (1..MAX) OF ETYPE-INFO2-ENTRY
/// ```
pub type EtypeInfo2 = SequenceOf<EtypeInfo2Entry>;

/// ```asn.1
/// AD-IF-RELEVANT          ::= AuthorizationData
/// ```
pub type AdIfRelevant = AuthorizationData;

/// ```asn.1
/// AD-KDCIssued            ::= SEQUENCE {
///         ad-checksum     [0] Checksum,
///         i-realm         [1] Realm OPTIONAL,
///         i-sname         [2] PrincipalName OPTIONAL,
///         elements        [3] AuthorizationData
/// }
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
pub struct AdKdcIssued {
    #[rasn(tag(explicit(0)))]
    pub ad_checksum: Checksum,
    #[rasn(tag(explicit(1)))]
    pub i_realm: Option<Realm>,
    #[rasn(tag(explicit(2)))]
    pub i_sname: Option<PrincipalName>,
    #[rasn(tag(explicit(3)))]
    pub elements: AuthorizationData
}

/// ```asn.1
/// AD-AND-OR               ::= SEQUENCE {
///         condition-count [0] Int32,
///         elements        [1] AuthorizationData
/// }
/// ```
#[derive(AsnType, Decode, Encode, Debug, Clone)]
pub struct AdAndOr {
    #[rasn(tag(explicit(0)))]
    pub condition_count: Int32,
    #[rasn(tag(explicit(1)))]
    pub elements: AuthorizationData
}

/// ```asn.1
/// AD-MANDATORY-FOR-KDC    ::= AuthorizationData
/// ```
pub type AdMandatoryForKdc = AuthorizationData;


// [MS-KILE Stuff follows]
#[derive(AsnType, Decode, Encode, Debug, Clone)]
pub struct KerbPaPacRequest {
    #[rasn(tag(explicit(0)))]
    pub include_pac: bool
}

