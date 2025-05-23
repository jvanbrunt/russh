use std::fmt::Debug;
use std::ops::Deref;

use hex_literal::hex;
use num_bigint::{BigUint, RandBigInt};
use rand;

#[derive(Clone)]
pub enum DhGroupUInt {
    Static(&'static [u8]),
    Owned(Vec<u8>),
}

impl From<Vec<u8>> for DhGroupUInt {
    fn from(x: Vec<u8>) -> Self {
        Self::Owned(x)
    }
}

impl DhGroupUInt {
    pub const fn new(x: &'static [u8]) -> Self {
        Self::Static(x)
    }
}

impl Deref for DhGroupUInt {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Static(x) => x,
            Self::Owned(x) => x,
        }
    }
}

#[derive(Clone)]
pub struct DhGroup {
    pub(crate) prime: DhGroupUInt,
    pub(crate) generator: DhGroupUInt,
    // pub(crate) exp_size: u64,
}

impl DhGroup {
    pub fn bit_size(&self) -> usize {
        let Some(fsb_idx) = self.prime.deref().iter().position(|&x| x != 0) else {
            return 0;
        };
        (self.prime.deref().len() - fsb_idx) * 8
    }
}

impl Debug for DhGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhGroup")
            .field("prime", &format!("<{} bytes>", self.prime.deref().len()))
            .field(
                "generator",
                &format!("<{} bytes>", self.generator.deref().len()),
            )
            .finish()
    }
}

pub const DH_GROUP1: DhGroup = DhGroup {
    prime: DhGroupUInt::new(
        hex!(
            "
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
         29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
         EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
         E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
         EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
         FFFFFFFF FFFFFFFF
        "
        )
        .as_slice(),
    ),
    generator: DhGroupUInt::new(&[2]),
    // exp_size: 256,
};

pub const DH_GROUP14: DhGroup = DhGroup {
    prime: DhGroupUInt::new(
        hex!(
            "
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
        E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
        EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
        C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
        83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
        670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
        E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
        DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
        15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
        "
        )
        .as_slice(),
    ),
    generator: DhGroupUInt::new(&[2]),
    // exp_size: 256,
};

/// https://www.ietf.org/rfc/rfc3526.txt
pub const DH_GROUP15: DhGroup = DhGroup {
    prime: DhGroupUInt::new(
        hex!(
            "
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
        E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
        EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
        C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
        83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
        670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
        E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
        DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
        15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
        ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
        ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
        F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
        BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
        43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF
            "
        )
        .as_slice(),
    ),
    generator: DhGroupUInt::new(&[2]),
};

pub const DH_GROUP16: DhGroup = DhGroup {
    prime: DhGroupUInt::new(
        hex!(
            "
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
        E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
        EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
        C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
        83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
        670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
        E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
        DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
        15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
        ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
        ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
        F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
        BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
        43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
        88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
        2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
        287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
        1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
        93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
        FFFFFFFF FFFFFFFF
        "
        )
        .as_slice(),
    ),
    generator: DhGroupUInt::new(&[2]),
    // exp_size: 512,
};

/// https://www.ietf.org/rfc/rfc3526.txt
pub const DH_GROUP17: DhGroup = DhGroup {
    prime: DhGroupUInt::new(
        hex!(
            "
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
    8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
    302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
    A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
    49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
    FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
    180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
    3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
    04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
    B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
    1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
    BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
    E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26
    99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB
    04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
    233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127
    D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
    36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406
    AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918
    DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151
    2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03
    F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F
    BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
    CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B
    B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632
    387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E
    6DCC4024 FFFFFFFF FFFFFFFF
    "
        )
        .as_slice(),
    ),
    generator: DhGroupUInt::new(&[2]),
};

/// https://www.ietf.org/rfc/rfc3526.txt
pub const DH_GROUP18: DhGroup = DhGroup {
    prime: DhGroupUInt::new(
        hex!(
            "
      FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
      ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
      ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
      F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
      BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
      43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
      88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
      2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
      287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
      1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
      93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
      36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD
      F8FF9406 AD9E530E E5DB382F 413001AE B06A53ED 9027D831
      179727B0 865A8918 DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B
      DB7F1447 E6CC254B 33205151 2BD7AF42 6FB8F401 378CD2BF
      5983CA01 C64B92EC F032EA15 D1721D03 F482D7CE 6E74FEF6
      D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F BEC7E8F3
      23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
      CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328
      06A1D58B B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C
      DA56C9EC 2EF29632 387FE8D7 6E3C0468 043E8F66 3F4860EE
      12BF2D5B 0B7474D6 E694F91E 6DBE1159 74A3926F 12FEE5E4
      38777CB6 A932DF8C D8BEC4D0 73B931BA 3BC832B6 8D9DD300
      741FA7BF 8AFC47ED 2576F693 6BA42466 3AAB639C 5AE4F568
      3423B474 2BF1C978 238F16CB E39D652D E3FDB8BE FC848AD9
      22222E04 A4037C07 13EB57A8 1A23F0C7 3473FC64 6CEA306B
      4BCBC886 2F8385DD FA9D4B7F A2C087E8 79683303 ED5BDD3A
      062B3CF5 B3A278A6 6D2A13F8 3F44F82D DF310EE0 74AB6A36
      4597E899 A0255DC1 64F31CC5 0846851D F9AB4819 5DED7EA1
      B1D510BD 7EE74D73 FAF36BC3 1ECFA268 359046F4 EB879F92
      4009438B 481C6CD7 889A002E D5EE382B C9190DA6 FC026E47
      9558E447 5677E9AA 9E3050E2 765694DF C81F56E8 80B96E71
      60C980DD 98EDD3DF FFFFFFFF FFFFFFFF
            "
        )
        .as_slice(),
    ),
    generator: DhGroupUInt::new(&[2]),
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct DH {
    prime_num: BigUint,
    generator: BigUint,
    private_key: BigUint,
    public_key: BigUint,
    shared_secret: BigUint,
}

impl DH {
    pub fn new(group: &DhGroup) -> Self {
        Self {
            prime_num: BigUint::from_bytes_be(&group.prime),
            generator: BigUint::from_bytes_be(&group.generator),
            private_key: BigUint::default(),
            public_key: BigUint::default(),
            shared_secret: BigUint::default(),
        }
    }

    pub fn generate_private_key(&mut self, is_server: bool) -> BigUint {
        let q = (&self.prime_num - &BigUint::from(1u8)) / &BigUint::from(2u8);
        let mut rng = rand::thread_rng();
        self.private_key =
            rng.gen_biguint_range(&if is_server { 1u8.into() } else { 2u8.into() }, &q);
        self.private_key.clone()
    }

    pub fn generate_public_key(&mut self) -> BigUint {
        self.public_key = self.generator.modpow(&self.private_key, &self.prime_num);
        self.public_key.clone()
    }

    pub fn compute_shared_secret(&mut self, other_public_key: BigUint) -> BigUint {
        self.shared_secret = other_public_key.modpow(&self.private_key, &self.prime_num);
        self.shared_secret.clone()
    }

    pub fn validate_shared_secret(&self, shared_secret: &BigUint) -> bool {
        let one = BigUint::from(1u8);
        let prime_minus_one = &self.prime_num - &one;

        shared_secret > &one && shared_secret < &prime_minus_one
    }

    pub fn decode_public_key(buffer: &[u8]) -> BigUint {
        BigUint::from_bytes_be(buffer)
    }

    pub fn validate_public_key(&self, public_key: &BigUint) -> bool {
        let one = BigUint::from(1u8);
        let prime_minus_one = &self.prime_num - &one;

        public_key > &one && public_key < &prime_minus_one
    }
}

pub(crate) const BUILTIN_SAFE_DH_GROUPS: &[&DhGroup] = &[&DH_GROUP14, &DH_GROUP16];
