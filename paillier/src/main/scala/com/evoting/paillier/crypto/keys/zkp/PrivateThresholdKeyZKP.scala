package com.evoting.paillier.crypto.keys.zkp

import com.evoting.paillier.SecretShareLike
import com.evoting.paillier.crypto.keys.PublicKeyLike
import com.evoting.paillier.crypto.messages.EncryptedMessage

/* PrivateThresholdKey
 * Holds all the necessary elements to decrypt and verify
 * */
case class PrivateThresholdKeyZKP(
    publicKey: PublicKeyLike,
    verificationPK: VerificationPublicKeyZKP,
    l: Int,
    w: Int,
    index: Int,
    secret: SecretShareLike,
    vi: SecretVerificationShare
)
