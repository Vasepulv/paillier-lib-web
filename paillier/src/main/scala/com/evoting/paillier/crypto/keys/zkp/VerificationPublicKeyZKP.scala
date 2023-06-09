package com.evoting.paillier.crypto.keys.zkp

import cats.effect.SyncIO

/* Verification key
 * A public key to verify the correct threshold decryption
 * */
case class VerificationPublicKeyZKP(v: BigInt)
