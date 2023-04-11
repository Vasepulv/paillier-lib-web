package com.evoting.paillier.crypto.cryptosystem.impl.zkp

import com.evoting.paillier.crypto.messages.EncryptedMessage

case class ThresholdDecryptionCommitmentZKP(e: BigInt, z: BigInt) {

  def verifyZKP(partialDecryption: PartialDecryptionZKP, ciphertext: EncryptedMessage): Boolean = {

    // u = c^4
    val u = ciphertext.toBigInt.modPow(4, partialDecryption.pk.squared)

    // uu = ci^2
    val uu = partialDecryption.partialDecrypted.toBigInt.modPow(2, partialDecryption.pk.squared)

    // a = c^4z * ci^(2*-e)
    val a = (u.modPow(z, partialDecryption.pk.squared) * uu.modPow(-e, partialDecryption.pk.squared)).mod(partialDecryption.pk.squared)

    // b = v^z * vi^(-e)
    val b =
      (partialDecryption.vpk.v.modPow(z, partialDecryption.pk.squared) * partialDecryption.vKey.toBigInt.modPow(-e, partialDecryption.pk.squared)).mod(partialDecryption.pk.squared)

    // e = H(a, b, u, uu)
    val challenge_string = "" + a + b + u + uu
    val md               = java.security.MessageDigest.getInstance("SHA-256")
    val challenge_sha256 = md.digest(challenge_string.getBytes("UTF-8"))

    BigInt(1, challenge_sha256) == e
  }
}
