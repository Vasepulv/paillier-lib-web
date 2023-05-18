
package com.evoting.paillier.crypto.cryptosystem.impl.zkp

import com.evoting.paillier.crypto.keys.PublicKeyLike
import com.evoting.paillier.crypto.keys.zkp.PrivateThresholdKeyZKP
import com.evoting.paillier.crypto.keys.zkp.SecretVerificationShare
import com.evoting.paillier.crypto.keys.zkp.VerificationPublicKeyZKP
import com.evoting.paillier.crypto.messages.Ciphertext
import com.evoting.paillier.crypto.messages.EncryptedMessage
import com.evoting.paillier.util.Utils.fact

import java.security.SecureRandom

object PartialDecryptionZKP {

  def apply(secret: PrivateThresholdKeyZKP, ciphertext: EncryptedMessage): PartialDecryptionZKP = {
    // random value of the size (s+2)k+t , where t = bitsize of the hash
    val r = BigInt(3 * secret.publicKey.bitLength + 256, new SecureRandom())

    // u = c^4 mod n^2
    val u = ciphertext.toBigInt.modPow(4, secret.publicKey.squared)

    // a = c^4r mod n^2
    val a = u.modPow(r, secret.publicKey.squared)

    // b = v^r mod n^2
    val b = secret.verificationPK.v.modPow(r, secret.publicKey.squared)

    // decrypted value
    val delta = fact(secret.l)
    val ci    = ciphertext.toBigInt.modPow(2 * delta * secret.secret.toBigInt, secret.publicKey.squared)

    // uu = ci^2
    val uu = ci.modPow(2, secret.publicKey.squared)

    // e = H(a, b, u, uu)
    val challenge_string = "" + a + b + u + uu
    val md               = java.security.MessageDigest.getInstance("SHA-256")
    val challenge_sha256 = md.digest(challenge_string.getBytes("UTF-8"))
    val e                = BigInt(1, challenge_sha256)

    // z = r + e*si*delta
    val z = r + e * delta * secret.secret.toBigInt

    new PartialDecryptionZKP(
      secret.publicKey,
      secret.verificationPK,
      secret.l,
      secret.w,
      secret.index,
      Ciphertext(ci),
      secret.vi,
      ThresholdDecryptionCommitmentZKP(e, z)
    )
  }
}

case class PartialDecryptionZKP(
    pk: PublicKeyLike,
    vpk: VerificationPublicKeyZKP,
    l: Int,
    w: Int,
    index: Int,
    partialDecrypted: EncryptedMessage,
    vKey: SecretVerificationShare,
    commitment: ThresholdDecryptionCommitmentZKP
)
