package com.evoting.paillier.crypto.cryptosystem

import com.evoting.paillier.crypto.keys.PrivateThresholdKey
import com.evoting.paillier.crypto.keys.PublicKeyLike
import com.evoting.paillier.crypto.messages.Ciphertext
import com.evoting.paillier.crypto.messages.EncryptedMessage
import com.evoting.paillier.util.Utils.fact

case class PartialDecryption(pk: PublicKeyLike, l: Int, w: Int, index: Int, partialDecrypted: EncryptedMessage) 

object PartialDecryption {

  // An auxiliary constructor to create a PartialDecryption object from the privateKey and the ciphertext
  def apply(privateKey: PrivateThresholdKey, ciphertext: EncryptedMessage): PartialDecryption = {
    val delta = fact(privateKey.l)
    val ci    = ciphertext.toBigInt.modPow(2 * delta * privateKey.secret.toBigInt, privateKey.publicKey.squared)
    PartialDecryption(privateKey.publicKey, privateKey.l, privateKey.w, privateKey.index, Ciphertext(ci))
  }

  // An auxiliary constructor to create a Vector of PartialDecryption object for arbitrary size plaintext
  def apply(privateKey: PrivateThresholdKey, ciphertext: Vector[EncryptedMessage]): Vector[PartialDecryption] = {
    val delta = fact(privateKey.l)
    ciphertext.map { ct =>
      val ci = ct.toBigInt.modPow(2 * delta * privateKey.secret.toBigInt, privateKey.publicKey.squared)
      PartialDecryption(privateKey.publicKey, privateKey.l, privateKey.w, privateKey.index, Ciphertext(ci))
    }
  }
}
