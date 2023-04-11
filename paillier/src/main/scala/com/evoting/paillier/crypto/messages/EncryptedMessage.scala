package com.evoting.paillier.crypto.messages

import com.evoting.paillier.Exportable
import com.evoting.paillier.Randomness

trait EncryptedMessage extends Exportable

case class Ciphertext(value: BigInt) extends EncryptedMessage {

  override val toBigInt: BigInt = value

}

case class CiphertextWithRandomness(ciphertext: EncryptedMessage, randomness: Randomness) extends EncryptedMessage {

  override val toBigInt: BigInt = ciphertext.toBigInt

}

case class CiphertextBase64(value: String) extends EncryptedMessage {

  override val toStringBase64: String = value

  override val toBigInt: BigInt = decodeBase64(value)
}
