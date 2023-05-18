
package com.evoting.paillier.crypto.cryptosystem.impl

import cats.effect.SyncIO
import com.evoting.paillier.Exportable
import com.evoting.paillier.crypto.cryptosystem.PartialDecryption
import com.evoting.paillier.crypto.keys.PublicKeyLike
import com.evoting.paillier.crypto.messages.CiphertextBase64
import com.evoting.paillier.crypto.messages.CiphertextWithRandomness

import com.evoting.paillier.crypto.messages.EncryptedMessage
import com.evoting.paillier.crypto.messages.PlainMessage
import com.evoting.paillier.crypto.messages.PlaintextBase64

import java.util.Base64

case class PaillierBase64(override val publicKey: PublicKeyLike) extends Paillier(publicKey) {

  override def encrypt(data: PlainMessage): SyncIO[Either[Throwable, EncryptedMessage]] =
    super.encrypt(data).map(_.map(e => CiphertextBase64(e.toStringBase64)))

  override def combine(partialDecryptions: Vector[PartialDecryption]): Either[Throwable, PlainMessage] =
    super.combine(partialDecryptions).map(pd => PlaintextBase64(pd.toStringBase64))

  override def encryptWithRandomness(data: PlainMessage): SyncIO[Either[Throwable, CiphertextWithRandomness]] =
    super.encryptWithRandomness(data).map(_.map(cwr => CiphertextWithRandomness(CiphertextBase64(cwr.ciphertext.toStringBase64), cwr.randomness)))

  override def add(lhs: EncryptedMessage, rhs: EncryptedMessage): Either[Throwable, EncryptedMessage] =
    super.add(lhs, rhs).map(sum => CiphertextBase64(sum.toStringBase64))

}
