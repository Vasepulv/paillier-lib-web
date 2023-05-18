package com.evoting.paillier.crypto.cryptosystem

import cats.effect.SyncIO
import com.evoting.paillier.crypto.keys.PublicKeyLike
import com.evoting.paillier.crypto.messages.CiphertextWithRandomness
import com.evoting.paillier.crypto.messages.EncryptedMessage
import com.evoting.paillier.crypto.messages.PlainMessage

trait PaillierLike {

  val publicKey: PublicKeyLike

  def encrypt(data: PlainMessage): SyncIO[Either[Throwable, EncryptedMessage]]

  def encryptWithRandomness(data: PlainMessage): SyncIO[Either[Throwable, CiphertextWithRandomness]]

  def add(lhs: EncryptedMessage, rhs: EncryptedMessage): Either[Throwable, EncryptedMessage]

  def combine(partialDecryptions: Vector[PartialDecryption]): Either[Throwable, PlainMessage]

  def reencrypt(message: EncryptedMessage): SyncIO[Either[Throwable, CiphertextWithRandomness]]
}
