package com.evoting.paillier.crypto.cryptosystem.impl.shuffle

import cats.effect.IO
import cats.effect.SyncIO
import com.evoting.paillier.crypto.cryptosystem.PaillierLike
import com.evoting.paillier.crypto.messages.CiphertextWithRandomness
import com.evoting.paillier.crypto.messages.EncryptedMessage
import cats.implicits._

class VerifiableShuffle(val paillier: PaillierLike) {

  def shuffle(encryptedMessages: Vector[EncryptedMessage], permutation: Permutation): SyncIO[Either[Throwable, Vector[CiphertextWithRandomness]]] = {
    val shuffled = permutation.invertedPermutation.map[EncryptedMessage](p => encryptedMessages(p))
    shuffled.map(message => paillier.reencrypt(message)).sequence.map(_.sequence)
  }

  def shuffleArbitrary(encryptedMessages: Vector[Vector[EncryptedMessage]], permutation: Permutation): SyncIO[Either[Throwable, Vector[Vector[CiphertextWithRandomness]]]] = {
    val shuffled = permutation.invertedPermutation.map[Vector[EncryptedMessage]](p => encryptedMessages(p))
    shuffled.map(s => s.map(m => paillier.reencrypt(m)).sequence.map(_.sequence)).sequence.map(_.sequence)
  }
}
