package com.evoting.paillier.crypto

object PaillierExceptions {

  final case class EncryptionException(message: String) extends Exception(message)

  final case class AdditionException(message: String) extends Exception(message)

  final case class DecryptionException(message: String) extends Exception(message)
}
