package com.evoting.paillier.crypto.cryptosystem.impl

import cats.effect.SyncIO
import cats.effect.IO
import cats.implicits._
import com.evoting.paillier.crypto.PaillierExceptions.AdditionException
import com.evoting.paillier.crypto.PaillierExceptions.EncryptionException
import com.evoting.paillier.crypto.cryptosystem.PartialDecryption
import com.evoting.paillier.crypto.keys.PublicKeyLike
import com.evoting.paillier.crypto.messages.EncryptedMessage
import com.evoting.paillier.crypto.messages.PlainMessage
import com.evoting.paillier.crypto.messages.Plaintext

case class PaillierArbitrary(override val publicKey: PublicKeyLike, candidateSize: Int) extends Paillier(publicKey) {

  def encryptArbitrary(data: PlainMessage): SyncIO[Either[Throwable, Vector[EncryptedMessage]]] = {
    // each block represents a (encrypted) vote
    // ie. 1024 bits, => 32 blocks or 32 possible candidates.
    // 2048 => 64 blocks or 64 possible candidates
    val spaceForEncryptedVotes = publicKey.bitLength / 32
    data match {
      case data if data.toBigInt.bitLength / 32.0 > candidateSize =>
        SyncIO.fromEither(
          Left(EncryptionException(s"The data requires ${Math.ceil(data.toBigInt.bitLength / 32.0)} candidates which is bigger than the number of candidates ($candidateSize)"))
        )
      case _                                                      =>
        // candidates are less than the number of candidates we can fit them all within the PK
        if (candidateSize <= spaceForEncryptedVotes)
          encrypt(data).map(_.map(encryptedData => Vector(encryptedData)))
        else {
          val totalOfBytes: Int                    = Math.ceil(data.toBigInt.bitLength / 8.0).toInt
          val totalNumberOfEncryptions: Int        = Math.ceil(candidateSize / spaceForEncryptedVotes.toDouble).toInt
          val dataByteArray: List[Byte]            = data.toBigInt.toByteArray.toList.takeRight(totalOfBytes)
          val totalNumberOfBytesPerEncryption: Int = publicKey.bitLength / 8
          val leftPadding: List[Byte]              = (for (_ <- 1 to totalNumberOfBytesPerEncryption * totalNumberOfEncryptions - totalOfBytes) yield 0.toByte).toList
          val totalBytesList: List[Byte]           = leftPadding ++ dataByteArray

          val bytesGrouped: List[Array[Byte]] =
            totalBytesList.reverse
              .grouped(4)
              .map(_.reverse.toArray)
              .toList
              .reverse //dataByteArray.take(totalOfBytes - fullBlocks * 8) +: dataByteArray.drop(totalOfBytes - fullBlocks * 8).grouped(4).toList
          val bytesToEncrypt: Vector[BigInt]                                     = bytesGrouped
            .grouped(spaceForEncryptedVotes)
            .map { numberToEncrypt =>
              numberToEncrypt.reverse.zipWithIndex.foldRight(BigInt(0)) {
                case (element, accumulator) =>
                  accumulator + (BigInt(1, element._1) << (element._2 * 32))
              }
            }
            .toVector
          val encryptedMessages: SyncIO[Either[Throwable, Vector[EncryptedMessage]]] = bytesToEncrypt.map(numbers => encrypt(Plaintext(numbers))).sequence.map(_.sequence)
          encryptedMessages
        }
    }
  }

  def addArbitrary(lhs: Vector[EncryptedMessage], rhs: Vector[EncryptedMessage]): Either[Throwable, Vector[EncryptedMessage]] =
    (lhs, rhs) match {
      case (left, right) if left.isEmpty            => Right(right) // lhs is empty, we return the non-empty value
      case (left, right) if right.isEmpty           => Right(left)  // rhs is empty, we return the non-empty value
      case (left, right) if right.size != left.size => Left(AdditionException("The encrypted messages must have same size"))
      case _                                        => rhs.zip(lhs).map { case (c1, c2) => add(c1, c2) }.sequence
    }

  def combineArbitrary(partialDecryptions: Vector[Vector[PartialDecryption]]): Either[Throwable, PlainMessage] = {
    val keySize: Int = partialDecryptions.flatMap(_.map(_.pk.bitLength)).head // x2 because the ciphertext is s^2 => the bitlength is x2
    val result       = partialDecryptions.transpose
      .map(pd => combine(pd))
      .sequence
      .map { plainMessages =>
        plainMessages.reverse.zipWithIndex
          .foldLeft(BigInt(0)) {
            case (accumulator, element) =>
              accumulator + (element._1.toBigInt << (keySize * element._2))
          }
      }
    result.map(Plaintext.apply)
  }

}
