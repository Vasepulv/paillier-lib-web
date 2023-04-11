package com.evoting.paillier.crypto.cryptosystem.impl

import cats.data.EitherT
import cats.effect.IO
import cats.effect.SyncIO
import com.evoting.paillier.Randomness
import com.evoting.paillier.crypto.PaillierExceptions.AdditionException
import com.evoting.paillier.crypto.PaillierExceptions.DecryptionException
import com.evoting.paillier.crypto.PaillierExceptions.EncryptionException
import com.evoting.paillier.crypto.cryptosystem.PaillierLike
import com.evoting.paillier.crypto.cryptosystem.PartialDecryption
import com.evoting.paillier.crypto.keys.PublicKeyLike
import com.evoting.paillier.crypto.messages._
import com.evoting.paillier.primes.PrimesGenerator.getBigIntRandomStream
import com.evoting.paillier.util.Utils.fact
import scala.concurrent.ExecutionContext.Implicits.global




class Paillier(val publicKey: PublicKeyLike) extends PaillierLike {

  override def encrypt(data: PlainMessage): SyncIO[Either[Throwable, EncryptedMessage]] = {
    val resultT = for {
      encryptedValue <- EitherT(encryptWithRandomness(data))
    } yield encryptedValue.ciphertext

    resultT.value
  }

  override def encryptWithRandomness(data: PlainMessage): SyncIO[Either[Throwable, CiphertextWithRandomness]] =
    // E = ((n+1)^m mod n2)(r^n mod n2) mod n2, r in Zn*
    data match {
      case data if data.toBigInt < 0 || data.toBigInt > publicKey.squared =>
        SyncIO.fromEither(Left(EncryptionException("Data to encrypt must be in n^s+1")))
      case _                                                              =>
        val randomIO: SyncIO[BigInt] = getBigIntRandomStream(publicKey.bitLength)
          .find(p => p.gcd(publicKey.n.value) == 1 && p >= 0 && p < publicKey.n.value)
          .compile
          .toList
          .map(_.head)

        randomIO.map { random =>
          // The following encryption only works if the generator is chosen to be modulus+1.
          // Luckily, the definition in this library ensures this property.
          // Instead of computing  g^m we compute n * m +1

          val ciphertext = Ciphertext(
            (((publicKey.n.value * data.toBigInt) + 1).mod(publicKey.squared) * random.modPow(publicKey.n.value, publicKey.squared)).mod(publicKey.squared)
          )
          Right(CiphertextWithRandomness(ciphertext, Randomness(random)))
        }
    }

  override def add(lhs: EncryptedMessage, rhs: EncryptedMessage): Either[Throwable, EncryptedMessage] =
    if (lhs.toBigInt < 0 || lhs.toBigInt > publicKey.squared || rhs.toBigInt < 0 || rhs.toBigInt > publicKey.squared)
      Left(AdditionException("Arguments must be in n^s+1"))
    else
      Right(Ciphertext((lhs.toBigInt * rhs.toBigInt).mod(publicKey.squared)))

  override def combine(partialDecryptions: Vector[PartialDecryption]): Either[Throwable, PlainMessage] =
    partialDecryptions match {
      case partialDecryptions if partialDecryptions.isEmpty                                                    => Left(DecryptionException("Decryptions are empty"))
      case partialDecryptions
          if partialDecryptions
            .count(p => p.pk.n == partialDecryptions.head.pk.n && p.l == partialDecryptions.head.l && p.w == partialDecryptions.head.w) != partialDecryptions.size =>
        Left(DecryptionException("Decryptions do not correspond to the same key"))
      case partialDecryptions if partialDecryptions.map(f => f.index).distinct.size != partialDecryptions.size =>
        Left(DecryptionException("Decryptions must have different indexes "))
      case partialDecryptions if partialDecryptions.size != partialDecryptions.head.w                          => Left(DecryptionException("Decryptions must be at least w elements"))
      case _                                                                                                   =>
        val delta  = fact(partialDecryptions.head.l)
        // l(x) = Pi(i=0..w\x)(-i/(x-i))
        def lambda(i: Int) = {
          // -i'/(i - i') may give floating points, I better split the division to get always integers
          val a = partialDecryptions.filter(p => p.index != i).map(p => -p.index).product
          val b = partialDecryptions.filter(p => p.index != i).map(p => i - p.index).product
          (delta * a) / b
        }
        // c' = Pi(i=0..w)(s(i)^(2*l) mod n2) mod n2
        val cprime = partialDecryptions.map(f => f.partialDecrypted.toBigInt.modPow(2 * lambda(f.index), publicKey.squared)).foldLeft(BigInt(1))(_ * _).mod(publicKey.squared)

        val result: BigInt = ((4 * delta.pow(2)).modInverse(publicKey.n.value) * ((cprime - 1) / publicKey.n.value)).mod(publicKey.n.value)
        Right(Plaintext(result))
    }

  override def reencrypt(message: EncryptedMessage): SyncIO[Either[Throwable, CiphertextWithRandomness]] = {
    val resultT = for {
      cipher0     <- EitherT(encryptWithRandomness(Plaintext(0)))
      reencrypted <- EitherT.fromEither[SyncIO](add(message, cipher0))
    } yield CiphertextWithRandomness(reencrypted, cipher0.randomness)

    resultT.value
  }
}
