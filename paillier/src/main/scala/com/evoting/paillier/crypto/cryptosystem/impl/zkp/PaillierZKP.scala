package com.evoting.paillier.crypto.cryptosystem.impl.zkp

import com.evoting.paillier.crypto.cryptosystem.impl.Paillier
import com.evoting.paillier.crypto.keys.PublicKeyLike
import com.evoting.paillier.crypto.messages.CiphertextWithRandomness
import com.evoting.paillier.crypto.messages.PlainMessage
import com.evoting.paillier.crypto.messages.Plaintext
import com.evoting.paillier.crypto.PaillierExceptions.AdditionException
import com.evoting.paillier.crypto.PaillierExceptions.DecryptionException
import com.evoting.paillier.crypto.PaillierExceptions.EncryptionException
import com.evoting.paillier.util.Utils._
import cats.effect.unsafe.implicits.global
import com.evoting.paillier.primes.PrimesGenerator._
import cats.implicits._
import cats.effect.IO
import scala.concurrent.ExecutionContext.Implicits.global
import com.evoting.paillier.primes.PrimeNumber
import cats.effect.SyncIO

import java.security.SecureRandom

case class PaillierZKP(override val publicKey: PublicKeyLike, candidateSize: Int) extends Paillier(publicKey) {
  // ZKP implementation
  // based on https://paillier.daylightingsociety.org/Paillier_Zero_Knowledge_Proof.pdf
  // and https://github.com/DaylightingSociety/Paillier/blob/master/lib/paillier/zkp.rb

  val sec_param       = 256 // the security parameter of the challenges and the hash
  val hashmod: BigInt = BigInt(2).pow(sec_param)

  // The idea behind this is to prove that the plaintext is inside the list of possible options valid_messages.
  def encryptWithZKP(plaintext: PlainMessage, valid_messages: List[PlainMessage]): Either[Throwable, EncryptedMessageWithCommitmentZKP] = {

    require(valid_messages.contains(plaintext))
    val ciphertextWithrandomness: Either[Throwable, CiphertextWithRandomness] = encryptWithRandomness(plaintext).unsafeRunSync()

    ciphertextWithrandomness match {
      case Left(error) => Left(error)
      case Right(cwr)  =>
        val positionPlaintext: Int = valid_messages.indexOf(plaintext)

        // First we filter the plaintext from the list
        // a_s, e_s and z_s are the lists with all the values of the possible elements but the plaintext
        var a_s: List[PlainMessage] = List()
        var e_s: List[PlainMessage] = List()
        var z_s: List[PlainMessage] = List()

        valid_messages.filterNot(p => p == plaintext).foreach { a =>
          val z_k: Plaintext = Plaintext(
            getBigIntRandomStream(publicKey.bitLength)
              .find(p => p.gcd(publicKey.n.value) == 1 && p >= 0 && p < publicKey.n.value)
              .compile
              .toList
              .unsafeRunSync()
              .head
          )
          val e_k: Plaintext = Plaintext(BigInt(sec_param, new SecureRandom()))

          // g ^ m_k mod n^2
          val g_mk: BigInt = publicKey.g.modPow(a.toBigInt, publicKey.squared)

          // u_k = c / g_mk (mod n^2)   => u_k = c * invmod(g_mk) (mod n^2)
          val u_k: BigInt = (cwr.ciphertext.toBigInt * g_mk.modInverse(publicKey.squared)).mod(publicKey.squared)

          // z_n = z^n (mod n^2)
          val z_n: BigInt = z_k.toBigInt.modPow(publicKey.n.value, publicKey.squared)

          //u_e = u^e_k (mod n^2)
          val u_e: Plaintext = Plaintext(u_k.modPow(e_k.toBigInt, publicKey.squared))

          // a_k = z_nth / u_eth (mod n^2) = z_nth * invmod(u_eth) (mod n^2)
          val a_k: Plaintext = Plaintext((z_n * u_e.toBigInt.modInverse(publicKey.squared)).mod(publicKey.squared))

          a_s = a_s :+ a_k
          e_s = e_s :+ e_k
          z_s = z_s :+ z_k

        }

        // All the random things are ready, now the plaintext:
        // a_p, z_p, e_p are the challange items related to the plaintext
        // those three values must be placed in their correct position in the list.
        val omega: BigInt  =
          getBigIntRandomStream(publicKey.bitLength).find(p => p.gcd(publicKey.n.value) == 1 && p >= 0 && p < publicKey.n.value).compile.toList.unsafeRunSync().head
        val a_p: Plaintext = Plaintext(omega.modPow(publicKey.n.value, publicKey.squared))
        a_s = a_s.insert(positionPlaintext, a_p)

        val challenge_string = a_s.foldLeft("")((r, c) => r + c.toString())

        val md               = java.security.MessageDigest.getInstance("SHA-256")
        val challenge_sha256 = md.digest(challenge_string.getBytes("UTF-8"))

        //  now that we have the "challenge", we calculate e_p and z_p
        val e_sum = e_s.foldLeft(BigInt(0))((c, r) => c + r.toBigInt).mod(hashmod)

        val e_p = Plaintext((BigInt(1, challenge_sha256) - e_sum).mod(hashmod))

        // THIS IS mod(n) NOT mod(n^2)
        val z_p = Plaintext((omega * cwr.randomness.value.modPow(e_p.toBigInt, publicKey.n.value)).mod(publicKey.n.value))

        // insert a_p, e_p and z_p in the correct place of the list.
        val commitment = EncryptionCommitmentZKP(a_s, e_s.insert(positionPlaintext, e_p), z_s.insert(positionPlaintext, z_p))

        Right(EncryptedMessageWithCommitmentZKP(cwr.ciphertext, commitment))
    }
  }


  def combineWithZKP(partialDecryptionsZKP: Vector[PartialDecryptionZKP]):Either[Throwable, PlainMessage]=
    partialDecryptionsZKP match{
      case partialDecryptionsZKP if partialDecryptionsZKP.isEmpty    => Left(DecryptionException("Decryptions are empty"))
      case partialDecryptionsZKP
          if partialDecryptionsZKP
            .count(p => p.pk.n == partialDecryptionsZKP.head.pk.n && p.l == partialDecryptionsZKP.head.l && p.w == partialDecryptionsZKP.head.w) != partialDecryptionsZKP.size =>
        Left(DecryptionException("Decryptions do not correspond to the same key"))
      case partialDecryptionsZKP if partialDecryptionsZKP.map(f => f.index).distinct.size != partialDecryptionsZKP.size =>
        Left(DecryptionException("Decryptions must have different indexes "))
      case partialDecryptionsZKP if partialDecryptionsZKP.size != partialDecryptionsZKP.head.w                          => Left(DecryptionException("Decryptions must be at least w elements"))
      case _                                                                                                   =>
        val delta  = fact(partialDecryptionsZKP.head.l)
        // l(x) = Pi(i=0..w\x)(-i/(x-i))
        def lambda(i: Int) = {
          // -i'/(i - i') may give floating points, I better split the division to get always integers
          val a = partialDecryptionsZKP.filter(p => p.index != i).map(p => -p.index).product
          val b = partialDecryptionsZKP.filter(p => p.index != i).map(p => i - p.index).product
          (delta * a) / b
        }
        // c' = Pi(i=0..w)(s(i)^(2*l) mod n2) mod n2
        val cprime = partialDecryptionsZKP.map(f => f.partialDecrypted.toBigInt.modPow(2 * lambda(f.index), publicKey.squared)).foldLeft(BigInt(1))(_ * _).mod(publicKey.squared)

        val result: BigInt = ((4 * delta.pow(2)).modInverse(publicKey.n.value) * ((cprime - 1) / publicKey.n.value)).mod(publicKey.n.value)
        Right(Plaintext(result))
    }

  
}
