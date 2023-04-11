package com.evoting.paillier

import cats.data.EitherT
import cats.effect.Clock
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.effect.unsafe.implicits.global
import cats.implicits.toTraverseOps
import com.evoting.paillier.crypto.cryptosystem.PartialDecryption
import com.evoting.paillier.crypto.cryptosystem.impl.Paillier
import com.evoting.paillier.crypto.cryptosystem.impl.shuffle._
import com.evoting.paillier.crypto.keys.KeyGenerator
import com.evoting.paillier.crypto.keys.PrivateThresholdKey
import com.evoting.paillier.crypto.messages.Ciphertext
import com.evoting.paillier.crypto.messages.Plaintext
import com.evoting.paillier.primes.PrimesGenerator.getBigIntRandomStream
import org.scalatest.Assertion
import org.scalatest.Succeeded
import org.scalatest.freespec.AsyncFreeSpec
import org.scalatest.matchers.should.Matchers

/*

class SpeedComparisonTest extends AsyncFreeSpec with AsyncIOSpec with Matchers {

  def measure[R](block: => R, tag: String = ""): R = {
    val start  = System.currentTimeMillis()
    val result = block // call-by-name
    val finish = System.currentTimeMillis()
    println(s"$tag: Elapsed ${finish - start}")
    result
  }

  def measureIO[R](block: => IO[R], tag: String = ""): IO[R] =
    for {
      start  <- Clock[IO].realTime
      result <- block
      finish <- Clock[IO].realTime
    } yield {
      println(s"$tag: Elapsed ${finish - start}")
      result
    }

  val l = 5

  val w = 3

  val bits = 2048 // 1024, 2048, 4096

  val keysIO: IO[Vector[PrivateThresholdKey]] = KeyGenerator.genThresholdKeys(bits, l, w)

  val MAX_OPTIONS = 32

  "VerifiableShuffle" - {
    "generates a provable permutation" in measureIO {
      val length      = 10000                                                    // 100, 500, 1000, ...
      val plaintexts  = (0 until length).map(i => Plaintext(BigInt(i))).toVector // plaintext bits 500, 1000, 2000
      val permutation = Permutation(length)

      val resultIO = for {
        keys          <- keysIO
        paillierSystem = new Paillier(keys.head.publicKey)
        ciphertexts   <- plaintexts.map(p => paillierSystem.encrypt(p)).sequence.map(_.sequence)
        shuffleSystem  = new VerifiableShuffle(paillierSystem)
      } yield ciphertexts match {
        case Left(err)                => fail(s"Encryption failed with error: ${err.getMessage}")
        case Right(encryptedMessages) =>
          val shuffledIO = measureIO(shuffleSystem.shuffle(encryptedMessages, permutation), "Shuffle")
          for {
            shuffle <- shuffledIO
          } yield shuffle match {
            case Left(err)                  => fail(s"Shuffle failed with error: ${err.getMessage}")
            case Right(reencryptedMessages) =>
              val proverParamsIO = measureIO(ProverParams(keys.head.publicKey, encryptedMessages.length), "Generate ProverParams")
              val randomIO       = getBigIntRandomStream(keys.head.publicKey.squared.bitLength)
                .map(_.mod(keys.head.publicKey.squared))

              val verificationIO: EitherT[IO, Throwable, Boolean] = for {
                proverParams     <- EitherT.liftF(proverParamsIO)
                publicMessages   <- EitherT.liftF(randomIO.take(encryptedMessages.length).compile.toVector)
                publicCiphertexts = publicMessages.map(Ciphertext)
                proverSystem      = ShuffleProver(keys.head.publicKey, encryptedMessages, reencryptedMessages, publicCiphertexts, permutation, proverParams)
                verifierSystem    = ShuffleVerifier(keys.head.publicKey, encryptedMessages, reencryptedMessages, publicCiphertexts)
                commitment        = measure(proverSystem.calculateCommitment(), "Calculate Commitment")
                challenge        <- EitherT(measureIO(verifierSystem.generateChallenge(commitment), "Generate Challenge"))
                response         <- EitherT.fromEither[IO](measure(proverSystem.respondChallenge(challenge), "Respond Challenge"))
                verification     <- EitherT.fromEither[IO](measure(verifierSystem.verifyResponse(commitment, response), "Verify Response"))
              } yield verification

              verificationIO.value.map {
                case Left(err)           => fail(err)
                case Right(verification) => assert(verification)
              }
          }
      }
      resultIO.flatten.flatten[Assertion]
    }
  }
}
*/
