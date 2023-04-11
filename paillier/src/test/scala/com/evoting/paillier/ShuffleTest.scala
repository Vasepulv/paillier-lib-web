package com.evoting.paillier

import cats.data.EitherT
import cats.effect.IO
import cats.effect.SyncIO
import com.evoting.paillier.crypto.keys.KeyGenerator
import com.evoting.paillier.crypto.keys.PrivateThresholdKey
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.implicits.toTraverseOps
import com.evoting.paillier.crypto.cryptosystem.PartialDecryption
import com.evoting.paillier.crypto.cryptosystem.impl.Paillier
import com.evoting.paillier.crypto.cryptosystem.impl.shuffle.Permutation
import com.evoting.paillier.crypto.cryptosystem.impl.shuffle.ProverParams
import com.evoting.paillier.crypto.cryptosystem.impl.shuffle.ShuffleProver
import com.evoting.paillier.crypto.cryptosystem.impl.shuffle.ShuffleVerifier
import com.evoting.paillier.crypto.cryptosystem.impl.shuffle.VerifiableShuffle
import com.evoting.paillier.crypto.messages.Ciphertext
import com.evoting.paillier.crypto.messages.Plaintext
import com.evoting.paillier.primes.PrimesGenerator.getBigIntRandomStream
import org.scalatest.Assertion
import org.scalatest.Succeeded
import org.scalatest.freespec.AsyncFreeSpec
import org.scalatest.matchers.should.Matchers

/*
class ShuffleTest extends AsyncFreeSpec with AsyncIOSpec with Matchers {

  def time[R](block: => R): R = {
    val t0     = System.currentTimeMillis()
    val result = block // call-by-name
    val t1     = System.currentTimeMillis()
    result
  }

  val l = 5

  val w = 3

  val bits = 512

  val keysIO: SyncIO[Vector[PrivateThresholdKey]] = time(KeyGenerator.genThresholdKeys(bits, l, w))

  val MAX_OPTIONS = 32

  "The public key" - {
    "have the required bits" in {
      keysIO.asserting(keys => keys.head.publicKey.n.bitLength shouldBe bits)
    }
  }

  "All generated threshold keys" - {
    "be different" in {
      keysIO.asserting(keys => assert(keys.map(f => f.secret).distinct.size == keys.size && keys.map(f => f.index).distinct.size == keys.size))
    }
  }

  "Permutation" - {
    "generates a valid permutation" in {
      val length      = 10
      val permutation = Permutation(length)

      assert(permutation.value.length == length)
      assert(permutation.value.sorted.equals(0 until length))
    }
  }

  "The reencryption" - {
    "decrypts to the same plaintext" in {
      val plaintext = Plaintext(BigInt(256216))

      val resultIO = for {
        keys          <- keysIO
        paillierSystem = new Paillier(keys.head.publicKey)
        ciphertext    <- paillierSystem.encrypt(plaintext)
      } yield ciphertext match {
        case Left(err)               => fail(s"Encryption failed with error: ${err.getMessage}")
        case Right(encryptedMessage) =>
          val reencryptedIO = paillierSystem.reencrypt(encryptedMessage)
          for {
            reencrypted <- reencryptedIO
          } yield reencrypted match {
            case Left(err)                 => fail(s"Reencryption failed with error: ${err.getMessage}")
            case Right(reencryptedMessage) =>
              assert(
                List(
                  reencryptedMessage.toBigInt == (reencryptedMessage.randomness.value
                    .modPow(keys.head.publicKey.n.value, keys.head.publicKey.squared) * encryptedMessage.toBigInt)
                    .mod(keys.head.publicKey.squared) shouldBe true,
                  keys
                    .combinations(w)
                    .map { f =>
                      val decryptedMessage1 = paillierSystem.combine(f.map(p => PartialDecryption(p, encryptedMessage)))
                      val decryptedMessage2 = paillierSystem.combine(f.map(p => PartialDecryption(p, reencryptedMessage)))
                      (decryptedMessage1, decryptedMessage2) match {
                        case (Left(_), _) | (_, Left(_))            => fail(s"Decryption failed")
                        case (Right(decrypted1), Right(decrypted2)) => decrypted1 == decrypted2 && decrypted1 == plaintext
                      }
                    }
                    .reduce(_ && _) shouldBe true
                ).forall(_ == Succeeded)
              )
          }
      }

      resultIO.flatMap((e)=>e)
    }
  }

  "VerifiableShuffle" - {
    "generates a reencrypted permutation" in {
      val length      = 10
      val plaintexts  = (0 until length).map(i => Plaintext(BigInt(i))).toVector
      val permutation = Permutation(length)

      val resultIO = for {
        keys          <- keysIO
        paillierSystem = new Paillier(keys.head.publicKey)
        ciphertexts   <- plaintexts.map(p => paillierSystem.encrypt(p)).sequence.map(_.sequence)
        shuffleSystem  = new VerifiableShuffle(paillierSystem)
      } yield ciphertexts match {
        case Left(err)                => fail(s"Encryption failed with error: ${err.getMessage}")
        case Right(encryptedMessages) =>
          val shuffledIO = shuffleSystem.shuffle(encryptedMessages, permutation)
          for {
            shuffle <- shuffledIO
          } yield shuffle match {
            case Left(err)                  => fail(s"Shuffle failed with error: ${err.getMessage}")
            case Right(reencryptedMessages) =>
              assert(
                List(
                  // encrypted and reencrypted values are all distinct pairwise
                  (for {
                    x <- reencryptedMessages
                    y <- encryptedMessages
                  } yield !x.equals(y)).reduce(_ && _) shouldBe true,
                  // decrpytion of the shuffle corresponds to the permutation of plaintexts
                  keys
                    .combinations(w)
                    .map { f =>
                      val decryptedShuffle = reencryptedMessages
                        .map(m =>
                          paillierSystem
                            .combine(f.map(p => PartialDecryption(p, m)))
                        )
                        .sequence
                      decryptedShuffle match {
                        case Left(err)        => fail(s"Decryption failed with error: ${err.getMessage}")
                        case Right(decrypted) =>
                          decrypted.indices.forall(i => decrypted(permutation.value(i)) == plaintexts(i))
                      }
                    }
                    .reduce(_ && _) shouldBe true
                ).forall(_ == Succeeded)
              )
          }
      }
      resultIO.flatMap((e)=>e)
    }
  }

  "VerifiableShuffle" - {
    "generates a provable permutation" in {
      val length      = 10
      val plaintexts  = (0 until length).map(i => Plaintext(BigInt(i))).toVector
      val permutation = Permutation(length)

      val resultIO = for {
        keys          <- keysIO
        paillierSystem = new Paillier(keys.head.publicKey)
        ciphertexts   <- plaintexts.map(p => paillierSystem.encrypt(p)).sequence.map(_.sequence)
        shuffleSystem  = new VerifiableShuffle(paillierSystem)
      } yield ciphertexts match {
        case Left(err)                => fail(s"Encryption failed with error: ${err.getMessage}")
        case Right(encryptedMessages) =>
          val shuffledIO = shuffleSystem.shuffle(encryptedMessages, permutation)
          for {
            shuffle <- shuffledIO
          } yield shuffle match {
            case Left(err)                  => fail(s"Shuffle failed with error: ${err.getMessage}")
            case Right(reencryptedMessages) =>
              val proverParamsIO = ProverParams(keys.head.publicKey, encryptedMessages.length)
              val randomIO       = getBigIntRandomStream(keys.head.publicKey.squared.bitLength)
                .map(_.mod(keys.head.publicKey.squared))

              val verificationIO: EitherT[SyncIO, Throwable, Boolean] = for {
                proverParams     <- EitherT.liftF(proverParamsIO)
                publicMessages   <- EitherT.liftF(randomIO.take(encryptedMessages.length).compile.toVector)
                publicCiphertexts = publicMessages.map(Ciphertext)
                proverSystem      = ShuffleProver(keys.head.publicKey, encryptedMessages, reencryptedMessages, publicCiphertexts, permutation, proverParams)
                verifierSystem    = ShuffleVerifier(keys.head.publicKey, encryptedMessages, reencryptedMessages, publicCiphertexts)
                commitment        = proverSystem.calculateCommitment()
                challenge        <- EitherT(verifierSystem.generateChallenge(commitment))
                response         <- EitherT.fromEither[SyncIO](proverSystem.respondChallenge(challenge))
                verification     <- EitherT.fromEither[SyncIO](verifierSystem.verifyResponse(commitment, response))
              } yield verification

              verificationIO.value.map {
                case Left(err)           => fail(err)
                case Right(verification) => assert(verification)
              }
          }
      }
      resultIO.flatMap((e)=>e).flatMap((e)=>e)
    }
  }

  "VerifiableShuffle" - {
    "fails on manipulated data" in {
      val length      = 10
      val plaintexts  = (0 until length).map(i => Plaintext(BigInt(i))).toVector
      val permutation = Permutation(length)

      val resultIO = for {
        ind <- 0 until length
      } yield for {
        keys          <- keysIO
        randomIO       = getBigIntRandomStream(keys.head.publicKey.squared.bitLength)
                           .map(_.mod(keys.head.publicKey.squared))
        fakeMessage   <- randomIO.take(1).compile.toList.map(_.head)
        paillierSystem = new Paillier(keys.head.publicKey)
        ciphertexts   <- plaintexts.map(p => paillierSystem.encrypt(p)).sequence.map(_.sequence)
        shuffleSystem  = new VerifiableShuffle(paillierSystem)
      } yield ciphertexts match {
        case Left(err)                => fail(s"Encryption failed with error: ${err.getMessage}")
        case Right(encryptedMessages) =>
          val shuffledIO = shuffleSystem.shuffle(encryptedMessages.updated(ind, Ciphertext(fakeMessage)), permutation)
          for {
            shuffle <- shuffledIO
          } yield shuffle match {
            case Left(err)                  => fail(s"Shuffle failed with error: ${err.getMessage}")
            case Right(reencryptedMessages) =>
              val proverParamsIO                                  = ProverParams(keys.head.publicKey, encryptedMessages.length)
              val verificationIO: EitherT[SyncIO, Throwable, Boolean] = for {
                proverParams     <- EitherT.liftF(proverParamsIO)
                publicMessages   <- EitherT.liftF(randomIO.take(length).compile.toVector)
                publicCiphertexts = publicMessages.map(Ciphertext)
                proverSystem      = ShuffleProver(keys.head.publicKey, encryptedMessages, reencryptedMessages, publicCiphertexts, permutation, proverParams)
                verifierSystem    = ShuffleVerifier(keys.head.publicKey, encryptedMessages, reencryptedMessages, publicCiphertexts)
                commitment        = proverSystem.calculateCommitment()
                challenge        <- EitherT(verifierSystem.generateChallenge(commitment))
                response         <- EitherT.fromEither[SyncIO](proverSystem.respondChallenge(challenge))
                verification     <- EitherT.fromEither[SyncIO](verifierSystem.verifyResponse(commitment, response))
              } yield !verification // verification should fail

              verificationIO.value.map {
                case Left(err)           => fail(err)
                case Right(verification) => assert(verification)
              }
          }
      }
      resultIO
        .map(x => x.flatMap((e)=>e).flatMap((e)=>e))
        .toVector
        .sequence
        .map(v => v.foldLeft(assert(true))((a, b) => (a, b) shouldBe (Succeeded, Succeeded)))
    }
  }

  "VerifiableShuffle" - {
    "fails on invalid shuffle" in {
      val length       = 10
      val plaintexts   = (0 until length).map(i => Plaintext(BigInt(i))).toVector
      val permutation  = Permutation(length)
      val permutation2 = Permutation(length)

      val resultIO = for {
        keys          <- keysIO
        randomIO       = getBigIntRandomStream(keys.head.publicKey.squared.bitLength)
                           .map(_.mod(keys.head.publicKey.squared))
        paillierSystem = new Paillier(keys.head.publicKey)
        ciphertexts   <- plaintexts.map(p => paillierSystem.encrypt(p)).sequence.map(_.sequence)
        shuffleSystem  = new VerifiableShuffle(paillierSystem)
      } yield ciphertexts match {
        case Left(err)                => fail(s"Encryption failed with error: ${err.getMessage}")
        case Right(encryptedMessages) =>
          val shuffledIO = shuffleSystem.shuffle(encryptedMessages, permutation)
          for {
            shuffle <- shuffledIO
          } yield shuffle match {
            case Left(err)                  => fail(s"Shuffle failed with error: ${err.getMessage}")
            case Right(reencryptedMessages) =>
              val proverParamsIO                                  = ProverParams(keys.head.publicKey, encryptedMessages.length)
              val verificationIO: EitherT[SyncIO, Throwable, Boolean] = for {
                proverParams     <- EitherT.liftF(proverParamsIO)
                publicMessages   <- EitherT.liftF(randomIO.take(length).compile.toVector)
                publicCiphertexts = publicMessages.map(Ciphertext)
                proverSystem      = ShuffleProver(keys.head.publicKey, encryptedMessages, reencryptedMessages, publicCiphertexts, permutation2, proverParams)
                verifierSystem    = ShuffleVerifier(keys.head.publicKey, encryptedMessages, reencryptedMessages, publicCiphertexts)
                commitment        = proverSystem.calculateCommitment()
                challenge        <- EitherT(verifierSystem.generateChallenge(commitment))
                response         <- EitherT.fromEither[SyncIO](proverSystem.respondChallenge(challenge))
                verification     <- EitherT.fromEither[SyncIO](verifierSystem.verifyResponse(commitment, response))
              } yield permutation.value.equals(permutation2.value) || !verification

              verificationIO.value.map {
                case Left(err)           => fail(err)
                case Right(verification) => assert(verification)
              }
          }
      }
      resultIO.flatMap((e)=>e).flatMap((e)=>e)
    }
  }
}
*/
