

import cats.data.EitherT
import cats.effect.SyncIO
import cats.effect.testing.scalatest.AsyncIOSpec
import cats.implicits.toTraverseOps
import com.evoting.paillier.crypto.cryptosystem.impl.PaillierArbitrary
import com.evoting.paillier.crypto.cryptosystem.impl.shuffle._
import com.evoting.paillier.crypto.keys.KeyGenerator
import com.evoting.paillier.crypto.keys.PrivateThresholdKey
import com.evoting.paillier.crypto.messages.Ciphertext
import com.evoting.paillier.crypto.messages.Plaintext
import com.evoting.paillier.primes.PrimesGenerator.getBigIntRandomStream
import org.scalatest.{Assertion, Ignore}
import org.scalatest.freespec.AsyncFreeSpec
import org.scalatest.matchers.should.Matchers

class ShuffleArbitraryTest extends AsyncFreeSpec with AsyncIOSpec with Matchers {

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

  "VerifiableShuffle" - {
    "generates a provable permutation" in {
      val length      = 10
      val plaintexts  = (0 until length).map(i => Plaintext(BigInt(i))).toVector
      val permutation = Permutation(length)

      val resultIO = for {
        keys          <- keysIO
        paillierSystem = PaillierArbitrary(keys.head.publicKey, 40)
        ciphertexts   <- plaintexts.map(p => paillierSystem.encryptArbitrary(p)).sequence.map(_.sequence)
        shuffleSystem  = new VerifiableShuffle(paillierSystem)
      } yield ciphertexts match {
        case Left(err)                => fail(s"Encryption failed with error: ${err.getMessage}")
        case Right(encryptedMessages) =>
          val shuffledIO = shuffleSystem.shuffleArbitrary(encryptedMessages, permutation)
          for {
            shuffle <- shuffledIO
          } yield shuffle match {
            case Left(err)                  => fail(s"Shuffle failed with error: ${err.getMessage}")
            case Right(reencryptedMessages) =>
              val proverParamsIO = ProverParams(keys.head.publicKey, encryptedMessages.length)
              val randomIO       = getBigIntRandomStream(keys.head.publicKey.squared.bitLength)
                .map(_.mod(keys.head.publicKey.squared))

              val verificationIO = for {
                proverParams     <- EitherT.liftF(proverParamsIO)
                publicMessages   <- EitherT.liftF(randomIO.take(encryptedMessages.length).compile.toVector)
                publicCiphertexts = publicMessages.map(Ciphertext)
                proverSystem      = ShuffleProverArbitrary(
                                      keys.head.publicKey,
                                      encryptedMessages,
                                      reencryptedMessages,
                                      publicCiphertexts,
                                      permutation,
                                      proverParams
                                    )
                verifierSystem    = ShuffleVerifierArbitrary(keys.head.publicKey, encryptedMessages, reencryptedMessages, publicCiphertexts)
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
}
