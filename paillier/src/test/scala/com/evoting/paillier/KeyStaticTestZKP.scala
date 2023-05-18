

import cats.data.EitherT
import cats.effect.SyncIO
import com.evoting.paillier.crypto.keys.KeyGenerator
import com.evoting.paillier.crypto.keys.PrivateThresholdKey
import cats.effect.testing.scalatest.AsyncIOSpec
import com.evoting.paillier.crypto.cryptosystem.PartialDecryption
import com.evoting.paillier.crypto.cryptosystem.impl.Paillier
import com.evoting.paillier.crypto.cryptosystem.impl.zkp.PaillierZKP
import com.evoting.paillier.crypto.messages.Ciphertext
import com.evoting.paillier.crypto.messages.Plaintext
import org.scalatest.freespec.AsyncFreeSpec
import org.scalatest.matchers.should.Matchers

class KeyStaticTestZKP extends AsyncFreeSpec with AsyncIOSpec with Matchers {

  def time[R](block: => R): R = {
    val t0     = System.currentTimeMillis()
    val result = block // call-by-name
    val t1     = System.currentTimeMillis()
    result
  }

  val l = 5

  val w = 3

  val bits = 512

  val keysIO: SyncIO[Either[Throwable, Vector[PrivateThresholdKey]]] = time(KeyGenerator.genThresholdKeys(bits, l, w).map(Right(_)))

  val MAX_OPTIONS = 32

  "The public key for ZKP" - {
    "have the required bits" in {
      keysIO.asserting(keys => keys.getOrElse(Vector()).head.publicKey.n.bitLength shouldBe bits)
    }
  }

  "The encryption with ZKP " - {


     "validate a real ZK proof" in {
       val plain = Plaintext(BigInt(256216))
       val valid_messages = scala.collection.immutable.List(BigInt(256215), BigInt(256216), BigInt(256217)).map(Plaintext(_))

       val resultIO = for {
         keys <- EitherT(keysIO)
         paillierSystem = new PaillierZKP(keys.head.publicKey, valid_messages)
         ciphertext <- EitherT(paillierSystem.encryptWithZKP(plain))
         validCipher <- EitherT(paillierSystem.verifyZKP(ciphertext))
       } yield (validCipher)

       resultIO.asserting {
         case (validCipher) =>  {
           assert(validCipher)
         }
       }.value.map(_ match {
         case Right(assert) => assert
         case _ => assert(false)
       })
    }

    "fail a real ZK proof" in {
      val plain = Plaintext(BigInt(877878))
      val valid_messages = scala.collection.immutable.List(BigInt(877878), BigInt(256215),  BigInt(256216), BigInt(256217)).map(Plaintext(_))
      val valid_messages2 = scala.collection.immutable.List(BigInt(534453), BigInt(256215), BigInt(256216), BigInt(256217)).map(Plaintext(_))

      val resultIO = for {
        keys <- EitherT(keysIO)
        paillierSystem = new PaillierZKP(keys.head.publicKey, valid_messages)
        ciphertext <- EitherT(paillierSystem.encryptWithZKP(plain))
        paillierSystem2 = new PaillierZKP(keys.head.publicKey, valid_messages2)
        validCipher <- EitherT(paillierSystem2.verifyZKP(ciphertext))
      } yield (validCipher)

      resultIO.asserting {
        case (validCipher) =>  {
          assert(!validCipher)
        }
      }.value.map(_ match {
        case Right(assert) => assert
        case _ => assert(false)
      })
    }
  }


}
