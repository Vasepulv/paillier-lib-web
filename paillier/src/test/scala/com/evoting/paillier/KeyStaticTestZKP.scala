package com.evoting.paillier

import java.security.SecureRandom

import cats.effect.SyncIO
import com.evoting.paillier.crypto.keys.zkp.KeyGeneratorZKP
import com.evoting.paillier.crypto.keys.zkp.PrivateThresholdKeyZKP
import com.evoting.paillier.crypto.cryptosystem.impl.zkp.PaillierZKP
import com.evoting.paillier.crypto.cryptosystem.impl.zkp.PartialDecryptionZKP
import com.evoting.paillier.crypto.cryptosystem.impl.zkp.ThresholdDecryptionCommitmentZKP
import com.evoting.paillier.crypto.PaillierExceptions.AdditionException
import com.evoting.paillier.crypto.PaillierExceptions.DecryptionException
import com.evoting.paillier.crypto.PaillierExceptions.EncryptionException
import org.scalatest._
import flatspec._
import com.evoting.paillier.crypto.messages.Ciphertext
import com.evoting.paillier.crypto.messages.Plaintext
import org.scalatest.freespec.AsyncFreeSpec
import org.scalatest.matchers.should.Matchers
import cats.effect.testing.scalatest.AsyncIOSpec

import scala.util.Random

class KeyStaticTestZKP extends AsyncFreeSpec with AsyncIOSpec with Matchers {

  def time[R](block: => R): R = {
    val t0     = System.currentTimeMillis()
    val result = block // call-by-name
    val t1     = System.currentTimeMillis()
    result
  }

  val l                                  = 5

  val w                                  = 3

  val bits                               = 512

  val keysIO: SyncIO[Vector[PrivateThresholdKeyZKP]] = time(KeyGeneratorZKP.genThresholdKeys(bits, l, w))

  val MAX_OPTIONS                        = 32

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

  "The encryption" -{
    "decrypt with any w shares" in {

    val plain    = Plaintext(BigInt(256216))

    val resultIO = for {
      keys <- keysIO
      paillier = new PaillierZKP(keys.head.publicKey,32)
      cipher   <- paillier.encrypt(plain)
    } yield ( keys ,paillier, cipher)

    resultIO.asserting {
        case (keys, paillier, cipher) =>
          val res = cipher match {
            case Left(err)               => fail(s"Encryption failed with error: ${err.getMessage}")
            case Right(encryptedMessage) =>
              keys
                .combinations(w)
                .map { f =>
                  val decryptedMessage = paillier.combineWithZKP(f.map(p => PartialDecryptionZKP(p, encryptedMessage)))
                  decryptedMessage match {
                    case Left(err)        => fail(s"Decryption failed with error: ${err.getMessage}")
                    case Right(decrypted) => decrypted == plain
                  }
                }
                .reduce(_ && _)
          }
          assert(res)
      }
  }
}
}
/*  

  "The encryption" should "generate zero-knowledge proofs of knowledge" in {
    val plain          = BigInt(256216)
    val paillier       = PaillierZKP(keys.head.publicKey,32)
    val valid_messages = scala.collection.immutable.List(BigInt(256215), BigInt(256216), BigInt(256217))
    val cipherWithZKP  = paillier.encryptWithZKP(plain, valid_messages)

    assert(cipherWithZKP._2.a_s.size == valid_messages.size)
    assert(cipherWithZKP._2.a_s.size == cipherWithZKP._2.e_s.size && cipherWithZKP._2.a_s.size == cipherWithZKP._2.z_s.size)

    keys.combinations(w).foreach { f =>
      assert(plain == paillier.combineZKP(f.map(p => PartialDecryptionZKP(p, cipherWithZKP._1))))

    }
  }

  "The encryption" should "validate zero-knowledge proofs of knowledge" in {
    val plain          = BigInt(1) << (MAX_OPTIONS * Random.nextInt(8))
    val valid_messages = (0 to 8).map(p => BigInt(1) << (MAX_OPTIONS * p)).toList
    val paillier       = PaillierZKP(keys.head.publicKey,32)
    val cipherWithZKP  = paillier.encryptWithZKP(plain, valid_messages)

    assert(cipherWithZKP._2.verifyZKP(keys.head.publicKey, cipherWithZKP._1, valid_messages))

    keys.combinations(w).foreach { f =>
      assert(plain == paillier.combineZKP(f.map(p => PartialDecryptionZKP(p, cipherWithZKP._1))))

    }
  }

  "The encryption" should "detect a fake ZK proof" in {
    val plain          = (BigInt(1) << (MAX_OPTIONS * Random.nextInt(8))) + (BigInt(1) << (MAX_OPTIONS * Random.nextInt(8)))
    val valid_messages = (0 to 8).map(p => BigInt(1) << (MAX_OPTIONS * p)).toList
    val paillier       = PaillierZKP(keys.head.publicKey,32)

    val fake_messages = scala.collection.immutable.List(BigInt(256211), BigInt(256216), BigInt(256217))
    val cipherWithZKP = paillier.encryptWithZKP(plain, valid_messages.tail :+ plain)

    assert(cipherWithZKP._2.verifyZKP(keys.head.publicKey, cipherWithZKP._1, valid_messages) == false)

    keys.combinations(w).foreach { f =>
      assert(plain == paillier.combineZKP(f.map(p => PartialDecryptionZKP(p, cipherWithZKP._1))))

    }
  }

  "The decryption of the encrypted sum" should "be the same that plain sum in any combination" in {

    val rnd      = new SecureRandom()
    val numbers  = Seq.fill(10)(BigInt(bits - 100, rnd))
    val paillier = PaillierZKP(keys.head.publicKey,32)

    val cipher = numbers.map(f => paillier.encrypt(f)).foldLeft(paillier.encrypt(BigInt(0)))(paillier.add)

    keys.combinations(w).foreach { f =>
      assert(numbers.sum == paillier.combineZKP(f.map(p => PartialDecryptionZKP(p, cipher))))
    }
  }

  "The decryption" should "validate a real ZK proof" in {
    val plain          = (BigInt(1) << (MAX_OPTIONS * Random.nextInt(8))) + (BigInt(1) << (MAX_OPTIONS * Random.nextInt(8)))
    val paillier       = PaillierZKP(keys.head.publicKey,32)
    val valid_messages = (0 to 8).map(p => BigInt(1) << (MAX_OPTIONS * p)).toList

    val fake_messages = scala.collection.immutable.List(BigInt(256211), BigInt(256216), BigInt(256217))
    val cipherWithZKP = paillier.encryptWithZKP(plain, valid_messages.tail :+ plain)

    val partialDecryptions = keys.combinations(w).flatMap(f => f.map(p => PartialDecryptionZKP(p, cipherWithZKP._1)))
    val verifications      = partialDecryptions.map(pd => pd.commitment.verifyZKP(pd, cipherWithZKP._1))
    assert(verifications.reduce(_ && _))
  }

  "The decryption" should "fail against a fake ZK proof" in {
    val plain          = (BigInt(1) << (MAX_OPTIONS * Random.nextInt(8))) + (BigInt(1) << (MAX_OPTIONS * Random.nextInt(8)))
    val paillier       = PaillierZKP(keys.head.publicKey,32)
    val valid_messages = (0 to 8).map(p => BigInt(1) << (MAX_OPTIONS * p)).toList

    val fake_messages = scala.collection.immutable.List(BigInt(256211), BigInt(256216), BigInt(256217))
    val cipherWithZKP = paillier.encryptWithZKP(plain, valid_messages.tail :+ plain)

    val partialDecryptions = keys.combinations(w).flatMap(f => f.map(p => PartialDecryptionZKP(p, cipherWithZKP._1))).toList
    val fakeProof          = partialDecryptions.head.copy(commitment = ThresholdDecryptionCommitmentZKP(0, 0))
    // all the good ones
    assert(partialDecryptions.map(pd => pd.commitment.verifyZKP(pd, cipherWithZKP._1)).reduce(_ && _))
    // the fake one
    assert(fakeProof.commitment.verifyZKP(partialDecryptions.toList.head, cipherWithZKP._1) == false)
  }

}
*/
