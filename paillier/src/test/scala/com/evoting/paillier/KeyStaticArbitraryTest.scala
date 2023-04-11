package com.evoting.paillier

import cats.effect.IO
import cats.effect.SyncIO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.evoting.paillier.crypto.cryptosystem.PartialDecryption
import com.evoting.paillier.crypto.cryptosystem.impl.PaillierArbitrary
import com.evoting.paillier.crypto.keys.KeyGenerator
import com.evoting.paillier.crypto.keys.PrivateThresholdKey
import com.evoting.paillier.crypto.keys.PublicKeyBase64
import com.evoting.paillier.crypto.messages.CiphertextBase64
import com.evoting.paillier.crypto.messages.EncryptedMessage
import com.evoting.paillier.crypto.messages.Plaintext
import org.scalatest.freespec.AsyncFreeSpec
import org.scalatest.matchers.should.Matchers
import com.evoting.paillier.crypto.PaillierExceptions.EncryptionException



class KeyStaticArbitraryTest extends AsyncFreeSpec with AsyncIOSpec with Matchers {

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

  "The encryption" - {
    "decrypt with any w shares 1024" in {

      val plaintext = Plaintext(BigInt(1) << 1024)

      val resultIO = for {
        keys          <- keysIO
        paillierSystem = PaillierArbitrary(keys.head.publicKey, 40)
        ciphertext    <- paillierSystem.encryptArbitrary(plaintext)
      } yield (keys, paillierSystem, ciphertext)

      resultIO.asserting {
        case (keys, paillierSystem, ciphertext) =>
          val res = ciphertext match {
            case Left(err)               => fail(s"Encryption failed with error: ${err.getMessage}")
            case Right(encryptedMessage) =>
              keys
                .combinations(w)
                .map { f =>
                  val decryptedMessage = paillierSystem.combineArbitrary(f.map(p => PartialDecryption(p, encryptedMessage)))
                  decryptedMessage match {
                    case Left(err)        => fail(s"Decryption failed with error: ${err.getMessage}")
                    case Right(decrypted) => decrypted == plaintext
                  }
                }
                .reduce(_ && _)
          }
          assert(res)
      }
    }
  }

  "The encryption" - {
    "fails with any 2048 bits and 40 candidates" in {

      val plaintext = Plaintext(BigInt(1) << 2048)

      val resultIO = for {
        keys          <- keysIO
        paillierSystem = PaillierArbitrary(keys.head.publicKey, 40)
        ciphertext    <- paillierSystem.encryptArbitrary(plaintext)
      } yield (keys, paillierSystem, ciphertext)

      recoverToSucceededIf[EncryptionException] {
        resultIO.asserting {
          case (keys, paillierSystem, ciphertext) =>
            val res = ciphertext match {
              case Left(err)               => fail(s"Encryption failed with error: ${err.getMessage}")
              case Right(encryptedMessage) =>
                keys
                  .combinations(w)
                  .map { f =>
                    val decryptedMessage = paillierSystem.combineArbitrary(f.map(p => PartialDecryption(p, encryptedMessage)))
                    decryptedMessage match {
                      case Left(err)        => fail(s"Decryption failed with error: ${err.getMessage}")
                      case Right(decrypted) => decrypted == plaintext
                    }
                  }
                  .reduce(_ && _)
            }
            assert(res)
        }
      }
    }
  }

  "The encryption" - {
    "fails with any 2048 bits and 64 candidates" in {

      val plaintext = Plaintext(BigInt(1) << 2048)

      val resultIO = for {
        keys          <- keysIO
        paillierSystem = PaillierArbitrary(keys.head.publicKey, 64)
        ciphertext    <- paillierSystem.encryptArbitrary(plaintext)
      } yield (keys, paillierSystem, ciphertext)

      recoverToSucceededIf[EncryptionException] {
        resultIO.asserting {
          case (keys, paillierSystem, ciphertext) =>
            val res = ciphertext match {
              case Left(err)               => fail(s"Encryption failed with error: ${err.getMessage}")
              case Right(encryptedMessage) =>
                keys
                  .combinations(w)
                  .map { f =>
                    val decryptedMessage = paillierSystem.combineArbitrary(f.map(p => PartialDecryption(p, encryptedMessage)))
                    decryptedMessage match {
                      case Left(err)        => fail(s"Decryption failed with error: ${err.getMessage}")
                      case Right(decrypted) => decrypted == plaintext
                    }
                  }
                  .reduce(_ && _)
            }
            assert(res)
        }
      }
    }
  }

  "The encryption" - {
    "work with any 2048 bits and 64 candidates" in {

      val plaintext = Plaintext(BigInt(1) << 2047)

      val resultIO = for {
        keys          <- keysIO
        paillierSystem = PaillierArbitrary(keys.head.publicKey, 64)
        ciphertext    <- paillierSystem.encryptArbitrary(plaintext)
      } yield (keys, paillierSystem, ciphertext)

      resultIO.asserting {
        case (keys, paillierSystem, ciphertext) =>
          val res = ciphertext match {
            case Left(err)               => fail(s"Encryption failed with error: ${err.getMessage}")
            case Right(encryptedMessage) =>
              keys
                .combinations(w)
                .map { f =>
                  val decryptedMessage = paillierSystem.combineArbitrary(f.map(p => PartialDecryption(p, encryptedMessage)))
                  decryptedMessage match {
                    case Left(err)        => fail(s"Decryption failed with error: ${err.getMessage}")
                    case Right(decrypted) =>
                      decrypted == plaintext
                  }
                }
                .reduce(_ && _)
          }
          assert(res)
      }
    }
  }

  "The encryption" - {
    "work with any 2048 (x4) bits and 64 candidates" in {

      val plaintext = Plaintext((BigInt(1) << 2047) + (BigInt(1) << 1535) + (BigInt(1) << 1023) + (BigInt(1) << 511))

      val resultIO = for {
        keys          <- keysIO
        paillierSystem = PaillierArbitrary(keys.head.publicKey, 64)
        ciphertext    <- paillierSystem.encryptArbitrary(plaintext)
      } yield (keys, paillierSystem, ciphertext)

      resultIO.asserting {
        case (keys, paillierSystem, ciphertext) =>
          val res = ciphertext match {
            case Left(err)               => fail(s"Encryption failed with error: ${err.getMessage}")
            case Right(encryptedMessage) =>
              keys
                .combinations(w)
                .map { f =>
                  val decryptedMessage = paillierSystem.combineArbitrary(f.map(p => PartialDecryption(p, encryptedMessage)))
                  decryptedMessage match {
                    case Left(err)        => fail(s"Decryption failed with error: ${err.getMessage}")
                    case Right(decrypted) =>
                      decrypted == plaintext
                  }
                }
                .reduce(_ && _)
          }
          assert(res)
      }
    }
  }

  "The encryption" - {
    "decrypt with an encryption generated by encrypter" in {

      val keysGenerated: SyncIO[Vector[PrivateThresholdKey]] = SyncIO(
        Vector(
          PrivateThresholdKey(
            PublicKeyBase64(
              "ANHAJ1AhnRXyS5pEXChk/vItwtSlgrup7M/ivypjAdtKSV7aBLDBoVjggT3//iRalxWIPVnsMwYINCsi9Erv9QkPf6CBv599SP+Lk+CJrcZbYQu5FJG29YdFvSbOk0wU4HfAToxJQ/sXSqMcydPzdxRSuC7dtynTZGMcGDvHtLb1"
            ),
            3,
            2,
            1,
            SecretShareBase64(
              "EjMwASFYlE9O9mVF++1cX715vvGBNSL2Ldol4kQ39a8WJl7U9unbrfF/j5ue9nbbNLOoWY9szSq2tj59ico0ud1vyO5HQPIRAZvHR7TUSaFawuW9bpIi04qJlkQeS1jBVTpWz7z7jDwqbFx8xCCUzq9A1DPaZYbFUI3f04WphLpJcMjh4FYUsRQI63suvFlEpCYh+uAwiWXBFeFjUT6xXBL7vkTEorK3PztgqHVgxEwdRLbQYBDxokmVjDI5ctcqrGQawD3nS41r3UkSoElS/7DoGR59ER1qnllURz3fPg4PCrGQzyw68/19/7Qt7nviB36o4D1kS9PHn4DiB7OZvA=="
            )
          ),
          PrivateThresholdKey(
            PublicKeyBase64(
              "ANHAJ1AhnRXyS5pEXChk/vItwtSlgrup7M/ivypjAdtKSV7aBLDBoVjggT3//iRalxWIPVnsMwYINCsi9Erv9QkPf6CBv599SP+Lk+CJrcZbYQu5FJG29YdFvSbOk0wU4HfAToxJQ/sXSqMcydPzdxRSuC7dtynTZGMcGDvHtLb1"
            ),
            3,
            2,
            2,
            SecretShareBase64(
              "EgicPPfbtF+VyXdlB6b3++FUuxVw9YhU7OSW1YfQkcDDUWhv4orRsjEBtUg0ips/ojwdiwKsreQuRgzY0gDmxHshM9V3l3338whNuPehAKBEe4terWjpnkyMsEWnwIdjCBMPiFiESqv5O2A7oXOhvGYje8W67fk+5mS1t7F1ofJYWDLP4dO0bvIo2c2f64vX++1DMYtKSu3rlNlViZjn6BesEv9AKxaWY8dD5rRPphxAnAgFQAgBoVKW/g6MPao8Dcx6AURXi2AAR/RlDaCWtgmIPdbrDqFfCfGWQiohFwPHjA3Jheuiuz7zbr4/8LHJ/GrGKNFpPJdCA+O0rjYIJw=="
            )
          ),
          PrivateThresholdKey(
            PublicKeyBase64(
              "ANHAJ1AhnRXyS5pEXChk/vItwtSlgrup7M/ivypjAdtKSV7aBLDBoVjggT3//iRalxWIPVnsMwYINCsi9Erv9QkPf6CBv599SP+Lk+CJrcZbYQu5FJG29YdFvSbOk0wU4HfAToxJQ/sXSqMcydPzdxRSuC7dtynTZGMcGDvHtLb1"
            ),
            3,
            2,
            3,
            SecretShareBase64(
              "Ed4IeM5e1G/cnImEE2CTmAUvtzlgte2zq+8HyMtpLdJwfHIKzivHtnCD2vTKHr+kD8SSvHXsjp2l1ds0GjeYzxjSnryn7gne5HTUKjptt58uNDD/7D+waQ6PykcxNbYEuuvIQPQNCRvICmP6fsauqh0GI1ebdmu4fDuLm91BvypnP5y941FULNBIyCARGr5rU7RkaDZkDHYWE9FHwfMedBxcZ7m7s3p1iFMnJPM+h+xj81k6H/8RoFuYb+rfCH1NbzTZQkrHyzKUsp+3evfabGIoYo9ZDCVTdYnYPRZi7/mADWoCPKsKgoBo3chR8uex8VbjcWVuLVq8aEaHVLh2kg=="
            )
          )
        )
      )

      val plaintext                                                   = Plaintext(BigInt(1) << (32 * 2))
      val cipherText: SyncIO[Either[Throwable, Vector[EncryptedMessage]]] = SyncIO(
        Right(
          Vector(
            CiphertextBase64(
              "ARUBk9pIsC1Il/aXMwCfynZZc4y74ycLhVS9Jls/0pW41bg6UDvQCVSTPoCNMhiM+9fszxt7cSRYsGA1o0wbwJRazFx5JUjI6xWKTPaYHAmVqIL9une7LA/+/ijgleq44O247cxIMotdwvE1IC1PlmaRX2nb7fGy8prOJuHCY/vWrykMdz75W2abQGayRgjK0y7KBTepxH3kgUSQXC5S0DAG6sK7SWpuEj9v/b+ITIGDgozkMzdcrPxFok4rEd4Sub7q4TsVXDJ+BIvfrsRGYESrF5zfIXDHm+1OVi7B99S8QGW4aeYZDUijvWGWSQCDzGgAyb0HmtGF3fOm8RgHmg=="
            )
          )
        )
      )

      val resultIO = for {
        keys          <- keysGenerated
        paillierSystem = PaillierArbitrary(keys.head.publicKey, 4)
        ciphertext    <- cipherText
      } yield (keys, paillierSystem, ciphertext)

      resultIO.asserting {
        case (keys, paillierSystem, ciphertext) =>
          val res = ciphertext match {
            case Left(err)               => fail(s"Encryption failed with error: ${err.getMessage}")
            case Right(encryptedMessage) =>
              keys
                .combinations(2)
                .map { f =>
                  val decryptedMessage = paillierSystem.combineArbitrary(f.map(p => PartialDecryption(p, encryptedMessage)))
                  decryptedMessage match {
                    case Left(err)        => fail(s"Decryption failed with error: ${err.getMessage}")
                    case Right(decrypted) => decrypted == plaintext
                  }
                }
                .reduce(_ && _)
          }
          assert(res)
      }
    }
  }

  "The encryption" - {
    "decrypt with an sum generated by restricted-api" in {

      val keysGenerated: SyncIO[Vector[PrivateThresholdKey]] = SyncIO(
        Vector(
          PrivateThresholdKey(
            PublicKeyBase64(
              "ANHAJ1AhnRXyS5pEXChk/vItwtSlgrup7M/ivypjAdtKSV7aBLDBoVjggT3//iRalxWIPVnsMwYINCsi9Erv9QkPf6CBv599SP+Lk+CJrcZbYQu5FJG29YdFvSbOk0wU4HfAToxJQ/sXSqMcydPzdxRSuC7dtynTZGMcGDvHtLb1"
            ),
            3,
            2,
            1,
            SecretShareBase64(
              "EjMwASFYlE9O9mVF++1cX715vvGBNSL2Ldol4kQ39a8WJl7U9unbrfF/j5ue9nbbNLOoWY9szSq2tj59ico0ud1vyO5HQPIRAZvHR7TUSaFawuW9bpIi04qJlkQeS1jBVTpWz7z7jDwqbFx8xCCUzq9A1DPaZYbFUI3f04WphLpJcMjh4FYUsRQI63suvFlEpCYh+uAwiWXBFeFjUT6xXBL7vkTEorK3PztgqHVgxEwdRLbQYBDxokmVjDI5ctcqrGQawD3nS41r3UkSoElS/7DoGR59ER1qnllURz3fPg4PCrGQzyw68/19/7Qt7nviB36o4D1kS9PHn4DiB7OZvA=="
            )
          ),
          PrivateThresholdKey(
            PublicKeyBase64(
              "ANHAJ1AhnRXyS5pEXChk/vItwtSlgrup7M/ivypjAdtKSV7aBLDBoVjggT3//iRalxWIPVnsMwYINCsi9Erv9QkPf6CBv599SP+Lk+CJrcZbYQu5FJG29YdFvSbOk0wU4HfAToxJQ/sXSqMcydPzdxRSuC7dtynTZGMcGDvHtLb1"
            ),
            3,
            2,
            2,
            SecretShareBase64(
              "EgicPPfbtF+VyXdlB6b3++FUuxVw9YhU7OSW1YfQkcDDUWhv4orRsjEBtUg0ips/ojwdiwKsreQuRgzY0gDmxHshM9V3l3338whNuPehAKBEe4terWjpnkyMsEWnwIdjCBMPiFiESqv5O2A7oXOhvGYje8W67fk+5mS1t7F1ofJYWDLP4dO0bvIo2c2f64vX++1DMYtKSu3rlNlViZjn6BesEv9AKxaWY8dD5rRPphxAnAgFQAgBoVKW/g6MPao8Dcx6AURXi2AAR/RlDaCWtgmIPdbrDqFfCfGWQiohFwPHjA3Jheuiuz7zbr4/8LHJ/GrGKNFpPJdCA+O0rjYIJw=="
            )
          ),
          PrivateThresholdKey(
            PublicKeyBase64(
              "ANHAJ1AhnRXyS5pEXChk/vItwtSlgrup7M/ivypjAdtKSV7aBLDBoVjggT3//iRalxWIPVnsMwYINCsi9Erv9QkPf6CBv599SP+Lk+CJrcZbYQu5FJG29YdFvSbOk0wU4HfAToxJQ/sXSqMcydPzdxRSuC7dtynTZGMcGDvHtLb1"
            ),
            3,
            2,
            3,
            SecretShareBase64(
              "Ed4IeM5e1G/cnImEE2CTmAUvtzlgte2zq+8HyMtpLdJwfHIKzivHtnCD2vTKHr+kD8SSvHXsjp2l1ds0GjeYzxjSnryn7gne5HTUKjptt58uNDD/7D+waQ6PykcxNbYEuuvIQPQNCRvICmP6fsauqh0GI1ebdmu4fDuLm91BvypnP5y941FULNBIyCARGr5rU7RkaDZkDHYWE9FHwfMedBxcZ7m7s3p1iFMnJPM+h+xj81k6H/8RoFuYb+rfCH1NbzTZQkrHyzKUsp+3evfabGIoYo9ZDCVTdYnYPRZi7/mADWoCPKsKgoBo3chR8uex8VbjcWVuLVq8aEaHVLh2kg=="
            )
          )
        )
      )

      val plaintext                                                   = Plaintext(BigInt(2) << (32 * 2))
      val cipherText: SyncIO[Either[Throwable, Vector[EncryptedMessage]]] = SyncIO(
        Right(
          Vector(
            CiphertextBase64(
              "MxbKHM+w+4wmq+BIbdOJLf8y3sWxKZwl1nwPAHH3JorwveuJh57tUXVE2T0aueK0EutpYESC23UvGsW5HOpH1uIuQG9H76m8XZnDgDvnYmGvXBQNnTIkG9kSJKXhk0GvDej5LFu16bV92TpLHKUrH+/Hx9IAwx3s/EiSoBwuRSRu1lkBVeptEvCy28+V/JdqTMggvriES/o7GQWqgZ1OOabhPqcRi6cFNk92Tz5yVT3fXTpvMZuaBMoasoBtcAxjXveb2AEsuadt38MXaN2xmm8LzezXFjGpNpI+5niJGdJVTERjTNebHibifxkteNXeNOapSJ0oqb2ZAXRQVFlh6Q=="
            )
          )
        )
      )

      val resultIO = for {
        keys          <- keysGenerated
        paillierSystem = PaillierArbitrary(keys.head.publicKey, 4)
        ciphertext    <- cipherText
      } yield (keys, paillierSystem, ciphertext)

      resultIO.asserting {
        case (keys, paillierSystem, ciphertext) =>
          val res = ciphertext match {
            case Left(err)               => fail(s"Encryption failed with error: ${err.getMessage}")
            case Right(encryptedMessage) =>
              keys
                .combinations(2)
                .map { f =>
                  val decryptedMessage = paillierSystem.combineArbitrary(f.map(p => PartialDecryption(p, encryptedMessage)))
                  decryptedMessage match {
                    case Left(err)        => fail(s"Decryption failed with error: ${err.getMessage}")
                    case Right(decrypted) => decrypted == plaintext
                  }
                }
                .reduce(_ && _)
          }
          assert(res)
      }
    }
  }

  "The encryption" - {
    "decrypt with partials generated by restricted-api" in {

      val key1 = PrivateThresholdKey(
        PublicKeyBase64(
          "ANHAJ1AhnRXyS5pEXChk/vItwtSlgrup7M/ivypjAdtKSV7aBLDBoVjggT3//iRalxWIPVnsMwYINCsi9Erv9QkPf6CBv599SP+Lk+CJrcZbYQu5FJG29YdFvSbOk0wU4HfAToxJQ/sXSqMcydPzdxRSuC7dtynTZGMcGDvHtLb1"
        ),
        3,
        2,
        1,
        SecretShareBase64(
          "EjMwASFYlE9O9mVF++1cX715vvGBNSL2Ldol4kQ39a8WJl7U9unbrfF/j5ue9nbbNLOoWY9szSq2tj59ico0ud1vyO5HQPIRAZvHR7TUSaFawuW9bpIi04qJlkQeS1jBVTpWz7z7jDwqbFx8xCCUzq9A1DPaZYbFUI3f04WphLpJcMjh4FYUsRQI63suvFlEpCYh+uAwiWXBFeFjUT6xXBL7vkTEorK3PztgqHVgxEwdRLbQYBDxokmVjDI5ctcqrGQawD3nS41r3UkSoElS/7DoGR59ER1qnllURz3fPg4PCrGQzyw68/19/7Qt7nviB36o4D1kS9PHn4DiB7OZvA=="
        )
      )

      val key2 = PrivateThresholdKey(
        PublicKeyBase64(
          "ANHAJ1AhnRXyS5pEXChk/vItwtSlgrup7M/ivypjAdtKSV7aBLDBoVjggT3//iRalxWIPVnsMwYINCsi9Erv9QkPf6CBv599SP+Lk+CJrcZbYQu5FJG29YdFvSbOk0wU4HfAToxJQ/sXSqMcydPzdxRSuC7dtynTZGMcGDvHtLb1"
        ),
        3,
        2,
        2,
        SecretShareBase64(
          "EgicPPfbtF+VyXdlB6b3++FUuxVw9YhU7OSW1YfQkcDDUWhv4orRsjEBtUg0ips/ojwdiwKsreQuRgzY0gDmxHshM9V3l3338whNuPehAKBEe4terWjpnkyMsEWnwIdjCBMPiFiESqv5O2A7oXOhvGYje8W67fk+5mS1t7F1ofJYWDLP4dO0bvIo2c2f64vX++1DMYtKSu3rlNlViZjn6BesEv9AKxaWY8dD5rRPphxAnAgFQAgBoVKW/g6MPao8Dcx6AURXi2AAR/RlDaCWtgmIPdbrDqFfCfGWQiohFwPHjA3Jheuiuz7zbr4/8LHJ/GrGKNFpPJdCA+O0rjYIJw=="
        )
      )

      val plaintext                                                   = Plaintext(BigInt(2) << (32 * 2))
      val cipherText: SyncIO[Either[Throwable, Vector[EncryptedMessage]]] = SyncIO(
        Right(
          Vector(
            CiphertextBase64(
              "MxbKHM+w+4wmq+BIbdOJLf8y3sWxKZwl1nwPAHH3JorwveuJh57tUXVE2T0aueK0EutpYESC23UvGsW5HOpH1uIuQG9H76m8XZnDgDvnYmGvXBQNnTIkG9kSJKXhk0GvDej5LFu16bV92TpLHKUrH+/Hx9IAwx3s/EiSoBwuRSRu1lkBVeptEvCy28+V/JdqTMggvriES/o7GQWqgZ1OOabhPqcRi6cFNk92Tz5yVT3fXTpvMZuaBMoasoBtcAxjXveb2AEsuadt38MXaN2xmm8LzezXFjGpNpI+5niJGdJVTERjTNebHibifxkteNXeNOapSJ0oqb2ZAXRQVFlh6Q=="
            )
          )
        )
      )

      val resultIO = for {
        paillierSystem <- SyncIO(PaillierArbitrary(key1.publicKey, 4))
      } yield paillierSystem

      resultIO.asserting { paillierSystem =>
        val decryptedMessage = paillierSystem.combineArbitrary(
          Vector(
            Vector(
              PartialDecryption(
                PublicKeyBase64(
                  "ANHAJ1AhnRXyS5pEXChk/vItwtSlgrup7M/ivypjAdtKSV7aBLDBoVjggT3//iRalxWIPVnsMwYINCsi9Erv9QkPf6CBv599SP+Lk+CJrcZbYQu5FJG29YdFvSbOk0wU4HfAToxJQ/sXSqMcydPzdxRSuC7dtynTZGMcGDvHtLb1"
                ),
                3,
                2,
                1,
                CiphertextBase64(
                  "SojpVKaProo6/lYD9PotMaV5UqMHCdlwwsJDCBGJGDT7/o2kslfy7Yz8GBCcoVt9ulifsa+4vBc4vIEGKEbPWXZcVy9LfnWCqeyHHwDpYmdcmxvWj5CsIm0xNY6gOO5itAcM5+/nAxcdItDAqY9ukzYOJim5dSQmjJbAIW+8nMalrYMiqozFIHpSKgg4xtO9cX4XM5eSVbMeVB+zPnu0afw6DyU0VEI9jd0ZMtd0y3lUoanz+R/4B7931roC2WCSr3RHR7rwUCaWWlMhZKI/6EalegmHZP4T4xUYij0m2ZhNTRuAEwOAFS+JRQAS+dg85ZyUR039i+BTPWnuErcQPw=="
                )
              )
            ),
            Vector(
              PartialDecryption(
                PublicKeyBase64(
                  "ANHAJ1AhnRXyS5pEXChk/vItwtSlgrup7M/ivypjAdtKSV7aBLDBoVjggT3//iRalxWIPVnsMwYINCsi9Erv9QkPf6CBv599SP+Lk+CJrcZbYQu5FJG29YdFvSbOk0wU4HfAToxJQ/sXSqMcydPzdxRSuC7dtynTZGMcGDvHtLb1"
                ),
                3,
                2,
                2,
                CiphertextBase64(
                  "JjsoK4TdU27ywmLuJHLONuBTMSrWDZgL6KL2JHs70J+Sk6+EBnFqP3d4W2OdysAd9kcEy0eLHm62Zp2Oletof2ZwaH4ezlQlOXwGcIIpqzYMLc/n1KUCMbmQWYCfOU07nJMBrFVrasuBacMcN4QkWC5yhPO4g48ALyVhoYOP/XVElwnf/Lhq3w1BStcRiUkVyrZ7VLyiStNiGJdQtKjIkU6c8V2UJDJuGA198oZJ/nUWTsUL+JAGHti9zmglGZucG9OpO33vplwSjSzDyqyCYwDZ97gw8TUNIZ7s2Kevi0f+rpeZMa766Qvzt/iwYEityxAzt5pTT0QzHW8Ont216w=="
                )
              )
            )
          )
        )

        decryptedMessage match {
          case Left(err)        => fail(s"Decryption failed with error: ${err.getMessage}")
          case Right(decrypted) => assert(decrypted == plaintext)
        }
      }
    }
  }
}
