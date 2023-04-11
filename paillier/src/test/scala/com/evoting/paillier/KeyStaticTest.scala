package com.evoting.paillier

import cats.data.EitherT
import cats.effect.SyncIO
import com.evoting.paillier.crypto.keys.KeyGenerator
import com.evoting.paillier.crypto.keys.PrivateThresholdKey
import cats.effect.testing.scalatest.AsyncIOSpec
import com.evoting.paillier.crypto.cryptosystem.PartialDecryption
import com.evoting.paillier.crypto.cryptosystem.impl.Paillier
import com.evoting.paillier.crypto.messages.Ciphertext
import com.evoting.paillier.crypto.messages.Plaintext
import org.scalatest.freespec.AsyncFreeSpec
import org.scalatest.matchers.should.Matchers


class KeyStaticTest extends AsyncFreeSpec with AsyncIOSpec with Matchers {

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
    "decrypt with any w shares" in {
      val plaintext = Plaintext(BigInt(256216))

      val resultIO = for {
        keys          <- keysIO
        paillierSystem = new Paillier(keys.head.publicKey)
        ciphertext    <- paillierSystem.encrypt(plaintext)
      } yield (keys, paillierSystem, ciphertext)

      resultIO.asserting {
        case (keys, paillierSystem, ciphertext) =>
          val res = ciphertext match {
            case Left(err)               => fail(s"Encryption failed with error: ${err.getMessage}")
            case Right(encryptedMessage) =>
              keys
                .combinations(w)
                .map { f =>
                  val decryptedMessage = paillierSystem.combine(f.map(p => PartialDecryption(p, encryptedMessage)))
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
    "add and decrypt with any w shares" in {
      val plain1 = Plaintext(BigInt(256216))
      val plain2 = Plaintext(BigInt(226216))

      val resultIO = for {
        keys          <- EitherT.liftF(keysIO)
        paillierSystem = new Paillier(keys.head.publicKey)
        ciphertext1IO <- EitherT.liftF(paillierSystem.encrypt(plain1))
        ciphertext2IO <- EitherT.liftF(paillierSystem.encrypt(plain2))
        ciphertext1   <- EitherT.fromEither[SyncIO](ciphertext1IO)
        ciphertext2   <- EitherT.fromEither[SyncIO](ciphertext2IO)
        addition       = paillierSystem.add(ciphertext1, ciphertext2)
      } yield (keys, paillierSystem, addition)

      resultIO.value.map {
        case Left(err)                               => fail(s"Addition failed with error: ${err.getMessage}")
        case Right((keys, paillierSystem, addition)) =>
          val res = addition match {
            case Left(err)               => fail(s"Addition failed with error: ${err.getMessage}")
            case Right(encryptedMessage) =>
              keys
                .combinations(w)
                .map { f =>
                  val decryptedMessage = paillierSystem.combine(f.map(p => PartialDecryption(p, encryptedMessage)))
                  decryptedMessage match {
                    case Left(err)        => fail(s"Decryption failed with error: ${err.getMessage}")
                    case Right(decrypted) =>
                      decrypted == plain1 + plain2
                  }
                }
                .reduce(_ && _)
          }
          assert(res)
      }
    }
  }

  "The encryption" - {
    "multiply (modpow) with a constant and decrypt with any w shares" in {
      val plain1 = Plaintext(BigInt(256216))
      val plain2 = Plaintext(BigInt(226216))

      val resultIO = for {
        keys          <- EitherT.liftF(keysIO)
        paillierSystem = new Paillier(keys.head.publicKey)
        ciphertext1IO <- EitherT.liftF(paillierSystem.encrypt(plain1))
        ciphertext2IO <- EitherT.liftF(paillierSystem.encrypt(plain2))
        ciphertext1   <- EitherT.fromEither[SyncIO](ciphertext1IO)
        ciphertext2   <- EitherT.fromEither[SyncIO](ciphertext2IO)
        addition       = paillierSystem.add(ciphertext1, ciphertext2)
        finalValue     = addition.map(_.toBigInt.modPow(2, keys.head.publicKey.squared))
      } yield (keys, paillierSystem, finalValue)

      resultIO.value.map {
        case Left(err)                                 => fail(s"Addition failed with error: ${err.getMessage}")
        case Right((keys, paillierSystem, finalValue)) =>
          val res = finalValue match {
            case Left(err)               => fail(s"Addition failed with error: ${err.getMessage}")
            case Right(encryptedMessage) =>
              keys
                .combinations(w)
                .map { f =>
                  val decryptedMessage = paillierSystem.combine(f.map(p => PartialDecryption(p, Ciphertext(encryptedMessage))))
                  decryptedMessage match {
                    case Left(err)        => fail(s"Decryption failed with error: ${err.getMessage}")
                    case Right(decrypted) =>
                      decrypted == Plaintext((plain1 + plain2).toBigInt * 2)
                  }
                }
                .reduce(_ && _)
          }
          assert(res)
      }

    }
  }
  /*


    "The encryption" should "decrypt with any w shares in base64" in {
      val plain64: String = Base64.getEncoder.encodeToString(BigInt(256216).toByteArray)

      val paillier             = PaillierTBase64(keys.head.publicKey)
      val cipher: StringBase64 = paillier.encryptBase64(plain64)

      keys.combinations(w).foreach { f =>
        assert(plain64 == paillier.combineBase64(f.map(p => PartialDecryptionBase64(p, cipher))))
      }
    }

    "The encryption" should "decrypt with any w shares in base64 without knowing the Secret Key" in {
      val plain64: String = Base64.getEncoder.encodeToString(BigInt(256216).toByteArray)

      val paillier = PaillierTBase64(keys.head.publicKey)
      val cipher   = paillier.encryptBase64(plain64)

      keys.combinations(w).foreach { f =>
        assert(plain64 == paillier.combineBase64(f.map { privateKey =>
          val cipherText: Ciphertext = BigInt(1, Base64.getDecoder.decode(cipher))
          val delta                  = fact(privateKey.l)
          val ci                     = cipherText.modPow(2 * delta * privateKey.secret, privateKey.publicKey.squared)
          val partiallyDecrypted     = Base64.getEncoder.encodeToString(ci.toByteArray)

          PartialDecryptionBase64(privateKey.publicKey, privateKey.l, privateKey.w, privateKey.index, partiallyDecrypted)
        }))
      }
    }

    "Decryption" should "Work with constants values generated by keygen 1.0" in {
      val examplePublicKeyBase64: String =
        "AKCMgAtVlLpr3i4ACv6P9UjB0Oxx614n/hlpWg2Z9oHYti1NWf3syK8TjTjruoc0LsZXthSRRma41tCTBbIYVHm6rT++Jupv7vk+1xQcuV1TRoISKVf37+/Qx/MIC1lQRSUk5tFj46VzLUsOTPnG1a+zJEdp72fa0IBxmt416cpvKBowwKRpHqAB8XB0PWoZQnUkYatPzf0XhF8qZA+vRx/I9D6Ov7E4U68OAZNc/jOngcmvMNCiqG+lA1pLTcfv7rTx/WLGkRw8Qj4U0oDwaiUNnYsmh3uoJZVvXmQknKw9U7vGkcQbLVioEDHwSIJE5gbDqlJK3SV77qj+bhShT3U="
      val examplePublicKey: PublicKey    = PublicKey(BigInt(1, Base64.getDecoder.decode(examplePublicKeyBase64)))
      val sumEncrypted: String           =
        "LKoxUsaPZgdCb37PBYYgWI+GgLQl/O1+Po6KmCBOLkbsZptHr+ToLaRtgEB+IyyzJOLlT99s+8D8CsI4x32ORK23JBlWGr/2eek3540TMrBWhJzzEJf6aMSj6eFyWXawk8Xpo/4nEd87ocBbFXNe5oYXBbSP3DIHZMwLaBRVkbAZxp8WB3MemkKLtwdKPnAIbj9ujpiKaoevBTvQZs9YS64tixxc1b6f/+mIb/rP83k0mG026sduUxfonS84Y16F4SleWSFBhq4Mc3elt3YN1NvQyJvPY8MduTRhXayNJiE0jiYIUxZYBtNqKpqgiMOqeb981gssdtXr3u/tkkW5XD8OM16ZMGQI3xrWyPQfwS06JCyCQhtgqCt/7oDLhiA5HbNTEC9dbcq1VBemq0qcDRXJUnZhUFEhxpr180LPMxVr3DKzu/uXiP/dDkRJPhZw+k0YfDZ0AJs3QciOMpby0ooZ9MhV4kPcFzog5laT9M3MSQgYowYo+lFS05UwXqiAqdq7ZqC8SzEmkP/WjhbTil12CSl0yl4SQ5pOK6n4GdcBAdI2bZEaiIreABG19rCuwuXeIgf22hyUzmAwLZoKch0ZIl+sjTxeMTD779Nu4duykogyqF6mvm25OZdMwBYwgIQDweEI7Gy40TNyegd7fWnSK1zEK/CRa0HbaKXmtKs="
      val paillier                       = PaillierTBase64(examplePublicKey)
      val numberKeys                     = 3
      val threshold                      = 2
      val key1                           = PrivateThresholdKey(
        examplePublicKey,
        numberKeys,
        threshold,
        1,
        BigInt(
          1,
          Base64.getDecoder.decode(
            "Bhiq3BXqLtVvemDZcmR23BgjaMTouoyyntj4qoIFocdSarKx77CTtZU5e59lGusYZFFFT/pU9Yh+B0UlMGygu0w88MKC9ba0Kf2djqhgabcABjptpD2XQPc/F0fHP3STOb0y3jNDzwAQfOCM5NlyWdXflT7H5zGAdNIneCXJEgfCwkzZFldkRkSJcpUDLxbVEDNPkquKgG9VjwcFNW3oKPdnpAEok7DjMGtyVGnPlIRpzhHvB3nMMKmYXZcC9a1wsi20+SpczKFs1ToSG7I/5cJDkikgHLh1ItTECxcXcGXpzNxkMqaMWRwx/4Ptd8GQf5QaBxtJk4DCAyvvUgcyljL1Z5dnVAxsJ7KH2YWMCTB2c26BeL24DN3EbGsIYBsM/Wywa2Tuf3xsaDQN8rbRkak+NrZrh8T5LmOdjco9t9hrjEyaHDWr+wRoXIvhxMUkasrT7ByGVOBgwoMcycyWS26r5ikT9auIZqMZJ621HmNrRpsoZpIipflaBQDjF9sQdE1wxD913HyNwbbwsFyFCWIwcu1S6oQoVKFd1fVb9DIccz2oBi7ke8yLQ9zcSDn8ssBPri1ig5CwQGe0qUZghTTkJqVinEP6Hshxc3SL7LyQS3+LLb30Tl0ZFCv6x7cm73NyiQhUwj8qapsxS9I8pgrHVD2Pt9e13rxvj8khFUg="
          )
        )
      )
      val key2                           = PrivateThresholdKey(
        examplePublicKey,
        numberKeys,
        threshold,
        2,
        BigInt(
          1,
          Base64.getDecoder.decode(
            "DlhHIDDRbR7O4HXoywz4wZTWg1VwfFj6jFa44oYNzRWnYI9E0Z4TWyP6QTtVxjVduaCB0LUeaLmXafAA6zC35/f3MT3R5VUdy0p4OKJ2J0QCFp0BO/T5044v/u7yxD54hC+buQBVp2knO2bnSQyo3mfE84j2SGZE7qE/pCoNJf7F5BJpkesAS2bpwyjhOYhzPoudHMvcsDjyWGMT7mUWNDEDqcUcq1qNL0qOywZaJfFAdov/5y7U4mkr84xdBRZXwMIC3j/4+IDFcT9IJpeqHbKmg4WwdF1wCQxU4ZDPn6/hUYh57qr4C7EsBGoAm+n75kcX4szwDEm1Na3u4bXFgCU8gkDDwP72QAvzDNntis0sWx1mKI1dssZZFZi9o4BxMjtc9zyCwoDB1HZzNhU10bze1a/VUpXfHjRZ493lDmJEUoL3lzMs4LYx7ChfoMTNWSMt9NDKX6kYzaNbKiReLn21NDveGPG3fTBy0iEKG5QZGnaI/FLiN2t9JRqdHnkbY3Lmkk5Dc9yzRF6e72h9N0TNuID2IfHDt7Wa+Y2j4mX2WeGeXlPMI7YZVAqHI9B4Pea5TvBpQoYaHSBgZqgbXPYzCgZc+Ga8QRNVcJSi/5aDkxwLlB2d4YjbBZdlGB/SYCBnpf4x8tNZL2X2C5TB//sdOOmoor9N3Vs9WQarlTI="
          )
        )
      )
      val key3                           = PrivateThresholdKey(
        examplePublicKey,
        numberKeys,
        threshold,
        3,
        BigInt(
          1,
          Base64.getDecoder.decode(
            "FpfjZEu4q2guRor4I7V6pxGJneX4PiVCedR5GooV+GP8VmvXs4uTALK7BtdGcX+jDu++UW/n2+qwzJrcpfTPFKOxcbkg1POHbJdS4pyL5NEEJv+U06xcZiUg5pYeSQhdzqIEk81nf9I9+e1BrT/fYvmqUdMkqZsJaHBX0C5ROfXJBdf6DX6cUIlKE7y/Q/oRbOPqpuwu4AKPIb8ip1xEP2qfr4kQwwQ3LimrQaLkt14XHwYQxuPdlCi/iYG3FH8+z1ZQw1WVJGAeDUR+MX0UVaMJdOJAzAJq70PluAqHzvnY1jSPqq9jvkYmCVATwBJnTPoVvn6WhRKoaC/ucWRYaheDnOogLfGAWGVeQC5PDGniQsxK2F0DWK7tvsZy5uXVZwoJgxQXBYUXQLjYeXOaEdB/dKk/HWbFDgUWOfGMZOwdGLlVEjCtxmf7e8TdfMR2R3uH/YUOanHQ2MOZinwmEYy+gk6oPDfmk73MfJRfGMTG7lHpkhOhyN2gRTRXJRcmUphcYF0RCzzYxwZNLnR1ZSdq/hSZWV9fGsnYHSXr0JnQQIWUtnizy5+nZDgx/2bzyQ0i77NwAXuD+dkMJAnWNLeB7WdXVIl+Y145bbS6EnB22riL+n1HdLSc9wLPaIh90M1cwvQPI2eH9DC6y1dHWetzHZXBjabl2/oLIkQ2FRw="
          )
        )
      )
      val keys                           = List(key1, key2, key3)

      keys.combinations(threshold).foreach { f =>
        assert("IgAAAAAAAAAD" == paillier.combineBase64(f.map { privateKey =>
          val cipherText: Ciphertext = BigInt(1, Base64.getDecoder.decode(sumEncrypted))
          val delta                  = fact(privateKey.l)
          val ci                     = cipherText.modPow(2 * delta * privateKey.secret, privateKey.publicKey.squared)
          val partiallyDecrypted     = Base64.getEncoder.encodeToString(ci.toByteArray)

          PartialDecryptionBase64(privateKey.publicKey, privateKey.l, privateKey.w, privateKey.index, partiallyDecrypted)
        }))
      }
    }

    "Decryption" should "Work with constants values generated by keygen 2.0" in {
      val examplePublicKeyBase64: String =
        "AIe5knKR+KWSbYFdc4S8yLEQUMm8iKVRrH1UFC9zN6M4OFG68QX2hmRjRi/VJSCQvoHJbCelWbjul+NpSXEv2V1JWLf9pvJvV4TirmHmWSecv+DnlEkOPZHVKhh8otvrGoIdrOALdtrdp3jWOJA2qcgyigsHs0LXTuTWxUP+yVcB"
      val examplePublicKey: PublicKey    = PublicKey(BigInt(1, Base64.getDecoder.decode(examplePublicKeyBase64)))

      val plain64: String = Base64.getEncoder.encodeToString(BigInt(256216).toByteArray)

      val paillier             = PaillierTBase64(examplePublicKey)
      val cipher: StringBase64 = paillier.encryptBase64(plain64)

      val numberKeys = 3
      val threshold  = 2
      val key1       = PrivateThresholdKey(
        examplePublicKey,
        numberKeys,
        threshold,
        1,
        BigInt(
          1,
          Base64.getDecoder.decode(
            "Cp/LdV+dNhAG2UdKKGu5qNwsmqJX99k7THYLK7XIwfC7OFGgKCjamNAK62+OyEu3njrzxFeF7OCuFcsavgYkMS3Zh8grgXnanNmjIyMqkHFOBBiOLO7e002e9BbBLb9j18jn+Jbks16yn+/hu8MfQ8KOM13IwEY43GomCBrw4lVDfyCp8nngmTcaXIvuT2yC+U2L3lQQSu+IlcRNjcAiCIN1P9cALN1H4YAlfIkbvWqM5gnVoCHw1GaWRvqdrf1qGumwVawp+ZWzh0g6v53fcjndHLDsUvtm9w6qgZnOgMOh0dV3mNR+7z8WT5yXPyIkeNzosSa7ju38P19bEnmnIQ=="
          )
        )
      )
      val key2       = PrivateThresholdKey(
        examplePublicKey,
        numberKeys,
        threshold,
        2,
        BigInt(
          1,
          Base64.getDecoder.decode(
            "AmEhYbSmwti1EnBI6snw3vmGvOE/WlOwaVLKXxTkdthF3S273bMGjKbs4ikb+0bL4AoqGwRuVJZkifH+GajxCZrmVxJ8BB9KIWOlBAn/MhJ5yqJwFYmT3y3vUr/CUseUnEkqGh2yvID8IyALeIk+kZVvsrQ5PBcFYQPNWKnVrPx3D0Y5nyIPo6kJWVWhibM8bxsPtsBrzlXb8rKUxYa0RTElKRbCtBfcuPqaBrx1oH1dH0eQCepqwCuI4QvcdjvtAnoXmhqsq6LapkZbiQ+5khrF0apprQz6M0kZ3Yk6ezU7PSUmIVlc4Oc8kUG88ILRzJ77f7oR+1pXJnI0PxIZEA=="
          )
        )
      )
      val key3       = PrivateThresholdKey(
        examplePublicKey,
        numberKeys,
        threshold,
        3,
        BigInt(
          1,
          Base64.getDecoder.decode(
            "DB/HDH6E1hLO9kzCcg7Xo58uu9HkMPBOD9+CgRbxrTLVQM8OvUML2IszhH9pRN9jL145mLbM5w2VFTi4ADYRfKOGncbantQHiSUYquFBY0E5mY5Ze/TvT3ETEaJxauaRRcBCy0/aoFhi7tnxYUFnxOm1HUTAC6XpL1sU48iAfvTJcfbKfuV+hxrp91JLKlWScq3nZjAfTgv8EEH+sME6uYWIhcnrdHwMZ+errK0ZkWFestqInfS6Z+fgpoIr4MRiq/ft/693v8vktFeFm8hzV9HLbLs8x5YhWulcHmELGvbBfh+vSon1OBFX5fNwoEyZhzwOhuSXkkicoxuW0DzSkA=="
          )
        )
      )
      val keys       = List(key1, key2, key3)

      keys.combinations(threshold).foreach { f =>
        assert(plain64 == paillier.combineBase64(f.map { privateKey =>
          val cipherText: Ciphertext = BigInt(1, Base64.getDecoder.decode(cipher))
          val delta                  = fact(privateKey.l)
          val ci                     = cipherText.modPow(2 * delta * privateKey.secret, privateKey.publicKey.squared)
          val partiallyDecrypted     = Base64.getEncoder.encodeToString(ci.toByteArray)

          PartialDecryptionBase64(privateKey.publicKey, privateKey.l, privateKey.w, privateKey.index, partiallyDecrypted)
        }))
      }
    }
   
}*/}
