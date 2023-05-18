package com.evoting.paillier.crypto.keys.zkp

import cats.effect.SyncIO
import com.evoting.paillier.SecretShare
import com.evoting.paillier.crypto.keys.PublicKey
import com.evoting.paillier.primes.PrimesGenerator._
import com.evoting.paillier.util.Utils.fact
import cats.implicits._
import com.evoting.paillier.primes.PrimeNumber

object KeyGeneratorZKP {

  def genThresholdKeys(bitsSize: Int, l: Int, w: Int): SyncIO[Vector[PrivateThresholdKeyZKP]] = {

    val pqrIO: SyncIO[(BigInt, BigInt)] = getSafePrimesStream(bitsSize / 2).zipWithNext
      .collect({ case (p, Some(q)) => (p, q) })
      .find(p => p._1 != p._2 && (2 * p._1 + 1) != p._2 && (2 * p._2 + 1) != p._1 && ((2 * p._1 + 1) * (2 * p._2 + 1)).bitLength == bitsSize)
      .compile
      .toList
      .map(_.head)

    val nIO: SyncIO[BigInt] = pqrIO.map(pqr => (2 * pqr._1 + 1) * (2 * pqr._2 + 1))
    val mIO: SyncIO[BigInt] = pqrIO.map(pqr => pqr._1 * pqr._2)
    val dIO: SyncIO[BigInt] = for {
      m <- mIO
      n <- nIO
    } yield m * m.modInverse(n)

    val nmIO: SyncIO[BigInt] = for {
      m <- mIO
      n <- nIO
    } yield n * m

    val vIO: SyncIO[BigInt] = for {
      n <- nIO
      v <- findGenerator(n.bitLength, n)
    } yield v

    val pkIO: SyncIO[PublicKey] = nIO.map(n => PublicKey(PrimeNumber(n)))

    val randomConstants: SyncIO[Vector[BigInt]] = nmIO.flatMap(nm => getBigIntRandomStream(nm.bitLength).filter(p => p < nm).take(w - 1).compile.toVector)

    val constantsIO: SyncIO[Seq[(Int, BigInt)]] = for {
      d        <- dIO
      constant <- randomConstants
    } yield (0, d) +: LazyList.from(1).zip(constant)

    val privateKeys: SyncIO[Vector[PrivateThresholdKeyZKP]] = (1 to l)
      .map { index =>
        for {
          nm        <- nmIO
          constants <- constantsIO
          pk        <- pkIO
          n         <- nIO
          v         <- vIO
        } yield {
          val si = constants.map(a => a._2 * BigInt(index).pow(a._1)).foldLeft(BigInt(0))(_ + _).mod(nm)
          val vi = v.modPow(fact(BigInt(l)) * si, n * n)
          PrivateThresholdKeyZKP(pk, VerificationPublicKeyZKP(v), l, w, index, SecretShare(si), SecretVerificationShare(vi))
        }
      }
      .toVector
      .sequence

    privateKeys
  }

}
