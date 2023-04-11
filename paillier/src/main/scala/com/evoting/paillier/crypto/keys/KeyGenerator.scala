package com.evoting.paillier.crypto.keys

import cats.effect.IO
import cats.effect.SyncIO
import com.evoting.paillier.primes.PrimesGenerator._
import cats.implicits._
import com.evoting.paillier.SecretShare
import com.evoting.paillier.primes.PrimeNumber

object KeyGenerator {

  def genThresholdKeys(bitsSize: Int, l: Int, w: Int): SyncIO[Vector[PrivateThresholdKey]] = {
    val pqrIO: SyncIO[(BigInt, BigInt)] = getSafePrimesStream(bitsSize / 2).zipWithNext
      .collect({ case (p, Some(q)) => (p, q) })
      .find(p => p._1 != p._2 && (2 * p._1 + 1) != p._2 && (2 * p._2 + 1) != p._1 && ((2 * p._1 + 1) * (2 * p._2 + 1)).bitLength == bitsSize)
      .compile
      .toVector
      .map(_.head)

    for {
      pqr          <- pqrIO
      n: BigInt     = (2 * pqr._1 + 1) * (2 * pqr._2 + 1)
      m: BigInt     = pqr._1 * pqr._2
      d: BigInt     = m * m.modInverse(n)
      nm: BigInt    = n * m
      pk: PublicKey = PublicKey(PrimeNumber(n))

      randomConstants <- getBigIntRandomStream(nm.bitLength).filter(p => p < nm).take(w - 1).compile.toVector

    } yield {
      val constants                                = (0, d) +: LazyList.from(1).zip(randomConstants)
      val privateKeys: Vector[PrivateThresholdKey] = (1 to l).toList.map { index =>
        val si = constants.map(a => a._2 * BigInt(index).pow(a._1)).foldLeft(BigInt(0))(_ + _).mod(nm)
        PrivateThresholdKey(pk, l, w, index, SecretShare(si))
      }.toVector
      privateKeys
    }
  }
}
