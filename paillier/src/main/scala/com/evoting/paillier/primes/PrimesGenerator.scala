package com.evoting.paillier.primes

import cats.effect.IO
import cats.effect.SyncIO
import cats.effect.Sync
import fs2.Stream
import java.security.SecureRandom


object PrimesGenerator {

  private val certainty: Int = 101 // same than Shoup implementation

  /*
   * The problems of not using safe primes are : Z*_n is not a cyclic group, its order is unknown, such generator
   * v do not exist and elements of maximal order cannot be easily found. However, by using safe primes,
   * then the group of squares in Z*_n is cyclic and it is easy to find generators.
   *
   * */
  // Generate a Prime number using a Future: This does not compute the value, just define the computation in the future.
  private def generatePrimeNumber(bitLength: Int): SyncIO[BigInt] = SyncIO(BigInt(bitLength - 1, certainty, new SecureRandom()))

  // Converts the IO (effect) into a Stream
  private def getPrimeStream(bitLength: Int): Stream[SyncIO, BigInt] = Stream.eval(generatePrimeNumber(bitLength))

  // Takes the Stream and finds the safe primes
  def getSafePrimesStream(bitLength: Int): Stream[SyncIO, BigInt] =
    Stream(getPrimeStream(bitLength).find(p => (2 * p + 1).isProbablePrime(certainty))).repeat.flatten

  
  // Create random Big Integer using SecureRandom
  def getBigIntRandomStream(bitLength: Int): Stream[SyncIO, BigInt] = Stream.eval(SyncIO(BigInt(bitLength, new SecureRandom()))).repeat

  /*
   * Qn is the (cyclic) subgroup of squares in Zn.
   * The use of safe primes guarantee that, with overwhelming probability, a random element in Qn is a generator .
   * This is better explained in FouSte01 than Shoup00.
   * */
  def findGenerator(bitLength: Int, n: BigInt): SyncIO[BigInt] =
    // qn is an element of QsubN - square mod n. This value is the group verifier
    getBigIntRandomStream(bitLength)
      .find(candidate => candidate.gcd(n) == 1)
      .head
      .compile
      .foldMonoid
      .map(qn => (qn * qn).mod(n))

}
