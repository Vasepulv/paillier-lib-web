package com.evoting.paillier

package object primes {

  case class PrimeNumber(val value: BigInt) {

    def pow(exp: Int): BigInt = value.pow(exp)

    def bitLength: Int = value.bitLength

    def +(that: Int): BigInt = value + that

  }

  case class SafePrimes(p: PrimeNumber, q: PrimeNumber)
}
