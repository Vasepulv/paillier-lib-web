
package com.evoting.paillier.crypto.keys

import com.evoting.paillier.Exportable
import com.evoting.paillier.primes.PrimeNumber

sealed trait PublicKeyLike extends Exportable {

  val n: PrimeNumber

  val squared: BigInt

  val bitLength: Int

  val g: BigInt

  val toBigInt: BigInt

}

/* Public key */
case class PublicKey(n: PrimeNumber) extends PublicKeyLike {

  override val squared: BigInt = n.pow(2)

  override val bitLength: Int = n.bitLength

  override val g: BigInt = n + 1

  override val toBigInt: BigInt = n.value
}

final case class PublicKeyBase64(value: String) extends PublicKeyLike {

  private val privateKey: PublicKey = PublicKey(PrimeNumber(decodeBase64(value)))

  override val n: PrimeNumber = privateKey.n

  override val squared: BigInt = privateKey.squared

  override val bitLength: Int = privateKey.bitLength

  override val g: BigInt = privateKey.n + 1

  override val toBigInt: BigInt = n.value

}
