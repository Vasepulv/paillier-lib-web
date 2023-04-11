package com.evoting.paillier.crypto.keys.zkp

import com.evoting.paillier.Exportable

case class SecretVerificationShare(value: BigInt) extends Exportable {

  override val toBigInt: BigInt = value
}
