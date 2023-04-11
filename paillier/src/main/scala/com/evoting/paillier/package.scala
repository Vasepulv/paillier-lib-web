package com.evoting

import java.util.Base64
import scala.language.implicitConversions

package object paillier {

  trait Exportable {

    val toBigInt: BigInt

    protected def encodeBase64(value: BigInt): String = Base64.getEncoder.encodeToString(value.toByteArray)

    protected def decodeBase64(value: String): BigInt = BigInt(1, Base64.getDecoder.decode(value))

    def toStringBase64: String = encodeBase64(toBigInt)
  }

//
//  trait StringBase64Like {
//
//    def toStringBase64: String
//    /*
//    val value: String
//
//    def toBigInt: BigInt = BigInt(1, Base64.getDecoder.decode(value))
//     */
//  }
//
//  trait BigIntLike {
//
//    def toBigInt: BigInt
//  }

  case class Randomness(value: BigInt)

  trait SecretShareLike extends Exportable

  case class SecretShare(value: BigInt) extends SecretShareLike {

    override val toBigInt: BigInt = value

    override val toStringBase64: String = Base64.getEncoder.encodeToString(value.toByteArray)
  }

  case class SecretShareBase64(value: String) extends SecretShareLike {

    override val toBigInt: BigInt = decodeBase64(value)

    override val toStringBase64: String = value
  }

}
