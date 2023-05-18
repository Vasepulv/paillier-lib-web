

package com.evoting.paillier.crypto.messages
import com.evoting.paillier.Exportable

import java.util.Base64

trait PlainMessage extends Exportable {

  def +(that: PlainMessage): PlainMessage
}

case class Plaintext(value: BigInt) extends PlainMessage {

  val toBigInt: BigInt = value

  def +(that: PlainMessage): PlainMessage = Plaintext(value + that.toBigInt)

}

case class PlaintextBase64(value: String) extends PlainMessage {

  def +(that: PlainMessage): PlainMessage = PlaintextBase64(Base64.getEncoder.encodeToString((this.toBigInt + that.toBigInt).toByteArray))

  override val toBigInt: BigInt = decodeBase64(value)
}
