
package com.evoting.paillier.crypto.keys

import com.evoting.paillier.SecretShareLike

/* PrivateThresholdKey
 * Holds all the necessary elements to decrypt without ZKP
 * */
final case class PrivateThresholdKey(publicKey: PublicKeyLike, l: Int, w: Int, index: Int, secret: SecretShareLike)
