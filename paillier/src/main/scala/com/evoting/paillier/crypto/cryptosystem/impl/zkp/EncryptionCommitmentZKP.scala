
package com.evoting.paillier.crypto.cryptosystem.impl.zkp

import com.evoting.paillier.crypto.keys.PublicKeyLike
import com.evoting.paillier.crypto.messages.EncryptedMessage
import com.evoting.paillier.crypto.messages.PlainMessage
import com.evoting.paillier.crypto.messages.Plaintext

case class EncryptedMessageWithCommitmentZKP(ciphertext: EncryptedMessage, commitment: EncryptionCommitmentZKP)

case class EncryptionCommitmentZKP(a_s: List[PlainMessage], e_s: List[PlainMessage], z_s: List[PlainMessage]) {

  def verifyZKP(publicKey: PublicKeyLike, ciphertext: BigInt, valid_messages: List[BigInt]): Boolean = {

    val sec_param = 256 // the security parameter of the challanges and the hash
    val hashmod   = BigInt(2).pow(sec_param)

    var u_s: List[PlainMessage] = List()

    valid_messages.foreach { a =>
      // g_mk = g ^ m_k (mod n^2)
      val g_mk = publicKey.g.modPow(a, publicKey.squared)

      //u_k = c / g_mk (mod n^2) = c * invmod(g_mk) (mod n^2)
      val u_k = Plaintext((ciphertext * g_mk.modInverse(publicKey.squared)).mod(publicKey.squared))

      u_s = u_s :+ u_k
    }

    val challenge_string   = a_s.foldLeft("")((r, c) => r + c.toString())
    val md                 = java.security.MessageDigest.getInstance("SHA-256")
    val challenge_sha256   = md.digest(challenge_string.getBytes("UTF-8"))
    val challenge_sha256BN = BigInt(1, challenge_sha256)
    val e_sum              = e_s.foldLeft(BigInt(0))((c, r) => c + r.toBigInt).mod(hashmod)

    // require(e_sum == challenge_sha256BN)
    // semantics: should it return an exception or false?
    if (e_sum != challenge_sha256BN)
      return false

    val allLists = List(a_s, e_s, z_s, u_s)

    val verification: List[Boolean] = allLists.transpose.map { l =>
      val a_k = l.head
      val e_k = l(1)
      val z_k = l(2)
      val u_k = l(3)

      //  LHS z_kn = z_k ^ n (mod n^2)
      val z_kn = z_k.toBigInt.modPow(publicKey.n.value, publicKey.squared)

      // RHS u_ke = u_k ^ e_k (mod n^2)
      val u_ke = u_k.toBigInt.modPow(e_k.toBigInt, publicKey.squared)

      // a_kue = a_k * u_ke (mod n^2)
      val a_kue = (a_k.toBigInt * u_ke).mod(publicKey.squared)

      //z_k ^ n ?= a_k * (u_k ^ e_k)
      z_kn == a_kue
    }
    verification.reduce(_ && _)
  }
}
