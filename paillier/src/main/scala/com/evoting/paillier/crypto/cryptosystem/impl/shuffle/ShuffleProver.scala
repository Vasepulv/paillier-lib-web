package com.evoting.paillier.crypto.cryptosystem.impl.shuffle

import cats.effect.SyncIO
import cats.implicits.toTraverseOps
import com.evoting.paillier.crypto.keys.PublicKeyLike
import com.evoting.paillier.crypto.messages.CiphertextWithRandomness
import com.evoting.paillier.crypto.messages.EncryptedMessage
import com.evoting.paillier.primes.PrimesGenerator.getBigIntRandomStream

trait ShuffleProverLike {

  def calculateCommitment(): ProverCommitmentLike

  def respondChallenge(challenge: ChallengeLike): Either[Throwable, ProverResponseLike]
}

case class ShuffleProver(
    publicKey: PublicKeyLike,
    encryptedMessages: Vector[EncryptedMessage],
    reencryptedMessages: Vector[CiphertextWithRandomness],
    publicCiphertexts: Vector[EncryptedMessage],
    permutation: Permutation,
    proverParams: ProverParams
) extends ShuffleProverLike {
  // Class based on the prover in the shuffle verification procedure of
  // https://www.researchgate.net/publication/221651791_Verifiable_Shuffles_A_Formal_Model_and_a_Paillier-Based_Efficient_Construction_with_Provable_Security

  override def calculateCommitment(): ProverCommitment = {
    val a    = proverParams.a
    val a_s  = proverParams.a_s
    val rt_s = proverParams.rt_s
    val at   = proverParams.at
    val d_s  = proverParams.d_s
    val p    = proverParams.p
    val p_s  = proverParams.p_s
    val t    = proverParams.t
    val t_s  = proverParams.t_s

    val indices = rt_s.indices
    val N       = publicKey.n.value
    val N2      = publicKey.squared

    ProverCommitment(
      // g~'_i  =   r~_i ^ N * g~_[invper_i]                    mod N^2
      indices.map(i => (rt_s(i).modPow(N, N2) * publicCiphertexts(permutation.invertedPermutation(i)).toBigInt).mod(N2)).toVector,
      // g~'    =   a~ ^ N * prod(g~_i ^ a_i)                   mod N^2
      (at.modPow(N, N2) * indices.foldLeft[BigInt](1)((cur, i) => cur * publicCiphertexts(i).toBigInt.modPow(a_s(i), N2))).mod(N2),
      // g'     =   a ^ N * prod(g_i ^ a_i)                     mod N^2
      (a.modPow(N, N2) * indices.foldLeft[BigInt](1)((cur, i) => cur * encryptedMessages(i).toBigInt.modPow(a_s(i), N2))).mod(N2),
      // t._i   =   d_i ^ N * (1 + N * 3 * a_[invper_i])        mod N^2
      indices.map(i => (d_s(i).modPow(N, N2) * (1 + N * 3 * a_s(permutation.invertedPermutation(i)))).mod(N2)).toVector,
      // v._i   =   p_i ^ N * (1 + N * 3 * a_[invper_i] ^ 2)    mod N^2
      indices.map(i => (p_s(i).modPow(N, N2) * (1 + N * 3 * a_s(permutation.invertedPermutation(i)).modPow(2, N2))).mod(N2)).toVector,
      // w._i   =   t_i ^ N * (1 + N * 2 * a_[invper_i])        mod N^2
      indices.map(i => (t_s(i).modPow(N, N2) * (1 + N * 2 * a_s(permutation.invertedPermutation(i)))).mod(N2)).toVector,
      // v.     =   p ^ N * (1 + N * sum(a_i ^ 3))              mod N^2
      (p.modPow(N, N2) * (1 + N * a_s.foldLeft[BigInt](0)((x, y) => (x + y.modPow(3, N2)).mod(N2)))).mod(N2),
      // w.     =   t ^ N * (1 + N * sum(a_i ^ 2))              mod N^2
      (t.modPow(N, N2) * (1 + N * a_s.foldLeft[BigInt](0)((x, y) => (x + y.modPow(2, N2)).mod(N2)))).mod(N2)
    )
  }

  override def respondChallenge(challenge: ChallengeLike): Either[Throwable, ProverResponse] =
    challenge match {
      case Challenge(c) =>
        val a       = proverParams.a
        val a_s     = proverParams.a_s
        val rt_s    = proverParams.rt_s
        val at      = proverParams.at
        val delta_s = proverParams.d_s
        val p       = proverParams.p
        val p_s     = proverParams.p_s
        val t       = proverParams.t
        val t_s     = proverParams.t_s
        val indices = c.indices
        val N       = publicKey.n.value

        // s_i  =   c_[perm_i] + a_i                              mod N
        val s_s = indices.map(i => (c(permutation.value(i)) + a_s(i)).mod(N)).toVector

        // d_i  =   (c_[perm_i] + a_i - s_i) / N
        val d_s = indices.map(i => (c(permutation.value(i)) + a_s(i) - s_s(i)) / N)

        Right(
          ProverResponse(
            Challenge(c),
            // s_i  =   c_[perm_i] + a_i                            mod N
            s_s,
            // st   =   at * prod(rt_i ^ c_i * gt_i ^ d_i)          mod N
            (at * indices
              .foldLeft[BigInt](1)((cur, i) =>
                (cur * rt_s(i)
                  .modPow(c(i), N) * publicCiphertexts(i).toBigInt.modPow(d_s(i), N)).mod(N)
              )).mod(N),
            // s    =   a * prod(r_i ^ c_i * g_i ^ d_i)             mod N
            (a * indices.foldLeft[BigInt](1)((cur, i) =>
              (cur * reencryptedMessages(i).randomness.value
                .modPow(c(i), N) * encryptedMessages(i).toBigInt.modPow(d_s(i), N)).mod(N)
            )).mod(N),
            // u    =   p * prod(p_i ^ c_i * delta_i ^ (c_i ^ 2))   mod N
            (p * indices.foldLeft[BigInt](1)((cur, i) =>
              (cur * p_s(i).modPow(c(i), N) * delta_s(i)
                .modPow(c(i).pow(2), N)).mod(N)
            )).mod(N),
            // v    =   t * prod(t_i ^ c_i)                         mod N
            (t * indices.foldLeft[BigInt](1)((cur, i) => cur * t_s(i).modPow(c(i), N))).mod(N)
          )
        )
      case _            => Left(new Exception(s"Invalid match, expected $Challenge, got ${challenge.getClass}."))
    }
}

case class ShuffleProverArbitrary(
    publicKey: PublicKeyLike,
    encryptedMessages: Vector[Vector[EncryptedMessage]],
    reencryptedMessages: Vector[Vector[CiphertextWithRandomness]],
    publicCiphertexts: Vector[EncryptedMessage],
    permutation: Permutation,
    proverParams: ProverParams
) extends ShuffleProverLike {

  val tEncryptedMessages: Vector[Vector[EncryptedMessage]] = encryptedMessages.transpose

  val tReencryptedMessages: Vector[Vector[CiphertextWithRandomness]] = reencryptedMessages.transpose

  val shuffleProvers: Vector[ShuffleProver] = tEncryptedMessages.indices
    .map(i => ShuffleProver(publicKey, tEncryptedMessages(i), tReencryptedMessages(i), publicCiphertexts, permutation, proverParams))
    .toVector

  def calculateCommitment(): ProverCommitmentArbitrary = ProverCommitmentArbitrary(shuffleProvers.map(sp => sp.calculateCommitment()))

  def respondChallenge(challenge: ChallengeLike): Either[Throwable, ProverResponseArbitrary] =
    challenge match {
      case ChallengeArbitrary(c) =>
        val responses = for { i <- c.indices } yield shuffleProvers(i).respondChallenge(c(i))
        responses.toVector.sequence.map(r => ProverResponseArbitrary(r))
    }
}

sealed trait ProverCommitmentLike

sealed case class ProverCommitment(gtp_s: Vector[BigInt], gtp: BigInt, gp: BigInt, td_s: Vector[BigInt], vd_s: Vector[BigInt], wd_s: Vector[BigInt], vd: BigInt, wd: BigInt)
    extends ProverCommitmentLike

sealed case class ProverCommitmentArbitrary(commitments: Vector[ProverCommitment]) extends ProverCommitmentLike

case class ProverParams(a: BigInt, a_s: Vector[BigInt], rt_s: Vector[BigInt], at: BigInt, d_s: Vector[BigInt], p: BigInt, p_s: Vector[BigInt], t: BigInt, t_s: Vector[BigInt])

sealed trait ProverResponseLike

case class ProverResponse(c: Challenge, s_s: Vector[BigInt], st: BigInt, s: BigInt, u: BigInt, v: BigInt) extends ProverResponseLike

case class ProverResponseArbitrary(responses: Vector[ProverResponse]) extends ProverResponseLike

sealed trait ChallengeLike

case class Challenge(value: Vector[BigInt]) extends ChallengeLike

case class ChallengeArbitrary(challenges: Vector[Challenge]) extends ChallengeLike

object ProverParams {

  def apply(publicKey: PublicKeyLike, totalMessages: Int): SyncIO[ProverParams] = {
    val randomIO = getBigIntRandomStream(publicKey.bitLength)
      .map(x => x.mod(publicKey.n.value))

    val coprimeIO = getBigIntRandomStream(publicKey.bitLength)
      .filter(p => p.gcd(publicKey.n.value) == 1 && p >= 0 && p < publicKey.n.value)

    for {
      a    <- coprimeIO.take(1).compile.toList.map(_.head)
      a_s  <- randomIO.take(totalMessages).compile.toVector
      rt_s <- coprimeIO.take(totalMessages).compile.toVector
      at   <- coprimeIO.take(1).compile.toList.map(_.head)
      d_s  <- coprimeIO.take(totalMessages).compile.toVector
      p    <- coprimeIO.take(1).compile.toList.map(_.head)
      p_s  <- coprimeIO.take(totalMessages).compile.toVector
      t    <- coprimeIO.take(1).compile.toList.map(_.head)
      t_s  <- coprimeIO.take(totalMessages).compile.toVector
    } yield new ProverParams(a, a_s, rt_s, at, d_s, p, p_s, t, t_s)
  }
}
