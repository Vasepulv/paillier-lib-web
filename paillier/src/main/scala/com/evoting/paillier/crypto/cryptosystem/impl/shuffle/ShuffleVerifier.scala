package com.evoting.paillier.crypto.cryptosystem.impl.shuffle

import cats.effect.IO
import cats.effect.SyncIO
import cats.implicits.toTraverseOps
import com.evoting.paillier.crypto.keys.PublicKeyLike
import com.evoting.paillier.crypto.messages.EncryptedMessage
import com.evoting.paillier.primes.PrimesGenerator.getBigIntRandomStream

trait ShuffleVerifierLike {

  def generateChallenge(pc: ProverCommitmentLike): SyncIO[Either[Throwable, ChallengeLike]]

  def verifyResponse(pc: ProverCommitmentLike, pr: ProverResponseLike): Either[Throwable, Boolean]
}

case class ShuffleVerifier(
    publicKey: PublicKeyLike,
    encryptedMessages: Vector[EncryptedMessage],
    reencryptedMessages: Vector[EncryptedMessage],
    publicCiphertexts: Vector[EncryptedMessage]
) extends ShuffleVerifierLike {
  // Class based on the verifier in the shuffle verification procedure of
  // https://www.researchgate.net/publication/221651791_Verifiable_Shuffles_A_Formal_Model_and_a_Paillier-Based_Efficient_Construction_with_Provable_Security

  override def generateChallenge(proverCommitment: ProverCommitmentLike): SyncIO[Either[Throwable, Challenge]] =
    proverCommitment match {
      case ProverCommitment(gtp_s, _, _, _, _, _, _, _) =>
        for {
          c <- getBigIntRandomStream(publicKey.bitLength).take(gtp_s.length).map(v => v.mod(publicKey.n.value)).compile.toVector
        } yield Right(Challenge(c))
      case _                                            => SyncIO.fromEither(Left(new Exception(s"Invalid match, expected $ProverCommitment, got ${proverCommitment.getClass}.")))
    }

  override def verifyResponse(pc: ProverCommitmentLike, pr: ProverResponseLike): Either[Throwable, Boolean] =
    (pc, pr) match {
      case (ProverCommitment(gtp_s, gtp, gp, td_s, vd_s, wd_s, vd, wd), ProverResponse(c, s_s, st, s, u, v)) =>
        val N       = publicKey.n.value
        val N2      = publicKey.squared
        val indices = encryptedMessages.indices

        // st ^ N * prod(gt_i ^ s_i)                  =   gtp * prod(gtp_i ^ c_i)                   mod N^2
        val eq1 = (st.modPow(N, N2) * indices.foldLeft[BigInt](1)((cur, i) =>
          (cur * publicCiphertexts(i).toBigInt
            .modPow(s_s(i), N2)).mod(N2)
        )).mod(N2) == (gtp * indices.foldLeft[BigInt](1)((cur, i) =>
          (cur * gtp_s(i)
            .modPow(c.value(i), N2)).mod(N2)
        )).mod(N2)

        // s ^ N * prod(g_i ^ s_i)                    =   gp * prod(gp_i ^ c_i)                     mod N^2
        val eq2 = (s.modPow(N, N2) * indices.foldLeft[BigInt](1)((cur, i) =>
          (cur * encryptedMessages(i).toBigInt
            .modPow(s_s(i), N2)).mod(N2)
        )).mod(N2) == (gp * indices.foldLeft[BigInt](1)((cur, i) =>
          (cur * reencryptedMessages(i).toBigInt
            .modPow(c.value(i), N2)).mod(N2)
        )).mod(N2)

        // u ^ N * (1 + N * sum(s_i ^ 3 - c_i ^ 3))   =   vd * prod(vd_i ^ c_i * td_i ^ (c_i ^ 2))  mod N^2
        val eq3 = (u.modPow(N, N2) * (1 + N * indices.foldLeft[BigInt](0)((cur, i) =>
          cur + s_s(i).modPow(3, N2) - c
            .value(i)
            .modPow(3, N2)
        ))).mod(N2) == (vd * indices.foldLeft[BigInt](1)((cur, i) =>
          (cur * vd_s(i)
            .modPow(c.value(i), N2) * td_s(i).modPow(c.value(i).pow(2), N2)).mod(N2)
        )).mod(N2)

        // v ^ N * (1 + N * sum(s_i ^ 3 - c_i ^ 3))   =   wd * prod(wd_i ^ c_i)                     mod N^2
        val eq4 = (v.modPow(N, N2) * (1 + N * indices.foldLeft[BigInt](0)((cur, i) =>
          cur + s_s(i)
            .modPow(2, N2) - c.value(i).modPow(2, N2)
        ))).mod(N2) == (wd * indices.foldLeft[BigInt](1)((cur, i) =>
          (cur * wd_s(i)
            .modPow(c.value(i), N2)).mod(N2)
        )).mod(N2)

        Right(eq1 && eq2 && eq3 && eq4)

      case _                                                                                                 =>
        Left(
          new Exception(
            s"Invalid match, expected ($ProverCommitmentArbitrary, $ProverResponseArbitrary), " +
              s"got (${pc.getClass}, ${pr.getClass}."
          )
        )

    }
}

case class ShuffleVerifierArbitrary(
    publicKey: PublicKeyLike,
    encryptedMessages: Vector[Vector[EncryptedMessage]],
    reencryptedMessages: Vector[Vector[EncryptedMessage]],
    publicCiphertexts: Vector[EncryptedMessage]
) extends ShuffleVerifierLike {

  val tEncryptedMessages: Vector[Vector[EncryptedMessage]] = encryptedMessages.transpose

  val tReencryptedMessages: Vector[Vector[EncryptedMessage]] = reencryptedMessages.transpose

  val shuffleVerifiers: Vector[ShuffleVerifier] = tEncryptedMessages.indices
    .map(i => ShuffleVerifier(publicKey, tEncryptedMessages(i), tReencryptedMessages(i), publicCiphertexts))
    .toVector

  override def generateChallenge(pc: ProverCommitmentLike): SyncIO[Either[Throwable, ChallengeArbitrary]] =
    pc match {
      case ProverCommitmentArbitrary(commitments) =>
        val challengesIO = commitments.zipWithIndex.map(t => shuffleVerifiers(t._2).generateChallenge(t._1)).sequence.map(_.sequence)
        challengesIO.map(challenges => challenges.map(c => ChallengeArbitrary(c)))
      case _                                      => SyncIO.fromEither(Left(new Exception(s"Invalid match, expected $ProverCommitmentArbitrary, got ${pc.getClass}.")))
    }

  override def verifyResponse(pc: ProverCommitmentLike, pr: ProverResponseLike): Either[Throwable, Boolean] =
    (pc, pr) match {
      case (ProverCommitmentArbitrary(commitments), ProverResponseArbitrary(responses)) =>
        val verifications = for {
          i <- shuffleVerifiers.indices
        } yield shuffleVerifiers(i).verifyResponse(commitments(i), responses(i))
        verifications.toVector.sequence.map(v => v.reduce((a, b) => a && b))
      case _                                                                            =>
        Left(
          new Exception(
            s"Invalid match, expected ($ProverCommitmentArbitrary, $ProverResponseArbitrary), got" +
              s" (${pc.getClass}, ${pr.getClass}."
          )
        )
    }
}
