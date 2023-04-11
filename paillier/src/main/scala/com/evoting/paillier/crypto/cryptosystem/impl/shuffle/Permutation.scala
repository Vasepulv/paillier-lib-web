package com.evoting.paillier.crypto.cryptosystem.impl.shuffle

import java.security.SecureRandom

import scala.util.Random

case class Permutation(value: Vector[Int]) {

  val invertedPermutation: Vector[Int] = value.zipWithIndex.sortWith(_._1 < _._1).map(_._2)
}

object Permutation {

  def apply(n: Int): Permutation =
    new Permutation(Random.javaRandomToRandom(new SecureRandom()).shuffle((0 until n).toVector))
}
