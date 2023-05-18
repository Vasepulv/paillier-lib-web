
package com.evoting.paillier.util

import scala.annotation.tailrec

object Utils {
  def fact(n: BigInt): BigInt = {
    @tailrec
    def factorialAccumulator(acc: BigInt, n: BigInt): BigInt = {
      if (n == 0) acc
      else factorialAccumulator(n*acc, n-1)
    }
    factorialAccumulator(1, n)
  }

  implicit class ListWithInsert[T](val list: List[T]) extends AnyVal {
    def insert(i: Int, values: T*): List[T] = {
      val (front, back) = list.splitAt(i)
      front ++ values ++ back
    }
  }
}
