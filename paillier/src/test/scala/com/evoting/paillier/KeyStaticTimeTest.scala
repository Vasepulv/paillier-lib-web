package com.evoting.paillier

import com.evoting.paillier.crypto.keys.KeyGenerator
import com.evoting.paillier.crypto.keys.PrivateThresholdKey
import org.scalatest._
import flatspec._


class KeyStaticTimeTest extends AnyFlatSpec {

  import Numeric.Implicits._

  def mean[T: Numeric](xs: Iterable[T]): Double = xs.sum.toDouble / xs.size

  def variance[T: Numeric](xs: Iterable[T]): Double = {
    val avg = mean(xs)

    xs.map(_.toDouble).map(a => math.pow(a - avg, 2)).sum / xs.size
  }

  def stdDev[T: Numeric](xs: Iterable[T]): Double = math.sqrt(variance(xs))

  def time[R](block: => R): Long = {
    val t0 = System.currentTimeMillis()
    val result = block    // call-by-name
    val t1 = System.currentTimeMillis()
    //println("Elapsed time: " + (t1 - t0) + "ms")
    result
    (t1 - t0)
  }

  val l = 5
  val w = 3


  "The public key" should "have the required bits" in {

    val keys1: Seq[Long] = for(i <- 1 to 20) yield time(KeyGenerator.genThresholdKeys(512, l, w))
    println("keys1")
    println(mean(keys1))
    println(variance(keys1))
    println(stdDev(keys1))

    val keys2: Seq[Long] = for(i <- 1 to 20) yield time(KeyGenerator.genThresholdKeys(1024, l, w))
    println("keys2")
    println(mean(keys2))
    println(variance(keys2))
    println(stdDev(keys2))

    val keys3: Seq[Long] = for(i <- 1 to 20) yield time(KeyGenerator.genThresholdKeys(2048, l, w))
    println("keys3")
    println(mean(keys3))
    println(variance(keys3))
    println(stdDev(keys3))

    val keys4: Seq[Long] = for(i <- 1 to 10) yield time(KeyGenerator.genThresholdKeys(3072, l, w))
    println("keys4")
    println(mean(keys4))
    println(variance(keys4))
    println(stdDev(keys4))

    val keys5: Seq[Long] = for(i <- 1 to 10) yield time(KeyGenerator.genThresholdKeys(4096, l, w))
    println("keys5")
    println(mean(keys5))
    println(variance(keys5))
    println(stdDev(keys5))

    assert(keys1.length == 20)
    assert(keys2.length == 20)
    assert(keys3.length == 20)
    assert(keys4.length == 10)
    assert(keys5.length == 10)
  }



}
 
