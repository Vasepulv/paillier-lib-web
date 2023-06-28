package com

import scala.math.BigInt
import java.security.SecureRandom 
import cats.effect.IO
import cats.effect.IOApp
import cats.effect.SyncIO
import cats.data.EitherT
import com.evoting.paillier.primes.PrimesGenerator
import com.evoting.paillier.crypto.keys.PublicKey
import com.evoting.paillier.crypto.cryptosystem.impl.Paillier
import com.evoting.paillier.crypto.cryptosystem.PartialDecryption
import com.evoting.paillier.crypto.messages._
import com.evoting.paillier.crypto.keys.KeyGenerator
import com.evoting.paillier.crypto.keys.PrivateThresholdKey
import com.evoting.paillier.crypto.PaillierExceptions.AdditionException
import com.evoting.paillier.crypto.PaillierExceptions.DecryptionException
import com.evoting.paillier.crypto.PaillierExceptions.EncryptionException
import com.evoting.paillier.crypto.cryptosystem.impl.zkp.PaillierZKP
import com.evoting.paillier.crypto.cryptosystem.impl.zkp._

import org.scalajs.dom.document


import scala.concurrent.Future


import scala.scalajs.js
import scala.scalajs.js.annotation.{JSExportTopLevel, JSImport}
import scala.scalajs.LinkingInfo
import org.scalajs.dom
import japgolly.scalajs.react._
import japgolly.scalajs.react.vdom.html_<^._

import com.github.plokhotnyuk.jsoniter_scala.macros._
import com.github.plokhotnyuk.jsoniter_scala.core._

import com.BenchmarkPlot._
import com.Sheet._


@JSImport("/src/style.css", JSImport.Default)
@js.native
object IndexCSS extends js.Object

object Main //extends IOApp.Simple
{
  val css = IndexCSS  

  
  implicit val codec: JsonValueCodec[List[Plaintext]] = JsonCodecMaker.make(CodecMakerConfig)

  implicit val codec2: JsonValueCodec[EncryptedMessageWithCommitmentZKP] = JsonCodecMaker.make{CodecMakerConfig
        .withAllowRecursiveTypes(true)}
 
  @JSExportTopLevel("encrypt", moduleID="encryption")
  def encrypt(toEncrypt: String, length:Int, amount:Int, l:Int, w:Int): String = {

    var possible_messages:List[PlainMessage]=generateValidMessages(amount, length)
    val keysIO: SyncIO[Either[Throwable,Vector[PrivateThresholdKey]]] = KeyGenerator.genThresholdKeys((length+2)*32, l, w).map(Right(_))
    
    val plaintext= Plaintext(BigInt(toEncrypt))
    val paillier:EitherT[SyncIO, Throwable, PaillierZKP]=for{
        keys <- EitherT(keysIO)
        paillierSystemZKP= new PaillierZKP(keys.head.publicKey,possible_messages)
      } yield(paillierSystemZKP)

    var startTime=System.currentTimeMillis()

    val resultIO:EitherT[SyncIO,Throwable, EncryptedMessageWithCommitmentZKP] = for {
        paillierSystemZKP <- paillier
        ciphertext    <- EitherT(paillierSystemZKP.encryptWithZKP(plaintext))
        validCipher <- EitherT(paillierSystemZKP.verifyZKP(ciphertext))
      } yield (ciphertext)

    val result=resultIO.value
    val res=result.unsafeRunSync()
    val res2= res match{
        case Left(err) => ""
        case Right(enc) => writeToString(enc)
      }
    val endTime=System.currentTimeMillis()
    val r=endTime-startTime
    println(r)
    res2
  }

}