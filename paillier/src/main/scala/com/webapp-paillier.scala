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

import org.scalajs.dom.document


import scala.concurrent.Future


import scala.scalajs.js
import scala.scalajs.js.annotation.{JSExportTopLevel, JSImport}
import scala.scalajs.LinkingInfo
import org.scalajs.dom
import japgolly.scalajs.react._
import japgolly.scalajs.react.vdom.html_<^._

import slinky.core._
import slinky.web.ReactDOM
import slinky.web.html._
import slinky.core.annotations.react
import slinky.web.html._

import com.BenchmarkPlot._
import com.Sheet._

@JSImport("/src/style.css", JSImport.Default)
@js.native
object IndexCSS extends js.Object

object Main //extends IOApp.Simple
{
  val css = IndexCSS

  @react class ElectionReact extends Component{
    case class Props(length: Int, amount:Int, l:Int, w:Int)

    case class State(plaintext:BigInt)

    def initialState: State=State(BigInt(0))

    val keysIO: SyncIO[Either[Throwable,Vector[PrivateThresholdKey]]] = KeyGenerator.genThresholdKeys((props.length+2)*32, props.l, props.w).map(Right(_))

    var possible_messages:List[PlainMessage]=generateValidMessages(props.amount, props.length)

    private def superEncrypt()
      //:List[Either[Throwable, PlainMessage]]
      ={

      val plaintext= state.plaintext

      val resultIO:EitherT[SyncIO,Throwable, Boolean] = for {
        keys          <- EitherT(keysIO)
        paillierSystemZKP = new PaillierZKP(keys.head.publicKey,possible_messages)
        ciphertext    <- EitherT(paillierSystemZKP.encryptWithZKP(Plaintext(plaintext)))
        validCipher <- EitherT(paillierSystemZKP.verifyZKP(ciphertext))
      } yield (validCipher)

      /*val result:SyncIO[List[Either[Throwable, PlainMessage]]] =resultIO.map{
        case (keys, paillierSystem, ciphertext) => ciphertext match{
          case Left(err) => List(Left(DecryptionException("Error al desencriptar")))
          case Right(cipher) => keys.combinations(props.w).map{
            e => paillierSystem.combine(e.map(p => PartialDecryption(p, cipher)))
          }.toList
        }
      }*/

      val result=resultIO.value
    
      println(possible_messages.length)
      println(result.unsafeRunSync())
    }

    def encryptHandle(bigint:BigInt)={
      setState(State(bigint), () =>this.superEncrypt())
    }

    def render()={
      Sheet(props.length, props.amount, state.plaintext, this.encryptHandle)
    }
  }
  
  @JSExportTopLevel("encrypt", moduleID="encryption")
  def encrypt(length:Int, amount:Int, l:Int, w:Int): Unit = {
    //generateTextParagraph()
    ReactDOM.render(
      div(ElectionReact(length,amount,l,w)),
      document.getElementById("root"))

}

}