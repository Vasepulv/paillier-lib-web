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

@JSImport("/src/index.css", JSImport.Default)
@js.native
object IndexCSS extends js.Object

object Main //extends IOApp.Simple
{
  val css = IndexCSS

  def generateTextParagraph(): Unit = {
    import org.scalajs.dom.document
    val paragraph = document.createElement("p")
    paragraph.textContent = "Esta es una pagina de prueba2"
    document.body.appendChild(paragraph)
}


  @react class ElectionReact extends Component{
    case class Props(length: Int, amount:Int, l:Int, w:Int)

    case class State(plaintext:BigInt)

    def initialState: State=State(BigInt(0))

    val keysIO: SyncIO[Vector[PrivateThresholdKey]] = KeyGenerator.genThresholdKeys((props.length+2)*32, props.l, props.w)

    private def superEncrypt()= {

      val plaintext= state.plaintext

      val resultIO = for {
        keys          <- keysIO
        paillierSystem = new Paillier(keys.head.publicKey)
        ciphertext    <- paillierSystem.encrypt(Plaintext(plaintext))
      } yield (keys, paillierSystem, ciphertext)

      val result =resultIO.map{
        case (keys, paillierSystem, ciphertext) => ciphertext match{
          case Left(err) =>
          case Right(cipher) => keys.combinations(props.w).map{
            e => paillierSystem.combine(e.map(p => PartialDecryption(p, cipher)))
          }.toList
        }
      }
      println(result.unsafeRunSync())
    }

    def encryptHandle(bigint:BigInt)={
      setState(State(bigint))
      this.superEncrypt()
    }

    def render()={
      div(Sheet(props.length, props.amount, state.plaintext, this.encryptHandle))
    }
  }

  
  @JSExportTopLevel("main")
  def main(args: Array[String]): Unit = {
    //generateTextParagraph()
    import org.scalajs.dom.document

    val length = 5
    val amount = 3
    val l=3
    val w =2
    
    ReactDOM.render(
      div(ElectionReact(length,amount,l,w)),
      document.getElementById("root")
    )

}

}