package com

import scala.math.BigInt
import java.security.SecureRandom 
import cats.effect.IO
import cats.effect.IOApp
import cats.effect.SyncIO
import com.evoting.paillier.primes.PrimesGenerator
import com.evoting.paillier.crypto.cryptosystem.impl.Paillier
import com.evoting.paillier.crypto.messages.Ciphertext
import com.evoting.paillier.crypto.messages.Plaintext
import com.evoting.paillier.crypto.keys.KeyGenerator
import com.evoting.paillier.crypto.keys.PrivateThresholdKey

import scala.scalajs.js
import org.scalajs.dom
import com.raquo.laminar.api.L._
import com.raquo.laminar.api.features.unitArrows
object Main //extends IOApp.Simple
{
  def generateTextParagraph(): Unit = {
    import org.scalajs.dom.document
    val paragraph = document.createElement("p")
    paragraph.textContent = "Esta es una pagina de prueba2"
    document.body.appendChild(paragraph)
}

  def getCiphertext(bigint:BigInt,keysIO:SyncIO[Vector[PrivateThresholdKey]]):String ={
    val plaintext = Plaintext(bigint)

    val resultIO = for {
        keys          <- keysIO
        paillierSystem = new Paillier(keys.head.publicKey)
        ciphertext    <- paillierSystem.encrypt(plaintext)
      } yield (keys, paillierSystem, ciphertext)


    val (keys, paillier, ciphertext)=resultIO.unsafeRunSync()
    val result=ciphertext match {
      case Left(err)=>"ERROR"
      case Right(cipher)=>cipher.toBigInt.toString
    }
    result
  }

  

  def main(args: Array[String]): Unit = {
    //generateTextParagraph()
    lazy val appContainer=dom.document.createElement("div")
    appContainer.id="appContainer"
    dom.document.body.appendChild(appContainer)

    val keysIO: SyncIO[Vector[PrivateThresholdKey]] = KeyGenerator.genThresholdKeys(512, 5, 3)
    
 
    val diffBus = new EventBus[String]
    val cipherBus=new EventBus[String]
    val inputMods = Seq(typ := "text", defaultValue := "1") 
    val keys=keysIO.unsafeRunSync().toSeq
    val keyStream =EventStream.fromSeq(keys.map(e => e.publicKey.toBigInt.toString))
    
    val example=div(
      h2("Genere un numero entero grande", color := "red"),
      input(inputMods, nameAttr := "numeroGrande", 
      value <-- cipherBus, onInput.mapToValue --> cipherBus),
      div(s"${nbsp}"),
      button("Click",color :="red", typ("button"),value <-- cipherBus, onClick.mapToValue --> diffBus )      //button(onClick()-->)
    )
    val diffStream: EventStream[String]=diffBus.events
    val stream:EventStream[String]=diffStream.map(e => getCiphertext(BigInt(e),keysIO))

    val example2=div(
      div("Llave escogida: ", child.text <-- keyStream),
      div("Valor escogido: ",child.text <-- diffStream),
      div("Resultado (Encriptado): ", child.text <-- stream)
    )
    val root: RootNode = render(appContainer, example)
    render(appContainer,example2)
}

}