package com

import scala.scalajs.js
import scala.scalajs.js.annotation.{JSExportTopLevel, JSImport, JSExport}
import scala.scalajs.LinkingInfo
import org.scalajs.dom
import japgolly.scalajs.react._
import japgolly.scalajs.react.vdom.html_<^._
import org.scalajs.dom.document

import slinky.core._
import slinky.web.ReactDOM
import slinky.web.html._
import slinky.core.annotations.react
import slinky.web.html._

import org.nspl._
import org.nspl.canvasrenderer._
import scala.util.Random.nextDouble

import com.evoting.paillier.crypto.messages._

@JSExportTopLevel("BenchmarkPlot",moduleID="benchmark")
object BenchmarkPlot{
   val css = IndexCSS

        @JSExport
        def generateValidMessages(amount:Int, length:Int):List[PlainMessage]={
        // (amount 0)(000)
        //Obtener todas las permutaciones posibles
        val amountValue =List.range(1, amount+1)
        val example=amountValue.map{e => ("1"*e) + ("0" * (length -e))}
        val iterator=example.map{e => e.permutations}

        //Con amount blank
        val blankV=List(amount.toString+"|0|" + ("0"*(length)))

        val blankList=List.range(0,amount)
        val m=amountValue.map{e => iterator(amount -e).toList}
        val z=blankList.map{e => m(e).map{f => (e).toString +"|0|" + f}}.flatten

        // Con null
        val nullVote=List("0|1|"+("0"*length))
   
        val totalList:List[String]=nullVote.head :: blankV.head :: z
        val possible_messages= totalList.map(e => Plaintext(encodeToBigInt(e, length)))

        //println(possible_messages)
        possible_messages

    }

    def encodeToBigInt(str:String, length:Int)={
      //Transforma un string en un bigint
      val strArray=str.split('|')

      val blank=strArray(0)
      val nullV =strArray(1)
      val rest=strArray(2).split("")

      val indices=rest.indices
      var bigint=indices.map{i => BigInt(rest(i)) << (32 * (length -1 -i))}.reduce((a,b) => a+b)
      bigint = (BigInt(blank) << (32*(length+1))) + (BigInt(nullV) << (32*(length))) + bigint
      bigint

      
    }

    def time[R](block: => R) = {
        val t0     = System.currentTimeMillis()
        val result = block // call-by-name
        val t1     = System.currentTimeMillis()
        (t1-t0).toDouble
        }

    @JSExport
    @react class DataPlot extends Component{
        case class Props(length:Int,time:List[Double], iter:Int)

        case class State(time:List[Double])

        def initialState:State= State(props.time)

        val nList=1 to (props.length+1)

        val tupleTime=nList.zip(props.time)

        def render()={
            div(table(thead(tr(th("Cantidad"),th("Tiempo")), className:="thead thead-dark"),
                tbody(tupleTime.map{case (a,b) => tr(td(a.toString),td(b.toString), key:=a.toString)}),            
                 className:="table is-bordered align-self-center"), className:="row")
        }

        
    }
      def calculateTime(amount:Int, length:Int, iter:Int, lTime:List[Double]):List[Double]={
        var t=0d
        var newList=lTime
        var newList2=lTime.take(length+1)
       for (i <- 1 to length){
           for (j <- 0 to iter){
            t=time(generateValidMessages(amount, i))
            val prevValue=newList(i)
            newList2=newList.updated(i, prevValue+t)
            newList=newList2.take(length+1)
          }
        }
        newList=newList.map{e => e/(iter+1)}
        newList
      }

    @JSExport
    def plot(length:Int, amount:Int, iter:Int):Array[Double]={

    val lTime=List.fill(length+1)(0d)
    val time=calculateTime(amount,length,iter,lTime)
    time.toArray
    }
    
}