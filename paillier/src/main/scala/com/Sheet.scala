package com

import com.evoting.paillier.crypto.messages.Plaintext


import slinky.core._
import slinky.web.ReactDOM
import slinky.web.html._
import slinky.core.annotations.react
import slinky.core.facade.Hooks._

@react class ListCandidates extends Component{

    case class Props(listName : List[String], length:Int, listB: List[Int], handleClick: Int => Unit)
    val listC=props.listName

    case class State(listC:List[Int])

    def initialState: State = State(props.listB)


    def render() ={
        val component =listC.map(m => div(
            h3(m),
        input(`type`:="checkbox", onClick:={(e) => props.handleClick(e.target.value.toInt)}, value:=listC.indexOf(m).toString),key:=m))   
        component  
    }
}


@react class Sheet extends Component{
    case class Props(length: Int, amount: Int, plaintext: BigInt, superEncrypt: BigInt => Unit)

    case class State(plaintext:BigInt, listBoolean: List[Int])

    def initialState: State = State(props.plaintext, List.fill(props.length)(0))

    val firstN = List.range(1, props.length+1)

    val candidates = firstN.map(e => f"Candidato $e")
    val amount=props.amount

    private def handleEncrypt()={
        //Revisar para cual lado es el mas significativo. Si es el de izquierda o el de derecha.
        val nullValue = (state.listBoolean.filter(e => e == 1).length  > amount)
        val nullValueInt=List(nullValue).map(e => if (e==true) 1 else 0).head
        
        val length = state.listBoolean.filter(e => e == 1).length
        val blankValue = (length < amount && !nullValue)
        val blankValueInt=List(blankValue).map(e => if (e==true) (amount-length) else 0).head
        
        var bigIntString=(BigInt(blankValueInt) << 32*(amount)) + (BigInt(nullValueInt) << (32*(amount -1)))
        val listB= state.listBoolean
        val newValue = listB.zipWithIndex.map{case (a,i) => (BigInt(a) << (32*(amount-2+i)))}.reduce((a,b) => a+b)
        bigIntString = bigIntString + newValue
        println(bigIntString.toString)
        //bigIntString = bigIntString + newValue
        //println(bigIntString.toBinaryString)
        //val bigint= (BigInt(state.listBoolean(0))) + (BigInt(state.listBoolean(1)))+ (BigInt(state.listBoolean(2).toString))
        //println(bigint)   
        
        props.superEncrypt(bigIntString)
    }

    def handleClick(index: Int)={
        val listB=state.listBoolean.take(props.length+1)
        val isChecked=listB(index)
        val newList=listB.updated(index, (isChecked+1)%2)
        println(newList)
        setState(State(state.plaintext,newList))
    }

    def render()={
        div(
            h2("Vote por una opcion"),
            ListCandidates(candidates, props.length, state.listBoolean, this.handleClick),
            div("\n"),
            div("\n"),
            button("Click me",name:="resp", className:="button-14", `type`:="button", onClick:={() => handleEncrypt()})
        )
    }

}


