package com

import com.evoting.paillier.crypto.messages.Plaintext


import slinky.core._
import slinky.web.ReactDOM
import slinky.web.html._
import slinky.core.annotations.react
import slinky.core.facade.Hooks._


object Sheet{

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

        private def toBigInt(l: List[Int]):BigInt={
            val nullValue = (l.filter(e => e == 1).length  > amount)
            val nullValueInt=List(nullValue).map(e => if (e==true) 1 else 0).head

            if (nullValueInt ==1){
                val bigIntString=BigInt(1) << 32*(props.length)
                return bigIntString

            }
            else{
                val length = l.filter(e => e == 1).length
                val blankValue = (length < amount && !nullValue)
                val blankValueInt=List(blankValue).map(e => if (e==true) (amount-length) else 0).head
        
                var bigIntString=BigInt(blankValueInt) << 32*(props.length+1)
                val newValue = l.zipWithIndex.map{case (a,i) => (BigInt(a) <<(32*(props.length-1-i)))}.reduce((a,b) => a+b)
                bigIntString = bigIntString + newValue
                return bigIntString
            }
        }

        private def handleEncrypt()={
        //Revisar para cual lado es el mas significativo. Si es el de izquierda o el de derecha.
            val bigIntString=toBigInt(state.listBoolean)
            println(bigIntString.toString)
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
                button("Votar", className:="button", `type`:="button", onClick:={() => handleEncrypt()})
            )
        }

}


}