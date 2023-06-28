import './style.css'
import {BenchmarkPlot} from '../target/scala-2.13/paillier-fastopt/benchmark.js' 
import {combinations } from 'mathjs'
import Plotly from 'plotly.js-dist-min'

const xArrayAmount=Array.from({length:1},(_, index) => index+32)
const amountArrayC=Array.from({length:2},(_,index)=> index+1)
const yArrayCombinations=xArrayAmount.map(f => 2 + amountArrayC.map(e => combinations(f,e)).reduce((l,r)=>l+r,0))
const yArrayAmount=BenchmarkPlot.generateValidMessages(2,32)
console.log(yArrayCombinations)
console.log(yArrayAmount)