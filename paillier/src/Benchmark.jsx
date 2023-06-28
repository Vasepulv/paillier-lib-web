
import './style.css'
import {BenchmarkPlot} from '../target/scala-2.13/paillier-fastopt/benchmark.js' 
import {combinations } from 'mathjs'
import Plotly from 'plotly.js-dist-min'

var data=window.location.href.split("?");
data=data[1].split("&");

var length=Number(data[0].split("=")[1]);
var amount=Number(data[1].split("=")[1]);
var iter=Number(data[2].split("=")[1]);

var time=BenchmarkPlot.plot(length,amount,iter);
time=time.u

const length0=100
const amount0=1
const xArray1=Array.from({length:length0},(_, index)=> index+1)
const amountArray1=Array.from({length:amount0},(_,index )=> index+1)
const yArray1=xArray1.map(f => 1+amountArray1.map(e => combinations(f,e)).reduce((l,r) => l+r, 0));

const amount02=2
const xArray2=Array.from({length:length0},(_, index)=> index+2)
const amountArray2=Array.from({length:amount02},(_,index )=> index+1)
const yArray2=xArray2.map(f => 1+amountArray2.map(e => combinations(f,e)).reduce((l,r) => l+r, 0));

const amount03=3
const xArray3=Array.from({length:length0},(_, index)=> index+3)
const amountArray3=Array.from({length:amount03},(_,index )=> index+1)
const yArray3=xArray3.map(f => 1+amountArray3.map(e => combinations(f,e)).reduce((l,r) => l+r, 0));


const dataPlot1={x:xArray1, y:yArray1, mode:"lines"}
const layout1={xaxis:{title:"Cantidad de opciones"},yaxis:{title:"Cantidad de votos validos"},
title:"Cantidad de votos validos al usar n opciones"}
const dataPlot2={x:xArray2, y:yArray2, mode:"lines"}
const dataPlot3={x:xArray3, y:yArray3,mode:"lines"}

const newDataPlot=[dataPlot1,dataPlot2, dataPlot3]
Plotly.newPlot('tester1', newDataPlot, layout1)


const length1=100
const amount1=10
const xArray10=Array.from({length:length1},(_, index)=> index+amount1)
const amountArray10=Array.from({length:amount1},(_,index )=> index+1)
const yArray10=xArray10.map(f => 1+amountArray10.map(e => combinations(f,e)).reduce((l,r) => l+r, 0));

const dataPlot10={x:xArray10, y:yArray10, mode:"lines"}
const layout10={xaxis:{title:"Cantidad de candidatos"},yaxis:{title:"Cantidad de votos validos"},title:"Cantidad de votos validos al usar 10 opciones"}
Plotly.newPlot('tester10', [dataPlot10], layout10)

const length2=1000
const amount2=100
const xArray100=Array.from({length:length2},(_, index) => index+amount2)
const amountArray100=Array.from({length:amount2},(_,index)=> index+1)
const yArray100=xArray100.map(f => 1 + amountArray100.map(e => combinations(f,e)).reduce((l,r)=>l+r,0))

const dataPlot100={x:xArray100, y:yArray100, mode:"lines"}
const layout100={xaxis:{title:"Cantidad de candidatos"},yaxis:{title:"Cantidad de votos validos"},title:"Cantidad de votos validos al usar 100 opciones"}
Plotly.newPlot('tester100',[dataPlot100], layout100)

const length3=50
const amount3=200
const xArray1000=Array.from({length:length3},(_, index) => index+amount3)
const amountArray1000=Array.from({length:amount3},(_,index)=> index+1)
const yArray1000=xArray1000.map(f => 1 + amountArray1000.map(e => combinations(f,e)).reduce((l,r)=>l+r,0))
const dataPlot1000={x:xArray1000, y:yArray1000, mode:"lines"}
const layout1000={xaxis:{title:"Cantidad de candidatos"},yaxis:{title:"Cantidad de votos validos"},title:"Cantidad de votos validos al usar 200 opciones"}
Plotly.newPlot('tester1000',[dataPlot1000], layout1000)


const xArray=Array.from({length:length+1},(_, index) => index +1);
const dataPlot={x:xArray, y:time, type:"bar"}
const layout={xaxis:{title:"Cantidad de Candidatos"}, yaxis:{title:"Tiempo (ms)"},title:"Tiempo en calcular todas los votos validos para n candidatos"}
Plotly.newPlot('root_benchmark', [dataPlot], layout)


