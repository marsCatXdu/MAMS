# Modified NS-3 for MAMS Simulations - Jingwei's Fork

Compile & Run:
```
./waf configure --enable-examples
./waf --run MAMS-test-2
```

Generate PNG Figure:
```
gnuplot -e "set terminal pngcairo; load 'FlowVSThroughput_.plt'"
```
