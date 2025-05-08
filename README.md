# Modified NS-3 for MAMS Simulations - Jingwei's Fork

Simulation code are in `scratch` directory, `MAMS-test-2.cc` is for MAMS simulation, `MAMS-test-late.cc` is for LATE, `MAMS-test-rr` is for MPQUIC-RR

Compile & Run:
```
./waf configure --enable-examples
./waf --run MAMS-test-2
```

Generate PNG Figure:
```
gnuplot -e "set terminal pngcairo; load 'FlowVSThroughput_.plt'"
```
