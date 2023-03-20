# Profiling

## Perf FlameGraphs
https://www.brendangregg.com/FlameGraphs/cpuflamegraphs.html

Get code from GitHub:
```
git clone https://github.com/brendangregg/FlameGraph
cd FlameGraph
```

Sample system with perf:
```
sudo perf record -F 99 -a -g -- sleep 10
sudo perf script | ./stackcollapse-perf.pl > out.perf-folded
./flamegraph.pl out.perf-folded > perf.svg
```

## Intel VTune

After installing VTune (on the monitoring device), set up the environment variables:
```
source <install-dir>/setvars.sh
```

Then start the VTune GUI:
```
vtune-gui
```

### Sampling Driver

The source is located in the VTune Profiler installation directory `<install_dir>/sepdk`. For remote targets, the source is located in `<install_dir>/target`, which can be copied to the remote and extracted there.

The installation is described in `sepdk/src/README.md`.

```shell
cd /path/to/sepdk/src/  #/opt/intel/oneapi/vtune/latest/sepdk/src
./build-driver          #maybe sudo 
sudo ./rmmod-sep
sudo ./insmod-sep
```

Add user to vtune group:
```
sudo usermod -a -G vtune <username>
```