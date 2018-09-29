#!/bin/bash

function gnu_plot() 
{
  # Use standalone (... epslatex standalone ...) to compile to pdf w/o document
  # echo "set terminal epslatex standalone size 6,3 color colortext 10"
  echo "set terminal pdf"
  filename="$(echo $1 | cut -d '.' -f1)"
  echo "set output '${filename}.pdf'" # tex'"
  echo "set style line 1 lc rgb '#000000' lt 1 lw 0 pt 7 ps 0.5 pi 0"
  echo "set style line 2 lc rgb '#000000' lt 2 lw 0 pt 6 ps 0.3 pi 0"
  echo "set style line 3 lc rgb '#666666' lt 3 lw 0 pt 5 ps 0.3 pi 0"
  echo "set style line 4 lc rgb '#666666' lt 4 lw 0 pt 4 ps 0.3 pi 0"
  echo "set style line 5 lc rgb '#bbbbbb' lt 5 lw 0 pt 3 ps 0.3 pi 0"
  echo "set style line 6 lc rgb '#bbbbbb' lt 6 lw 0 pt 2 ps 0.3 pi 0"
  echo "set title  \"\""
  echo "set xlabel \"Message Length (bytes)\""
  echo "set ylabel \"Performance (cpb)\""
  echo "set logscale x 2"
  echo "set grid ytics ls 3"
  echo "set grid xtics ls 8"
  echo "set xrange [128:65536]"
  echo "set yzeroaxis"
  echo "set yrange [0:20]"
  echo "set title  \"\""
  # echo -n "plot 0.25 title '', '$1' with linespoints ls 1 title '$2'"
  echo -n "plot '$1' with linespoints ls 1 title '$2'"
  COUNTER=2
  # NEXT=0
  arg=("$@")
  for (( i=2; i<$#; i+=2 ))
  do
    echo ", \\"
    echo -n "      '${arg[i]}' with linespoints ls $COUNTER title '${arg[i+1]}'"
    COUNTER=$((COUNTER + 1))
  done
}

function usage()
{
  echo "Usage: $0 <data-file(s)>"
  echo "- <data-file>: (<=6) File with two-column layout of message length, speed"
  echo "  16 300"
  echo "  32 200"
  echo "  .. ..."
}

if [ \( $# -eq 0 \)  -o \( $# -gt 14 \) ];then
  usage > /dev/stderr
  exit 1
fi
# 

gnu_plot $@ > $1.gp
gnuplot $1.gp
rm $1.gp
exit 0
