#!/usr/bin/env python3

import argparse
from typing import List, Tuple
import numpy
from numpy import log2
import matplotlib.pyplot as pyplot
import seaborn

# ----------------------------------------------------------
# Necessary to setup the LaTeX font cache to plot TeX expressions.
# ----------------------------------------------------------

_COMMENT_CHAR = '#'


# ----------------------------------------------------------

def plot(x_values: List[int], y_values: List[float], out_path: str) -> None:
    seaborn.set_style("whitegrid")
    seaborn.axes_style("whitegrid") 
    seaborn.set_style("ticks",
                      {"xtick.major.size": 8, "ytick.major.size":8})

    plot = seaborn.lineplot(x_values, y_values)
    plot.set(xscale="log")
    
    axes = plot.axes
    axes.set_ylim(0,20)
    axes.xticks = [2**i for i in range(7, 16)]
    axes.yticks = [0, 5, 10, 15, 20]

    figure = plot.get_figure()

    # pyplot.title(r'SPRP-Advantage')
    figure.savefig(out_path + ".eps")
    figure.savefig(out_path + ".pdf")


# ---------------------------------------------------------

def get_tuple(line: str) -> Tuple[int, int]:
    if (line is None) or (len(line) < 1):
        return None, None

    line = line.strip()

    if (len(line) < 1) or (line[0] == _COMMENT_CHAR):
        return None, None

    item = line.split(' ')

    if (item is None) or (len(item) < 2):
        return None, None

    return int(item[0]), float(item[1])


# ---------------------------------------------------------

def read(in_path: str) -> Tuple[List[int], List[float]]:
    x_values = []
    y_values = []

    with open(in_path, "r") as f:
        for line in f.readlines():
            x, y = get_tuple(line)

            if x is None:
                continue

            x_values.append(x)
            y_values.append(y)

    return x_values, y_values


# ---------------------------------------------------------

def parse_args() -> (int, int):
    parser = argparse.ArgumentParser(description="""
        Plots an input file of a 2-dimensional list given as a spaces-separated 
        as two columns <x> <y> per line as a line plot with log scale
        of the x axis.""")
    parser.add_argument("-i",
                        "--input",
                        help="Path to input dat file",
                        type=str,
                        required=True)
    parser.add_argument("-o",
                        "--output",
                        help="Output path",
                        type=str,
                        required=True)
    args = parser.parse_args()
    return args.input, args.output


# ---------------------------------------------------------

def main():
    in_path, out_path = parse_args()
    x_values, y_values = read(in_path)
    plot(x_values, y_values, out_path)


# ---------------------------------------------------------

if __name__ == '__main__':
    main()
