#!/bin/bash
rm *.aux *.log *.toc *.ps *.dvi *.bbl *.blg *.pdf
echo R | latex report.tex
bibtex8 -B -c cp1251.csf report # Not: "bibtex8 -B -c sty/cp1251.csf report", cause my cp1251.csf is bad
echo R | latex report.tex
echo R | latex report.tex
dvips -t portrait report.dvi
ps2pdf report.ps report.pdf
rm *.aux *.log *.toc *.ps *.dvi *.bbl *.blg
