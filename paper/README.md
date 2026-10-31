# UniShield paper draft (IEEE conference format)

- `unishield_ieee.tex`: the paper, in the IEEE conference template (`IEEEtran`).
- `references.bib`: the bibliography.

## Build

On Overleaf, upload both files and compile with pdfLaTeX (IEEEtran is built in).
Locally, with a TeX distribution:

```bash
pdflatex unishield_ieee && bibtex unishield_ieee && pdflatex unishield_ieee && pdflatex unishield_ieee
```

## Before submission

1. Add the authors and affiliations (placeholders at the top).
2. Check the target conference's call for papers: page limit, template version,
   whether the review is double-blind (if so, remove the GitHub link and
   anonymise the artifact section).
3. Verify every entry in `references.bib` against the publisher's page.
4. Every number comes from `../reports/` (a comment above each table names the
   file). If you re-run the scripts, update the numbers from the new reports.
5. Optional figures: `python scripts/generate_charts.py` writes PNGs to
   `reports/figures/` that can be added with `\includegraphics`.
