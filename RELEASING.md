# Releasing

The package is published under the name `airbag-git` (the plain name `airbag` on PyPI belongs to another project).
The command you run is still `airbag`.

1. Bump `version` in `pyproject.toml` and `__version__` in `airbag/__init__.py`, and merge to `main` once CI is green.
2. Tag and publish a GitHub Release (`vX.Y.Z`). The Release workflow builds the package and attaches the sdist and wheel to it.
3. To publish to PyPI (needs your PyPI account and an API token):

   ```bash
   python -m pip install build twine
   python -m build
   python -m twine check dist/*
   python -m twine upload dist/*
   ```

4. After the first upload, change the README's install section to `pip install airbag-git`.
