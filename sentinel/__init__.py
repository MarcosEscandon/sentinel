"""Sentinel: motor de detección y escaneo de malware modular.

El proyecto se organiza en tres capas:

* ``sentinel.engine``: detección (firmas, heurística, YARA opcional).
* ``sentinel.core``: cuarentena, historial y modelos de datos.
* ``sentinel.cli``: interfaz de línea de comandos.

Todo el código es de uso defensivo: no incluye cargas útiles dañinas.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
